// Command harness drives the oracle (wireguard-go) through a set of
// deterministic scenarios and writes snapshot files used by twinshot to
// verify the Crystal port byte-for-byte.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sort"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ratelimiter"
	"golang.zx2c4.com/wireguard/replay"
	"golang.zx2c4.com/wireguard/tai64n"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

var outDir string

func writeSnap(name string) *bufio.Writer {
	f, err := os.Create(filepath.Join(outDir, name))
	if err != nil {
		panic(err)
	}
	w := bufio.NewWriter(f)
	return w
}

func doneSnap(w *bufio.Writer, name string) {
	if err := w.Flush(); err != nil {
		panic(err)
	}
	_ = w
	fmt.Println("wrote", name)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// ---------------------------------------------------------------- 01 x25519

const sk1Hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
const sk2Hex = "5152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70"

func snapX25519() {
	w := writeSnap("01_x25519.txt")
	defer doneSnap(w, "01_x25519.txt")

	// mirror device.NoisePrivateKey.{FromHex,publicKey,sharedSecret}: the
	// exported FromHex clamps, the unexported crypto helpers call x/crypto.
	clamp := func(sk []byte) {
		sk[0] &= 248
		sk[31] = (sk[31] & 127) | 64
	}
	pubkey := func(sk []byte) []byte {
		var pk [32]byte
		curve25519.ScalarBaseMult(&pk, (*[32]byte)(sk))
		return pk[:]
	}
	shared := func(sk, pk []byte) ([]byte, error) {
		var ss [32]byte
		curve25519.ScalarMult(&ss, (*[32]byte)(sk), (*[32]byte)(pk))
		if bytes.Equal(ss[:], make([]byte, 32)) {
			return ss[:], fmt.Errorf("invalid public key")
		}
		return ss[:], nil
	}

	sk1 := mustHex(sk1Hex)
	sk2 := mustHex(sk2Hex)
	clamp(sk1)
	clamp(sk2)
	pk1 := pubkey(sk1)
	pk2 := pubkey(sk2)
	fmt.Fprintf(w, "pk1=%x\n", pk1)
	fmt.Fprintf(w, "pk2=%x\n", pk2)

	ss1, err1 := shared(sk1, pk2)
	ss2, err2 := shared(sk2, pk1)
	fmt.Fprintf(w, "ss1=%x\n", ss1)
	fmt.Fprintf(w, "ss2=%x\n", ss2)
	fmt.Fprintf(w, "ss_equal=%v err1=%v err2=%v\n", bytes.Equal(ss1, ss2), err1, err2)

	// RFC 7748 section 6.1 agent scalars (clamped, like NoisePrivateKey.FromHex).
	aSk := mustHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	bSk := mustHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	clamp(aSk)
	clamp(bSk)
	aPk := pubkey(aSk)
	bPk := pubkey(bSk)
	ssa, erra := shared(aSk, bPk)
	fmt.Fprintf(w, "rfc7748_apk=%x\n", aPk)
	fmt.Fprintf(w, "rfc7748_bpk=%x\n", bPk)
	fmt.Fprintf(w, "rfc7748_ss=%x err=%v\n", ssa, erra)

	// low-order public key: all-zero shared secret must be rejected
	_, err := shared(sk1, make([]byte, 32))
	fmt.Fprintf(w, "zero_pk_err=%v\n", err)
}

// ------------------------------------------------------------- 02 hash / kdf

func snapHashKdf() {
	w := writeSnap("02_hash_kdf.txt")
	defer doneSnap(w, "02_hash_kdf.txt")

	hash := func(data []byte) []byte {
		h, _ := blake2s.New256(nil)
		h.Write(data)
		return h.Sum(nil)
	}
	fmt.Fprintf(w, "blake2s256(wireguard)=%x\n", hash([]byte("wireguard")))
	fmt.Fprintf(w, "blake2s256(empty)=%x\n", hash(nil))
	seq := make([]byte, 256)
	for i := range seq {
		seq[i] = byte(i)
	}
	fmt.Fprintf(w, "blake2s256(00..ff)=%x\n", hash(seq))

	keyed := func(key, data []byte, size int) []byte {
		var h interface {
			Write([]byte) (int, error)
			Sum([]byte) []byte
		}
		if size == 16 {
			hh, _ := blake2s.New128(key)
			h = hh
		} else {
			hh, _ := blake2s.New256(key)
			h = hh
		}
		h.Write(data)
		return h.Sum(nil)
	}
	fmt.Fprintf(w, "keyed128(16b-key)=%x\n", keyed(mustHex("000102030405060708090a0b0c0d0e0f"), []byte("mac1 data"), 16))
	fmt.Fprintf(w, "keyed128(empty-data)=%x\n", keyed(mustHex("abababababababababababababababababababababababababababababababab"), nil, 16))
	fmt.Fprintf(w, "keyed256(32b-key)=%x\n", keyed(mustHex(strings.Repeat("cc", 32)), []byte("x"), 32))

	var sum [32]byte
	device.HMAC1(&sum, mustHex("746573742d6b6579"), mustHex("746573742d696e707574"))
	fmt.Fprintf(w, "hmac1=%x\n", sum)
	device.HMAC2(&sum, mustHex("776972656775617264"), mustHex("776972656775617264"), []byte("extra"))
	fmt.Fprintf(w, "hmac2=%x\n", sum)

	type kdfVec struct{ key, input string }
	for i, v := range []kdfVec{
		{"746573742d6b6579", "746573742d696e707574"},
		{"776972656775617264", "776972656775617264"},
		{"", ""},
	} {
		key, input := mustHex(v.key), mustHex(v.input)
		var t0 [32]byte
		device.KDF1(&t0, key, input)
		fmt.Fprintf(w, "kdf1[%d]=%x\n", i, t0)
		var t1, t2 [32]byte
		device.KDF2(&t0, &t1, key, input)
		fmt.Fprintf(w, "kdf2[%d]=%x %x\n", i, t0, t1)
		device.KDF3(&t0, &t1, &t2, key, input)
		fmt.Fprintf(w, "kdf3[%d]=%x %x %x\n", i, t0, t1, t2)
	}
}

// ----------------------------------------------------------------- 03 tai64n

func snapTai64n() {
	w := writeSnap("03_tai64n.txt")
	defer doneSnap(w, "03_tai64n.txt")

	var t1, t2, t3 tai64n.Timestamp
	copy(t1[:], mustHex("4000000000000a4e0d3f2e1c")) // 12 bytes exactly
	copy(t2[:], mustHex("4000000000000a4e0d3f2e1d"))
	copy(t3[:], mustHex("4000000000000a4e0d3f2e1c"))
	fmt.Fprintf(w, "after_older=%v\n", t1.After(t2))
	fmt.Fprintf(w, "after_newer=%v\n", t2.After(t1))
	fmt.Fprintf(w, "after_equal=%v\n", t1.After(t3))
}

// ---------------------------------------------------------------- 04 messages

func snapMessages() {
	w := writeSnap("04_messages.txt")
	defer doneSnap(w, "04_messages.txt")

	init := device.MessageInitiation{
		Type:      device.MessageInitiationType,
		Sender:    0x11223344,
	}
	copy(init.Ephemeral[:], bytes.Repeat([]byte{0x11}, 32))
	copy(init.Static[:], bytes.Repeat([]byte{0x22}, 48))
	copy(init.Timestamp[:], bytes.Repeat([]byte{0x33}, 28))
	copy(init.MAC1[:], bytes.Repeat([]byte{0x44}, 16))
	copy(init.MAC2[:], bytes.Repeat([]byte{0x55}, 16))
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, init); err != nil {
		panic(err)
	}
	fmt.Fprintf(w, "initiation_marshal=%x\n", buf.Bytes())
	var init2 device.MessageInitiation
	if err := binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, &init2); err != nil {
		panic(err)
	}
	fmt.Fprintf(w, "initiation_unmarshal type=%d sender=%08x ephemeral=%x static=%x timestamp=%x mac1=%x mac2=%x\n",
		init2.Type, init2.Sender, init2.Ephemeral, init2.Static, init2.Timestamp, init2.MAC1, init2.MAC2)

	resp := device.MessageResponse{
		Type:     device.MessageResponseType,
		Sender:   0xaabbccdd,
		Receiver: 0x99887766,
	}
	copy(resp.Ephemeral[:], bytes.Repeat([]byte{0x66}, 32))
	copy(resp.Empty[:], bytes.Repeat([]byte{0x77}, 16))
	copy(resp.MAC1[:], bytes.Repeat([]byte{0x88}, 16))
	copy(resp.MAC2[:], bytes.Repeat([]byte{0x99}, 16))
	buf.Reset()
	if err := binary.Write(&buf, binary.LittleEndian, resp); err != nil {
		panic(err)
	}
	fmt.Fprintf(w, "response_marshal=%x\n", buf.Bytes())
	var resp2 device.MessageResponse
	if err := binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, &resp2); err != nil {
		panic(err)
	}
	fmt.Fprintf(w, "response_unmarshal type=%d sender=%08x receiver=%08x ephemeral=%x empty=%x mac1=%x mac2=%x\n",
		resp2.Type, resp2.Sender, resp2.Receiver, resp2.Ephemeral, resp2.Empty, resp2.MAC1, resp2.MAC2)

	cookie := device.MessageCookieReply{
		Type:     device.MessageCookieReplyType,
		Receiver: 0xcafebabe,
	}
	copy(cookie.Nonce[:], bytes.Repeat([]byte{0xaa}, 24))
	copy(cookie.Cookie[:], bytes.Repeat([]byte{0xbb}, 32))
	buf.Reset()
	if err := binary.Write(&buf, binary.LittleEndian, cookie); err != nil {
		panic(err)
	}
	fmt.Fprintf(w, "cookie_marshal=%x\n", buf.Bytes())
	var cookie2 device.MessageCookieReply
	if err := binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, &cookie2); err != nil {
		panic(err)
	}
	fmt.Fprintf(w, "cookie_unmarshal type=%d receiver=%08x nonce=%x cookie=%x\n",
		cookie2.Type, cookie2.Receiver, cookie2.Nonce, cookie2.Cookie)

	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:], device.MessageTransportType)
	binary.LittleEndian.PutUint32(header[4:], 0x12345678)
	binary.LittleEndian.PutUint64(header[8:], 0x0102030405060708)
	fmt.Fprintf(w, "transport_header=%x\n", header)

	fmt.Fprintf(w, "sizes=%d %d %d %d %d\n",
		device.MessageInitiationSize, device.MessageResponseSize,
		device.MessageCookieReplySize, device.MessageTransportHeaderSize,
		device.MessageKeepaliveSize)
}

// ------------------------------------------------------------------ 05 cookie

func snapCookie() {
	w := writeSnap("05_cookie.txt")
	defer doneSnap(w, "05_cookie.txt")

	var pk device.NoisePublicKey
	copy(pk[:], bytes.Repeat([]byte{0x77}, 32))

	msg := make([]byte, device.MessageInitiationSize)
	for i := range msg {
		msg[i] = byte(i & 0xff)
	}

	checker := &device.CookieChecker{}
	checker.Init(pk)
	generator := &device.CookieGenerator{}
	generator.Init(pk)

	freshGen := &device.CookieGenerator{}
	freshGen.Init(pk)

	generator.AddMacs(msg)
	smac2 := len(msg) - 16
	smac1 := smac2 - 16
	fmt.Fprintf(w, "mac1=%x\n", msg[smac1:smac2])
	fmt.Fprintf(w, "mac2_empty=%x\n", msg[smac2:])
	fmt.Fprintf(w, "check_mac1_ok=%v\n", checker.CheckMAC1(msg))

	tampered := append([]byte(nil), msg...)
	tampered[smac1+3] ^= 0xff
	fmt.Fprintf(w, "check_mac1_tampered=%v\n", checker.CheckMAC1(tampered))

	src := []byte{1, 2, 3, 4, 0xab, 0xcd}
	reply, err := checker.CreateReply(msg, 42, src)
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(w, "create_reply=ok type=%d receiver=%08x\n", reply.Type, reply.Receiver)

	fmt.Fprintf(w, "consume_reply_no_mac1=%v\n", freshGen.ConsumeReply(reply))
	fmt.Fprintf(w, "consume_reply=%v\n", generator.ConsumeReply(reply))

	msg2 := append([]byte(nil), msg...)
	generator.AddMacs(msg2)
	fmt.Fprintf(w, "check_mac2_ok=%v\n", checker.CheckMAC2(msg2, src))
	fmt.Fprintf(w, "check_mac2_wrong_src=%v\n", checker.CheckMAC2(msg2, []byte{9, 9, 9, 9, 0, 1}))
}

// --------------------------------------------------------------- 06 handshake

func snapHandshake() {
	w := writeSnap("06_handshake.txt")
	defer doneSnap(w, "06_handshake.txt")

	logger := device.NewLogger(device.LogLevelError, "")
	dev1 := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), logger)
	dev2 := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), logger)
	defer dev1.Close()
	defer dev2.Close()

	conf1 := "private_key=" + sk1Hex + "\nreplace_peers=true\npublic_key=" +
		dev2PK() + "\npreshared_key=" + pskHex + "\n"
	conf2 := "private_key=" + sk2Hex + "\nreplace_peers=true\npublic_key=" +
		dev1PK() + "\npreshared_key=" + pskHex + "\n"
	if err := dev1.IpcSet(conf1); err != nil {
		panic(err)
	}
	if err := dev2.IpcSet(conf2); err != nil {
		panic(err)
	}

	peer2 := dev1.LookupPeer(mustPK(dev2PK())) // peer for dev2 on dev1
	peer1 := dev2.LookupPeer(mustPK(dev1PK())) // peer for dev1 on dev2
	peer1.Start()
	peer2.Start()

	msg1, err := dev1.CreateMessageInitiation(peer2)
	fmt.Fprintf(w, "create_init=%v type=%d size=%d\n", err == nil, msg1.Type, device.MessageInitiationSize)

	p := dev2.ConsumeMessageInitiation(msg1)
	fmt.Fprintf(w, "consume_init=%v\n", p == peer1)

	msg2, err := dev2.CreateMessageResponse(peer1)
	fmt.Fprintf(w, "create_resp=%v type=%d\n", err == nil, msg2.Type)

	p = dev1.ConsumeMessageResponse(msg2)
	fmt.Fprintf(w, "consume_resp=%v\n", p == peer2)

	fmt.Fprintf(w, "begin_symmetric_initiator=%v\n", peer2.BeginSymmetricSession() == nil)
	fmt.Fprintf(w, "begin_symmetric_responder=%v\n", peer1.BeginSymmetricSession() == nil)

	fmt.Fprintf(w, "replay_same_init_rejected=%v\n", dev2.ConsumeMessageInitiation(msg1) == nil)

	tamperedE := *msg1
	tamperedE.Ephemeral[0] ^= 1
	fmt.Fprintf(w, "tampered_ephemeral_rejected=%v\n", dev2.ConsumeMessageInitiation(&tamperedE) == nil)

	tamperedEmpty := *msg2
	tamperedEmpty.Empty[0] ^= 1
	fmt.Fprintf(w, "tampered_empty_rejected=%v\n", dev1.ConsumeMessageResponse(&tamperedEmpty) == nil)

	wrongRecv := device.MessageResponse{Type: device.MessageResponseType, Receiver: 0xffffffff}
	fmt.Fprintf(w, "wrong_receiver_rejected=%v\n", dev1.ConsumeMessageResponse(&wrongRecv) == nil)
}

func mustPK(hexStr string) device.NoisePublicKey {
	var pk device.NoisePublicKey
	if err := pk.FromHex(hexStr); err != nil {
		panic(err)
	}
	return pk
}

func dev1PK() string { return pkHexFromSk(sk1Hex) }
func dev2PK() string { return pkHexFromSk(sk2Hex) }

func pkHexFromSk(skHex string) string {
	sk := mustHex(skHex)
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
	var pk [32]byte
	curve25519.ScalarBaseMult(&pk, (*[32]byte)(sk))
	return hex.EncodeToString(pk[:])
}

const pskHex = "443d1c4a5d6f8e9a7b2c1d0e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a"

// ------------------------------------------------------------------ 07 replay

func snapReplay() {
	w := writeSnap("07_replay.txt")
	defer doneSnap(w, "07_replay.txt")

	var f replay.Filter
	const limit = 1048576
	for _, c := range []uint64{1, 2, 3, 2, 4, 8, 7, 0, 4097, 2, 5000, 4999} {
		fmt.Fprintf(w, "counter=%d allow=%v\n", c, f.ValidateCounter(c, limit))
	}
}

// -------------------------------------------------------------- 08 allowedips

func snapAllowedIPs() {
	w := writeSnap("08_allowedips.txt")
	defer doneSnap(w, "08_allowedips.txt")

	peerA := &device.Peer{}
	peerB := &device.Peer{}
	table := &device.AllowedIPs{}

	insert := func(cidr string, peer *device.Peer) {
		table.Insert(netip.MustParsePrefix(cidr), peer)
		fmt.Fprintf(w, "insert %s %s\n", cidr, peerName(peer, peerA, peerB))
	}
	insert("192.168.4.0/24", peerA)
	insert("192.168.5.0/24", peerB)
	insert("10.0.0.0/8", peerA)
	insert("10.1.0.0/16", peerB)
	insert("2001:db8::/32", peerB)
	insert("64:ff9b::/96", peerA)

	lookup := func(ip string) {
		p := table.Lookup(netip.MustParseAddr(ip).AsSlice())
		name := "none"
		if p != nil {
			name = peerName(p, peerA, peerB)
		}
		fmt.Fprintf(w, "lookup %s %s\n", ip, name)
	}
	lookup("192.168.4.20")
	lookup("192.168.5.99")
	lookup("192.168.6.1")
	lookup("10.1.2.3")
	lookup("10.2.0.1")
	lookup("2001:db8::1")
	lookup("2001:db9::1")
	lookup("64:ff9b::1")
	lookup("64:ff9b::1:1")

	table.Remove(netip.MustParsePrefix("10.1.0.0/16"), peerB)
	fmt.Fprintf(w, "remove 10.1.0.0/16 B\n")
	lookup("10.1.2.3")

	table.RemoveByPeer(peerB)
	fmt.Fprintf(w, "remove_by_peer B\n")
	lookup("192.168.5.99")
	lookup("2001:db8::1")
	lookup("10.1.2.3")
}

func peerName(p, a, b *device.Peer) string {
	switch p {
	case a:
		return "A"
	case b:
		return "B"
	default:
		return "?"
	}
}

// ------------------------------------------------------------- 09 ratelimiter

func snapRatelimiter() {
	w := writeSnap("09_ratelimiter.txt")
	defer doneSnap(w, "09_ratelimiter.txt")

	rl := ratelimiter.Ratelimiter{}
	rl.Init()
	defer rl.Close()

	ip1 := netip.MustParseAddr("123.123.123.123")
	for i := 0; i < 10; i++ {
		fmt.Fprintf(w, "burst1[%d]=%v\n", i, rl.Allow(ip1))
	}
	ip2 := netip.MustParseAddr("124.124.124.124")
	fmt.Fprintf(w, "other_ip=%v\n", rl.Allow(ip2))
}

// --------------------------------------------------------------- 10 transport

// memBind routes datagrams between two in-memory devices. Each datagram
// carries its sender so the receiving side can reply.
type memPacket struct {
	from string
	data []byte
}

type memRouter struct {
	inboxes map[string]chan memPacket
}

func newMemRouter(names ...string) *memRouter {
	r := &memRouter{inboxes: map[string]chan memPacket{}}
	for _, n := range names {
		r.inboxes[n] = make(chan memPacket, 256)
	}
	return r
}

type memEndpoint struct {
	dst string // name of the receiving device
}

func (e *memEndpoint) ClearSrc()           {}
func (e *memEndpoint) SrcToString() string { return "mem-src" }
func (e *memEndpoint) DstToString() string { return e.dst }
func (e *memEndpoint) DstToBytes() []byte  { return []byte(e.dst) }
func (e *memEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e *memEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type memBind struct {
	name   string
	router *memRouter
	closed bool
}

func (b *memBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// a real UDP bind re-creates its socket on each Open, so do the same
	b.closed = false
	b.router.inboxes[b.name] = make(chan memPacket, 256)
	inbox := b.router.inboxes[b.name]
	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		p, ok := <-inbox
		if !ok {
			return 0, net.ErrClosed
		}
		copy(packets[0], p.data)
		sizes[0] = len(p.data)
		eps[0] = &memEndpoint{dst: p.from} // reply address = sender
		return 1, nil
	}
	return []conn.ReceiveFunc{fn}, 1, nil
}

func (b *memBind) Close() error {
	if !b.closed {
		b.closed = true
		close(b.router.inboxes[b.name])
	}
	return nil
}

func (b *memBind) SetMark(mark uint32) error { return nil }

func (b *memBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	dst, ok := ep.(*memEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	inbox := b.router.inboxes[dst.dst]
	for _, buf := range bufs {
		cp := append([]byte(nil), buf...)
		sent := true
		func() {
			// a real UDP socket would drop the packet if the bind was
			// re-created concurrently; emulate that instead of panicking
			defer func() {
				if recover() != nil {
					sent = false
				}
			}()
			inbox <- memPacket{from: b.name, data: cp}
		}()
		if !sent {
			return net.ErrClosed
		}
	}
	return nil
}

func (b *memBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if _, ok := b.router.inboxes[s]; !ok {
		return nil, fmt.Errorf("unknown mem endpoint %q", s)
	}
	return &memEndpoint{dst: s}, nil
}

func (b *memBind) BatchSize() int { return 1 }

func snapTransport() {
	w := writeSnap("10_transport.txt")
	defer doneSnap(w, "10_transport.txt")

	router := newMemRouter("A", "B")
	bindA := &memBind{name: "A", router: router}
	bindB := &memBind{name: "B", router: router}
	logger := device.NewLogger(device.LogLevelError, "")
	tunA := tuntest.NewChannelTUN()
	tunB := tuntest.NewChannelTUN()
	devA := device.NewDevice(tunA.TUN(), bindA, logger)
	devB := device.NewDevice(tunB.TUN(), bindB, logger)
	defer devA.Close()
	defer devB.Close()

	confA := "private_key=" + sk1Hex + "\nreplace_peers=true\npublic_key=" +
		dev2PK() + "\nendpoint=B\nallowed_ip=10.0.0.0/24\npreshared_key=" + pskHex + "\n"
	confB := "private_key=" + sk2Hex + "\nreplace_peers=true\npublic_key=" +
		dev1PK() + "\nendpoint=A\nallowed_ip=10.0.0.0/24\npreshared_key=" + pskHex + "\n"
	fmt.Fprintf(w, "ipc_set=%v %v\n", devA.IpcSet(confA) == nil, devB.IpcSet(confB) == nil)

	if err := devA.Up(); err != nil {
		panic(err)
	}
	if err := devB.Up(); err != nil {
		panic(err)
	}

	// A -> B data packets (src 10.0.0.1, dst 10.0.0.2)
	packetsAB := [][]byte{
		ipv4Packet(10, 32, 1),
		ipv4Packet(10, 48, 2),
		ipv4Packet(10, 32, 3),
		ipv4Packet(10, 37, 4),
		ipv4Packet(10, 64, 5),
	}
	for _, p := range packetsAB {
		cp := append([]byte(nil), p...)
		tunA.Outbound <- cp // inject into A as if written by the OS
	}

	readNonEmpty := func(ch chan []byte, n int, timeout time.Duration) [][]byte {
		var out [][]byte
		deadline := time.After(timeout)
		for len(out) < n {
			select {
			case p := <-ch:
				if len(p) > 0 {
					out = append(out, p)
				}
			case <-deadline:
				panic(fmt.Sprintf("timed out waiting for packets, got %d of %d", len(out), n))
			}
		}
		return out
	}

	// give the handshake (and a possible retransmission) plenty of time
	const recvTimeout = 15 * time.Second

	for i, p := range readNonEmpty(tunB.Inbound, len(packetsAB), recvTimeout) {
		fmt.Fprintf(w, "data_ab[%d]=%x\n", i, p)
	}

	// B -> A data packets (src 10.0.0.2, dst 10.0.0.1)
	packetsBA := [][]byte{
		ipv4Packet(10, 48, 6),
		ipv4Packet(10, 32, 7),
		ipv4Packet(10, 96, 8),
	}
	for _, p := range packetsBA {
		cp := append([]byte(nil), p...)
		tunB.Outbound <- cp // inject into B as if written by the OS
	}
	for i, p := range readNonEmpty(tunA.Inbound, len(packetsBA), recvTimeout) {
		fmt.Fprintf(w, "data_ba[%d]=%x\n", i, p)
	}

	time.Sleep(200 * time.Millisecond) // let counters settle

	printCounters := func(dev *device.Device, label string) {
		conf, err := dev.IpcGet()
		if err != nil {
			panic(err)
		}
		type stat struct{ pk string; rx, tx uint64 }
		var stats []stat
		var cur *stat
		for _, line := range splitLines(conf) {
			var k, v string
			ok := false
			for i := 0; i < len(line); i++ {
				if line[i] == '=' {
					k, v, ok = line[:i], line[i+1:], true
					break
				}
			}
			if !ok {
				continue
			}
			switch k {
			case "public_key":
				stats = append(stats, stat{pk: v})
				cur = &stats[len(stats)-1]
			case "rx_bytes":
				fmt.Sscan(v, &cur.rx)
			case "tx_bytes":
				fmt.Sscan(v, &cur.tx)
			}
		}
		sort.Slice(stats, func(i, j int) bool { return stats[i].pk < stats[j].pk })
		for _, s := range stats {
			fmt.Fprintf(w, "counters %s %s rx=%d tx=%d\n", label, s.pk, s.rx, s.tx)
		}
	}
	printCounters(devA, "A")
	printCounters(devB, "B")
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// ipv4Packet builds a deterministic IPv4 packet: src 10.0.0.(prefix%250+1), dst
// 10.0.0.((prefix%250+1)%250+1), total length `total`, payload filled with a
// pattern seeded by seq.
func ipv4Packet(prefix byte, total int, seq int) []byte {
	p := make([]byte, total)
	p[0] = 0x45
	p[1] = 0
	binary.BigEndian.PutUint16(p[2:], uint16(total))
	p[4], p[5] = 0, 0
	p[6], p[7] = 0, 0
	p[8] = 64
	p[9] = 17 // UDP
	p[10], p[11] = 0, 0 // checksum (not validated by wireguard)
	src := netip.MustParseAddr("10.0.0.1").AsSlice()
	if seq%2 == 0 {
		src = netip.MustParseAddr("10.0.0.2").AsSlice()
	}
	copy(p[12:16], src)
	var dst [4]byte = [4]byte{10, 0, 0, 2}
	if seq%2 == 0 {
		dst = [4]byte{10, 0, 0, 1}
	}
	copy(p[16:20], dst[:])
	for i := 20; i < total; i++ {
		p[i] = byte('a' + (i+seq)%26)
	}
	return p
}

// ----------------------------------------------------------------------- main

func main() {
	outDir = "artifacts/go"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}
	snapX25519()
	snapHashKdf()
	snapTai64n()
	snapMessages()
	snapCookie()
	snapHandshake()
	snapReplay()
	snapAllowedIPs()
	snapRatelimiter()
	snapTransport()
}
