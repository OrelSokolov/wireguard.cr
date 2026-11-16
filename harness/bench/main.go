// Protocol benchmark for the wireguard-go oracle: micro-benchmarks of the
// protocol primitives plus a UDP client/server echo benchmark through the
// full device pipeline. Mirrored by tools/bench.cr on the Crystal side.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

const sk1Hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
const sk2Hex = "5152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70"

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// distinct static key per client flow id (mirrors tools/bench.cr)
func clientSkHex(id int) string {
	base := sk1Hex[:len(sk1Hex)-2]
	return base + fmt.Sprintf("%02x", id%256)
}

func clampPub(skHex string) (sk, pk []byte) {
	sk = mustHex(skHex)
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
	pk = make([]byte, 32)
	curve25519.ScalarBaseMult((*[32]byte)(pk), (*[32]byte)(sk))
	return
}

// --------------------------------------------------------------------- micro

func benchMicro(seconds float64) {
	deadline := time.Now().Add(time.Duration(seconds * float64(time.Second)))

	// x25519 shared secrets
	sk1, pk2 := clampPub(sk1Hex)
	_, pk1b := clampPub(sk1Hex)
	_ = pk1b
	sk2, pk2b := clampPub(sk2Hex)
	_ = sk2
	_ = pk2b
	// use sk1 with pk2 for each op
	n := 0
	start := time.Now()
	for time.Now().Before(deadline) {
		var ss [32]byte
		curve25519.ScalarMult(&ss, (*[32]byte)(sk1), (*[32]byte)(pk2))
		n++
	}
	el := time.Since(start).Seconds()
	fmt.Printf("micro x25519_ops=%.0f\n", float64(n)/el)

	// blake2s-256 over 64 KiB blocks
	block := make([]byte, 64*1024)
	for i := range block {
		block[i] = byte(i)
	}
	deadline = time.Now().Add(time.Duration(seconds * float64(time.Second)))
	var total uint64
	start = time.Now()
	for time.Now().Before(deadline) {
		h, _ := blake2s.New256(nil)
		h.Write(block)
		h.Sum(nil)
		total += uint64(len(block))
	}
	el = time.Since(start).Seconds()
	fmt.Printf("micro blake2s_mbs=%.2f\n", float64(total)/el/1024/1024)

	// KDF3 (HMAC-BLAKE2s xN)
	key := mustHex("776972656775617264")
	input := mustHex("776972656775617264")
	deadline = time.Now().Add(time.Duration(seconds * float64(time.Second)))
	n = 0
	start = time.Now()
	var t0, t1, t2 [32]byte
	for time.Now().Before(deadline) {
		device.KDF3(&t0, &t1, &t2, key, input)
		n++
	}
	el = time.Since(start).Seconds()
	fmt.Printf("micro kdf3_ops=%.0f\n", float64(n)/el)

	// chacha20poly1305 seal/open on 1400-byte plaintexts
	aead, _ := chacha20poly1305.New(mustHex("cc02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"))
	pt := make([]byte, 1400)
	nonce := make([]byte, 12)
	deadline = time.Now().Add(time.Duration(seconds * float64(time.Second)))
	total = 0
	start = time.Now()
	for time.Now().Before(deadline) {
		binary.LittleEndian.PutUint64(nonce[4:], uint64(total))
		ct := aead.Seal(nil, nonce, pt, nil)
		total += uint64(len(pt))
		_ = ct
	}
	el = time.Since(start).Seconds()
	fmt.Printf("micro seal_mbs=%.2f\n", float64(total)/el/1024/1024)

	deadline = time.Now().Add(time.Duration(seconds * float64(time.Second)))
	total = 0
	start = time.Now()
	binary.LittleEndian.PutUint64(nonce[4:], 0)
	ct := aead.Seal(nil, nonce, pt, nil)
	for time.Now().Before(deadline) {
		pt2, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			panic(err)
		}
		total += uint64(len(pt2))
	}
	el = time.Since(start).Seconds()
	fmt.Printf("micro open_mbs=%.2f\n", float64(total)/el/1024/1024)
}

// ------------------------------------------------------------ device helpers

func buildDevice(skHex string, listenPort uint16) (*device.Device, *tuntest.ChannelTUN) {
	tun := tuntest.NewChannelTUN()
	dev := device.NewDevice(tun.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	conf := "private_key=" + skHex + "\nreplace_peers=true\n"
	if listenPort != 0 {
		conf += fmt.Sprintf("listen_port=%d\n", listenPort)
	}
	if err := dev.IpcSet(conf); err != nil {
		panic(err)
	}
	if err := dev.Up(); err != nil {
		panic(err)
	}
	return dev, tun
}

// ipv4 packet for flow id: src 10.0.id.1, dst 10.0.id.2
func benchPacket(size int, seq int, id int) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(size))
	p[8] = 64
	p[9] = 17
	copy(p[12:], net4(fmt.Sprintf("10.0.%d.1", id)))
	copy(p[16:], net4(fmt.Sprintf("10.0.%d.2", id)))
	for i := 20; i < size; i++ {
		p[i] = byte('a' + (i+seq)%26)
	}
	return p
}

func net4(s string) []byte {
	addr := netip.MustParseAddr(s)
	return addr.AsSlice()
}

// -------------------------------------------------------------------- server

func runServer(port int, peers int) {
	dev, tun := buildDevice(sk2Hex, uint16(port))
	defer dev.Close()
	for i := 0; i < peers; i++ {
		_, pk := clampPub(clientSkHex(i))
		conf := "public_key=" + hex.EncodeToString(pk) +
			fmt.Sprintf("\nallowed_ip=10.0.%d.0/24\n", i)
		if err := dev.IpcSet(conf); err != nil {
			panic(err)
		}
	}

	// echo everything the device delivers back into the tunnel
	go func() {
		for p := range tun.Inbound {
			tun.Outbound <- p
		}
	}()

	fmt.Println("server_ready")
	flush := func() {
		out, _ := dev.IpcGet()
		for _, line := range splitLines(out) {
			if len(line) > 11 && line[:11] == "rx_bytes=" || len(line) > 11 && line[:11] == "tx_bytes=" {
				fmt.Println("server " + line)
			}
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	flush()
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

// -------------------------------------------------------------------- client

func runClient(port, packets, size, id int) {
	dev, tun := buildDevice(clientSkHex(id), 0)
	defer dev.Close()
	_, pk2 := clampPub(sk2Hex)
	conf := "public_key=" + hex.EncodeToString(pk2) +
		fmt.Sprintf("\nendpoint=127.0.0.1:%d\nallowed_ip=10.0.%d.0/24\n", port, id)
	if err := dev.IpcSet(conf); err != nil {
		panic(err)
	}

	received := make(chan struct{}, packets)
	var doneCount atomic.Int64
	go func() {
		for range tun.Inbound {
			doneCount.Add(1)
			received <- struct{}{}
		}
	}()

	// first packet: full handshake round trip
	first := benchPacket(size, 0, id)
	t0 := time.Now()
	tun.Outbound <- first
	<-received
	handshakeRtt := time.Since(t0)
	fmt.Printf("client handshake_rtt_us=%.0f\n", float64(handshakeRtt.Microseconds()))

	// bulk: inject the rest while the reader drains; a small in-flight
	// window bounds the staging queues and kernel UDP buffers (mirrors the
	// Crystal client)
	var sentCount atomic.Int64
	sentCount.Store(1)
	go func() {
		for i := 1; i < packets; i++ {
			for sentCount.Load()-doneCount.Load() > 256 {
				runtime.Gosched()
			}
			tun.Outbound <- benchPacket(size, i, id)
			sentCount.Add(1)
		}
	}()

	t1 := time.Now()
	for i := 1; i < packets; i++ {
		<-received
		doneCount.Store(int64(i + 1))
	}
	el := time.Since(t1).Seconds()
	bytes := uint64(packets-1) * uint64(size)
	fmt.Printf("client packets=%d bytes=%d time_s=%.3f mbps=%.2f pps=%.0f\n",
		packets-1, bytes, el, float64(bytes)/el/1024/1024, float64(packets-1)/el)
}

func main() {
	seconds := flag.Float64("seconds", 1.0, "micro benchmark duration per primitive")
	port := flag.Int("port", 51820, "server listen / client target port")
	packets := flag.Int("packets", 20000, "bulk packet count")
	size := flag.Int("size", 1400, "packet payload size")
	id := flag.Int("id", 0, "client flow id (distinct static key and subnet)")
	peers := flag.Int("peers", 1, "number of pre-registered client flows")

	// the subcommand comes first, then its flags (bench server --port N)
	args := os.Args[1:]
	mode := "micro"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		mode, args = args[0], args[1:]
	}
	flag.CommandLine.Parse(args)
	switch mode {
	case "micro":
		benchMicro(*seconds)
	case "server":
		runServer(*port, *peers)
	case "client":
		runClient(*port, *packets, *size, *id)
	default:
		fmt.Fprintln(os.Stderr, "usage: bench [micro|server|client] [flags]")
		os.Exit(2)
	}
}
