# Crystal snapshot harness: drives the wireguard.cr port through exactly the
# same scenarios as the Go oracle harness (harness/main.go) and writes the
# same files, compared 1:1 by twinshot.

require "../src/wireguard"

OUT_DIR = ARGV[0]? || "artifacts/cr"

SK1_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
SK2_HEX = "5152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70"
PSK_HEX = "443d1c4a5d6f8e9a7b2c1d0e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a"

def write_snap(name : String, & : IO -> _) : Nil
  Dir.mkdir_p(OUT_DIR)
  File.open(File.join(OUT_DIR, name), "w") do |f|
    yield f
  end
  puts "wrote #{name}"
end

def unhex(s : String) : Bytes
  s.hexbytes
end

def pk_of(sk_hex : String) : Bytes
  sk = unhex(sk_hex)
  Wireguard::X25519.clamp(sk)
  Wireguard::X25519.public_key(sk)
end

# ---------------------------------------------------------------- 01 x25519

def snap_x25519 : Nil
  write_snap("01_x25519.txt") do |w|
    sk1 = unhex(SK1_HEX)
    sk2 = unhex(SK2_HEX)
    Wireguard::X25519.clamp(sk1)
    Wireguard::X25519.clamp(sk2)
    pk1 = Wireguard::X25519.public_key(sk1)
    pk2 = Wireguard::X25519.public_key(sk2)
    w << "pk1=" << pk1.hexstring << "\n"
    w << "pk2=" << pk2.hexstring << "\n"

    ss1 = Wireguard::X25519.shared_secret(sk1, pk2)
    ss2 = Wireguard::X25519.shared_secret(sk2, pk1)
    w << "ss1=" << ss1.hexstring << "\n"
    w << "ss2=" << ss2.hexstring << "\n"
    w << "ss_equal=" << (ss1 == ss2) << " err1=<nil> err2=<nil>\n"

    a_sk = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b_sk = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    Wireguard::X25519.clamp(a_sk)
    Wireguard::X25519.clamp(b_sk)
    a_pk = Wireguard::X25519.public_key(a_sk)
    b_pk = Wireguard::X25519.public_key(b_sk)
    ss = Wireguard::X25519.shared_secret(a_sk, b_pk)
    w << "rfc7748_apk=" << a_pk.hexstring << "\n"
    w << "rfc7748_bpk=" << b_pk.hexstring << "\n"
    w << "rfc7748_ss=" << ss.hexstring << " err=<nil>\n"

    begin
      Wireguard::X25519.shared_secret(sk1, Bytes.new(32))
      w << "zero_pk_err=<nil>\n"
    rescue e : Wireguard::X25519::Error
      w << "zero_pk_err=" << e.message << "\n"
    end
  end
end

# ------------------------------------------------------------- 02 hash / kdf

def snap_hash_kdf : Nil
  write_snap("02_hash_kdf.txt") do |w|
    b2 = Wireguard::Blake2s
    w << "blake2s256(wireguard)=" << b2.digest256("wireguard".to_slice).hexstring << "\n"
    w << "blake2s256(empty)=" << b2.digest256(Bytes.empty).hexstring << "\n"
    seq = Bytes.new(256) { |i| i.to_u8! }
    w << "blake2s256(00..ff)=" << b2.digest256(seq).hexstring << "\n"

    nh = Wireguard::NoiseHelpers
    w << "keyed128(16b-key)=" << b2.digest128("mac1 data".to_slice, unhex("000102030405060708090a0b0c0d0e0f")).hexstring << "\n"
    w << "keyed128(empty-data)=" << b2.digest128(Bytes.empty, unhex("ab" * 32)).hexstring << "\n"
    key32 = unhex("cc" * 32)
    w << "keyed256(32b-key)=" << b2.digest256("x".to_slice, key32).hexstring << "\n"

    w << "hmac1=" << nh.hmac1(unhex("746573742d6b6579"), unhex("746573742d696e707574")).hexstring << "\n"
    w << "hmac2=" << nh.hmac2(unhex("776972656775617264"), unhex("776972656775617264"), "extra".to_slice).hexstring << "\n"

    vectors = [
      {"746573742d6b6579", "746573742d696e707574"},
      {"776972656775617264", "776972656775617264"},
      {"", ""},
    ]
    vectors.each_with_index do |(key_hex, input_hex), i|
      key = unhex(key_hex)
      input = unhex(input_hex)
      t0 = nh.kdf1(key, input)
      w << "kdf1[" << i << "]=" << t0.hexstring << "\n"
      u0, u1 = nh.kdf2(key, input)
      w << "kdf2[" << i << "]=" << u0.hexstring << " " << u1.hexstring << "\n"
      v0, v1, v2 = nh.kdf3(key, input)
      w << "kdf3[" << i << "]=" << v0.hexstring << " " << v1.hexstring << " " << v2.hexstring << "\n"
    end
  end
end

# ----------------------------------------------------------------- 03 tai64n

def snap_tai64n : Nil
  write_snap("03_tai64n.txt") do |w|
    t1 = unhex("4000000000000a4e0d3f2e1c")
    t2 = unhex("4000000000000a4e0d3f2e1d")
    t3 = unhex("4000000000000a4e0d3f2e1c")
    t = Wireguard::Tai64n
    w << "after_older=" << t.after(t1, t2) << "\n"
    w << "after_newer=" << t.after(t2, t1) << "\n"
    w << "after_equal=" << t.after(t1, t3) << "\n"
  end
end

# ---------------------------------------------------------------- 04 messages

def snap_messages : Nil
  write_snap("04_messages.txt") do |w|
        init = Wireguard::Messages::MessageInitiation.new
    init.sender = 0x11223344
    init.ephemeral.fill(0x11)
    init.static_box.fill(0x22)
    init.timestamp_box.fill(0x33)
    init.mac1.fill(0x44)
    init.mac2.fill(0x55)
    marshalled = init.marshal
    w << "initiation_marshal=" << marshalled.hexstring << "\n"
    init2 = Wireguard::Messages::MessageInitiation.new
    init2.unmarshal(marshalled)
    w << "initiation_unmarshal type=" << init2.type << " sender=" << sender_hex(init2.sender) \
      << " ephemeral=" << init2.ephemeral.hexstring << " static=" << init2.static_box.hexstring \
      << " timestamp=" << init2.timestamp_box.hexstring << " mac1=" << init2.mac1.hexstring \
      << " mac2=" << init2.mac2.hexstring << "\n"

    resp = Wireguard::Messages::MessageResponse.new
    resp.sender = 0xaabbccdd
    resp.receiver = 0x99887766
    resp.ephemeral.fill(0x66)
    resp.empty_box.fill(0x77)
    resp.mac1.fill(0x88)
    resp.mac2.fill(0x99)
    data = resp.marshal
    w << "response_marshal=" << data.hexstring << "\n"
    resp2 = Wireguard::Messages::MessageResponse.new
    resp2.unmarshal(data)
    w << "response_unmarshal type=" << resp2.type << " sender=" << sender_hex(resp2.sender) \
      << " receiver=" << sender_hex(resp2.receiver) << " ephemeral=" << resp2.ephemeral.hexstring \
      << " empty=" << resp2.empty_box.hexstring << " mac1=" << resp2.mac1.hexstring \
      << " mac2=" << resp2.mac2.hexstring << "\n"

    cookie = Wireguard::Messages::MessageCookieReply.new
    cookie.receiver = 0xcafebabe
    cookie.nonce.fill(0xaa)
    cookie.cookie_box.fill(0xbb)
    data = cookie.marshal
    w << "cookie_marshal=" << data.hexstring << "\n"
    cookie2 = Wireguard::Messages::MessageCookieReply.new
    cookie2.unmarshal(data)
    w << "cookie_unmarshal type=" << cookie2.type << " receiver=" << sender_hex(cookie2.receiver) \
      << " nonce=" << cookie2.nonce.hexstring << " cookie=" << cookie2.cookie_box.hexstring << "\n"

    header = Bytes.new(16)
    IO::ByteFormat::LittleEndian.encode(Wireguard::Messages::MESSAGE_TRANSPORT_TYPE, header[0, 4])
    IO::ByteFormat::LittleEndian.encode(0x12345678_u32, header[4, 4])
    IO::ByteFormat::LittleEndian.encode(0x0102030405060708_u64, header[8, 8])
    w << "transport_header=" << header.hexstring << "\n"

    w << "sizes=" << Wireguard::Messages::MESSAGE_INITIATION_SIZE << " " << Wireguard::Messages::MESSAGE_RESPONSE_SIZE << " " \
      << Wireguard::Messages::MESSAGE_COOKIE_REPLY_SIZE << " " << Wireguard::Messages::MESSAGE_TRANSPORT_HEADER_SIZE << " " \
      << Wireguard::Messages::MESSAGE_KEEPALIVE_SIZE << "\n"
  end
end

def sender_hex(v : UInt32) : String
  v.to_s(16).rjust(8, '0')
end

# ------------------------------------------------------------------ 05 cookie

def snap_cookie : Nil
  write_snap("05_cookie.txt") do |w|
    pk = Bytes.new(32, 0x77)

    msg = Bytes.new(Wireguard::Messages::MESSAGE_INITIATION_SIZE) { |i| (i & 0xff).to_u8! }

    checker = Wireguard::CookieChecker.new
    checker.init(pk)
    generator = Wireguard::CookieGenerator.new
    generator.init(pk)
    fresh_gen = Wireguard::CookieGenerator.new
    fresh_gen.init(pk)

    generator.add_macs(msg)
    smac2 = msg.size - 16
    smac1 = smac2 - 16
    w << "mac1=" << msg[smac1, 16].hexstring << "\n"
    w << "mac2_empty=" << msg[smac2, 16].hexstring << "\n"
    w << "check_mac1_ok=" << checker.check_mac1(msg) << "\n"

    tampered = msg.dup
    tampered[smac1 + 3] ^= 0xff
    w << "check_mac1_tampered=" << checker.check_mac1(tampered) << "\n"

    src = Bytes[1, 2, 3, 4, 0xab, 0xcd]
    secret = Bytes.new(32) { |i| (i * 7 + 3).to_u8! }
    nonce = Bytes.new(24) { |i| (i + 0x30).to_u8! }
    reply = checker.create_reply(msg, 42, src, secret, nonce)
    w << "create_reply=ok type=" << reply.type << " receiver=" << sender_hex(reply.receiver) << "\n"

    w << "consume_reply_no_mac1=" << fresh_gen.consume_reply(reply) << "\n"
    w << "consume_reply=" << generator.consume_reply(reply) << "\n"

    msg2 = msg.dup
    generator.add_macs(msg2)
    w << "check_mac2_ok=" << checker.check_mac2(msg2, src) << "\n"
    w << "check_mac2_wrong_src=" << checker.check_mac2(msg2, Bytes[9, 9, 9, 9, 0, 1]) << "\n"
  end
end

# --------------------------------------------------------------- 06 handshake

def snap_handshake : Nil
  write_snap("06_handshake.txt") do |w|
    dev1 = Wireguard::Device.new("dev1")
    dev2 = Wireguard::Device.new("dev2")
    pk1 = pk_of(SK1_HEX)
    pk2 = pk_of(SK2_HEX)

    dev1.set_private_key(unhex(SK1_HEX))
    dev2.set_private_key(unhex(SK2_HEX))
    peer2 = dev1.new_peer(pk2)
    peer1 = dev2.new_peer(pk1)
    peer1.preshared_key = unhex(PSK_HEX)
    peer2.preshared_key = unhex(PSK_HEX)
    peer1.start
    peer2.start

    msg1 = dev1.create_message_initiation(peer2)
    if msg1
      w << "create_init=true type=" << msg1.type << " size=" \
        << Wireguard::Messages::MESSAGE_INITIATION_SIZE << "\n"
    else
      w << "create_init=false\n"
    end

    p = dev2.consume_message_initiation(msg1.not_nil!)
    w << "consume_init=" << (p == peer1) << "\n"

    msg2 = dev2.create_message_response(peer1)
    if msg2
      w << "create_resp=true type=" << msg2.type << "\n"
    else
      w << "create_resp=false\n"
    end

    p = dev1.consume_message_response(msg2.not_nil!)
    w << "consume_resp=" << (p == peer2) << "\n"

    w << "begin_symmetric_initiator=" << dev1.begin_symmetric_session(peer2) << "\n"
    w << "begin_symmetric_responder=" << dev2.begin_symmetric_session(peer1) << "\n"

    w << "replay_same_init_rejected=" << dev2.consume_message_initiation(msg1.not_nil!).nil? << "\n"

    tampered = msg1.not_nil!.dup
    tampered.ephemeral[0] ^= 1
    w << "tampered_ephemeral_rejected=" << dev2.consume_message_initiation(tampered).nil? << "\n"

    tampered2 = msg2.not_nil!.dup
    tampered2.empty_box[0] ^= 1
    w << "tampered_empty_rejected=" << dev1.consume_message_response(tampered2).nil? << "\n"

    wrong = Wireguard::Messages::MessageResponse.new
    wrong.type = Wireguard::Messages::MESSAGE_RESPONSE_TYPE
    wrong.receiver = 0xffffffff_u32
    w << "wrong_receiver_rejected=" << dev1.consume_message_response(wrong).nil? << "\n"
  end
end

# ------------------------------------------------------------------ 07 replay

def snap_replay : Nil
  write_snap("07_replay.txt") do |w|
    f = Wireguard::ReplayFilter.new
    limit = 1048576_u64
    [1, 2, 3, 2, 4, 8, 7, 0, 4097, 2, 5000, 4999].each do |c|
      w << "counter=" << c << " allow=" << f.validate_counter(c.to_u64!, limit) << "\n"
    end
  end
end

# -------------------------------------------------------------- 08 allowedips

class StatPeer
  getter name : String

  def initialize(@name)
  end
end

def snap_allowedips : Nil
  # AllowedIPs stores abstract peers; make lightweight stand-ins
  write_snap("08_allowedips.txt") do |w|
    peer_a = Wireguard::Peer.allocate
    peer_b = Wireguard::Peer.allocate
    table = Wireguard::AllowedIPs.new

    insert = ->(cidr : String, peer : Wireguard::Peer, name : String) do
      table.insert(cidr, peer)
      w << "insert " << cidr << " " << name << "\n"
    end
    insert.call("192.168.4.0/24", peer_a, "A")
    insert.call("192.168.5.0/24", peer_b, "B")
    insert.call("10.0.0.0/8", peer_a, "A")
    insert.call("10.1.0.0/16", peer_b, "B")
    insert.call("2001:db8::/32", peer_b, "B")
    insert.call("64:ff9b::/96", peer_a, "A")

    lookup = ->(ip : String) do
      bytes = ip.includes?(":") ? ipv6_bytes(ip) : ipv4_bytes(ip)
      p = table.lookup(bytes)
      name = "none"
      {p, name}
    end
    {"192.168.4.20", "192.168.5.99", "192.168.6.1", "10.1.2.3", "10.2.0.1",
     "2001:db8::1", "2001:db9::1", "64:ff9b::1", "64:ff9b::1:1"}.each do |ip|
      bytes = ip.includes?(":") ? ipv6_bytes(ip) : ipv4_bytes(ip)
      p = table.lookup(bytes)
      name = case p
             when peer_a then "A"
             when peer_b then "B"
             else             "none"
             end
      w << "lookup " << ip << " " << name << "\n"
    end

    table.remove("10.1.0.0/16", peer_b)
    w << "remove 10.1.0.0/16 B\n"
    bytes = ipv4_bytes("10.1.2.3")
    p = table.lookup(bytes)
    w << "lookup 10.1.2.3 " << (p == peer_a ? "A" : "none") << "\n"

    table.remove_by_peer(peer_b)
    w << "remove_by_peer B\n"
    {"192.168.5.99" => ipv4_bytes("192.168.5.99"), "2001:db8::1" => ipv6_bytes("2001:db8::1"),
     "10.1.2.3" => ipv4_bytes("10.1.2.3")}.each do |ip, b|
      p = table.lookup(b)
      name = case p
             when peer_a then "A"
             else             "none"
             end
      w << "lookup " << ip << " " << name << "\n"
    end
  end
end

def ipv4_bytes(s : String) : Bytes
  parts = s.split('.')
  Bytes.new(4) { |i| parts[i].to_u8 }
end

def ipv6_bytes(s : String) : Bytes
  halves = s.split("::")
  head = halves[0].split(':').reject(&.empty?)
  tail = halves.size == 2 ? halves[1].split(':').reject(&.empty?) : [] of String
  groups = head + Array.new(8 - head.size - tail.size) { "0" } + tail
  Bytes.new(16) do |i|
    v = groups[i // 2].to_u16(16)
    i.even? ? ((v >> 8).to_u8) : (v & 0xFF).to_u8
  end
end

# ------------------------------------------------------------- 09 ratelimiter

def snap_ratelimiter : Nil
  write_snap("09_ratelimiter.txt") do |w|
    rl = Wireguard::RateLimiter.new
    10.times do |i|
      w << "burst1[" << i << "]=" << rl.allow("123.123.123.123") << "\n"
    end
    w << "other_ip=" << rl.allow("124.124.124.124") << "\n"
  end
end

# --------------------------------------------------------------- 10 transport

def snap_transport : Nil
  write_snap("10_transport.txt") do |w|
    router = Wireguard::MemBind::Router.new
    bind_a = Wireguard::MemBind.new(router, "A")
    bind_b = Wireguard::MemBind.new(router, "B")
    dev_a = Wireguard::Device.new("A")
    dev_b = Wireguard::Device.new("B")
    dev_a.attach_bind(bind_a)
    dev_b.attach_bind(bind_b)
    pk1 = pk_of(SK1_HEX)
    pk2 = pk_of(SK2_HEX)

    begin
      dev_a.ipc_set("private_key=#{SK1_HEX}\nreplace_peers=true\npublic_key=#{pk2.hexstring}\nendpoint=B\nallowed_ip=10.0.0.0/24\npreshared_key=#{PSK_HEX}\n")
      dev_b.ipc_set("private_key=#{SK2_HEX}\nreplace_peers=true\npublic_key=#{pk1.hexstring}\nendpoint=A\nallowed_ip=10.0.0.0/24\npreshared_key=#{PSK_HEX}\n")
      w << "ipc_set=true true\n"
    rescue
      w << "ipc_set=false false\n"
    end

    dev_a.start
    dev_b.start

    # A -> B data packets (src 10.0.0.1, dst 10.0.0.2)
    packets_ab = [{32, 1}, {48, 2}, {32, 3}, {37, 4}, {64, 5}].map { |total, seq| ipv4_packet(total, seq) }
    packets_ab.each do |p|
      dev_a.tun.outbound.send(p)
    end

    packets_ab.each_with_index do |want, i|
      got = recv_non_empty(dev_b.tun.inbound)
      w << "data_ab[" << i << "]=" << got.hexstring << "\n"
    end

    # B -> A data packets (src 10.0.0.2, dst 10.0.0.1)
    packets_ba = [{48, 6}, {32, 7}, {96, 8}].map { |total, seq| ipv4_packet(total, seq) }
    packets_ba.each_with_index do |p, i|
      dev_b.tun.outbound.send(p)
      got = recv_non_empty(dev_a.tun.inbound)
      w << "data_ba[" << i << "]=" << got.hexstring << "\n"
    end

    sleep 50.milliseconds # let counters settle

    print_counters = ->(dev : Wireguard::Device, label : String) do
      stats = [] of {String, UInt64, UInt64}
      dev.peers.each do |pk, peer|
        stats << {pk.hexstring, peer.rx_bytes, peer.tx_bytes}
      end
      stats.sort_by!(&.[0])
      stats.each do |pk, rx, tx|
        w << "counters " << label << " " << pk << " rx=" << rx << " tx=" << tx << "\n"
      end
    end
    print_counters.call(dev_a, "A")
    print_counters.call(dev_b, "B")
  end
end

def recv_non_empty(ch : Channel(Bytes), timeout : Time::Span = 15.seconds) : Bytes
  deadline = Time.monotonic + timeout
  loop do
    remaining = deadline - Time.monotonic
    raise "timed out waiting for packet" if remaining <= Time::Span::ZERO
    select
    when p = ch.receive
      return p unless p.empty?
    when timeout remaining
      raise "timed out waiting for packet"
    end
  end
end

def ipv4_packet(total : Int32, seq : Int32) : Bytes
  p = Bytes.new(total)
  p[0] = 0x45
  IO::ByteFormat::BigEndian.encode(total.to_u16, p[2, 2])
  p[8] = 64
  p[9] = 17 # UDP
  if seq.odd?
    copy_ipv4(p[12, 4], "10.0.0.1")
    copy_ipv4(p[16, 4], "10.0.0.2")
  else
    copy_ipv4(p[12, 4], "10.0.0.2")
    copy_ipv4(p[16, 4], "10.0.0.1")
  end
  (20...total).each do |i|
    p[i] = ('a'.ord + (i + seq) % 26).to_u8!
  end
  p
end

def copy_ipv4(dst : Bytes, s : String) : Nil
  parts = s.split('.')
  4.times { |i| dst[i] = parts[i].to_u8 }
end

# ----------------------------------------------------------------------- main

snap_x25519
snap_hash_kdf
snap_tai64n
snap_messages
snap_cookie
snap_handshake
snap_replay
snap_allowedips
snap_ratelimiter
snap_transport
