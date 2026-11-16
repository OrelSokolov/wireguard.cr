# Protocol benchmark for the Crystal port: micro-benchmarks of the protocol
# primitives plus a UDP client/server echo benchmark through the full device
# pipeline. Mirrors harness/bench/main.go on the Go side.

require "../src/wireguard"
require "signal"
require "atomic"

SK1_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
SK2_HEX = "5152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70"

# distinct static key per client flow (the server pre-registers all of them)
def client_sk_hex(id : Int32) : String
  s = SK1_HEX.rchop.rchop # drop the last byte (2 hex chars)
  s + (id % 256).to_s(16).rjust(2, '0')
end

def clamp_pub(sk_hex) : {Bytes, Bytes}
  sk = sk_hex.hexbytes
  Wireguard::X25519.clamp(sk)
  {sk, Wireguard::X25519.public_key(sk)}
end

def bench_packet(size : Int32, seq : Int32, id : Int32 = 0) : Bytes
  p = Bytes.new(size)
  p[0] = 0x45
  IO::ByteFormat::BigEndian.encode(size.to_u16, p[2, 2])
  p[8] = 64
  p[9] = 17
  copy_ipv4(p[12, 4], "10.0.#{id}.1")
  copy_ipv4(p[16, 4], "10.0.#{id}.2")
  (20...size).each { |i| p[i] = ('a'.ord + (i + seq) % 26).to_u8! }
  p
end

def copy_ipv4(dst : Bytes, s : String) : Nil
  parts = s.split('.')
  4.times { |i| dst[i] = parts[i].to_u8 }
end

# --------------------------------------------------------------------- micro

def bench_micro(seconds : Float64) : Nil
  _, pk2 = clamp_pub(SK2_HEX)
  sk1, _ = clamp_pub(SK1_HEX)

  # x25519 shared secrets
  deadline = Time.monotonic + seconds.seconds
  n = 0
  start = Time.monotonic
  while Time.monotonic < deadline
    Wireguard::X25519.shared_secret(sk1, pk2)
    n += 1
  end
  el = (Time.monotonic - start).total_seconds
  printf("micro x25519_ops=%.0f\n", n / el)

  # blake2s-256 over 64 KiB blocks
  block = Bytes.new(64 * 1024) { |i| i.to_u8! }
  deadline = Time.monotonic + seconds.seconds
  total = 0_u64
  start = Time.monotonic
  while Time.monotonic < deadline
    Wireguard::Blake2s.digest256(block)
    total += block.size
  end
  el = (Time.monotonic - start).total_seconds
  printf("micro blake2s_mbs=%.2f\n", total / el / 1024 / 1024)

  # KDF3
  key = "776972656775617264".hexbytes
  input = "776972656775617264".hexbytes
  nh = Wireguard::NoiseHelpers
  deadline = Time.monotonic + seconds.seconds
  n = 0
  start = Time.monotonic
  while Time.monotonic < deadline
    nh.kdf3(key, input)
    n += 1
  end
  el = (Time.monotonic - start).total_seconds
  printf("micro kdf3_ops=%.0f\n", n / el)

  # chacha20poly1305 seal/open on 1400-byte plaintexts
  aead = Wireguard::ChaCha20Poly1305
  aead_key = "cc02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".hexbytes
  raise "bad key" unless aead_key.size == 32
  pt = Bytes.new(1400)
  nonce = Bytes.new(12)
  counter = 0_u64

  deadline = Time.monotonic + seconds.seconds
  total = 0_u64
  start = Time.monotonic
  while Time.monotonic < deadline
    IO::ByteFormat::LittleEndian.encode(counter, nonce[4, 8])
    counter += 1
    aead.seal(aead_key, nonce, pt, nil)
    total += pt.size
  end
  el = (Time.monotonic - start).total_seconds
  printf("micro seal_mbs=%.2f\n", total / el / 1024 / 1024)

  IO::ByteFormat::LittleEndian.encode(0_u64, nonce[4, 8])
  ct = aead.seal(aead_key, nonce, pt, nil)
  deadline = Time.monotonic + seconds.seconds
  total = 0_u64
  start = Time.monotonic
  while Time.monotonic < deadline
    out = aead.open(aead_key, nonce, ct, nil)
    raise "open failed" unless out
    total += out.size
  end
  el = (Time.monotonic - start).total_seconds
  printf("micro open_mbs=%.2f\n", total / el / 1024 / 1024)
end

# ------------------------------------------------------------ device helpers

def build_device(sk_hex : String, port : UInt16 = 0) : {Wireguard::Device, Wireguard::UdpBind}
  bind = Wireguard::UdpBind.new(port)
  dev = Wireguard::Device.new("bench")
  dev.attach_bind(bind)
  dev.ipc_set("private_key=#{sk_hex}\nreplace_peers=true\n")
  dev.start
  {dev, bind}
end

# -------------------------------------------------------------------- server

def server_child(port : Int32, peers : Int32, id : Int32) : Nil
  # each worker binds the same port via SO_REUSEPORT; the kernel spreads
  # flows across workers (nginx model, cf. serverx.cr)
  bind = Wireguard::UdpBind.new(port.to_u16, "worker#{id}", reuseport: true)
  dev = Wireguard::Device.new("worker#{id}")
  dev.attach_bind(bind)
  dev.ipc_set("private_key=#{SK2_HEX}\nreplace_peers=true\n")
  (0...peers).each do |i|
    _, pk = clamp_pub(client_sk_hex(i))
    dev.ipc_set("public_key=#{pk.hexstring}\nallowed_ip=10.0.#{i}.0/24\n")
  end
  dev.start

  spawn do
    loop do
      p = dev.tun.inbound.receive?
      break unless p
      dev.tun.outbound.send(p)
    end
  end

  puts "server_ready"
  STDOUT.flush
  Signal::INT.trap { exit }
  Signal::TERM.trap { exit }
  sleep
end

def run_server(port : Int32, workers : Int32, peers : Int32) : Nil
  children = [] of Int32
  kill_all = ->{ children.each { |pid| Process.signal(Signal::KILL, pid) rescue nil }; exit }
  Signal::INT.trap { kill_all.call }
  Signal::TERM.trap { kill_all.call }
  workers.times do |i|
    pid = Process.fork { server_child(port, peers, i) }
    children << pid.as(Int32) if pid.is_a?(Int32)
  end
  sleep # signals above clean up the workers
end

# -------------------------------------------------------------------- client

def run_client(port : Int32, packets : Int32, size : Int32, id : Int32) : Nil
  dev, _bind = build_device(client_sk_hex(id))
  _, pk2 = clamp_pub(SK2_HEX)
  dev.ipc_set("public_key=#{pk2.hexstring}\nendpoint=127.0.0.1:#{port}\nallowed_ip=10.0.#{id}.0/24\n")

  received = Channel(Nil).new(packets)
  spawn do
    loop do
      p = dev.tun.inbound.receive?
      break unless p
      received.send(nil)
    end
  end

  # first packet: full handshake round trip
  t0 = Time.monotonic
  dev.tun.outbound.send(bench_packet(size, 0, id))
  received.receive
  rtt = Time.monotonic - t0
  printf("client handshake_rtt_us=%.0f\n", rtt.total_microseconds)

  # bulk: inject the rest while the reader drains; a small in-flight window
  # keeps the unbounded staging queue from overflowing the kernel UDP buffers
  done_count = Atomic(Int32).new(1)
  sent_count = Atomic(Int32).new(1)
  spawn do
    (1...packets).each do |i|
      while sent_count.get - done_count.get > 256
        Fiber.yield
      end
      dev.tun.outbound.send(bench_packet(size, i, id))
      sent_count.add(1)
    end
  end

  done_count = Atomic(Int32).new(1)
  t1 = Time.monotonic
  (1...packets).each do
    received.receive
    done_count.add(1)
  end
  el = (Time.monotonic - t1).total_seconds
  total_bytes = (packets - 1) * size
  printf("client packets=%d bytes=%d time_s=%.3f mbps=%.2f pps=%.0f\n",
    packets - 1, total_bytes, el, total_bytes / el / 1024 / 1024, (packets - 1) / el)
end

# ----------------------------------------------------------------------- main

def flag_val(name : String) : String?
  ARGV.each_with_index do |arg, i|
    if arg == name
      return ARGV[i + 1]? if ARGV[i + 1]?
    elsif arg.starts_with?(name + "=")
      return arg[(name.size + 1)..]
    end
  end
  nil
end

mode = ARGV[0]? || "micro"
seconds = (flag_val("--seconds") || "1.0").to_f64
port = (flag_val("--port") || "51820").to_i32
packets = (flag_val("--packets") || "20000").to_i32
size = (flag_val("--size") || "1400").to_i32
id = (flag_val("--id") || "0").to_i32
workers = (flag_val("--workers") || "1").to_i32
peers = (flag_val("--peers") || 1).to_i32

case mode
when "micro"   then bench_micro(seconds)
when "server"  then run_server(port, workers, peers)
when "client"  then run_client(port, packets, size, id)
else
  STDERR.puts "usage: bench [micro|server|client] [--seconds F] [--port N] [--packets N] [--size N] [--id N] [--workers N] [--peers N]"
  exit 2
end
