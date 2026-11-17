# wireguard.cr

WireGuard protocol implementation in Crystal, built as a clean-room-style port
of [wireguard-go](https://git.zx2c4.com/wireguard-go/) — with the Go
implementation vendored as an **oracle** and verified against it via
[twinshot](https://github.com/ruby/twinshot) snapshot (differential) testing.

```
✓ 11/11 snapshots — 1:1 parity with wireguard-go (twinshot review)
```

## Layout

| Path                  | What it is                                                    |
|-----------------------|---------------------------------------------------------------|
| `oracle/wireguard-go/`| vendored copy of wireguard-go (the oracle, unmodified)        |
| `harness/`            | Go harness: drives the oracle, writes `artifacts/go/*.txt`    |
| `src/wireguard/`      | the Crystal port (see below)                                  |
| `tools/snapshot.cr`   | Crystal harness: same scenarios, writes `artifacts/cr/*.txt`  |
| `twinshot.yml`        | oracle/current config for `twinshot compare`                  |
| `bin/record-go`       | regenerate the oracle tree                                    |
| `bin/record-cr`       | regenerate the port tree                                      |
| `bin/bench-matrix`    | performance matrix vs wireguard-go (micro + UDP e2e)          |

## What the port implements (`src/wireguard/`)

- **Crypto core** — pure-Crystal BLAKE2s (keyed 128/256, HMAC, KDF1-3),
  X25519 via libcrypto EVP, ChaCha20-Poly1305 via libcrypto EVP, and
  XChaCha20-Poly1305 (HChaCha20 + AEAD) for the cookie mechanism.
- **Noise IKpsk2 handshake** — `CreateMessageInitiation/Response`,
  `ConsumeMessage{Initiation,Response}`, `BeginSymmetricSession`, with
  replay/flood protection and TAI64N timestamps.
- **Wire formats** — initiation/response/cookie-reply messages,
  marshal/unmarshal byte-identical to wireguard-go.
- **Cookie mechanism** — MAC1/MAC2 checking, cookie reply creation and
  consumption under load.
- **Transport** — authenticated data packets with counters, padding,
  RFC 6479 anti-replay window, keepalives, and wireguard-go-compatible
  rx/tx byte accounting.
- **AllowedIPs** — longest-prefix-match trie (IPv4/IPv6).
- **Rate limiter** — token-bucket handshake flood protection.
- **Device/Peer** — in-process device with a channel-based mem bind and
  tun channels (the same topology wireguard-go's own tests use via
  `tuntest.ChannelTUN` + a channel bind), keypair expiry
  (`REJECT_AFTER_TIME`/`REJECT_AFTER_MESSAGES`), random receiver indexes,
  key rotation (`ExpireCurrentKeypairs` semantics), roaming endpoints, and
  constant-time MAC comparison.
- **Timers** — the full wireguard-go timer state machine (port of
  `timers.go`): handshake retransmission with backoff and give-up, rekey on
  traffic/messages, keepalives, persistent keepalive, and zero-key-material
  destruction.
- **Under-load cookies** — MAC2 checking, cookie replies, and the handshake
  rate limiter wired into the device receive path.
- **UAPI** — the configuration subset needed for `private_key`,
  `public_key`, `preshared_key`, `endpoint`, `allowed_ip`, `remove`,
  `replace_peers`, `update_only`, `replace_allowed_ips`,
  `persistent_keepalive_interval`, plus a `wg`-compatible `ipc_get`
  (private key, listen port, fwmark, full per-peer dump with handshake
  times and allowed ips).
- **Real transports** — `UdpBind`: dual-stack IPv6/IPv4 UDP socket with
  recvmmsg/sendmmsg batching; `TunDevice`: Linux TUN interface
  (`/dev/net/tun`, `IFF_TUN|IFF_NO_PI`) bridged to the device channels.
- **UAPI socket + CLI** — `UapiServer`: the xplatform configuration
  protocol over a unix socket (the wire format `wg` speaks);
  `bin/wg-cr`: `show`/`set`/`genkey`/`pubkey` against that socket.

## Differential testing with twinshot

Both harnesses run the same eleven deterministic scenarios and print the same
files; `twinshot` then requires line-for-line parity:

| Snapshot            | Scenario                                                    |
|---------------------|-------------------------------------------------------------|
| `01_x25519`         | public keys, shared secrets, RFC 7748 vectors, low-order rejection |
| `02_hash_kdf`       | BLAKE2s plain/keyed, HMAC1/2, KDF1/2/3 vectors              |
| `03_tai64n`         | timestamp ordering                                          |
| `04_messages`       | marshal/unmarshal of all message types, wire sizes          |
| `05_cookie`         | MAC1/MAC2, cookie reply roundtrip                           |
| `06_handshake`      | full Noise handshake state machine + tamper/replay rejects  |
| `07_replay`         | anti-replay window sequences                                |
| `08_allowedips`     | trie insert/lookup/remove behavior                          |
| `09_ratelimiter`    | handshake flood bucket                                      |
| `10_transport`      | two devices end-to-end: handshake over a mem bind, data both |
|                     | directions, padding, byte counters — all byte-identical     |
| `11_uapi`           | UAPI lifecycle: peer remove (routing cleanup), update_only, |
|                     | peer re-add, and private-key rotation with re-handshake     |

Random inputs (ephemeral keys, cookie secrets/nonces) are never printed, so
the parity surface is fully deterministic.

Run it:

```sh
twinshot review      # regenerate both trees, then compare
twinshot compare     # compare existing trees only
```

## Usage

```crystal
require "./src/wireguard"

router = Wireguard::MemBind::Router.new
dev = Wireguard::Device.new("A")
dev.attach_bind(Wireguard::MemBind.new(router, "A"))
dev.ipc_set("private_key=...\npublic_key=...\nendpoint=B\nallowed_ip=10.0.0.0/24\n")
dev.start

dev.tun.outbound.send(ip_packet)   # OS → device
packet = dev.tun.inbound.receive   # device → OS
```

Running against real sockets (Linux): a dual-stack UDP bind, a TUN
interface, and a `wg`-compatible UAPI socket:

```crystal
dev = Wireguard::Device.new("wgcr0")
dev.attach_bind(Wireguard::UdpBind.new(51820, "wgcr0"))
dev.attach_tun(Wireguard::TunDevice.new("wgcr0").tap(&.start))
Wireguard::UapiServer.new(dev, "/var/run/wireguard/wgcr0.sock").start
dev.start
```

Then `bin/wg-cr show /var/run/wireguard/wgcr0.sock` (or the system `wg`)
configures and inspects the device. Smoke tests for these paths:
`tools/smoke_udp.cr` (loopback handshake over IPv6 and IPv4),
`tools/smoke_uapi.cr` (socket protocol + CLI), `tools/smoke_tun.cr`
(skips without CAP_NET_ADMIN).

## Requirements

- Crystal >= 1.11 (built with 1.21)
- Go >= 1.23 (to run the oracle harness)
- OpenSSL/libcrypto (X25519 + ChaCha20-Poly1305)
- twinshot (`gem install twinshot`)

## Performance vs wireguard-go

`bin/bench-matrix` measures both implementations on the same machine:
micro benchmarks of the protocol primitives, an end-to-end UDP client/server
echo benchmark (fixed keys, 1400-byte packets, a 256-packet in-flight
window, loopback), and a multi-flow run (4 concurrent clients). The cross
combinations (Go server ↔ Crystal client and back) double as an interop
check — the two implementations speak byte-identical WireGuard. In the
multi-flow run the Crystal server uses nginx-style fork workers with
`SO_REUSEPORT` (one process per core); the Go server is a single
multi-goroutine process on all cores.

```sh
bin/bench-matrix --seconds 2 --packets 20000   # writes bench-results.txt
```

Sample run (this machine; single-flow rows are one Crystal event loop
vs one multi-goroutine Go process):

```
                                     go      crystal
x25519 ops/s                      16097        18016
blake2s MB/s                     829.29       693.73
kdf3 ops/s                      406181       518253
chacha seal MB/s                1580.49      1177.46
chacha open MB/s                1708.60      1183.72

                                go→go      cr→cr
e2e handshake rtt µs              3977         1308
e2e echo MB/s                    191.49       172.89
e2e echo pps                     143424       129491

                           go srv→cr cli cr srv→go cli
cross handshake rtt µs            1935         3919
cross echo MB/s                  165.93       188.64
cross echo pps                   124276       141286

                                  go×4 cr×4 (4 workers)
multiflow echo MB/s              170.06       422.13
multiflow echo pps               127377       316167
multiflow avg rtt µs              3374         1419
```

Reading it:

- **x25519** is slightly faster on Crystal — both call the same libcrypto,
  but Go's oracle uses its own pure-Go curve25519.
- **blake2s / kdf / AEAD**: after the SSA-style pure-Crystal BLAKE2s and the
  pooled EVP AEAD (fetched provider cipher, ctx re-init without
  re-selection) the remaining gap is small — kdf3 is faster than Go,
  blake2s and AEAD sit within ~1.2–1.45× of wireguard-go's optimized
  pure-Go.
- **End-to-end single-flow** Crystal reaches ~90% of Go's throughput
  (~129k vs ~143k pps) on one fiber per direction, while Go parallelizes
  its pipeline across goroutines.
- **Cross combos** run at full speed in both directions (Go server ↔
  Crystal client and back), confirming interop over real UDP with no
  bottleneck on either side.
- **Multi-flow** is where the fork-worker model pays off: 4 Crystal
  workers sustain ~316k pps vs Go's ~127k (~2.5×), with lower average
  handshake RTT — each worker owns a whole event loop instead of sharing
  one scheduler across goroutines.


## Roadmap (not yet ported)

- Interface/address/route management (link up, addresses — `ip` tooling's
  job in wg-quick terms) and re-binding the socket on `listen_port` changes
- Retransmission is covered by the timer state machine, but a wg-quick-style
  launcher script tying TUN + UdpBind + UapiServer together is not shipped

The parity harness is designed to grow with the port: every new capability
gets a scenario in `harness/main.go`, the identical scenario in
`tools/snapshot.cr`, and a line in `twinshot.yml`'s trees.
