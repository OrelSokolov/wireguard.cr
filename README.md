# wireguard.cr

WireGuard protocol implementation in Crystal, built as a clean-room-style port
of [wireguard-go](https://git.zx2c4.com/wireguard-go/) — with the Go
implementation vendored as an **oracle** and verified against it via
[twinshot](https://github.com/ruby/twinshot) snapshot (differential) testing.

```
✓ 10/10 snapshots — 1:1 parity with wireguard-go (twinshot review)
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
  `tuntest.ChannelTUN` + a channel bind).
- **UAPI** — the configuration subset needed for `private_key`,
  `public_key`, `preshared_key`, `endpoint`, `allowed_ip`, `remove`,
  `replace_peers`, plus a deterministic `ipc_get`.

## Differential testing with twinshot

Both harnesses run the same ten deterministic scenarios and print the same
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

## Requirements

- Crystal >= 1.11 (built with 1.21)
- Go >= 1.23 (to run the oracle harness)
- OpenSSL/libcrypto (X25519 + ChaCha20-Poly1305)
- twinshot (`gem install twinshot`)

## Performance vs wireguard-go

`bin/bench-matrix` measures both implementations on the same machine:
micro benchmarks of the protocol primitives, plus an end-to-end UDP
client/server echo benchmark (fixed keys, 1400-byte packets, a 256-packet
in-flight window, loopback). The cross combinations (Go server ↔ Crystal
client and back) double as an interop check — the two implementations speak
byte-identical WireGuard.

```sh
bin/bench-matrix --seconds 2 --packets 20000   # writes bench-results.txt
```

Sample run (this machine, single-threaded Crystal event loop vs Go's
multi-goroutine pipeline):

```
                                     go      crystal
x25519 ops/s                      14726        16633
blake2s MB/s                     783.48       371.79
kdf3 ops/s                       352463       139779
chacha seal MB/s                 736.95       357.41
chacha open MB/s                 973.09       610.50

                                go→go      cr→cr
e2e handshake rtt µs              1918         3083
e2e echo MB/s                    178.53        65.31
e2e echo pps                     133717       48917

                           go srv→cr cli cr srv→go cli
cross handshake rtt µs            1887         4742
cross echo MB/s                   77.15        68.60
cross echo pps                    57784        51377
```

Reading it:

- **x25519** is slightly faster on Crystal — both call the same libcrypto,
  but Go's oracle uses its own pure-Go curve25519.
- **blake2s / kdf / AEAD** are ~2–2.5× slower: the port hashes with pure
  Crystal and allocates per EVP call; wireguard-go uses optimized pure-Go.
- **End-to-end** Crystal reaches roughly a third of Go's throughput
  (~49k vs ~134k pps). The gap tracks the crypto gap plus the port's
  single-fiber receive pipeline versus Go's multi-goroutine queues.
- **Cross combos** are capped by the Crystal side (~51–58k pps), confirming
  the bottleneck is symmetric and that interop works over real UDP.


## Roadmap (not yet ported)

- Retransmission/rekey/keepalive **timers** (currently handshakes are
  triggered by queued data, like the oracle test path)
- Real UDP bind and TUN device plumbing (Linux)
- UAPI socket and `wg`-compatible CLI
- Under-load cookie flow through the device receive path

The parity harness is designed to grow with the port: every new capability
gets a scenario in `harness/main.go`, the identical scenario in
`tools/snapshot.cr`, and a line in `twinshot.yml`'s trees.
