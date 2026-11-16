# wireguard.cr — WireGuard protocol implementation in Crystal.
#
# Verified against the wireguard-go oracle via twinshot snapshot testing:
# see harness/ (Go oracle) and tools/snapshot.cr (Crystal harness).

require "./wireguard/blake2s"
require "./wireguard/x25519"
require "./wireguard/chacha20poly1305"
require "./wireguard/noise_helpers"
require "./wireguard/tai64n"
require "./wireguard/messages"
require "./wireguard/cookie"
require "./wireguard/replay"
require "./wireguard/allowed_ips"
require "./wireguard/ratelimiter"
require "./wireguard/keypair"
require "./wireguard/device"
require "./wireguard/udp_bind"
require "./wireguard/uapi"

module Wireguard
  VERSION = "0.1.0"
end
