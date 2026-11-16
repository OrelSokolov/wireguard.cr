# Session keypair: send/receive keys, counters, replay filter.

require "./chacha20poly1305"
require "./replay"

module Wireguard
  class Keypair
    REJECT_AFTER_MESSAGES = 1_u64 << 60
    REJECT_AFTER_TIME = Time::Span.new(seconds: 180)

    getter send_key : Bytes
    getter receive_key : Bytes
    getter replay_filter = ReplayFilter.new
    getter? is_initiator : Bool
    getter created_at : Time::Span = Time.monotonic
    getter local_index : UInt32
    getter remote_index : UInt32
    property send_nonce : UInt64 = 0

    def initialize(@send_key : Bytes, @receive_key : Bytes,
                   @is_initiator : Bool, @local_index : UInt32, @remote_index : UInt32)
    end
  end
end
