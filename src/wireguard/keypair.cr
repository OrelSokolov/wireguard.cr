# Session keypair: send/receive keys, counters, replay filter.

require "./chacha20poly1305"
require "./replay"

module Wireguard
  class Keypair
    # (1<<64) - (1<<13) - 1, like wireguard-go's RejectAfterMessages
    REJECT_AFTER_MESSAGES = UInt64::MAX - (1_u64 << 13)
    REJECT_AFTER_TIME = Time::Span.new(seconds: 180)
    REKEY_AFTER_MESSAGES = 1_u64 << 60
    REKEY_AFTER_TIME = Time::Span.new(seconds: 120)

    getter send_key : Bytes
    getter receive_key : Bytes
    getter replay_filter = ReplayFilter.new
    getter? is_initiator : Bool
    getter created_at : Time::Span = Time.monotonic
    getter local_index : UInt32
    getter remote_index : UInt32
    getter peer : Peer?
    property send_nonce : UInt64 = 0

    def initialize(@send_key : Bytes, @receive_key : Bytes,
                   @is_initiator : Bool, @local_index : UInt32, @remote_index : UInt32,
                   @peer : Peer? = nil)
    end

    def initiator? : Bool
      @is_initiator
    end

    def expired? : Bool
      Time.monotonic - created_at >= REJECT_AFTER_TIME
    end

    # May this keypair still be used for sending? (wireguard-go keypairs.Current
    # + the SendStagedPackets validity checks)
    def sendable? : Bool
      send_nonce < REJECT_AFTER_MESSAGES && !expired?
    end

    def zero! : Nil
      send_key.fill(0)
      receive_key.fill(0)
    end
  end
end
