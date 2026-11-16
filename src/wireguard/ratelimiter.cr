# Token-bucket rate limiter for handshake initiations (port of
# wireguard-go ratelimiter/). Uses a monotonic clock.

module Wireguard
  class RateLimiter
    PACKETS_PER_SECOND   =   20
    PACKETS_BURSTABLE    =    5
    PACKET_COST_NS       =    1_000_000_000_i64 // PACKETS_PER_SECOND
    MAX_TOKENS           =    PACKET_COST_NS * PACKETS_BURSTABLE

    private class Entry
      property last_time : Time::Span
      property tokens : Int64

      def initialize(@tokens : Int64, @last_time : Time::Span)
      end
    end

    @table : Hash(String, Entry)
    @clock : Proc(Time::Span)

    def initialize(@clock : Proc(Time::Span) = ->{ Time.monotonic })
      @table = {} of String => Entry
    end

    def allow(ip : String) : Bool
      entry = @table[ip]?
      unless entry
        @table[ip] = Entry.new(MAX_TOKENS - PACKET_COST_NS, @clock.call)
        return true
      end
      now = @clock.call
      entry.tokens += (now - entry.last_time).total_nanoseconds.to_i64
      entry.last_time = now
      entry.tokens = MAX_TOKENS if entry.tokens > MAX_TOKENS
      if entry.tokens > PACKET_COST_NS
        entry.tokens -= PACKET_COST_NS
        true
      else
        false
      end
    end
  end
end
