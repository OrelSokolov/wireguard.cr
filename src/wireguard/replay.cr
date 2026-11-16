# RFC 6479 anti-replay sliding-window filter (port of wireguard-go replay/).

module Wireguard
  class ReplayFilter
    BLOCK_BIT_LOG = 6
    BLOCK_BITS    = 1 << BLOCK_BIT_LOG # 64
    RING_BLOCKS   = 1 << 7             # 128
    WINDOW_SIZE   = (RING_BLOCKS - 1) * BLOCK_BITS
    BLOCK_MASK    = RING_BLOCKS - 1
    BIT_MASK      = BLOCK_BITS - 1

    @last : UInt64 = 0
    @ring : StaticArray(UInt64, RING_BLOCKS)

    def initialize
      @ring = StaticArray(UInt64, RING_BLOCKS).new(0_u64)
    end

    def reset : Nil
      @last = 0
      @ring[0] = 0
    end

    def validate_counter(counter : UInt64, limit : UInt64) : Bool
      return false if counter >= limit
      index_block = counter >> BLOCK_BIT_LOG
      if counter > @last # move window forward
        current = @last >> BLOCK_BIT_LOG
        diff = index_block - current
        diff = RING_BLOCKS.to_u64 if diff > RING_BLOCKS
        (current + 1..current + diff).each do |i|
          @ring[i & BLOCK_MASK] = 0
        end
        @last = counter
      elsif @last - counter > WINDOW_SIZE # behind current window
        return false
      end
      # check and set bit
      ib = index_block & BLOCK_MASK
      index_bit = counter & BIT_MASK
      old = @ring[ib]
      new = old | (1_u64 << index_bit)
      @ring[ib] = new
      old != new
    end
  end
end
