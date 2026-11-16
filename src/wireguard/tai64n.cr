# TAI64N timestamps (port of wireguard-go tai64n package).

module Wireguard
  module Tai64n
    TIMESTAMP_SIZE = 12
    private BASE = 0x400000000000000a_u64
    private WHITENER_MASK = 0x1000000_u32 - 1

    def self.stamp(time : Time) : Bytes
      res = Bytes.new(TIMESTAMP_SIZE)
      secs = BASE + time.to_unix.to_u64!
      nano = (time.nanosecond.to_u32!) & ~WHITENER_MASK
      IO::ByteFormat::BigEndian.encode(secs, res[0, 8])
      IO::ByteFormat::BigEndian.encode(nano, res[8, 4])
      res
    end

    def self.now : Bytes
      stamp(Time.utc)
    end

    # true if t1 is strictly after t2 (bytewise comparison)
    def self.after(t1 : Bytes, t2 : Bytes) : Bool
      (t1 <=> t2) > 0
    end
  end
end
