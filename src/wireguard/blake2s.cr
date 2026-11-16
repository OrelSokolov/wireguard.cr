# Pure-Crystal BLAKE2s (RFC 7693) with keyed mode and configurable digest
# length. WireGuard needs plain 32-byte digests, keyed 16-byte MACs (mac1 /
# mac2 / cookies) and keyed 32-byte digests, which OpenSSL's EVP does not
# expose, hence this implementation.

module Wireguard
  module Blake2s
    BLOCK_SIZE = 64
    SIZE       = 32
    SIZE128    = 16

    private IV = {
      0x6A09E667_u32, 0xBB67AE85_u32, 0x3C6EF372_u32, 0xA54FF53A_u32,
      0x510E527F_u32, 0x9B05688C_u32, 0x1F83D9AB_u32, 0x5BE0CD19_u32,
    }

    private SIGMA = {
      {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
      {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
      {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
      {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
      {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
      {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
      {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
      {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
      {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
      {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    }

    private class State
      @h : StaticArray(UInt32, 8)
      @t : UInt64 = 0
      @buf : Bytes
      @buf_len : Int32 = 0
      @out_len : Int32
      @key_block : Bytes

      def initialize(key : Bytes?, @out_len : Int32)
        @h = StaticArray(UInt32, 8).new { |i| IV[i] }
        @buf = Bytes.new(BLOCK_SIZE)
        @key_block = Bytes.new(BLOCK_SIZE)
        # parameter block: digest length, key length, fanout 1, depth 1
        key_len = key ? key.not_nil!.size : 0
        @h[0] ^= @out_len.to_u32! | (key_len.to_u32! << 8) |
                 (1_u32 << 16) | (1_u32 << 24)
        if key && !key.empty?
          key.copy_to(@key_block)
          update(@key_block) # the key counts as the first data block
        end
      end

      def update(data : Bytes) : Nil
        pos = 0
        while pos < data.size
          if @buf_len == BLOCK_SIZE
            @t += BLOCK_SIZE
            compress(@buf, false)
            @buf_len = 0
          end
          take = {BLOCK_SIZE - @buf_len, data.size - pos}.min
          data[pos, take].copy_to(@buf[@buf_len, take])
          @buf_len += take
          pos += take
        end
      end

      def final : Bytes
        @t += @buf_len.to_u64!
        (@buf_len...BLOCK_SIZE).each { |i| @buf[i] = 0 }
        compress(@buf, true)
        out = Bytes.new(@out_len)
        @out_len.times { |i| out[i] = (@h[i >> 2] >> (8 * (i & 3))).to_u8! }
        out
      end

      # G mixing as a macro: StaticArray is a value type, so a helper method
      # would silently mutate a copy.
      macro blake2s_g(v, m, a, b, c, d, x, y)
        {{v}}[{{a}}] = {{v}}[{{a}}] &+ {{v}}[{{b}}] &+ {{m}}[{{x}}]
        {{v}}[{{d}}] = (({{v}}[{{d}}] ^ {{v}}[{{a}}]) >> 16) | (({{v}}[{{d}}] ^ {{v}}[{{a}}]) << 16)
        {{v}}[{{c}}] = {{v}}[{{c}}] &+ {{v}}[{{d}}]
        {{v}}[{{b}}] = (({{v}}[{{b}}] ^ {{v}}[{{c}}]) >> 12) | (({{v}}[{{b}}] ^ {{v}}[{{c}}]) << 20)
        {{v}}[{{a}}] = {{v}}[{{a}}] &+ {{v}}[{{b}}] &+ {{m}}[{{y}}]
        {{v}}[{{d}}] = (({{v}}[{{d}}] ^ {{v}}[{{a}}]) >> 8) | (({{v}}[{{d}}] ^ {{v}}[{{a}}]) << 24)
        {{v}}[{{c}}] = {{v}}[{{c}}] &+ {{v}}[{{d}}]
        {{v}}[{{b}}] = (({{v}}[{{b}}] ^ {{v}}[{{c}}]) >> 7) | (({{v}}[{{b}}] ^ {{v}}[{{c}}]) << 25)
      end

      private def compress(block : Bytes, last : Bool) : Nil
        m = StaticArray(UInt32, 16).new do |i|
          IO::ByteFormat::LittleEndian.decode(UInt32, block[i * 4, 4]).unsafe_as(UInt32)
        end
        v = StaticArray(UInt32, 16).new { |i| i < 8 ? @h[i] : IV[i - 8] }
        v[12] ^= (@t & 0xFFFFFFFF).to_u32!
        v[13] ^= ((@t >> 32) & 0xFFFFFFFF).to_u32!
        v[14] = v[14] ^ 0xFFFFFFFF_u32 if last

        10.times do |r|
          s = SIGMA[r]
          blake2s_g(v, m, 0, 4, 8, 12, s[0], s[1])
          blake2s_g(v, m, 1, 5, 9, 13, s[2], s[3])
          blake2s_g(v, m, 2, 6, 10, 14, s[4], s[5])
          blake2s_g(v, m, 3, 7, 11, 15, s[6], s[7])
          blake2s_g(v, m, 0, 5, 10, 15, s[8], s[9])
          blake2s_g(v, m, 1, 6, 11, 12, s[10], s[11])
          blake2s_g(v, m, 2, 7, 8, 13, s[12], s[13])
          blake2s_g(v, m, 3, 4, 9, 14, s[14], s[15])
        end

        8.times { |i| @h[i] ^= v[i] ^ v[i + 8] }
      end
    end

    def self.digest256(data : Bytes, key : Bytes? = nil) : Bytes
      s = State.new(key.try(&.empty?) ? nil : key, SIZE)
      s.update(data)
      s.final
    end

    def self.digest128(data : Bytes, key : Bytes? = nil) : Bytes
      s = State.new(key.try(&.empty?) ? nil : key, SIZE128)
      s.update(data)
      s.final
    end
  end
end
