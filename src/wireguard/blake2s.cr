# Pure-Crystal BLAKE2s (RFC 7693) with keyed mode and configurable digest
# length. WireGuard needs plain 32-byte digests, keyed 16-byte MACs (mac1 /
# mac2 / cookies) and keyed 32-byte digests, which OpenSSL's EVP does not
# expose, hence this implementation.
#
# Performance notes: the compression function runs on class-level scratch
# memory accessed through raw pointers (no bounds checks), and the state is
# reusable. This is safe because Crystal fibers are cooperative and no code
# in here ever yields.

module Wireguard
  module Blake2s
    BLOCK_SIZE = 64
    SIZE       = 32
    SIZE128    = 16

    # little-endian assumption for the word loads (x86_64/aarch64); the
    # WireGuard protocol itself is little-endian on the wire
    {% raise "BLAKE2s fast path requires a little-endian target" if flag?(:big_endian) %}

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

    class State

      # G mixing as a macro: raw pointer indexing keeps LLVM able to keep the
      # words in registers (no bounds checks, no StaticArray value copies).
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



      @h : StaticArray(UInt32, 8)
      @t : UInt64 = 0
      @buf : Bytes
      @buf_len : Int32 = 0
      @out_len : Int32

      def initialize(key : Bytes?, @out_len : Int32)
        @h = StaticArray(UInt32, 8).new { |i| IV[i] }
        @buf = Bytes.new(BLOCK_SIZE)
        # parameter block: digest length, key length, fanout 1, depth 1
        key_len = key ? key.not_nil!.size : 0
        @h[0] ^= @out_len.to_u32! | (key_len.to_u32! << 8) |
                 (1_u32 << 16) | (1_u32 << 24)
        if key && !key.empty?
          key.copy_to(@buf[0, key.size])
          @buf_len = BLOCK_SIZE # the key counts as the first data block
        end
      end

      # Re-initialize the state (same semantics as a fresh State) without
      # reallocating the buffers.
      def reset(key : Bytes?) : Nil
        @h = StaticArray(UInt32, 8).new { |i| IV[i] }
        @t = 0
        @buf.fill(0)
        key_len = key ? key.not_nil!.size : 0
        @h[0] ^= @out_len.to_u32! | (key_len.to_u32! << 8) |
                 (1_u32 << 16) | (1_u32 << 24)
        if key && !key.empty?
          key.copy_to(@buf[0, key.size])
          @buf_len = BLOCK_SIZE
        else
          @buf_len = 0
        end
      end

      # incremental update; multiple chunks avoid intermediate concatenations
      def update(data : Bytes) : Nil
        pos = 0
        buf = @buf
        while pos < data.size
          if @buf_len == BLOCK_SIZE
            @t += BLOCK_SIZE
            compress(buf, false)
            @buf_len = 0
          end
          take = {BLOCK_SIZE - @buf_len, data.size - pos}.min
          (data.to_unsafe + pos).move_to(buf.to_unsafe + @buf_len, take)
          @buf_len += take
          pos += take
        end
      end

      def final : Bytes
        @t += @buf_len.to_u64!
        (@buf_len...BLOCK_SIZE).each { |i| @buf[i] = 0 }
        compress(@buf, true)
        out = Bytes.new(@out_len)
        h = @h.to_unsafe
        @out_len.times { |i| out.to_unsafe[i] = (h[i >> 2] >> (8 * (i & 3))).to_u8! }
        out
      end

      def final_into(dst : Bytes) : Nil
        raise "bad digest size" unless dst.size == @out_len
        @t += @buf_len.to_u64!
        (@buf_len...BLOCK_SIZE).each { |i| @buf[i] = 0 }
        compress(@buf, true)
        h = @h.to_unsafe
        @out_len.times { |i| dst.to_unsafe[i] = (h[i >> 2] >> (8 * (i & 3))).to_u8! }
      end

      # G on named locals so LLVM can keep everything in registers (SSA):
      # no pointer stores inside a round means no aliasing reloads.
      macro b2g(a, b, c, d, x, y)
        {{a}} = {{a}} &+ {{b}} &+ {{x}}
        {{d}} = ({{d}} ^ {{a}}).rotate_right(16)
        {{c}} = {{c}} &+ {{d}}
        {{b}} = ({{b}} ^ {{c}}).rotate_right(12)
        {{a}} = {{a}} &+ {{b}} &+ {{y}}
        {{d}} = ({{d}} ^ {{a}}).rotate_right(8)
        {{c}} = {{c}} &+ {{d}}
        {{b}} = ({{b}} ^ {{c}}).rotate_right(7)
      end

      private def compress(block : Bytes, last : Bool) : Nil
        mw = block.to_unsafe.as(Pointer(UInt32))

        # load the whole state and message into locals
        hp = @h.to_unsafe
        h0 = hp[0]; h1 = hp[1]; h2 = hp[2]; h3 = hp[3]
        h4 = hp[4]; h5 = hp[5]; h6 = hp[6]; h7 = hp[7]
        m0 = mw[0]; m1 = mw[1]; m2 = mw[2]; m3 = mw[3]
        m4 = mw[4]; m5 = mw[5]; m6 = mw[6]; m7 = mw[7]
        m8 = mw[8]; m9 = mw[9]; m10 = mw[10]; m11 = mw[11]
        m12 = mw[12]; m13 = mw[13]; m14 = mw[14]; m15 = mw[15]

        v0 = h0; v1 = h1; v2 = h2; v3 = h3
        v4 = h4; v5 = h5; v6 = h6; v7 = h7
        v8 = 0x6A09E667_u32; v9 = 0xBB67AE85_u32; v10 = 0x3C6EF372_u32; v11 = 0xA54FF53A_u32
        v12 = 0x510E527F_u32 ^ (@t & 0xFFFFFFFF).to_u32!
        v13 = 0x9B05688C_u32 ^ ((@t >> 32) & 0xFFFFFFFF).to_u32!
        v14 = last ? (0x1F83D9AB_u32 ^ 0xFFFFFFFF_u32) : 0x1F83D9AB_u32
        v15 = 0x5BE0CD19_u32

        {% for r in 0...10 %}
          b2g(v0, v4, v8, v12, m{{ SIGMA[r][0] }}, m{{ SIGMA[r][1] }})
          b2g(v1, v5, v9, v13, m{{ SIGMA[r][2] }}, m{{ SIGMA[r][3] }})
          b2g(v2, v6, v10, v14, m{{ SIGMA[r][4] }}, m{{ SIGMA[r][5] }})
          b2g(v3, v7, v11, v15, m{{ SIGMA[r][6] }}, m{{ SIGMA[r][7] }})
          b2g(v0, v5, v10, v15, m{{ SIGMA[r][8] }}, m{{ SIGMA[r][9] }})
          b2g(v1, v6, v11, v12, m{{ SIGMA[r][10] }}, m{{ SIGMA[r][11] }})
          b2g(v2, v7, v8, v13, m{{ SIGMA[r][12] }}, m{{ SIGMA[r][13] }})
          b2g(v3, v4, v9, v14, m{{ SIGMA[r][14] }}, m{{ SIGMA[r][15] }})
        {% end %}

        hp[0] = h0 ^ v0 ^ v8
        hp[1] = h1 ^ v1 ^ v9
        hp[2] = h2 ^ v2 ^ v10
        hp[3] = h3 ^ v3 ^ v11
        hp[4] = h4 ^ v4 ^ v12
        hp[5] = h5 ^ v5 ^ v13
        hp[6] = h6 ^ v6 ^ v14
        hp[7] = h7 ^ v7 ^ v15
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
