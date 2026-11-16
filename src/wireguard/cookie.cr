# Cookie mechanism (port of wireguard-go device/cookie.go): MAC1/MAC2
# validation and cookie reply generation/consumption.

require "./blake2s"
require "./chacha20poly1305"
require "./noise_helpers"

module Wireguard
  class CookieChecker
    @mac1_key : Bytes = Bytes.new(Blake2s::SIZE)
    @mac2_secret : Bytes = Bytes.new(Blake2s::SIZE)
    @mac2_secret_set_at : Time::Span? = nil
    @encryption_key : Bytes = Bytes.new(ChaCha20Poly1305::KEY_SIZE)

    COOKIE_REFRESH_TIME = Time::Span.new(seconds: 120)

    def init(pk : Bytes) : Nil
      @mac1_key = Blake2s.digest256((NoiseHelpers::WG_LABEL_MAC1.to_slice + pk))
      @encryption_key = Blake2s.digest256((NoiseHelpers::WG_LABEL_COOKIE.to_slice + pk))
      @mac2_secret_set_at = nil
    end

    def check_mac1(msg : Bytes) : Bool
      return false if msg.size < 32
      smac2 = msg.size - Blake2s::SIZE128
      smac1 = smac2 - Blake2s::SIZE128
      mac1 = Blake2s.digest128(msg[0, smac1], @mac1_key)
      mac1 == msg[smac1, 16]
    end

    def check_mac2(msg : Bytes, src : Bytes) : Bool
      set_at = @mac2_secret_set_at
      return false if set_at.nil? || (Time.monotonic - set_at) > COOKIE_REFRESH_TIME
      cookie = Blake2s.digest128(src, @mac2_secret)
      smac2 = msg.size - Blake2s::SIZE128
      mac2 = Blake2s.digest128(msg[0, smac2], cookie)
      mac2 == msg[smac2, 16]
    end

    # Creates a cookie reply for a handshake message. The random secret and
    # nonce are supplied by the caller so tests stay deterministic.
    def create_reply(msg : Bytes, recv : UInt32, src : Bytes,
                     secret : Bytes, nonce : Bytes) : Messages::MessageCookieReply
      raise "bad secret size" unless secret.size == Blake2s::SIZE
      raise "bad nonce size" unless nonce.size == 24
      @mac2_secret = secret.dup
      @mac2_secret_set_at = Time.monotonic

      cookie = Blake2s.digest128(src, @mac2_secret)
      smac2 = msg.size - Blake2s::SIZE128
      smac1 = smac2 - Blake2s::SIZE128

      reply = Messages::MessageCookieReply.new
      reply.type = Messages::MESSAGE_COOKIE_REPLY_TYPE
      reply.receiver = recv
      nonce.copy_to(reply.nonce)
      reply.cookie_box = ChaCha20Poly1305.seal_x(
        @encryption_key, nonce, cookie, msg[smac1, 16])
      reply
    end
  end

  class CookieGenerator
    @mac1_key : Bytes = Bytes.new(Blake2s::SIZE)
    @cookie : Bytes = Bytes.new(Blake2s::SIZE128)
    @cookie_set_at : Time::Span? = nil
    @has_last_mac1 = false
    @last_mac1 : Bytes = Bytes.new(Blake2s::SIZE128)
    @encryption_key : Bytes = Bytes.new(ChaCha20Poly1305::KEY_SIZE)

    def init(pk : Bytes) : Nil
      @mac1_key = Blake2s.digest256((NoiseHelpers::WG_LABEL_MAC1.to_slice + pk))
      @encryption_key = Blake2s.digest256((NoiseHelpers::WG_LABEL_COOKIE.to_slice + pk))
      @cookie_set_at = nil
    end

    def add_macs(msg : Bytes) : Nil
      raise "message too short" if msg.size < 32
      smac2 = msg.size - Blake2s::SIZE128
      smac1 = smac2 - Blake2s::SIZE128
      mac1 = Blake2s.digest128(msg[0, smac1], @mac1_key)
      mac1.copy_to(msg[smac1, 16])
      # store last mac1 for cookie replies
      @last_mac1 = mac1.dup
      @has_last_mac1 = true
      if @cookie_set_at
        mac2 = Blake2s.digest128(msg[0, smac2], @cookie)
        mac2.copy_to(msg[smac2, 16])
      end
    end

    def consume_reply(reply : Messages::MessageCookieReply) : Bool
      return false unless @has_last_mac1
      cookie = ChaCha20Poly1305.open_x(
        @encryption_key, reply.nonce, reply.cookie_box, @last_mac1)
      return false unless cookie
      @cookie = cookie
      @cookie_set_at = Time.monotonic
      true
    end
  end
end
