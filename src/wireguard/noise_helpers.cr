# Noise protocol helper functions: HMAC-BLAKE2s, HKDF-style KDFs, initial
# chain key / hash — byte-for-byte ports of wireguard-go device/noise-helpers.go.
#
# HMAC and the KDFs are allocation-free on the hot path: ipad/opad scratch and
# hash states are reused, and multi-part inputs are fed incrementally instead
# of being concatenated first. Safe under Crystal's cooperative scheduler
# (none of this yields).

require "./blake2s"
require "./x25519"

module Wireguard
  module NoiseHelpers
    NOISE_CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
    WG_IDENTIFIER      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
    WG_LABEL_MAC1      = "mac1----"
    WG_LABEL_COOKIE    = "cookie--"

    BLOCK_SIZE = 64

    # reusable HMAC scratch (module-level; no yields inside hmac)
    @@ipad = Bytes.new(BLOCK_SIZE, 0x36_u8)
    @@opad = Bytes.new(BLOCK_SIZE, 0x5c_u8)
    @@inner = Blake2s::State.new(nil, Blake2s::SIZE)
    @@outer = Blake2s::State.new(nil, Blake2s::SIZE)
    @@digest = Bytes.new(Blake2s::SIZE)
    @@inner_digest = Bytes.new(Blake2s::SIZE)

    # HMAC with BLAKE2s-256 (RFC 2104), block size 64.
    def self.hmac(key : Bytes, data : Bytes) : Bytes
      hmac_into(key, data)
      @@digest.dup
    end

    # Same as hmac but the result lives in reusable storage: valid until the
    # next NoiseHelpers call. Callers that keep the value must copy it.
    def self.hmac_scratch(key : Bytes, data : Bytes) : Bytes
      hmac_into(key, data)
      @@digest
    end

    private def self.hmac_into(key : Bytes, data : Bytes) : Nil
      if key.size > BLOCK_SIZE
        key = Blake2s.digest256(key)
      end
      ipad = @@ipad
      opad = @@opad
      ipad.fill(0x36)
      opad.fill(0x5c)
      key.size.times do |i|
        ipad[i] = key.unsafe_fetch(i) ^ 0x36
        opad[i] = key.unsafe_fetch(i) ^ 0x5c
      end

      @@inner.reset(nil)
      @@inner.update(ipad)
      @@inner.update(data)
      @@inner.final_into(@@inner_digest)

      @@outer.reset(nil)
      @@outer.update(opad)
      @@outer.update(@@inner_digest)
      @@outer.final_into(@@digest)
    end

    def self.hmac1(key : Bytes, in0 : Bytes) : Bytes
      hmac(key, in0)
    end

    def self.hmac2(key : Bytes, in0 : Bytes, in1 : Bytes) : Bytes
      # two-part input fed incrementally, no concatenation
      if key.size > BLOCK_SIZE
        key = Blake2s.digest256(key)
      end
      ipad = @@ipad
      opad = @@opad
      ipad.fill(0x36)
      opad.fill(0x5c)
      key.size.times do |i|
        ipad[i] = key.unsafe_fetch(i) ^ 0x36
        opad[i] = key.unsafe_fetch(i) ^ 0x5c
      end

      @@inner.reset(nil)
      @@inner.update(ipad)
      @@inner.update(in0)
      @@inner.update(in1)
      @@inner.final_into(@@inner_digest)

      @@outer.reset(nil)
      @@outer.update(opad)
      @@outer.update(@@inner_digest)
      @@outer.final_into(@@digest)
      @@digest.dup
    end

    def self.kdf1(key : Bytes, input : Bytes) : Bytes
      t0 = hmac_scratch(key, input)
      hmac1(t0, Bytes[1])
    end

    def self.kdf2(key : Bytes, input : Bytes) : {Bytes, Bytes}
      prk = hmac(key, input) # private copy: @@digest is reused below
      t0 = hmac1(prk, Bytes[1])
      t1 = hmac2(prk, t0, Bytes[2])
      {t0, t1}
    end

    def self.kdf3(key : Bytes, input : Bytes) : {Bytes, Bytes, Bytes}
      prk = hmac(key, input) # private copy: @@digest is reused below
      t0 = hmac1(prk, Bytes[1])
      t1 = hmac2(prk, t0, Bytes[2])
      t2 = hmac2(prk, t1, Bytes[3])
      {t0, t1, t2}
    end

    def self.mix_key(chain_key : Bytes, data : Bytes) : Bytes
      kdf1(chain_key, data)
    end

    def self.mix_hash(hash : Bytes, data : Bytes) : Bytes
      Blake2s.digest256(hash + data)
    end

    INITIAL_CHAIN_KEY = Blake2s.digest256(NOISE_CONSTRUCTION.to_slice)
    INITIAL_HASH = mix_hash(INITIAL_CHAIN_KEY, WG_IDENTIFIER.to_slice)
    ZERO_NONCE = Bytes.new(12)
  end
end
