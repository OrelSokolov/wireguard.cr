# Noise protocol helper functions: HMAC-BLAKE2s, HKDF-style KDFs, initial
# chain key / hash — byte-for-byte ports of wireguard-go device/noise-helpers.go.

require "./blake2s"
require "./x25519"

module Wireguard
  module NoiseHelpers
    NOISE_CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
    WG_IDENTIFIER      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
    WG_LABEL_MAC1      = "mac1----"
    WG_LABEL_COOKIE    = "cookie--"

    # HMAC with BLAKE2s-256 (RFC 2104), block size 64.
    def self.hmac(key : Bytes, data : Bytes) : Bytes
      key = key.dup
      if key.size > Blake2s::BLOCK_SIZE
        key = Blake2s.digest256(key)
      end
      ipad = Bytes.new(Blake2s::BLOCK_SIZE, 0x36_u8)
      opad = Bytes.new(Blake2s::BLOCK_SIZE, 0x5c_u8)
      key.size.times do |i|
        ipad[i] ^= key[i]
        opad[i] ^= key[i]
      end
      inner = Blake2s.digest256(ipad + data)
      Blake2s.digest256(opad + inner)
    end

    def self.hmac1(key : Bytes, in0 : Bytes) : Bytes
      hmac(key, in0)
    end

    def self.hmac2(key : Bytes, in0 : Bytes, in1 : Bytes) : Bytes
      hmac(key, in0 + in1)
    end

    def self.kdf1(key : Bytes, input : Bytes) : Bytes
      t0 = hmac1(key, input)
      hmac1(t0, Bytes[1])
    end

    def self.kdf2(key : Bytes, input : Bytes) : {Bytes, Bytes}
      prk = hmac1(key, input)
      t0 = hmac1(prk, Bytes[1])
      t1 = hmac2(prk, t0, Bytes[2])
      {t0, t1}
    end

    def self.kdf3(key : Bytes, input : Bytes) : {Bytes, Bytes, Bytes}
      prk = hmac1(key, input)
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
