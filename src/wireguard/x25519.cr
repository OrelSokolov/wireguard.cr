# X25519 via libcrypto EVP (RFC 7748). The private scalar is clamped exactly
# like wireguard-go's NoisePrivateKey before use; OpenSSL applies the same
# clamping internally, so this matches x/crypto/curve25519 byte-for-byte.

module Wireguard
  module X25519
    class Error < Exception
    end

    INVALID_PUBLIC_KEY = Error.new("invalid public key")

    @[Link("crypto")]
    lib LibCryptoX
      fun EVP_PKEY_new_raw_private_key(a : Int32, e : Void*, key : UInt8*, keylen : LibC::SizeT) : Void*
      fun EVP_PKEY_new_raw_public_key(a : Int32, e : Void*, key : UInt8*, keylen : LibC::SizeT) : Void*
      fun EVP_PKEY_get_raw_public_key(pkey : Void*, key : UInt8*, keylen : LibC::SizeT*) : Int32
      fun EVP_PKEY_CTX_new(pkey : Void*, e : Void*) : Void*
      fun EVP_PKEY_derive_init(ctx : Void*) : Int32
      fun EVP_PKEY_derive_set_peer(ctx : Void*, peer : Void*) : Int32
      fun EVP_PKEY_derive(ctx : Void*, key : UInt8*, keylen : LibC::SizeT*) : Int32
      fun EVP_PKEY_CTX_free(ctx : Void*)
      fun EVP_PKEY_free(pkey : Void*)
    end

    NID_X25519 = 1034

    def self.clamp(sk : Bytes) : Nil
      raise Error.new("bad private key size") unless sk.size == 32
      sk[0] &= 248
      sk[31] = (sk[31] & 127) | 64
    end

    # Returns the public key for a (clamped) private scalar.
    def self.public_key(sk : Bytes) : Bytes
      raise Error.new("bad private key size") unless sk.size == 32
      pkey = LibCryptoX.EVP_PKEY_new_raw_private_key(NID_X25519, nil, sk, 32)
      raise Error.new("EVP_PKEY_new_raw_private_key failed") if pkey.null?
      begin
        pk = Bytes.new(32)
        len = LibC::SizeT.new(32)
        ret = LibCryptoX.EVP_PKEY_get_raw_public_key(pkey, pk, pointerof(len))
        raise Error.new("EVP_PKEY_get_raw_public_key failed") if ret != 1
        pk
      ensure
        LibCryptoX.EVP_PKEY_free(pkey)
      end
    end

    # Scalar multiplication; raises on an all-zero shared secret (low-order
    # public key), mirroring wireguard-go's sharedSecret.
    def self.shared_secret(sk : Bytes, pk : Bytes) : Bytes
      raise Error.new("bad key sizes") unless sk.size == 32 && pk.size == 32
      priv = LibCryptoX.EVP_PKEY_new_raw_private_key(NID_X25519, nil, sk, 32)
      raise Error.new("EVP_PKEY_new_raw_private_key failed") if priv.null?
      pub = LibCryptoX.EVP_PKEY_new_raw_public_key(NID_X25519, nil, pk, 32)
      if pub.null?
        LibCryptoX.EVP_PKEY_free(priv)
        raise Error.new("EVP_PKEY_new_raw_public_key failed")
      end
      ctx = LibCryptoX.EVP_PKEY_CTX_new(priv, nil)
      if ctx.null? || LibCryptoX.EVP_PKEY_derive_init(ctx) != 1 ||
         LibCryptoX.EVP_PKEY_derive_set_peer(ctx, pub) != 1
        raise Error.new("derive setup failed")
      end
      ss = Bytes.new(32)
      len = LibC::SizeT.new(32)
      ret = LibCryptoX.EVP_PKEY_derive(ctx, ss, pointerof(len))
      LibCryptoX.EVP_PKEY_CTX_free(ctx)
      LibCryptoX.EVP_PKEY_free(pub)
      LibCryptoX.EVP_PKEY_free(priv)
      if ret != 1
        raise INVALID_PUBLIC_KEY
      end
      if ss.all?(&.zero?)
        raise INVALID_PUBLIC_KEY
      end
      ss
    end
  end
end
