# ChaCha20-Poly1305 AEAD via libcrypto EVP, plus XChaCha20-Poly1305 (used
# for cookie encryption) built as HChaCha20 + the standard AEAD, the same
# construction golang.org/x/crypto/chacha20poly1305.NewX uses.

module Wireguard
  module ChaCha20Poly1305
    KEY_SIZE     = 32
    NONCE_SIZE   = 12
    TAG_SIZE     = 16
    NONCE_SIZE_X = 24

    class OpenError < Exception
    end

    @[Link("crypto")]
    lib Evp
      fun EVP_chacha20_poly1305 : Void*
      fun EVP_CIPHER_CTX_new : Void*
      fun EVP_CIPHER_CTX_free(ctx : Void*)
      fun EVP_EncryptInit_ex(ctx : Void*, cipher : Void*, impl : Void*, key : UInt8*, iv : UInt8*) : Int32
      fun EVP_EncryptUpdate(ctx : Void*, out : UInt8*, outl : Int32*, in : UInt8*, inl : Int32) : Int32
      fun EVP_EncryptFinal_ex(ctx : Void*, out : UInt8*, outl : Int32*) : Int32
      fun EVP_DecryptInit_ex(ctx : Void*, cipher : Void*, impl : Void*, key : UInt8*, iv : UInt8*) : Int32
      fun EVP_DecryptUpdate(ctx : Void*, out : UInt8*, outl : Int32*, in : UInt8*, inl : Int32) : Int32
      fun EVP_DecryptFinal_ex(ctx : Void*, out : UInt8*, outl : Int32*) : Int32
      fun EVP_CIPHER_CTX_ctrl(ctx : Void*, cmd : Int32, arg : Int32, ptr : Void*) : Int32
    end

    private CTRL_AEAD_GET_TAG = 0x10
    private CTRL_AEAD_SET_TAG = 0x11

    def self.seal(key : Bytes, nonce : Bytes, plaintext : Bytes, aad : Bytes?) : Bytes
      ctx = Evp.EVP_CIPHER_CTX_new
      raise OpenError.new("ctx_new failed") if ctx.null?
      begin
        rc = Evp.EVP_EncryptInit_ex(ctx, Evp.EVP_chacha20_poly1305, nil, key, nonce)
        raise OpenError.new("encrypt_init failed") if rc != 1
        outl = 0
        if aad && !aad.empty?
          rc = Evp.EVP_EncryptUpdate(ctx, nil, pointerof(outl), aad, aad.size)
          raise OpenError.new("aad failed") if rc != 1
        end
        ct = Bytes.new(plaintext.size)
        if plaintext.size > 0
          rc = Evp.EVP_EncryptUpdate(ctx, ct, pointerof(outl), plaintext, plaintext.size)
          raise OpenError.new("update failed") if rc != 1
        end
        fin = Bytes.new(16)
        rc = Evp.EVP_EncryptFinal_ex(ctx, fin, pointerof(outl))
        raise OpenError.new("final failed") if rc != 1
        tag = Bytes.new(TAG_SIZE)
        rc = Evp.EVP_CIPHER_CTX_ctrl(ctx, CTRL_AEAD_GET_TAG, TAG_SIZE, tag)
        raise OpenError.new("get_tag failed") if rc != 1
        ct + tag
      ensure
        Evp.EVP_CIPHER_CTX_free(ctx)
      end
    end

    # Returns nil on authentication failure (like Go's aead.Open).
    def self.open(key : Bytes, nonce : Bytes, ciphertext_and_tag : Bytes, aad : Bytes?) : Bytes?
      return nil unless ciphertext_and_tag.size >= TAG_SIZE
      tag = ciphertext_and_tag[ciphertext_and_tag.size - TAG_SIZE, TAG_SIZE]
      ct = ciphertext_and_tag[0, ciphertext_and_tag.size - TAG_SIZE]
      ctx = Evp.EVP_CIPHER_CTX_new
      return nil if ctx.null?
      begin
        rc = Evp.EVP_DecryptInit_ex(ctx, Evp.EVP_chacha20_poly1305, nil, key, nonce)
        return nil if rc != 1
        outl = 0
        if aad && !aad.empty?
          rc = Evp.EVP_DecryptUpdate(ctx, nil, pointerof(outl), aad, aad.size)
          return nil if rc != 1
        end
        pt = Bytes.new(ct.size)
        if ct.size > 0
          rc = Evp.EVP_DecryptUpdate(ctx, pt, pointerof(outl), ct, ct.size)
          return nil if rc != 1
        end
        rc = Evp.EVP_CIPHER_CTX_ctrl(ctx, CTRL_AEAD_SET_TAG, TAG_SIZE, tag)
        return nil if rc != 1
        fin = Bytes.new(16)
        rc = Evp.EVP_DecryptFinal_ex(ctx, fin, pointerof(outl))
        return nil if rc != 1
        pt
      ensure
        Evp.EVP_CIPHER_CTX_free(ctx)
      end
    end

    # HChaCha20 (draft-irtf-cfrg-xchacha section 2.2): derive the subkey from
    # key and the first 16 bytes of an extended nonce.
    private CONST = {
      0x61707865_u32, 0x3320646e_u32, 0x79622d32_u32, 0x6b206574_u32,
    }

    private QR_IDX = {
      {0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15},
      {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14},
    }

    macro rotr32(x, n)
      (({{x}} >> {{n}}) | ({{x}} << (32 - {{n}})))
    end

    private def self.qr(state, a : Int32, b : Int32, c : Int32, d : Int32) : Nil
      state[a] = state[a] &+ state[b]
      state[d] = rotr32(state[d] ^ state[a], 16)
      state[c] = state[c] &+ state[d]
      state[b] = rotr32(state[b] ^ state[c], 12)
      state[a] = state[a] &+ state[b]
      state[d] = rotr32(state[d] ^ state[a], 8)
      state[c] = state[c] &+ state[d]
      state[b] = rotr32(state[b] ^ state[c], 7)
    end

    def self.hchacha20(key : Bytes, nonce16 : Bytes) : Bytes
      state = StaticArray(UInt32, 16).new do |i|
        if i < 4
          CONST[i]
        elsif i < 8
          IO::ByteFormat::LittleEndian.decode(UInt32, nonce16[(i - 4) * 4, 4]).unsafe_as(UInt32)
        else
          IO::ByteFormat::LittleEndian.decode(UInt32, key[(i - 8) * 4, 4]).unsafe_as(UInt32)
        end
      end
      10.times do
        8.times do |i|
          qr(state, QR_IDX[i][0], QR_IDX[i][1], QR_IDX[i][2], QR_IDX[i][3])
        end
      end
      res = Bytes.new(32)
      4.times do |i|
        IO::ByteFormat::LittleEndian.encode(state[i], res[i * 4, 4])
      end
      4.times do |i|
        IO::ByteFormat::LittleEndian.encode(state[i + 12], res[16 + i * 4, 4])
      end
      res
    end

    # XChaCha20-Poly1305 seal with a 24-byte nonce.
    def self.seal_x(key : Bytes, nonce24 : Bytes, plaintext : Bytes, aad : Bytes?) : Bytes
      subkey = hchacha20(key, nonce24[0, 16])
      nonce = Bytes.new(12)
      nonce24[16, 8].copy_to(nonce[4, 8])
      seal(subkey, nonce, plaintext, aad)
    end

    def self.open_x(key : Bytes, nonce24 : Bytes, ct_and_tag : Bytes, aad : Bytes?) : Bytes?
      subkey = hchacha20(key, nonce24[0, 16])
      nonce = Bytes.new(12)
      nonce24[16, 8].copy_to(nonce[4, 8])
      open(subkey, nonce, ct_and_tag, aad)
    end
  end
end
