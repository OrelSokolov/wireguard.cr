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
      fun EVP_CIPHER_fetch(ctx : Void*, algorithm : UInt8*, properties : UInt8*) : Void*
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

    # pooled contexts: created once, re-initialized per call (cooperative
    # scheduler, no yields inside, so a single shared ctx is safe).
    # The cipher is fetched once through the OpenSSL 3 provider path — the
    # static EVP_chacha20_poly1305 handle routes through the legacy path,
    # which is noticeably slower. The cipher is also installed on each ctx
    # exactly once; per call we re-init with cipher=NULL (key+nonce only),
    # which skips the provider re-selection and is measurably faster than
    # a full EVP_EncryptInit_ex with the cipher handle on every call.
    @@cipher : Void* = Evp.EVP_CIPHER_fetch(nil, "chacha20-poly1305", nil)
    @@enc_ctx : Void* = begin
      ctx = Evp.EVP_CIPHER_CTX_new
      Evp.EVP_EncryptInit_ex(ctx, @@cipher, nil, nil, nil)
      ctx
    end
    @@dec_ctx : Void* = begin
      ctx = Evp.EVP_CIPHER_CTX_new
      Evp.EVP_DecryptInit_ex(ctx, @@cipher, nil, nil, nil)
      ctx
    end

    # Encrypts into dst at offset: ciphertext followed by the 16-byte tag.
    # Returns the number of bytes written (plaintext.size + TAG_SIZE).
    def self.seal_into(dst : Bytes, offset : Int32, key : Bytes, nonce : Bytes,
                       plaintext : Bytes, aad : Bytes?) : Int32
      raise OpenError.new("ctx_new failed") if @@enc_ctx.null?
      rc = Evp.EVP_EncryptInit_ex(@@enc_ctx, nil, nil, key, nonce)
      raise OpenError.new("encrypt_init failed") if rc != 1
      outl = 0
      if aad && !aad.empty?
        rc = Evp.EVP_EncryptUpdate(@@enc_ctx, nil, pointerof(outl), aad, aad.size)
        raise OpenError.new("aad failed") if rc != 1
      end
      outp = dst.to_unsafe + offset
      if plaintext.size > 0
        rc = Evp.EVP_EncryptUpdate(@@enc_ctx, outp, pointerof(outl), plaintext, plaintext.size)
        raise OpenError.new("update failed") if rc != 1
      end
      fin = uninitialized UInt8[16]
      rc = Evp.EVP_EncryptFinal_ex(@@enc_ctx, fin, pointerof(outl))
      raise OpenError.new("final failed") if rc != 1
      rc = Evp.EVP_CIPHER_CTX_ctrl(@@enc_ctx, CTRL_AEAD_GET_TAG, TAG_SIZE, outp + plaintext.size)
      raise OpenError.new("get_tag failed") if rc != 1
      plaintext.size + TAG_SIZE
    end

    def self.seal(key : Bytes, nonce : Bytes, plaintext : Bytes, aad : Bytes?) : Bytes
      res = Bytes.new(plaintext.size + TAG_SIZE)
      seal_into(res, 0, key, nonce, plaintext, aad)
      res
    end

    # Decrypts ct_and_tag into dst (must have room for ct_and_tag.size -
    # TAG_SIZE bytes). Returns the plaintext length, or nil on authentication
    # failure (like Go's aead.Open).
    def self.open_into(dst : Bytes, key : Bytes, nonce : Bytes,
                       ct_and_tag : Bytes, aad : Bytes?) : Int32?
      return nil unless ct_and_tag.size >= TAG_SIZE
      return nil if @@dec_ctx.null?
      rc = Evp.EVP_DecryptInit_ex(@@dec_ctx, nil, nil, key, nonce)
      return nil if rc != 1
      outl = 0
      if aad && !aad.empty?
        rc = Evp.EVP_DecryptUpdate(@@dec_ctx, nil, pointerof(outl), aad, aad.size)
        return nil if rc != 1
      end
      ct_len = ct_and_tag.size - TAG_SIZE
      if ct_len > 0
        rc = Evp.EVP_DecryptUpdate(@@dec_ctx, dst.to_unsafe, pointerof(outl),
          ct_and_tag.to_unsafe, ct_len)
        return nil if rc != 1
      end
      rc = Evp.EVP_CIPHER_CTX_ctrl(@@dec_ctx, CTRL_AEAD_SET_TAG, TAG_SIZE,
        ct_and_tag.to_unsafe + ct_len)
      return nil if rc != 1
      fin = uninitialized UInt8[16]
      rc = Evp.EVP_DecryptFinal_ex(@@dec_ctx, fin, pointerof(outl))
      return nil if rc != 1
      ct_len
    end

    # Returns nil on authentication failure (like Go's aead.Open).
    def self.open(key : Bytes, nonce : Bytes, ciphertext_and_tag : Bytes, aad : Bytes?) : Bytes?
      return nil unless ciphertext_and_tag.size >= TAG_SIZE
      res = Bytes.new(ciphertext_and_tag.size - TAG_SIZE)
      if open_into(res, key, nonce, ciphertext_and_tag, aad)
        res
      else
        nil
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
