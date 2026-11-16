# WireGuard message wire formats (port of wireguard-go device/noise-protocol.go
# message structures and their little-endian marshalling).



module Wireguard
  module Messages
    MESSAGE_INITIATION_TYPE   =  1_u32
    MESSAGE_RESPONSE_TYPE     =  2_u32
    MESSAGE_COOKIE_REPLY_TYPE =  3_u32
    MESSAGE_TRANSPORT_TYPE    =  4_u32

    MESSAGE_INITIATION_SIZE      = 148
    MESSAGE_RESPONSE_SIZE        = 92
    MESSAGE_COOKIE_REPLY_SIZE    = 64
    MESSAGE_TRANSPORT_HEADER_SIZE = 16
    MESSAGE_TRANSPORT_SIZE       = MESSAGE_TRANSPORT_HEADER_SIZE + 16
    MESSAGE_KEEPALIVE_SIZE      = MESSAGE_TRANSPORT_SIZE

    class MessageLengthError < Exception
      def initialize
        super("message length mismatch")
      end
    end

    struct MessageInitiation
      property type : UInt32 = MESSAGE_INITIATION_TYPE
      property sender : UInt32 = 0
      property ephemeral : Bytes = Bytes.new(32)          # remote ephemeral public key
      property static_box : Bytes = Bytes.new(32 + 16)    # encrypted static key
      property timestamp_box : Bytes = Bytes.new(12 + 16) # encrypted timestamp
      property mac1 : Bytes = Bytes.new(16)
      property mac2 : Bytes = Bytes.new(16)

      def marshal : Bytes
        raise MessageLengthError.new unless
          ephemeral.size == 32 && static_box.size == 48 &&
          timestamp_box.size == 28 && mac1.size == 16 && mac2.size == 16
        io = IO::Memory.new(MESSAGE_INITIATION_SIZE)
        io.write_bytes(type, IO::ByteFormat::LittleEndian)
        io.write_bytes(sender, IO::ByteFormat::LittleEndian)
        io.write(ephemeral)
        io.write(static_box)
        io.write(timestamp_box)
        io.write(mac1)
        io.write(mac2)
        io.to_slice
      end

      def unmarshal(b : Bytes) : Nil
        raise MessageLengthError.new unless b.size == MESSAGE_INITIATION_SIZE
        @type = IO::ByteFormat::LittleEndian.decode(UInt32, b[0, 4])
        @sender = IO::ByteFormat::LittleEndian.decode(UInt32, b[4, 4])
        b[8, 32].copy_to(ephemeral)
        b[40, 48].copy_to(static_box)
        b[88, 28].copy_to(timestamp_box)
        b[116, 16].copy_to(mac1)
        b[132, 16].copy_to(mac2)
      end
    end

    struct MessageResponse
      property type : UInt32 = MESSAGE_RESPONSE_TYPE
      property sender : UInt32 = 0
      property receiver : UInt32 = 0
      property ephemeral : Bytes = Bytes.new(32)
      property empty_box : Bytes = Bytes.new(16)
      property mac1 : Bytes = Bytes.new(16)
      property mac2 : Bytes = Bytes.new(16)

      def marshal : Bytes
        io = IO::Memory.new(MESSAGE_RESPONSE_SIZE)
        io.write_bytes(type, IO::ByteFormat::LittleEndian)
        io.write_bytes(sender, IO::ByteFormat::LittleEndian)
        io.write_bytes(receiver, IO::ByteFormat::LittleEndian)
        io.write(ephemeral)
        io.write(empty_box)
        io.write(mac1)
        io.write(mac2)
        io.to_slice
      end

      def unmarshal(b : Bytes) : Nil
        raise MessageLengthError.new unless b.size == MESSAGE_RESPONSE_SIZE
        @type = IO::ByteFormat::LittleEndian.decode(UInt32, b[0, 4])
        @sender = IO::ByteFormat::LittleEndian.decode(UInt32, b[4, 4])
        @receiver = IO::ByteFormat::LittleEndian.decode(UInt32, b[8, 4])
        b[12, 32].copy_to(ephemeral)
        b[44, 16].copy_to(empty_box)
        b[60, 16].copy_to(mac1)
        b[76, 16].copy_to(mac2)
      end
    end

    struct MessageCookieReply
      property type : UInt32 = MESSAGE_COOKIE_REPLY_TYPE
      property receiver : UInt32 = 0
      property nonce : Bytes = Bytes.new(24)
      property cookie_box : Bytes = Bytes.new(16 + 16)

      def marshal : Bytes
        io = IO::Memory.new(MESSAGE_COOKIE_REPLY_SIZE)
        io.write_bytes(type, IO::ByteFormat::LittleEndian)
        io.write_bytes(receiver, IO::ByteFormat::LittleEndian)
        io.write(nonce)
        io.write(cookie_box)
        io.to_slice
      end

      def unmarshal(b : Bytes) : Nil
        raise MessageLengthError.new unless b.size == MESSAGE_COOKIE_REPLY_SIZE
        @type = IO::ByteFormat::LittleEndian.decode(UInt32, b[0, 4])
        @receiver = IO::ByteFormat::LittleEndian.decode(UInt32, b[4, 4])
        b[8, 24].copy_to(nonce)
        b[32, 32].copy_to(cookie_box)
      end
    end
  end
end
