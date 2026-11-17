# Linux TUN device (the kernel end of the tunnel): opens /dev/net/tun,
# creates the interface with IFF_TUN|IFF_NO_PI, and bridges it to a
# TunChannels pair with two fibers (fd -> inbound, outbound -> fd). Bringing
# the link up and setting addresses/routes stays with the usual `ip` tooling
# (the same division of labor wg-quick uses).

require "./device"
require "socket"

module Wireguard
  class TunDevice
    getter name : String
    getter channels : TunChannels
    getter mtu : Int32
    @io : IO::FileDescriptor
    @running = false

    TUNSETIFF = 0x400454ca_u64
    IFF_TUN   = 0x0001
    IFF_NO_PI = 0x1000

    @[Extern]
    private struct Ifreq
      property name : StaticArray(UInt8, 16)
      property flags : UInt16

      def initialize(@flags)
        @name = StaticArray(UInt8, 16).new(0)
      end
    end

    @[Link("c")]
    lib L
      fun ioctl(fd : LibC::Int, request : LibC::ULong, arg : Void*) : LibC::Int
    end

    def initialize(@name : String, @mtu : Int32 = 1420)
      fd = LibC.open("/dev/net/tun", LibC::O_RDWR)
      raise IO::Error.new("cannot open /dev/net/tun: #{Errno.value}") if fd < 0

      ifreq = Ifreq.new((IFF_TUN | IFF_NO_PI).to_u16!)
      @name.bytes.each_with_index { |b, i| ifreq.name[i] = b if i < 15 }
      err = L.ioctl(fd, TUNSETIFF, pointerof(ifreq).as(Void*))
      raise IO::Error.new("TUNSETIFF failed: #{Errno.value}") if err < 0
      # the kernel may pick a different name (wg0%d style); read it back
      actual = String.new(ifreq.name.to_unsafe)
      @name = actual unless actual.empty?

      @io = IO::FileDescriptor.new(fd, blocking: false)
      @channels = TunChannels.new
      @channels.mtu = @mtu
    end

    def start : Nil
      return if @running
      @running = true
      spawn read_loop
      spawn write_loop
    end

    def stop : Nil
      @running = false
      @io.close
    end

    private def read_loop : Nil
      buf = Bytes.new(65536)
      while @running
        n = @io.read(buf)
        break if n == 0 # EOF: device closed
        next if n < 0
        @channels.inbound.send(buf[0, n].dup)
      end
    rescue ex : IO::Error
      return unless @running # stopped: expected
      raise ex
    end

    private def write_loop : Nil
      while @running
        packet = @channels.outbound.receive?
        break unless packet
        @io.write(packet)
      end
    rescue ex : IO::Error
      return unless @running
      raise ex
    end
  end
end
