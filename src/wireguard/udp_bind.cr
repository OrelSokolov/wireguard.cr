# Real UDP transport for the device: binds a local socket and feeds received
# datagrams into the device pipeline, addressing replies as "ip:port" strings.

require "./device"
require "socket"

module Wireguard
  class UdpBind
    include Bind

    getter inbox : Channel(MemBind::Packet)
    getter name : String

    @socket : UDPSocket

    def initialize(port : UInt16 = 0, @name : String = "udp")
      @socket = UDPSocket.new
      # generous buffers keep the benchmark pipeline from dropping datagrams
      begin
        # enlarge kernel socket buffers (best effort, like wireguard-go's
        # bind does with its own generous buffer sizes)
        buf = 4*1024*1024
        LibC.setsockopt(@socket.fd, LibC::SOL_SOCKET, LibC::SO_RCVBUF,
          pointerof(buf).as(Void*), sizeof(Int32))
        LibC.setsockopt(@socket.fd, LibC::SOL_SOCKET, LibC::SO_SNDBUF,
          pointerof(buf).as(Void*), sizeof(Int32))
      rescue
        # fall back to system defaults
      end
      @socket.bind("127.0.0.1", port)
      @inbox = Channel(MemBind::Packet).new(1024)
    end

    def local_port : UInt16
      @socket.local_address.port.to_u16
    end

    def start : Nil
      spawn do
        loop do
          buf = Bytes.new(65535)
          n, addr = @socket.receive(buf)
          next if n == 0
          @inbox.send(MemBind::Packet.new(
            "#{addr.address}:#{addr.port}", buf[0, n]))
        end
      rescue ex : IO::Error | Socket::Error
        # socket closed or fatal error: stop feeding the device
      end
    end

    def send(dst : String, data : Bytes) : Nil
      host, _, port = dst.rpartition(':')
      @socket.send(data, Socket::IPAddress.new(host, port.to_i))
    rescue ex : IO::Error | Socket::Error | ArgumentError
      # unreachable peer: drop the datagram, like a UDP send failure
    end
  end
end
