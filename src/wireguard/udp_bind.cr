# Real UDP transport for the device: reads datagrams into a reusable buffer
# and addresses replies as "ip:port" strings. Endpoint strings and parsed
# addresses are cached — the hot path does no allocation per packet beyond
# what the device pipeline itself needs.

require "./device"
require "socket"

module Wireguard
  class UdpBind
    include Bind

    getter name : String

    @socket : UDPSocket
    @recv_buf : Bytes
    @last_from : String?
    @last_addr : Socket::IPAddress?
    @addr_cache : Hash(String, Socket::IPAddress)

    def initialize(port : UInt16 = 0, @name : String = "udp", reuseport : Bool = false)
      @socket = UDPSocket.new
      if reuseport
        # nginx-style: several forked workers each bind the same port and
        # the kernel spreads datagrams across them by flow hash
        one = 1
        LibC.setsockopt(@socket.fd, LibC::SOL_SOCKET, LibC::SO_REUSEPORT,
          pointerof(one).as(Void*), sizeof(Int32))
      end
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
      @recv_buf = Bytes.new(65536)
      @last_from = nil
      @last_addr = nil
      @addr_cache = {} of String => Socket::IPAddress
    end

    def local_port : UInt16
      @socket.local_address.port.to_u16
    end

    # Receiving happens directly on the socket: the device loop processes one
    # datagram at a time before reading the next, so a single reusable buffer
    # is safe (no reference to it escapes the receive path; the device copies
    # out whatever it keeps).
    def next_packet? : MemBind::Packet?
      n, addr = @socket.receive(@recv_buf)
      return nil if n == 0
      from = @last_from
      if !from || !@last_addr || @last_addr.not_nil! != addr
        from = "#{addr.address}:#{addr.port}"
        @last_from = from
        @last_addr = addr
      end
      MemBind::Packet.new(from, @recv_buf[0, n])
    rescue ex : IO::Error | Socket::Error
      nil
    end

    # in-memory devices still route through channels; UDP has no inbox
    def inbox : Channel(MemBind::Packet)
      raise "UdpBind receives directly via next_packet?, not through inbox"
    end

    def send(dst : String, data : Bytes) : Nil
      addr = @addr_cache.fetch(dst, nil)
      unless addr
        host, _, port = dst.rpartition(':')
        addr = Socket::IPAddress.new(host, port.to_i)
        @addr_cache[dst] = addr
      end
      @socket.send(data, addr)
    rescue ex : IO::Error | Socket::Error | ArgumentError
      # unreachable peer: drop the datagram, like a UDP send failure
    end
  end
end
