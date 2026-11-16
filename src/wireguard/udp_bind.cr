# Real UDP transport for the device with syscall batching (the last big
# single-flow lever): datagrams are read in batches with recvmmsg and sent
# with sendmmsg, mirroring wireguard-go's batched socket bind. The socket is
# non-blocking; when nothing is readable the fiber parks in wait_readable,
# which integrates with Crystal's epoll event loop.
#
# Correctness rules that make buffer reuse safe: the receive loop processes
# one datagram at a time and only refills the batch when it is drained, and
# nothing on the send path references scratch memory (each outgoing packet
# is a fresh allocation owned by the device until handed to us).

require "./device"
require "socket"

module Wireguard
  class UdpBind
    include Bind

    getter name : String

    BATCH = 32
    SLOT_SIZE = 2048 # covers WireGuard transport (mtu 1420 + overhead)

    MSG_DONTWAIT = 0x80
    MSG_TRUNC    = 0x20
    AF_INET      = 2

    @[Extern]
    private struct SockaddrIn
      property family : UInt16
      property port : UInt16    # network byte order
      property addr : UInt32    # network byte order
      property zero : UInt64

      def initialize(@family, @port, @addr, @zero)
      end
    end

    @[Extern]
    private struct IoVec
      property base : Void*
      property len : LibC::SizeT

      def initialize(@base, @len)
      end
    end

    @[Extern]
    private struct Msghdr
      property name : Void*
      property namelen : LibC::UInt
      property iov : IoVec*
      property iovlen : LibC::SizeT
      property control : Void*
      property controllen : LibC::SizeT
      property flags : LibC::Int

      def initialize(@name, @namelen, @iov, @iovlen, @control, @controllen, @flags)
      end
    end

    @[Extern]
    private struct MMsgHdr
      property hdr : Msghdr
      property len : LibC::UInt

      def initialize(@hdr, @len)
      end
    end

    @[Link("crypto")] # shares the libcrypto link already pulled by the port
    lib N
      fun recvmmsg(fd : LibC::Int, msgs : MMsgHdr*, vlen : LibC::UInt, flags : LibC::Int, timeout : Void*) : LibC::Int
      fun sendmmsg(fd : LibC::Int, msgs : MMsgHdr*, vlen : LibC::UInt, flags : LibC::Int) : LibC::Int
    end

    @socket : UDPSocket
    @recv_bufs : Pointer(Pointer(UInt8))
    @recv_iovs : Pointer(IoVec)
    @recv_addrs : Pointer(SockaddrIn)
    @recv_msgs : Pointer(MMsgHdr)
    @send_iovs : Pointer(IoVec)
    @send_addrs : Pointer(SockaddrIn)
    @send_msgs : Pointer(MMsgHdr)
    @pending : Array({Bytes, UInt64}) # payload + destination key (see @dst_cache)
    @dst_cache : Hash(String, UInt64) # "ip:port" -> sockaddr key (addr<<16|port, host order)
    @from_cache : Hash(UInt64, String) # sockaddr key -> "ip:port"
    @batch_base : Int32 = 0
    @batch_count : Int32 = 0
    @rx_idle : Bool = true
    @big_buf : Bytes # idle/oversized fallback buffer

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
        buf = 4*1024*1024
        LibC.setsockopt(@socket.fd, LibC::SOL_SOCKET, LibC::SO_RCVBUF,
          pointerof(buf).as(Void*), sizeof(Int32))
        LibC.setsockopt(@socket.fd, LibC::SOL_SOCKET, LibC::SO_SNDBUF,
          pointerof(buf).as(Void*), sizeof(Int32))
      rescue
        # fall back to system defaults
      end
      @socket.bind("127.0.0.1", port)
      @socket.blocking = false

      # receive batch structures (built once)
      @recv_bufs = Pointer(Pointer(UInt8)).malloc(BATCH)
      @recv_iovs = Pointer(IoVec).malloc(BATCH)
      @recv_addrs = Pointer(SockaddrIn).malloc(BATCH)
      @recv_msgs = Pointer(MMsgHdr).malloc(BATCH)
      BATCH.times do |i|
        @recv_bufs[i] = Pointer(UInt8).malloc(SLOT_SIZE)
        @recv_iovs[i] = IoVec.new(@recv_bufs[i].as(Void*), SLOT_SIZE.to_u64!)
        @recv_addrs[i] = SockaddrIn.new(0, 0, 0, 0)
        @recv_msgs[i] = MMsgHdr.new(
          Msghdr.new(@recv_addrs.as(Void*) + i.to_u64! * sizeof(SockaddrIn), sizeof(SockaddrIn).to_u32!,
            @recv_iovs + i, 1, Pointer(Void).null, 0, 0), 0)
      end

      # send batch structures
      @send_iovs = Pointer(IoVec).malloc(BATCH)
      @send_addrs = Pointer(SockaddrIn).malloc(BATCH)
      @send_msgs = Pointer(MMsgHdr).malloc(BATCH)
      BATCH.times do |i|
        @send_addrs[i] = SockaddrIn.new(0, 0, 0, 0)
        @send_iovs[i] = IoVec.new(Pointer(Void).null, 0.to_u64!)
        @send_msgs[i] = MMsgHdr.new(
          Msghdr.new(@send_addrs.as(Void*) + i.to_u64! * sizeof(SockaddrIn), sizeof(SockaddrIn).to_u32!,
            @send_iovs + i, 1, Pointer(Void).null, 0, 0), 0)
      end

      @pending = Array({Bytes, UInt64}).new(BATCH * 4)
      @dst_cache = {} of String => UInt64
      @from_cache = {} of UInt64 => String
      @big_buf = Bytes.new(65536)
    end

    def local_port : UInt16
      @socket.local_address.port.to_u16
    end

    # ------------------------------------------------------------- receiving

    def next_packet? : MemBind::Packet?
      loop do
        if @batch_count > 0
          i = @batch_base
          @batch_base += 1
          @batch_count -= 1
          len = @recv_msgs[i].len.to_i32
          # oversized datagram (handshake from exotic mtu): recvmmsg truncated
          # it; fall back to a plain big receive for the next arrival
          if (@recv_msgs[i].hdr.flags & MSG_TRUNC) != 0
            drain_oversized
            next
          end
          from = from_string(@recv_addrs[i])
          return MemBind::Packet.new(from, Bytes.new(@recv_bufs[i], len))
        end
        flush_pending unless @pending.empty?
        n = N.recvmmsg(@socket.fd, @recv_msgs, BATCH, MSG_DONTWAIT, nil)
        if n > 0
          @batch_base = 0
          @batch_count = n
          @rx_idle = false
        else
          # nothing in flight: park the fiber via the standard blocking
          # receive (the event loop wakes us on the next datagram) and
          # flush anything the device queued while we were idle
          flush_pending unless @pending.empty?
          @rx_idle = true
          len, addr = @socket.receive(@big_buf)
          @rx_idle = false
          next if len == 0
          return MemBind::Packet.new("#{addr.address}:#{addr.port}", @big_buf[0, len])
        end
      end
    rescue ex : IO::Error | Socket::Error
      nil
    end

    private def drain_oversized : Nil
      # consume the truncated datagram with a plain receive loop (rare path)
      while true
        n, _addr = begin
          @socket.receive(@big_buf)
        rescue IO::Error | Socket::Error
          return
        end
        # data lost (slot buffer was truncated): nothing sensible to do
        return
      end
    end

    # caches "ip:port" strings by sender address (bounded by peer count)
    private def from_string(addr : SockaddrIn) : String
      key = sockaddr_key(addr)
      cached = @from_cache[key]?
      return cached if cached
      ip = addr.addr
      s = String.build do |io|
        io << (ip & 0xFF) << '.' << ((ip >> 8) & 0xFF) << '.'
        io << ((ip >> 16) & 0xFF) << '.' << ((ip >> 24) & 0xFF)
        io << ':' << ((addr.port & 0xFF) << 8 | (addr.port >> 8))
      end
      @from_cache[key] = s
      s
    end

    private def sockaddr_key(addr : SockaddrIn) : UInt64
      (addr.addr.to_u64 << 16) | addr.port.to_u64
    end

    # ------------------------------------------------------------- sending

    def send(dst : String, data : Bytes) : Nil
      key = @dst_cache.fetch(dst, 0_u64)
      if key == 0
        key = parse_dst(dst) || return
        @dst_cache[dst] = key
      end
      @pending << {data, key}
      return unless @rx_idle
      # the receive fiber is parked and would not flush on its own
      flush_pending
    end

    private def parse_dst(dst : String) : UInt64?
      host, _, port_s = dst.rpartition(':')
      port = port_s.to_i? rescue nil
      return nil unless port
      parts = host.split('.')
      return nil unless parts.size == 4
      ip = 0_u32
      4.times do |i|
        octet = parts[i].to_i? rescue nil
        return nil unless octet && octet < 256
        ip |= (octet << (8 * i))
      end
      port_be = (((port >> 8) & 0xFF) | ((port & 0xFF) << 8)).to_u16!
      (ip.to_u64 << 16) | port_be.to_u64
    end

    private def flush_pending : Nil
      while !@pending.empty?
        count = {@pending.size, BATCH}.min
        count.times do |i|
          data, key = @pending[i]
          # mutate through the pointer: @send_addrs[i] would return a copy
          addr = @send_addrs + i
          addr.value.family = AF_INET.to_u16!
          addr.value.addr = (key >> 16).to_u32!
          addr.value.port = key.to_u16!
          addr.value.zero = 0
          @send_iovs[i] = IoVec.new(data.to_unsafe.as(Void*), data.size.to_u64!)
        end
        n = N.sendmmsg(@socket.fd, @send_msgs, count, MSG_DONTWAIT)
        if n <= 0
          # EAGAIN: socket send buffer full — keep the queue, retry on the
          # next flush (kernel drops would be equivalent for UDP anyway)
          return
        end
        @pending.shift(n)
      end
    end
  end
end
