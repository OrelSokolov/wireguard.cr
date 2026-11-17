# Real UDP transport for the device with syscall batching (the last big
# single-flow lever): datagrams are read in batches with recvmmsg and sent
# with sendmmsg, mirroring wireguard-go's batched socket bind. The socket is
# a dual-stack IPv6 one (v4 peers arrive as v4-mapped addresses, so both
# "1.2.3.4:53" and "[::1]:53" endpoints work). The socket is non-blocking;
# when nothing is readable the fiber parks in wait_readable, which
# integrates with Crystal's epoll event loop.
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
    AF_INET6     = 10
    IPPROTO_IPV6 = 26
    IPV6_V6ONLY  = 26

    @[Extern]
    private struct SockaddrIn6
      # sin6_family, sin6_port (network order), sin6_flowinfo,
      # sin6_addr (16 bytes as four host-order words), sin6_scope_id
      property family : UInt16
      property port : UInt16
      property flowinfo : UInt32
      property a0 : UInt32
      property a1 : UInt32
      property a2 : UInt32
      property a3 : UInt32
      property scope_id : UInt32

      def initialize(@family, @port, @flowinfo, @a0, @a1, @a2, @a3, @scope_id)
      end

      def self.v4_mapped(octets : StaticArray(UInt8, 4) | Array(UInt8), port : UInt16) : self
        be = (((port & 0xFF) << 8) | ((port >> 8) & 0xFF)).to_u16!
        a3 = (octets[3].to_u32! << 24) | (octets[2].to_u32! << 16) |
             (octets[1].to_u32! << 8) | octets[0].to_u32!
        new(AF_INET6.to_u16!, be, 0_u32, 0_u32, 0_u32, 0xffff0000_u32, a3, 0_u32)
      end

      def self.v6(bytes : Bytes, port : UInt16) : self
        be = (((port & 0xFF) << 8) | ((port >> 8) & 0xFF)).to_u16!
        groups = uninitialized UInt32[4]
        4.times do |g|
          v = 0_u32
          4.times do |i|
            v |= bytes[4 * g + i].to_u32! << (8 * i)
          end
          groups[g] = v
        end
        new(AF_INET6.to_u16!, be, 0_u32, groups[0], groups[1], groups[2], groups[3], 0_u32)
      end

      def addr_bytes : Bytes
        dst = Bytes.new(16)
        {@a0, @a1, @a2, @a3}.each_with_index do |word, g|
          4.times do |i|
            dst[4 * g + i] = ((word >> (8 * i)) & 0xFF).to_u8!
          end
        end
        dst
      end

      def key : String
        String.build do |io|
          io << @port.to_s(16, precision: 4)
          addr_bytes.each { |b| io << b.to_s(16, precision: 2) }
        end
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
    @recv_addrs : Pointer(SockaddrIn6)
    @recv_msgs : Pointer(MMsgHdr)
    @send_iovs : Pointer(IoVec)
    @send_addrs : Pointer(SockaddrIn6)
    @send_msgs : Pointer(MMsgHdr)
    @pending : Array({Bytes, SockaddrIn6}) # payload + destination sockaddr
    @dst_cache : Hash(String, SockaddrIn6)  # "ip:port" -> sockaddr
    @from_cache : Hash(String, String)      # sockaddr key -> "ip:port"
    @batch_base : Int32 = 0
    @batch_count : Int32 = 0
    @rx_idle : Bool = true
    @big_buf : Bytes # idle/oversized fallback buffer

    def initialize(port : UInt16 = 0, @name : String = "udp", reuseport : Bool = false)
      @socket = UDPSocket.new(Socket::Family::INET6)
      if reuseport
        # nginx-style: several forked workers each bind the same port and
        # the kernel spreads datagrams across them by flow hash
        one = 1
        LibC.setsockopt(@socket.fd, LibC::SOL_SOCKET, LibC::SO_REUSEPORT,
          pointerof(one).as(Void*), sizeof(Int32))
      end
      begin
        # dual stack: IPv4 peers arrive as v4-mapped addresses
        zero = 0
        LibC.setsockopt(@socket.fd, IPPROTO_IPV6, IPV6_V6ONLY,
          pointerof(zero).as(Void*), sizeof(Int32))
      rescue
        # keep the system default
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
      @socket.bind("::", port)
      @socket.blocking = false

      # receive batch structures (built once)
      @recv_bufs = Pointer(Pointer(UInt8)).malloc(BATCH)
      @recv_iovs = Pointer(IoVec).malloc(BATCH)
      @recv_addrs = Pointer(SockaddrIn6).malloc(BATCH)
      @recv_msgs = Pointer(MMsgHdr).malloc(BATCH)
      BATCH.times do |i|
        @recv_bufs[i] = Pointer(UInt8).malloc(SLOT_SIZE)
        @recv_iovs[i] = IoVec.new(@recv_bufs[i].as(Void*), SLOT_SIZE.to_u64!)
        @recv_addrs[i] = SockaddrIn6.new(0, 0, 0, 0, 0, 0, 0, 0)
        @recv_msgs[i] = MMsgHdr.new(
          Msghdr.new(@recv_addrs.as(Void*) + i.to_u64! * sizeof(SockaddrIn6), sizeof(SockaddrIn6).to_u32!,
            @recv_iovs + i, 1, Pointer(Void).null, 0, 0), 0)
      end

      # send batch structures
      @send_iovs = Pointer(IoVec).malloc(BATCH)
      @send_addrs = Pointer(SockaddrIn6).malloc(BATCH)
      @send_msgs = Pointer(MMsgHdr).malloc(BATCH)
      BATCH.times do |i|
        @send_addrs[i] = SockaddrIn6.new(0, 0, 0, 0, 0, 0, 0, 0)
        @send_iovs[i] = IoVec.new(Pointer(Void).null, 0.to_u64!)
        @send_msgs[i] = MMsgHdr.new(
          Msghdr.new(@send_addrs.as(Void*) + i.to_u64! * sizeof(SockaddrIn6), sizeof(SockaddrIn6).to_u32!,
            @send_iovs + i, 1, Pointer(Void).null, 0, 0), 0)
      end

      @pending = Array({Bytes, SockaddrIn6}).new(BATCH * 4)
      @dst_cache = {} of String => SockaddrIn6
      @from_cache = {} of String => String
      @big_buf = Bytes.new(65536)
    end

    def local_port : UInt16
      @socket.local_address.port.to_u16
    end

    # Sustained send backlog: the device should cookie-filter handshakes
    # (see Device#under_load?).
    def under_load? : Bool
      @pending.size >= BATCH * 2
    end

    def close : Nil
      @socket.close
    rescue IO::Error | Socket::Error
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
          ip = addr.address
          ip = "[#{ip}]" if ip.includes?(':')
          return MemBind::Packet.new("#{ip}:#{addr.port}", @big_buf[0, len])
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
    private def from_string(addr : SockaddrIn6) : String
      key = addr.key
      cached = @from_cache[key]?
      return cached if cached
      s = "#{format_ip(addr)}:#{format_port(addr.port)}"
      @from_cache[key] = s
      s
    end

    private def format_port(port : UInt16) : UInt16
      ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
    end

    # "127.0.0.1" for v4-mapped, "[::1]" for real IPv6
    private def format_ip(addr : SockaddrIn6) : String
      b = addr.addr_bytes
      if b[0..9].all?(&.zero?) && b[10] == 0xff && b[11] == 0xff
        return String.build do |io|
          io << b[12] << '.' << b[13] << '.' << b[14] << '.' << b[15]
        end
      end
      "[#{UdpBind.format_v6(b)}]"
    end

    def self.format_v6(b : Bytes) : String
      # find the longest zero run (length >= 2) for "::" compression
      best_start = -1
      best_len = 0
      i = 0
      while i < 8
        if b[2 * i] == 0 && b[2 * i + 1] == 0
          j = i
          while j < 8 && b[2 * j] == 0 && b[2 * j + 1] == 0
            j += 1
          end
          if j - i > best_len
            best_len = j - i
            best_start = i
          end
          i = j
        else
          i += 1
        end
      end
      if best_len < 2
        best_start = -1
      end
      String.build do |io|
        g = 0
        while g < 8
          if g == best_start
            io << ':' if g == 0
            io << ':'
            g += best_len
            io << ':' if g == 8
            next
          end
          io << ':' unless g == 0
          io << ((b[2 * g].to_u16! << 8) | b[2 * g + 1]).to_s(16)
          g += 1
        end
      end
    end

    # --------------------------------------------------------------- sending

    def send(dst : String, data : Bytes) : Nil
      sockaddr = @dst_cache.fetch(dst, nil) || begin
        parsed = parse_dst(dst)
        return unless parsed
        @dst_cache[dst] = parsed
        parsed
      end
      @pending << {data, sockaddr}
      return unless @rx_idle
      # the receive fiber is parked and would not flush on its own
      flush_pending
    end

    # "1.2.3.4:53", "[::1]:53" or "fe80::1:53" (more than one colon -> IPv6)
    private def parse_dst(dst : String) : SockaddrIn6?
      if dst.starts_with?('[')
        close = dst.index(']') || return
        host = dst[1...close]
        rest = dst[(close + 1)..]
        return nil unless rest.starts_with?(':')
        port = rest[1..].to_i? || return nil
        return nil unless port > 0 && port <= 65535
        bytes = parse_v6(host) || return nil
        return SockaddrIn6.v6(bytes, port.to_u16!)
      end
      head, _, tail = dst.rpartition(':')
      return nil if head.empty?
      port = tail.to_i? || return nil
      return nil unless port > 0 && port <= 65535
      if head.count(':') == 0
        parts = head.split('.')
        return nil unless parts.size == 4
        octets = Array(UInt8).new(4, 0_u8)
        4.times do |i|
          octet = parts[i].to_i? || return nil
          return nil unless octet >= 0 && octet < 256
          octets[i] = octet.to_u8!
        end
        SockaddrIn6.v4_mapped(octets, port.to_u16!)
      else
        bytes = parse_v6(head) || return nil
        SockaddrIn6.v6(bytes, port.to_u16!)
      end
    end

    # Parses an IPv6 literal (with "::" compression and an optional embedded
    # IPv4 tail) into 16 bytes, or nil.
    def self.parse_v6(s : String) : Bytes?
      return nil if s.empty?
      tail_v4 = nil
      if s.count('.') == 3
        # embedded IPv4: "x::1.2.3.4"
        idx = s.rindex(':') || return nil
        head = s[0...idx]
        v4 = s[(idx + 1)..]
        parts = v4.split('.')
        return nil unless parts.size == 4
        tail_v4 = Bytes.new(4)
        4.times do |i|
          octet = parts[i].to_i? || return nil
          return nil unless octet >= 0 && octet < 256
          tail_v4[i] = octet.to_u8!
        end
        s = head
      end
      want = 8 - (tail_v4 ? 2 : 0)
      halves = s.split("::")
      return nil if halves.size > 2
      left = split_v6_groups(halves[0]) || return nil
      if halves.size == 2
        right = split_v6_groups(halves[1]) || return nil
        # "::" must stand for at least one zero group
        return nil if left.size + right.size > want - 1
        words = Array(UInt16).new(8, 0_u16)
        left.each_with_index { |g, i| words[i] = g }
        right.each_with_index { |g, i| words[want - right.size + i] = g }
      else
        return nil unless left.size == want
        words = left + Array(UInt16).new(8 - left.size, 0_u16)
      end
      dst = Bytes.new(16)
      8.times do |i|
        dst[2 * i] = (words[i] >> 8).to_u8!
        dst[2 * i + 1] = words[i].to_u8!
      end
      if tail_v4
        tail_v4.copy_to(dst[12, 4])
      end
      dst
    end

    private def self.split_v6_groups(s : String) : Array(UInt16)?
      return [] of UInt16 if s.empty?
      parts = s.split(':')
      arr = [] of UInt16
      parts.each do |p|
        return nil if p.empty? || p.size > 4
        v = p.to_u16?(16)
        return nil unless v
        arr << v
      end
      arr
    end

    private def parse_v6(s : String) : Bytes?
      UdpBind.parse_v6(s)
    end

    private def flush_pending : Nil
      while !@pending.empty?
        count = {@pending.size, BATCH}.min
        count.times do |i|
          data, sockaddr = @pending[i]
          # mutate through the pointer: @send_addrs[i] would return a copy
          addr = @send_addrs + i
          addr.value.family = sockaddr.family
          addr.value.port = sockaddr.port
          addr.value.flowinfo = 0
          addr.value.a0 = sockaddr.a0
          addr.value.a1 = sockaddr.a1
          addr.value.a2 = sockaddr.a2
          addr.value.a3 = sockaddr.a3
          addr.value.scope_id = 0
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
