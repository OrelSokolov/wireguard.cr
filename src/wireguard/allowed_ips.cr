# Longest-prefix-match trie for AllowedIPs, matching the lookup semantics of
# wireguard-go's device/allowedips.go (IPv4 and IPv6 tries per family).

module Wireguard
  class AllowedIPs
    private class Node
      property cidr : Int32 = 0 # prefix length stored here (0 = no entry)
      property peer : Peer? = nil
      property left : Node? = nil  # bit 0
      property right : Node? = nil # bit 1

      def empty? : Bool
        cidr == 0 && peer.nil? && left.nil? && right.nil?
      end
    end

    @roots : Hash(Int32, Node?)

    def initialize
      @roots = Hash(Int32, Node?).new
      @roots[4] = nil
      @roots[16] = nil
    end

    def insert(cidr : String, peer : Peer) : Nil
      ip, prefix = parse_cidr(cidr)
      root = (@roots[ip.size] ||= Node.new)
      node = root
      prefix.times do |i|
        child = bit_at(ip, i) == 0 ? node.left : node.right
        if child.nil?
          child = Node.new
          if bit_at(ip, i) == 0
            node.left = child
          else
            node.right = child
          end
        end
        node = child.not_nil!
      end
      node.cidr = prefix
      node.peer = peer
    end

    def lookup(ip : Bytes) : Peer?
      node = @roots[ip.size]
      return nil unless node
      best = nil
      n : Node? = node
      bit_index = 0
      limit = ip.size * 8
      while cur = n
        best = cur.peer if cur.cidr == bit_index && cur.peer
        break if bit_index >= limit
        n = bit_at(ip, bit_index) == 0 ? cur.left : cur.right
        bit_index += 1
      end
      best
    end

    def remove(cidr : String, peer : Peer) : Nil
      ip, prefix = parse_cidr(cidr)
      n : Node? = @roots[ip.size]
      return unless n
      prefix.times do |i|
        break unless cur = n
        n = bit_at(ip, i) == 0 ? cur.left : cur.right
      end
      if cur = n
        if cur.cidr == prefix && cur.peer == peer
          cur.cidr = 0
          cur.peer = nil
        end
      end
      prune(ip.size)
    end

    def remove_by_peer(peer : Peer) : Nil
      walk_clear(@roots[4], peer)
      walk_clear(@roots[16], peer)
      prune(4)
      prune(16)
    end

    private def walk_clear(node : Node?, peer : Peer) : Nil
      return unless node
      if node.peer == peer
        node.cidr = 0
        node.peer = nil
      end
      walk_clear(node.left, peer)
      walk_clear(node.right, peer)
    end

    private def prune(family : Int32) : Nil
      root = @roots[family]
      return unless root
      prune_node(root)
    end

    private def prune_node(node : Node) : Nil
      if l = node.left
        prune_node(l)
        node.left = nil if l.empty?
      end
      if r = node.right
        prune_node(r)
        node.right = nil if r.empty?
      end
    end

    private def parse_cidr(cidr : String) : {Bytes, Int32}
      addr, _, len = cidr.partition("/")
      prefix_len = len.to_i
      bytes = ip_bytes(addr)
      raise "prefix too long for family" if prefix_len > bytes.size * 8
      {bytes, prefix_len}
    end

    private def ip_bytes(addr : String) : Bytes
      if addr.includes?(":")
        parse_ipv6(addr)
      else
        parts = addr.split('.')
        raise "invalid IPv4" unless parts.size == 4
        Bytes.new(4) { |i| parts[i].to_u8 }
      end
    end

    # minimal IPv6 parser (handles "::" compression, no embedded IPv4)
    private def parse_ipv6(addr : String) : Bytes
      raise "invalid IPv6" unless addr.matches?(/\A[0-9a-fA-F:.]+\z/)
      halves = addr.split("::")
      raise "invalid IPv6" if halves.size > 2
      head = halves[0].split(':').reject(&.empty?)
      tail = halves.size == 2 ? halves[1].split(':').reject(&.empty?) : [] of String
      if halves.size == 2
        fill = 8 - head.size - tail.size
        raise "invalid IPv6" if fill < 0
        groups = (head + Array.new(fill) { "0" } + tail)
      else
        raise "invalid IPv6" unless head.size == 8
        groups = head
      end
      Bytes.new(16) do |i|
        v = groups[i // 2].to_u16(16)
        i.even? ? ((v >> 8).to_u8) : (v & 0xFF).to_u8
      end
    end

    private def bit_at(ip : Bytes, i : Int32) : Int32
      ((ip[i >> 3] >> (7 - (i & 7))) & 1).to_i32
    end
  end
end
