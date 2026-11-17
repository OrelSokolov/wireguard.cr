# UAPI configuration (a subset of wireguard-go's device/uapi.go protocol):
# key=value lines, hex-encoded 32-byte keys, `public_key` starts a peer block.

require "base64"

module Wireguard
  class UapiError < Exception
    # negative errno reported over the UAPI socket (IpcError* in wireguard-go)
    property errno : Int32

    def initialize(message : String, @errno : Int32 = -22)
      super(message)
    end
  end

  class Device
    # Parses a UAPI configuration. Supported keys: private_key,
    # replace_peers, remove, update_only, preshared_key, public_key,
    # endpoint, allowed_ip, replace_allowed_ips,
    # persistent_keepalive_interval, protocol_version.
    def ipc_set(conf : String) : Nil
      current_peer : Peer? = nil
      peer_created = false # the peer under construction was newly created
      peer_dummy = false   # lines are ignored until the next public_key
      saw_peer_block = false
      pka_peers = [] of Peer

      conf.each_line do |line|
        line = line.chomp
        next if line.empty?
        key, eq, value = line.partition("=")
        raise UapiError.new("failed to parse line", errno: -71) if eq.empty?

        if key == "public_key"
          pk = hex_bytes(value, 32)
          saw_peer_block = true
          if pk == @pk
            # peer with our own public key: dummy, like handlePublicKeyLine
            peer_dummy = true
            peer_created = false
            current_peer = nil
          else
            peer_dummy = false
            existing = lookup_peer(pk)
            peer_created = existing.nil?
            current_peer = existing || new_peer(pk)
          end
          next
        end

        peer = current_peer

        unless saw_peer_block
          case key
          when "private_key"
            sk = hex_bytes(value, 32)
            set_private_key(sk) unless sk.all?(&.zero?)
          when "replace_peers"
            @peers.keys.dup.each { |k| remove_peer(k) }
          when "listen_port"
            port = value.to_i?
            raise UapiError.new("invalid listen port") unless port && port >= 0 && port <= 65535
            @listen_port = port.to_u16
          when "fwmark"
            mark = value.to_i?(16)
            raise UapiError.new("invalid fwmark") unless mark && mark >= 0
            @fwmark = mark.to_u32
          else
            raise UapiError.new("unknown device key: #{key}")
          end
          next
        end

        case key
        when "remove"
          raise UapiError.new("invalid remove value") unless value == "true"
          if p = peer
            remove_peer(p.remote_static)
          end
          current_peer = nil
          peer_dummy = true
        when "update_only"
          # don't create the peer if it does not exist yet
          raise UapiError.new("invalid update_only value") unless value == "true"
          if peer_created && !peer_dummy && (p = peer)
            remove_peer(p.remote_static)
          end
          peer_created = false
          peer_dummy = true
          current_peer = nil
        when "preshared_key"
          peer.preshared_key = hex_bytes(value, 32) if peer && !peer_dummy
        when "endpoint"
          peer.endpoint = value if peer && !peer_dummy
        when "allowed_ip"
          if peer && !peer_dummy
            add = !value.starts_with?('-')
            cidr = add ? value : value[1..]
            if add
              @allowedips.insert(cidr, peer)
              peer.allowed_ips << cidr unless peer.allowed_ips.includes?(cidr)
            else
              @allowedips.remove(cidr, peer)
              peer.allowed_ips.delete(cidr)
            end
          end
        when "replace_allowed_ips"
          if peer && !peer_dummy
            @allowedips.remove_by_peer(peer)
            peer.allowed_ips.clear
          end
        when "persistent_keepalive_interval"
          interval = value.to_i?
          raise UapiError.new("invalid keepalive interval") unless interval && interval >= 0
          if peer && !peer_dummy
            peer.persistent_keepalive_interval = interval
            pka_peers << peer if interval > 0
          end
        when "protocol_version"
          raise UapiError.new("invalid protocol version") unless value == "1"
        else
          raise UapiError.new("unknown peer key: #{key}")
        end
      end

      # handlePostConfig: start peers if the device is up, kick a keepalive
      # for freshly enabled persistent keepalive, then flush staged packets
      if @up
        @peers.each_value do |peer|
          peer.start
          peer.send_keepalive if pka_peers.includes?(peer)
          peer.flush_staged
        end
      end
    end

    # Renders the UAPI get operation (the xplatform configuration protocol,
    # the same fields wireguard-go reports; see device/uapi.go).
    def ipc_get : String
      String.build do |io|
        io << "private_key=" << @sk.hexstring unless @sk.all?(&.zero?)
        io << "\nlisten_port=" << @listen_port if @listen_port != 0
        io << "\nfwmark=" << @fwmark.to_s(16) if @fwmark != 0
        @peers.each do |pk, peer|
          io << "\npublic_key=" << pk.hexstring
          io << "\npreshared_key=" << peer.preshared_key.hexstring
          io << "\nprotocol_version=1"
          if ep = peer.current_endpoint
            io << "\nendpoint=" << ep
          end
          nano = peer.last_handshake_unix_nano
          io << "\nlast_handshake_time_sec=" << (nano // 1_000_000_000)
          io << "\nlast_handshake_time_nsec=" << (nano % 1_000_000_000)
          io << "\ntx_bytes=" << peer.tx_bytes
          io << "\nrx_bytes=" << peer.rx_bytes
          io << "\npersistent_keepalive_interval=" << peer.persistent_keepalive_interval
          peer.allowed_ips.each do |cidr|
            io << "\nallowed_ip=" << cidr
          end
        end
        io << "\n"
      end
    end

    private def hex_bytes(s : String, n : Int32) : Bytes
      raise UapiError.new("bad hex length") unless s.size == n * 2
      bytes = Bytes.new(n)
      n.times do |i|
        bytes[i] = s[(i * 2), 2].to_u8(16)
      end
      bytes
    end
  end
end
