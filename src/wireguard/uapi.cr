# UAPI configuration (a subset of wireguard-go's device/uapi.go protocol):
# key=value lines, hex-encoded 32-byte keys, `public_key` starts a peer block.

require "base64"

module Wireguard
  class UapiError < Exception
  end

  class Device
    # Parses a UAPI configuration. Supported keys: private_key,
    # replace_peers, remove, preshared_key, public_key, endpoint,
    # allowed_ip, persistent_keepalive_interval (accepted, no timer yet),
    # replace_allowed_ips, update_only.
    def ipc_set(conf : String) : Nil
      current_peer : Peer? = nil

      conf.each_line do |line|
        line = line.chomp
        next if line.empty?
        key, eq, value = line.partition("=")
        raise UapiError.new("failed to parse line") if eq.empty?

        if key == "public_key"
          pk = hex_bytes(value, 32)
          existing = lookup_peer(pk)
          current_peer = existing || new_peer(pk)
          next
        end

        if current_peer.nil?
          case key
          when "private_key"
            sk = hex_bytes(value, 32)
            set_private_key(sk) unless sk.all?(&.zero?)
          when "replace_peers"
            @peers.clear
            @allowedips = AllowedIPs.new
          when "listen_port", "fwmark"
            # no-op for the in-memory device
          else
            raise UapiError.new("unknown device key: #{key}")
          end
        else
          peer = current_peer.not_nil!
          case key
          when "remove"
            @peers.delete(peer.remote_static)
            current_peer = nil
          when "preshared_key"
            peer.preshared_key = hex_bytes(value, 32)
          when "endpoint"
            peer.endpoint = value
          when "allowed_ip"
            add = !value.starts_with?('-')
            cidr = add ? value : value[1..]
            if add
              @allowedips.insert(cidr, peer)
            else
              @allowedips.remove(cidr, peer)
            end
          when "replace_allowed_ips"
            @allowedips.remove_by_peer(peer)
          when "persistent_keepalive_interval", "protocol_version"
            # accepted, unused
          else
            raise UapiError.new("unknown peer key: #{key}")
          end
        end
      end

      # start peers if the device is up (like wireguard-go handlePostConfig)
      @peers.each_value(&.start) if @up
    end

    # Renders the deterministic subset of the UAPI get operation.
    def ipc_get : String
      String.build do |io|
        io << "private_key=" << @sk.hex unless @sk.all?(&.zero?)
        @peers.each do |pk, peer|
          io << "\npublic_key=" << pk.hex
          if ep = peer.endpoint
            io << "\nendpoint=" << ep
          end
          io << "\nrx_bytes=" << peer.rx_bytes
          io << "\ntx_bytes=" << peer.tx_bytes
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
