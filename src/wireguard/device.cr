# Device, Peer and the Noise IK handshake + transport pipeline.
# A behavioral port of wireguard-go's device/ package for in-process use:
# packets flow through an injectable bind (see MemBind) and tun channels.

require "./blake2s"
require "./chacha20poly1305"
require "./noise_helpers"
require "./messages"
require "./tai64n"
require "./cookie"
require "./replay"
require "./allowed_ips"
require "./keypair"
require "./ratelimiter"
require "./timers"
require "random"

module Wireguard
  # A transport for device datagrams: an inbox of received packets (with the
  # sender's reply address) and a send-by-address operation. Implementations:
  # MemBind (in-process router) and UdpBind (real UDP sockets).
  module Bind
    # Blocking receive of one datagram. Implementations that receive
    # synchronously (UdpBind) may reuse an internal buffer, valid only until
    # the next call — the device pipeline copies out anything it keeps.
    abstract def next_packet? : MemBind::Packet?

    abstract def send(dst : String, data : Bytes) : Nil

    # True when the transport is under sustained pressure and handshake
    # messages should be cookie-filtered (see Device#under_load?).
    def under_load? : Bool
      false
    end

    def start : Nil
    end

    def close : Nil
    end

    def inbox : Channel(MemBind::Packet)
      raise "this bind receives via next_packet?"
    end
  end

  # In-memory transport: routes datagrams between devices by name, the
  # equivalent of the Go harness memBind. Replies are addressed by sender.
  class MemBind
    include Bind

    class Packet
      getter from : String
      getter data : Bytes

      def initialize(@from, @data)
      end
    end

    getter name : String
    getter inbox : Channel(Packet)

    def initialize(router : Router, @name : String)
      @inbox = Channel(Packet).new(256)
      @closed = false
      @router = router
      router.register(self)
    end

    def next_packet? : Packet?
      inbox.receive?
    rescue Channel::ClosedError
      nil
    end

    def send(dst : String, data : Bytes) : Nil
      @router.not_nil!.as(Router).send(@name, dst, data)
    end

    def close : Nil
      return if @closed
      @closed = true
      inbox.close
    end

    class Router
      @devices = {} of String => MemBind

      def register(bind : MemBind) : Nil
        @devices[bind.name] = bind
      end

      def send(from : String, dst : String, data : Bytes) : Nil
        target = @devices[dst]?
        return unless target
        spawn do
          target.inbox.send(Packet.new(from, data.dup))
        rescue Channel::ClosedError
          # device closed: drop, like a UDP send to a dead socket
        end
      end
    end
  end

  # Channels between the device and the "OS": the OS injects IP packets via
  # `outbound` and consumes decrypted packets from `inbound` (the same
  # convention as wireguard-go's tun/tuntest.ChannelTUN).
  class TunChannels
    getter outbound : Channel(Bytes) # OS -> device
    getter inbound : Channel(Bytes)  # device -> OS
    property mtu : Int32 = 1420

    def initialize
      @outbound = Channel(Bytes).new
      @inbound = Channel(Bytes).new
    end
  end

  class Device
    # hot-path scratch, shared per process: Crystal fibers are cooperative and
    # none of the transport code yields while using these
    @@nonce_scratch = Bytes.new(12)
    @@pt_scratch = Bytes.new(65536) # transport plaintext (padded)

    getter sk : Bytes = Bytes.new(32)   # static private key
    getter pk : Bytes = Bytes.new(32)   # static public key
    getter peers : Hash(Bytes, Peer) = {} of Bytes => Peer
    getter allowedips = AllowedIPs.new
    getter cookie_checker = CookieChecker.new
    getter rate_limiter = RateLimiter.new
    getter tun = TunChannels.new
    getter bind : Bind?
    property up : Bool = false
    property name : String = ""
    # configured listen port / fwmark (reported by ipc_get; re-binding the
    # attached bind on change is not implemented)
    property listen_port : UInt16 = 0
    property fwmark : UInt32 = 0
    # manual under-load switch for the cookie mechanism (in addition to any
    # pressure signal reported by the bind itself)
    property manual_under_load : Bool = false

    @index_table : Hash(UInt32, IndexEntry) = {} of UInt32 => IndexEntry
    @next_index : UInt32 = 1

    def initialize(@name : String)
      @tun_channels = @tun
    end

    # Use a different tun channel pair (e.g. the fibers of a TunDevice).
    def attach_tun(channels : TunChannels) : Nil
      @tun = channels
      @tun_channels = channels
    end

    def under_load? : Bool
      manual_under_load || !!@bind.try(&.under_load?)
    end

    def set_private_key(sk : Bytes) : Nil
      @sk = sk.dup
      X25519.clamp(@sk)
      @pk = X25519.public_key(@sk)
      @cookie_checker.init(@pk)
      # drop peers whose public key matches ours, like wireguard-go
      @peers.reject! { |k, _| k == @pk }
      # recompute static-static secrets and expire sessions (like
      # wireguard-go's Device.SetPrivateKey)
      @peers.each_value do |peer|
        begin
          ss = X25519.shared_secret(@sk, peer.remote_static)
          ss.copy_to(peer.precomputed_static_static)
        rescue X25519::Error
          peer.precomputed_static_static.fill(0)
        end
        peer.expire_current_keypairs
      end
    end

    def new_peer(pk : Bytes) : Peer
      peer = Peer.new(self, pk)
      # precompute static-static shared secret
      begin
        ss = X25519.shared_secret(@sk, pk)
        ss.copy_to(peer.precomputed_static_static)
      rescue X25519::Error
        # invalid public key: zero precomputed, handshake will fail
      end
      @peers[pk.dup] = peer
      peer
    end

    def lookup_peer(pk : Bytes) : Peer?
      @peers[pk]?
    end

    # Full peer teardown (wireguard-go's removePeerLocked): routing, timers,
    # key material and index entries.
    def remove_peer(pk : Bytes) : Nil
      peer = @peers[pk]?
      return unless peer
      @allowedips.remove_by_peer(peer)
      peer.stop_and_cleanup
      @peers.delete(pk)
    end

    def attach_bind(bind : Bind) : Nil
      @bind = bind
    end

    # Bring the device up: start the receive and tun loops.
    def start : Nil
      return if @up
      @up = true
      @peers.each_value(&.start)
      if bind = @bind
        bind.start
        spawn receive_loop(bind)
      end
      spawn tun_loop
    end

    def stop : Nil
      @up = false
      @peers.each_value(&.stop)
      @bind.try(&.close)
    end

    # ------------------------------------------------------------- indexes

    private class IndexEntry
      property peer : Peer?
      property keypair : Keypair?

      def initialize(@peer : Peer?, @keypair : Keypair?)
      end
    end

    def new_index(peer : Peer, keypair : Keypair?) : UInt32
      # random indexes, like wireguard-go's indexTable (unguessable receiver
      # indices); fall back to the sequential counter after rare collisions
      8.times do
        idx = Random::Secure.rand(UInt32)
        next if idx == 0 || @index_table[idx]?
        @index_table[idx] = IndexEntry.new(peer, keypair)
        return idx
      end
      idx = @next_index
      @next_index += 1
      @next_index = 1 if @next_index == 0
      @index_table[idx] = IndexEntry.new(peer, keypair)
      idx
    end

    def lookup_index(idx : UInt32) : IndexEntry?
      @index_table[idx]?
    end

    def delete_index(idx : UInt32) : Nil
      @index_table.delete(idx)
    end

    def swap_index_for_keypair(idx : UInt32, kp : Keypair) : Nil
      e = @index_table[idx]?
      if e
        e.keypair = kp
        e.peer = nil
      end
    end

    # ------------------------------------------------------------ handshake

    HANDSHAKE_RATE_LIMIT_NS = 20_000_000_i64 # 1/50 s, like wireguard-go

    def create_message_initiation(peer : Peer) : Messages::MessageInitiation?
      msg = Messages::MessageInitiation.new
      peer.handshake_hash = NoiseHelpers::INITIAL_HASH.dup
      peer.handshake_chain_key = NoiseHelpers::INITIAL_CHAIN_KEY.dup

      peer.handshake_hash = NoiseHelpers.mix_hash(peer.handshake_hash, peer.remote_static)
      peer.local_ephemeral = Bytes.new(32)
      Random::Secure.random_bytes(peer.local_ephemeral)
      X25519.clamp(peer.local_ephemeral)
      eph_pub = X25519.public_key(peer.local_ephemeral)
      msg.ephemeral.copy_from(eph_pub)

      peer.handshake_chain_key = NoiseHelpers.mix_key(peer.handshake_chain_key, eph_pub)
      peer.handshake_hash = NoiseHelpers.mix_hash(peer.handshake_hash, eph_pub)

      ss = X25519.shared_secret(peer.local_ephemeral, peer.remote_static)
      ck, key = NoiseHelpers.kdf2(peer.handshake_chain_key, ss)
      peer.handshake_chain_key = ck
      msg.static_box = ChaCha20Poly1305.seal(
        key, NoiseHelpers::ZERO_NONCE, @pk, peer.handshake_hash)
      peer.handshake_hash = NoiseHelpers.mix_hash(peer.handshake_hash, msg.static_box)

      return nil if peer.precomputed_static_static.all?(&.zero?)
      ck, key = NoiseHelpers.kdf2(peer.handshake_chain_key, peer.precomputed_static_static)
      peer.handshake_chain_key = ck
      timestamp = Tai64n.now
      msg.timestamp_box = ChaCha20Poly1305.seal(
        key, NoiseHelpers::ZERO_NONCE, timestamp, peer.handshake_hash)

      delete_index(peer.local_index)
      msg.sender = new_index(peer, nil)
      peer.local_index = msg.sender
      peer.handshake_hash = NoiseHelpers.mix_hash(peer.handshake_hash, msg.timestamp_box)
      peer.state = :initiation_created
      msg
    end

    def consume_message_initiation(msg : Messages::MessageInitiation) : Peer?
      return nil unless msg.type == Messages::MESSAGE_INITIATION_TYPE

      hash = NoiseHelpers.mix_hash(NoiseHelpers::INITIAL_HASH, @pk)
      hash = NoiseHelpers.mix_hash(hash, msg.ephemeral)
      chain_key = NoiseHelpers.mix_key(NoiseHelpers::INITIAL_CHAIN_KEY, msg.ephemeral)

      ss = X25519.shared_secret(@sk, msg.ephemeral)
      chain_key, key = NoiseHelpers.kdf2(chain_key, ss)
      peer_pk = ChaCha20Poly1305.open(key, NoiseHelpers::ZERO_NONCE, msg.static_box, hash)
      return nil unless peer_pk
      hash = NoiseHelpers.mix_hash(hash, msg.static_box)

      peer = lookup_peer(peer_pk)
      return nil unless peer && peer.running
      return nil if peer.precomputed_static_static.all?(&.zero?)

      chain_key, key = NoiseHelpers.kdf2(chain_key, peer.precomputed_static_static)
      timestamp = ChaCha20Poly1305.open(key, NoiseHelpers::ZERO_NONCE, msg.timestamp_box, hash)
      return nil unless timestamp
      hash = NoiseHelpers.mix_hash(hash, msg.timestamp_box)

      # replay & flood protection
      return nil unless Tai64n.after(timestamp, peer.last_timestamp)
      now = Time.monotonic
      return nil if (now - peer.last_initiation_consumption).total_nanoseconds.to_i64 <= HANDSHAKE_RATE_LIMIT_NS

      peer.handshake_hash = hash
      peer.handshake_chain_key = chain_key
      peer.remote_index = msg.sender
      peer.remote_ephemeral = msg.ephemeral.dup
      peer.last_timestamp = timestamp
      peer.last_initiation_consumption = now
      peer.state = :initiation_consumed
      peer
    end

    def create_message_response(peer : Peer) : Messages::MessageResponse?
      return nil unless peer.state == :initiation_consumed

      msg = Messages::MessageResponse.new
      delete_index(peer.local_index)
      peer.local_index = new_index(peer, nil)
      msg.sender = peer.local_index
      msg.receiver = peer.remote_index

      peer.local_ephemeral = Bytes.new(32)
      Random::Secure.random_bytes(peer.local_ephemeral)
      X25519.clamp(peer.local_ephemeral)
      eph_pub = X25519.public_key(peer.local_ephemeral)
      msg.ephemeral.copy_from(eph_pub)

      peer.handshake_hash = NoiseHelpers.mix_hash(peer.handshake_hash, eph_pub)
      peer.handshake_chain_key = NoiseHelpers.mix_key(peer.handshake_chain_key, eph_pub)

      ss = X25519.shared_secret(peer.local_ephemeral, peer.remote_ephemeral)
      peer.handshake_chain_key = NoiseHelpers.mix_key(peer.handshake_chain_key, ss)
      ss = X25519.shared_secret(peer.local_ephemeral, peer.remote_static)
      peer.handshake_chain_key = NoiseHelpers.mix_key(peer.handshake_chain_key, ss)

      ck, tau, key = NoiseHelpers.kdf3(peer.handshake_chain_key, peer.preshared_key)
      peer.handshake_chain_key = ck
      peer.handshake_hash = NoiseHelpers.mix_hash(peer.handshake_hash, tau)

      msg.empty_box = ChaCha20Poly1305.seal(key, NoiseHelpers::ZERO_NONCE, Bytes.empty, peer.handshake_hash)
      peer.handshake_hash = NoiseHelpers.mix_hash(peer.handshake_hash, msg.empty_box)
      peer.state = :response_created
      msg
    end

    def consume_message_response(msg : Messages::MessageResponse) : Peer?
      return nil unless msg.type == Messages::MESSAGE_RESPONSE_TYPE
      entry = lookup_index(msg.receiver)
      return nil unless entry
      peer = entry.peer
      return nil unless peer
      return nil unless peer.state == :initiation_created

      hash = NoiseHelpers.mix_hash(peer.handshake_hash, msg.ephemeral)
      chain_key = NoiseHelpers.mix_key(peer.handshake_chain_key, msg.ephemeral)

      ss = X25519.shared_secret(peer.local_ephemeral, msg.ephemeral)
      chain_key = NoiseHelpers.mix_key(chain_key, ss)
      ss = X25519.shared_secret(@sk, msg.ephemeral)
      chain_key = NoiseHelpers.mix_key(chain_key, ss)

      chain_key, tau, key = NoiseHelpers.kdf3(chain_key, peer.preshared_key)
      hash = NoiseHelpers.mix_hash(hash, tau)

      return nil unless ChaCha20Poly1305.open(key, NoiseHelpers::ZERO_NONCE, msg.empty_box, hash)
      hash = NoiseHelpers.mix_hash(hash, msg.empty_box)

      peer.handshake_hash = hash
      peer.handshake_chain_key = chain_key
      peer.remote_index = msg.sender
      peer.state = :response_consumed
      peer
    end

    def begin_symmetric_session(peer : Peer) : Bool
      is_initiator = false
      case peer.state
      when :response_consumed
        send_key, recv_key = NoiseHelpers.kdf2(peer.handshake_chain_key, Bytes.empty)
        is_initiator = true
      when :response_created
        recv_key, send_key = NoiseHelpers.kdf2(peer.handshake_chain_key, Bytes.empty)
        is_initiator = false
      else
        return false
      end

      peer.handshake_chain_key = Bytes.new(32)
      peer.handshake_hash = Bytes.new(32)
      peer.local_ephemeral = Bytes.new(32)
      peer.state = :zeroed

      kp = Keypair.new(send_key, recv_key, is_initiator, peer.local_index, peer.remote_index, peer)
      swap_index_for_keypair(peer.local_index, kp)
      peer.local_index = 0
      peer.insert_keypair(kp)
      true
    end

    # ------------------------------------------------------------ transport

    PADDING_MULTIPLE = 16

    def calculate_padding_size(packet_size : Int32, mtu : Int32) : Int32
      last_unit = packet_size
      if mtu == 0
        return ((last_unit + PADDING_MULTIPLE - 1) // PADDING_MULTIPLE) * PADDING_MULTIPLE - last_unit
      end
      last_unit %= mtu if last_unit > mtu
      padded = ((last_unit + PADDING_MULTIPLE - 1) // PADDING_MULTIPLE) * PADDING_MULTIPLE
      padded = mtu if padded > mtu
      padded - last_unit
    end

    # Send an IP packet: route by destination, stage, initiate if needed.
    def send_packet(packet : Bytes) : Nil
      return if packet.size < 12 # need at least src/dst addresses
      dst = case packet[0] >> 4
            when 4 then packet[16, 4]
            when 6 then packet[24, 16]
            else return
            end
      peer = @allowedips.lookup(dst)
      return unless peer
      peer.stage_packet(packet)
    end

    private def tun_loop : Nil
      while @up
        packet = @tun_channels.outbound.receive?
        break unless packet
        send_packet(packet)
      end
    end

    private def receive_loop(bind : Bind) : Nil
      while @up
        pkt = bind.next_packet?
        break unless pkt
        handle_datagram(pkt.from, pkt.data)
      end
    end

    def handle_datagram(src : String, data : Bytes) : Nil
      return if data.size < 4
      msg_type = IO::ByteFormat::LittleEndian.decode(UInt32, data[0, 4])
      case msg_type
      when Messages::MESSAGE_INITIATION_TYPE, Messages::MESSAGE_RESPONSE_TYPE
        return unless @cookie_checker.check_mac1(data)
        if under_load?
          # under load: demand MAC2, else answer with a cookie reply and let
          # the rate limiter cap accepted handshakes (receive.go)
          unless @cookie_checker.check_mac2(data, source_ip(src).to_slice)
            send_cookie_reply(src, data)
            return
          end
          return unless @rate_limiter.allow(source_ip(src))
        end
        handle_handshake_datagram(src, data, msg_type)
      when Messages::MESSAGE_COOKIE_REPLY_TYPE
        handle_cookie_reply(data)
      when Messages::MESSAGE_TRANSPORT_TYPE
        handle_transport(src, data)
      end
    end

    # Source "ip:port" -> "ip" (mem-bind names pass through whole).
    private def source_ip(src : String) : String
      head, _, tail = src.rpartition(':')
      tail.empty? || head.empty? ? src : head
    end

    private def send_cookie_reply(src : String, data : Bytes) : Nil
      recv = IO::ByteFormat::LittleEndian.decode(UInt32, data[4, 4])
      secret = Bytes.new(32)
      nonce = Bytes.new(24)
      Random::Secure.random_bytes(secret)
      Random::Secure.random_bytes(nonce)
      reply = @cookie_checker.create_reply(
        data, recv, source_ip(src).to_slice, secret, nonce)
      @bind.try(&.send(src, reply.marshal))
    end

    private def handle_handshake_datagram(src : String, data : Bytes, msg_type : UInt32) : Nil
      case msg_type
      when Messages::MESSAGE_INITIATION_TYPE
        msg = Messages::MessageInitiation.new
        begin
          msg.unmarshal(data)
        rescue Messages::MessageLengthError
          return
        end
        peer = consume_message_initiation(msg)
        return unless peer
        peer.timers_any_authenticated_packet_traversal
        peer.timers_any_authenticated_packet_received
        peer.rx_bytes &+= data.size
        peer.endpoint_src = src
        # respond: build, derive session keys, then send (the order of
        # wireguard-go's SendHandshakeResponse)
        resp = create_message_response(peer)
        return unless resp
        return unless begin_symmetric_session(peer)
        peer.timers_session_derived
        peer.timers_any_authenticated_packet_traversal
        peer.timers_any_authenticated_packet_sent
        send_handshake_message(peer, resp.marshal)
      when Messages::MESSAGE_RESPONSE_TYPE
        msg = Messages::MessageResponse.new
        begin
          msg.unmarshal(data)
        rescue Messages::MessageLengthError
          return
        end
        peer = consume_message_response(msg)
        return unless peer
        peer.endpoint_src = src
        peer.rx_bytes &+= data.size
        peer.timers_any_authenticated_packet_traversal
        peer.timers_any_authenticated_packet_received
        return unless begin_symmetric_session(peer)
        peer.timers_session_derived
        peer.timers_handshake_complete
        # keepalive only when nothing else is queued, then flush staged
        # (wireguard-go: timersHandshakeComplete + SendKeepalive)
        peer.send_keepalive
      end
    end

    private def handle_cookie_reply(data : Bytes) : Nil
      msg = Messages::MessageCookieReply.new
      begin
        msg.unmarshal(data)
      rescue Messages::MessageLengthError
        return
      end
      entry = lookup_index(msg.receiver)
      peer = entry.try(&.peer)
      return unless peer
      peer.cookie_generator.consume_reply(msg)
    end

    private def handle_transport(src : String, data : Bytes) : Nil
      return unless data.size >= Messages::MESSAGE_TRANSPORT_HEADER_SIZE + 16
      receiver = IO::ByteFormat::LittleEndian.decode(UInt32, data[4, 4])
      counter = IO::ByteFormat::LittleEndian.decode(UInt64, data[8, 8])
      entry = lookup_index(receiver)
      return unless entry
      kp = entry.keypair
      return unless kp

      # expired session: drop it from the table, like lookupKeypair
      if kp.expired?
        delete_index(receiver)
        kp.zero!
        return
      end

      nonce = @@nonce_scratch
      IO::ByteFormat::LittleEndian.encode(counter, nonce[4, 8])
      pt = @@pt_scratch
      content_len = ChaCha20Poly1305.open_into(pt, kp.receive_key, nonce, data[16..], nil)
      return unless content_len

      peer = kp.peer
      return unless peer

      # rx accounting happens for every authenticated packet, then the
      # replay filter runs (order mirrors wireguard-go: validate, account)
      return unless kp.replay_filter.validate_counter(counter, Keypair::REJECT_AFTER_MESSAGES)
      peer.rx_bytes &+= content_len + 32

      if peer.received_with_keypair(kp)
        peer.endpoint_src = src
        peer.timers_handshake_complete
        peer.flush_staged
      end
      peer.endpoint_src = src
      peer.keep_key_fresh_receiving
      peer.timers_any_authenticated_packet_traversal
      peer.timers_any_authenticated_packet_received

      return if content_len == 0 # keepalive
      peer.timers_data_received

      content = Bytes.empty
      ver = pt.unsafe_fetch(0) >> 4
      deliver = case ver
                when 4
                  return false_flag unless content_len >= 20
                  length = IO::ByteFormat::BigEndian.decode(UInt16, pt[2, 2]).to_i32
                  return if length > content_len || length < 20
                  # the delivered packet escapes to the tun reader: fresh copy
                  content = pt[0, length].dup
                  @allowedips.lookup(content[12, 4]) == peer
                when 6
                  return false_flag unless content_len >= 40
                  length = IO::ByteFormat::BigEndian.decode(UInt16, pt[4, 2]).to_i32 + 40
                  return if length > content_len
                  content = pt[0, length].dup
                  @allowedips.lookup(content[8, 16]) == peer
                else
                  false
                end
      return unless deliver
      @tun_channels.inbound.send(content)
    end

    private def false_flag
      false
    end

    def send_handshake_message(peer : Peer, bytes : Bytes) : Nil
      # macs are attached to every handshake message (initiation and response)
      full = bytes.dup
      peer.cookie_generator.add_macs(full)
      peer.tx_bytes &+= full.size
      peer.current_endpoint.try do |ep|
        @bind.try(&.send(ep, full))
      end
    end

    def send_transport(peer : Peer, content : Bytes, kp : Keypair) : Nil
      nonce_counter = kp.send_nonce
      kp.send_nonce &+= 1

      # one allocation per packet: header + padded ciphertext + tag
      pad = calculate_padding_size(content.size, @tun_channels.mtu)
      padded_len = content.size + pad
      packet = Bytes.new(Messages::MESSAGE_TRANSPORT_HEADER_SIZE + padded_len + ChaCha20Poly1305::TAG_SIZE)

      IO::ByteFormat::LittleEndian.encode(Messages::MESSAGE_TRANSPORT_TYPE, packet[0, 4])
      IO::ByteFormat::LittleEndian.encode(kp.remote_index, packet[4, 4])
      IO::ByteFormat::LittleEndian.encode(nonce_counter, packet[8, 8])

      pt = @@pt_scratch
      content.copy_to(pt)
      packet[16 + padded_len, pad].fill(0) if pad > 0

      nonce = @@nonce_scratch
      IO::ByteFormat::LittleEndian.encode(nonce_counter, nonce[4, 8])
      ChaCha20Poly1305.seal_into(packet, Messages::MESSAGE_TRANSPORT_HEADER_SIZE,
        kp.send_key, nonce, pt[0, padded_len], nil)

      peer.tx_bytes &+= packet.size
      peer.timers_any_authenticated_packet_traversal
      peer.timers_any_authenticated_packet_sent
      peer.current_endpoint.try do |ep|
        @bind.try(&.send(ep, packet))
      end
      # keepalive-sized packets don't push the rekey/new-handshake timers
      peer.timers_data_sent if content.size > 0
      peer.keep_key_fresh_sending
    end
  end

  class Peer
    getter device : Device
    getter remote_static : Bytes
    getter precomputed_static_static : Bytes = Bytes.new(32)
    property preshared_key : Bytes = Bytes.new(32)
    # configured endpoint (UAPI) and the address learned from authenticated
    # packets (roaming); retransmits clear the learned source
    property endpoint : String?
    property endpoint_src : String? = nil
    property running : Bool = false

    def current_endpoint : String?
      @endpoint_src || @endpoint
    end

    # handshake state
    property state : Symbol = :zeroed
    property handshake_hash : Bytes = Bytes.new(32)
    property handshake_chain_key : Bytes = Bytes.new(32)
    property local_ephemeral : Bytes = Bytes.new(32)
    property local_index : UInt32 = 0
    property remote_index : UInt32 = 0
    property remote_ephemeral : Bytes = Bytes.new(32)
    property last_timestamp : Bytes = Bytes.new(Tai64n::TIMESTAMP_SIZE)
    property last_initiation_consumption : Time::Span = Time.monotonic - 2.seconds
    @last_sent_handshake_at : Time::Span = Time.monotonic - 1.hour

    # keypairs
    property current_keypair : Keypair?
    property previous_keypair : Keypair?
    property next_keypair : Keypair?

    # staging + accounting
    @staged : Array(Bytes) = [] of Bytes
    property tx_bytes : UInt64 = 0
    property rx_bytes : UInt64 = 0
    # configured allowed ips as given (for the UAPI get operation)
    property allowed_ips : Array(String) = [] of String
    # wall-clock nanoseconds of the last completed handshake (0 = never)
    property last_handshake_unix_nano : Int64 = 0

    getter cookie_generator = CookieGenerator.new

    def initialize(@device, @remote_static)
      @cookie_generator.init(@remote_static)
    end

    def start : Nil
      @running = true
      # allow an immediate handshake, like Go Peer.Start
      @last_sent_handshake_at = Time.monotonic - (REKEY_TIMEOUT + 1.second)
      start_timers
    end

    def stop : Nil
      @running = false
      timers_stop
    end

    # ---------------------------------------------------------- keypairs

    # Insert a freshly derived keypair (wireguard-go Keypairs.insert).
    def insert_keypair(kp : Keypair) : Nil
      if kp.initiator?
        drop_keypair(@previous_keypair) if @previous_keypair
        @previous_keypair = @current_keypair
        @current_keypair = kp
        @next_keypair = nil
      else
        drop_keypair(@next_keypair) if @next_keypair
        @next_keypair = kp
        @previous_keypair = nil
      end
    end

    # Remove a keypair from the index table and zero its keys.
    def drop_keypair(kp : Keypair?) : Nil
      return unless kp
      @device.delete_index(kp.local_index)
      kp.zero!
      @current_keypair = nil if @current_keypair == kp
      @previous_keypair = nil if @previous_keypair == kp
      @next_keypair = nil if @next_keypair == kp
    end

    # Zero handshake state (wireguard-go Handshake.Clear).
    private def handshake_clear : Nil
      @local_ephemeral.fill(0)
      @remote_ephemeral.fill(0)
      @handshake_chain_key.fill(0)
      @handshake_hash.fill(0)
      @local_index = 0
      @state = :zeroed
    end

    # Invalidate current sessions after a key rotation (Go ExpireCurrentKeypairs):
    # also drop the pending handshake index and release the initiation guard,
    # so a fresh handshake starts immediately.
    def expire_current_keypairs : Nil
      @device.delete_index(@local_index)
      handshake_clear
      @last_sent_handshake_at = Time.monotonic - (REKEY_TIMEOUT + 1.second)
      @current_keypair.try { |kp| kp.send_nonce = Keypair::REJECT_AFTER_MESSAGES }
      @next_keypair.try { |kp| kp.send_nonce = Keypair::REJECT_AFTER_MESSAGES }
    end

    # Zero all key material and drop staged packets (Go ZeroAndFlushAll).
    def zero_and_flush_all : Nil
      drop_keypair(@current_keypair)
      drop_keypair(@previous_keypair)
      drop_keypair(@next_keypair)
      @device.delete_index(@local_index)
      handshake_clear
      @staged.clear
    end

    # Full teardown on peer removal.
    def stop_and_cleanup : Nil
      stop
      zero_and_flush_all
      @preshared_key.fill(0)
      @endpoint_src = nil
    end

    # Promote next -> current on first authenticated packet of the session.
    def received_with_keypair(kp : Keypair) : Bool
      return false unless @next_keypair == kp
      drop_keypair(@previous_keypair)
      @previous_keypair = @current_keypair
      @current_keypair = @next_keypair
      @next_keypair = nil
      true
    end

    # ------------------------------------------------------------ sending

    def stage_packet(packet : Bytes) : Nil
      @staged << packet.dup
      send_staged
    end

    def send_staged : Nil
      return if @staged.empty? || !@device.up
      kp = current_keypair
      kp = nil if kp && !kp.sendable?
      if kp.nil?
        # no valid keypair: (re-)initiate; retries are paced by the
        # retransmit timer and the RekeyTimeout send guard
        send_handshake_initiation
        return
      end
      while packet = @staged.shift?
        unless kp.sendable?
          @staged.unshift(packet)
          send_handshake_initiation
          return
        end
        @device.send_transport(self, packet, kp)
      end
    end

    def send_handshake_initiation(retry : Bool = false) : Nil
      unless retry
        @handshake_attempts = 0
      end
      # at most one initiation per RekeyTimeout, like SendHandshakeInitiation
      return if (Time.monotonic - @last_sent_handshake_at) < REKEY_TIMEOUT
      @last_sent_handshake_at = Time.monotonic

      msg = @device.create_message_initiation(self)
      return unless msg
      timers_any_authenticated_packet_traversal
      timers_any_authenticated_packet_sent
      @device.send_handshake_message(self, msg.marshal)
      timers_handshake_initiated
    end

    def flush_staged : Nil
      send_staged
    end

    # Stage a keepalive if nothing else is queued, then send (Go SendKeepalive).
    def send_keepalive : Nil
      @staged << Bytes.empty if @staged.empty? && @running
      send_staged
    end

    # Rekey triggers (Go keepKeyFreshSending / keepKeyFreshReceiving).
    def keep_key_fresh_sending : Nil
      kp = current_keypair
      return unless kp
      if kp.send_nonce > Keypair::REKEY_AFTER_MESSAGES ||
         (kp.initiator? && Time.monotonic - kp.created_at > Keypair::REKEY_AFTER_TIME)
        send_handshake_initiation
      end
    end

    def keep_key_fresh_receiving : Nil
      kp = current_keypair
      return unless kp
      if kp.initiator? &&
         Time.monotonic - kp.created_at > (Keypair::REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT)
        send_handshake_initiation
      end
    end
  end
end
