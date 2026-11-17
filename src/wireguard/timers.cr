# Timer state machine (port of wireguard-go device/timers.go): the wireguard
# protocol's time-based behavior — handshake retransmission, keepalives,
# rekey triggers and key-material destruction. One fiber per peer services
# the deadlines; Mod/Del wake it so an armed timer never waits on a stale
# sleep. Timer hooks no-op unless the peer is running and the device is up,
# exactly like timersActive().

module Wireguard
  class Peer
    REKEY_TIMEOUT            = Time::Span.new(seconds: 5)
    REKEY_ATTEMPT_TIME       = Time::Span.new(seconds: 90)
    MAX_TIMER_HANDSHAKES     = 18 # RekeyAttemptTime / RekeyTimeout
    REKEY_TIMEOUT_JITTER_MAX = Time::Span.new(seconds: 0, nanoseconds: 334_000_000)
    KEEPALIVE_TIMEOUT        = Time::Span.new(seconds: 10)

    @t_retransmit_handshake : Time::Span? = nil
    @t_send_keepalive : Time::Span? = nil
    @t_new_handshake : Time::Span? = nil
    @t_zero_key_material : Time::Span? = nil
    @t_persistent_keepalive : Time::Span? = nil
    @handshake_attempts : Int32 = 0
    @need_another_keepalive = false
    @timer_wake = Channel(Nil).new(1)
    @timers_started = false

    property persistent_keepalive_interval : Int32 = 0

    def timers_active? : Bool
      @running && @device.up
    end

    def start_timers : Nil
      return if @timers_started
      @timers_started = true
      spawn timer_loop
    end

    def timers_stop : Nil
      @t_retransmit_handshake = nil
      @t_send_keepalive = nil
      @t_new_handshake = nil
      @t_zero_key_material = nil
      @t_persistent_keepalive = nil
    end

    private def wake_timer : Nil
      select
      when @timer_wake.send(nil)
      else
      end
    end

    private def timer_loop : Nil
      while @running
        now = Time.monotonic
        deadlines = {@t_retransmit_handshake, @t_send_keepalive, @t_new_handshake,
                     @t_zero_key_material, @t_persistent_keepalive}
        next fire_due_timers(now) if deadlines.any? { |d| d && d <= now }
        earliest = deadlines.to_a.compact.min?
        wait = earliest ? earliest - now : nil
        case wait
        when Nil
          @timer_wake.receive
        when .>(Time::Span::ZERO)
          select
          when timeout(wait)
          when @timer_wake.receive
          end
        end
      end
    end

    private def fire_due_timers(now : Time::Span) : Nil
      if (d = @t_retransmit_handshake) && d <= now
        @t_retransmit_handshake = nil
        expired_retransmit_handshake
      end
      if (d = @t_send_keepalive) && d <= now
        @t_send_keepalive = nil
        expired_send_keepalive
      end
      if (d = @t_new_handshake) && d <= now
        @t_new_handshake = nil
        expired_new_handshake
      end
      if (d = @t_zero_key_material) && d <= now
        @t_zero_key_material = nil
        expired_zero_key_material
      end
      if (d = @t_persistent_keepalive) && d <= now
        @t_persistent_keepalive = nil
        expired_persistent_keepalive
      end
    end

    # ---------------------------------------------------- expiration bodies

    private def expired_retransmit_handshake : Nil
      if @handshake_attempts > MAX_TIMER_HANDSHAKES
        # give up: drop everything staged, destroy residue later
        @t_send_keepalive = nil if timers_active?
        @staged.clear
        if timers_active? && @t_zero_key_material.nil?
          @t_zero_key_material = Time.monotonic + Keypair::REJECT_AFTER_TIME * 3
          wake_timer
        end
      else
        @handshake_attempts += 1
        @endpoint_src = nil # in case the source is the trouble
        send_handshake_initiation(true)
      end
    end

    private def expired_send_keepalive : Nil
      send_keepalive
      return unless @need_another_keepalive
      @need_another_keepalive = false
      if timers_active?
        @t_send_keepalive = Time.monotonic + KEEPALIVE_TIMEOUT
        wake_timer
      end
    end

    private def expired_new_handshake : Nil
      # we stopped hearing back: force a new handshake
      @endpoint_src = nil
      send_handshake_initiation
    end

    private def expired_zero_key_material : Nil
      zero_and_flush_all
    end

    private def expired_persistent_keepalive : Nil
      send_keepalive if @persistent_keepalive_interval > 0
    end

    # ------------------------------------------------------------ Mod/Del API

    # After an authenticated data packet is sent.
    def timers_data_sent : Nil
      if timers_active? && @t_new_handshake.nil?
        @t_new_handshake = Time.monotonic + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + jitter
        wake_timer
      end
    end

    # After an authenticated data packet is received.
    def timers_data_received : Nil
      if timers_active?
        if @t_send_keepalive.nil?
          @t_send_keepalive = Time.monotonic + KEEPALIVE_TIMEOUT
          wake_timer
        else
          @need_another_keepalive = true
        end
      end
    end

    # After any authenticated packet (keepalive, data, handshake) is sent.
    def timers_any_authenticated_packet_sent : Nil
      @t_send_keepalive = nil if timers_active?
    end

    # After any authenticated packet is received.
    def timers_any_authenticated_packet_received : Nil
      @t_new_handshake = nil if timers_active?
    end

    # After a handshake initiation is sent.
    def timers_handshake_initiated : Nil
      if timers_active?
        @t_retransmit_handshake = Time.monotonic + REKEY_TIMEOUT + jitter
        wake_timer
      end
    end

    # After a handshake response is processed or key confirmation arrives.
    def timers_handshake_complete : Nil
      @t_retransmit_handshake = nil if timers_active?
      @handshake_attempts = 0
      now = Time.utc
      @last_handshake_unix_nano = (now - Time.unix(0)).total_nanoseconds.to_i64
    end

    # After an ephemeral key is created (session keys derived).
    def timers_session_derived : Nil
      if timers_active?
        @t_zero_key_material = Time.monotonic + Keypair::REJECT_AFTER_TIME * 3
        wake_timer
      end
    end

    # Before any authenticated packet is sent, or after one is received.
    def timers_any_authenticated_packet_traversal : Nil
      interval = @persistent_keepalive_interval
      return unless interval > 0 && timers_active?
      @t_persistent_keepalive = Time.monotonic + Time::Span.new(seconds: interval)
      wake_timer
    end

    private def jitter : Time::Span
      REKEY_TIMEOUT_JITTER_MAX * rand
    end
  end
end
