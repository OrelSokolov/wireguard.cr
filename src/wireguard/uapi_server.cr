# UAPI socket server: exposes a Device over the xplatform configuration
# protocol (the wire format `wg` speaks). Clients connect to a unix socket,
# send "set=1\n<key=value lines>\n\n" or "get=1\n\n", and read the reply
# terminated by "errno=0\n\n" (see wireguard-go ipc/ + device/uapi.go).

require "./device"
require "./uapi"
require "socket"

module Wireguard
  class UapiServer
    getter path : String
    @server : UNIXServer
    @running = false

    def initialize(@device : Device, @path : String)
      File.delete(path) if File.exists?(path)
      @server = UNIXServer.new(path)
    end

    def self.default_path(iface : String) : String
      "/var/run/wireguard/#{iface}.sock"
    end

    def start : Nil
      return if @running
      @running = true
      spawn accept_loop
    end

    def stop : Nil
      @running = false
      @server.close
    rescue IO::Error
    end

    private def accept_loop : Nil
      while @running
        client = @server.accept?
        break unless client
        spawn handle_connection(client.not_nil!)
      end
    rescue ex : IO::Error
      return unless @running
      raise ex
    end

    private def handle_connection(client : UNIXSocket) : Nil
      loop do
        op = client.gets
        return unless op
        case op
        when "set=1"
          conf = String.build do |io|
            while line = client.gets
              break if line.empty?
              io << line << '\n'
            end
          end
          begin
            @device.ipc_set(conf)
            client << "errno=0\n\n"
          rescue ex : UapiError
            client << "errno=" << (ex.errno) << "\n\n"
          end
        when "get=1"
          # a single trailing newline must follow
          ch = client.read_char
          return if ch.nil?
          if ch != '\n'
            client << "errno=-22\n\n"
          else
            client << @device.ipc_get
            client << "errno=0\n\n"
          end
        else
          return
        end
        client.flush
      end
    ensure
      client.close
    end
  end
end
