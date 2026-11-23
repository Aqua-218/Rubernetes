# frozen_string_literal: true

require "ipaddr"
require_relative "../transport/http_server"

module Rubernetes
  module Node
    # The kubelet's local, unauthenticated health check has its own HTTP socket.
    class KubeletHealthz
      DEFAULT_HOST = "127.0.0.1"
      DEFAULT_PORT = 10_248
      HEADERS = {"content-type" => "text/plain; charset=utf-8"}.freeze

      def self.loopback_address?(address)
        address.is_a?(String) && !address.include?("/") && IPAddr.new(address).loopback?
      rescue IPAddr::InvalidAddressError, IPAddr::AddressFamilyError
        false
      end

      # kubelet serves /healthz from a loop (cmd/kubelet/app/server.go): a
      # port that cannot be bound is logged and tried again five seconds
      # later, and never stops the kubelet.
      RETRY_SECONDS = 5

      def initialize(host:, port:, ready:, logger: nil, retry_seconds: RETRY_SECONDS)
        raise ArgumentError, "kubelet healthz requires a loopback IP address" unless self.class.loopback_address?(host)

        @ready = ready
        @host = host
        @port = port
        @logger = logger
        @retry_seconds = retry_seconds
        @mutex = Mutex.new
        @stopped = false
      end

      def start
        @retry = Thread.new { listen_until_bound } unless listen
        self
      end

      def stop
        server = @mutex.synchronize do
          @stopped = true
          @server
        end
        @retry&.join
        server&.stop
      end

      def listening? = @mutex.synchronize { !@server.nil? }

      private

      def listen
        server = Transport::HTTPServer.new(method(:call), host: @host, port: @port, logger: @logger, max_connections: 32)
        server.start(background: true)
        keep = @mutex.synchronize { @stopped ? false : (@server = server) }
        server.stop unless keep
        true
      rescue Transport::ConfigurationError => error
        @logger&.error("Failed to start healthz server", error: error.class.name, message: error.message)
        false
      end

      def listen_until_bound
        loop do
          slept = 0.0
          while slept < @retry_seconds
            return if @mutex.synchronize { @stopped }

            sleep([0.05, @retry_seconds - slept].min)
            slept += 0.05
          end
          return if @mutex.synchronize { @stopped } || listen
        end
      end

      def call(request)
        return [404, HEADERS, ["404 page not found\n"]] unless request.path == "/healthz"
        return [405, HEADERS.merge("allow" => "GET, HEAD"), ["method not allowed\n"]] unless %w[GET HEAD].include?(request.method)

        @ready.call ? [200, HEADERS, ["ok"]] : [500, HEADERS, ["kubelet is not ready\n"]]
      end
    end
  end
end
