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

      def initialize(host:, port:, ready:, logger: nil)
        raise ArgumentError, "kubelet healthz requires a loopback IP address" unless self.class.loopback_address?(host)

        @ready = ready
        @server = Transport::HTTPServer.new(method(:call), host: host, port: port, logger: logger, max_connections: 32)
      end

      def start = @server.start(background: true)
      def stop = @server.stop

      private

      def call(request)
        return [404, HEADERS, ["404 page not found\n"]] unless request.path == "/healthz"
        return [405, HEADERS.merge("allow" => "GET, HEAD"), ["method not allowed\n"]] unless %w[GET HEAD].include?(request.method)

        @ready.call ? [200, HEADERS, ["ok"]] : [500, HEADERS, ["kubelet is not ready\n"]]
      end
    end
  end
end
