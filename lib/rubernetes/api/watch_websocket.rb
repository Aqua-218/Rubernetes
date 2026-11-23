# frozen_string_literal: true

require "uri"
require_relative "../transport/websocket"

module Rubernetes
  module API
    # WebSocket watches use one message per event, with no HTTP stream framing.
    class WatchWebSocket
      WebSocket = Transport::WebSocket

      def self.headers(request)
        return unless WebSocket.upgrade_request?(request)

        protocols = WebSocket.offered_protocols(request)
        headers = WebSocket.handshake_headers(request, protocol: protocols.first)
        raise Status::Forbidden.new("watch WebSocket requires a valid Origin") unless valid_origin?(request.header("origin"))
        raise Status::BadRequest.new("watch WebSocket accepts a single subprotocol") if protocols.size > 1

        headers
      rescue WebSocket::ProtocolError => error
        raise Status::BadRequest.new(error.message)
      end

      def self.valid_origin?(origin)
        URI.parse(origin.to_s).absolute?
      rescue URI::InvalidURIError
        false
      end
      private_class_method :valid_origin?

      def initialize(events, binary:)
        @events = events
        @binary = binary
      end

      def call(socket, _request)
        connection = WebSocket::Connection.new(socket, max_message_bytes: 4096)
        reader = Thread.new { consume_control_frames(connection) }
        @events.each(timeout: nil) { |event| connection.write_message(event, binary: @binary) }
      rescue IOError, SystemCallError, WebSocket::Closed
        nil
      ensure
        connection&.close
        reader&.kill
        close
      end

      def close
        @events.close
      end

      private

      # Clients send control frames only. Closing the stream wakes a sender
      # waiting on the next event so an idle watch releases its subscription.
      def consume_control_frames(connection)
        connection.each_message do |_message|
          # Client messages have no effect on the watch.
        end
      rescue WebSocket::ProtocolError
        connection.close(WebSocket::CLOSE_PROTOCOL_ERROR)
      rescue IOError, SystemCallError
        nil
      ensure
        close
      end
    end
  end
end
