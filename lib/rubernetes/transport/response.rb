# frozen_string_literal: true

require "json"

require_relative "errors"
require_relative "headers"

module Rubernetes
  module Transport
    # Response value accepted by HTTPServer and convenient for small handlers.
    class Response
      NO_BODY_STATUSES = (100..199).to_a + [204, 304]

      attr_reader :status, :headers, :body, :upgrade

      def initialize(status: 200, headers: {}, body: "", stream: nil, upgrade: nil, unbounded: false)
        @status = Integer(status)
        raise ResponseError, "response status must be between 100 and 599" unless (100..599).cover?(@status)

        @headers = headers.is_a?(Headers) ? headers : Headers.new(headers)
        @body = body.nil? ? "" : body
        @stream = stream.nil? ? body_enumerable?(@body) : !!stream
        # A watch, a followed log or any other open-ended stream has no
        # response size: it ends when the client goes away.  The byte limit
        # bounds a response that is produced in full, and applying it to a
        # long-lived stream severs a healthy connection once it has simply
        # carried enough traffic.
        @unbounded = !!unbounded
        @upgrade = upgrade
        raise ResponseError, "response upgrade must respond to call" if @upgrade && !@upgrade.respond_to?(:call)
      rescue ArgumentError, TypeError => error
        raise ResponseError, "invalid response status: #{status.inspect}", cause: error
      end

      def status_code
        status
      end

      def success?
        (200..299).cover?(status)
      end

      def [](name)
        headers[name]
      end

      def json
        return body unless body.is_a?(String)
        return nil if body.empty?

        JSON.parse(body)
      rescue JSON::ParserError => error
        raise ResponseError, "response body is not valid JSON: #{error.message}", cause: error
      end

      def body_json
        body.is_a?(String) ? body : JSON.generate(body)
      end

      def stream?
        @stream
      end

      def unbounded?
        @unbounded
      end

      def upgrade?
        !@upgrade.nil?
      end

      def no_body?
        NO_BODY_STATUSES.include?(status)
      end

      def to_h
        payload = { status: status, headers: headers, body: body }
        payload[:stream] = stream? if stream?
        payload[:upgrade] = upgrade if upgrade?
        payload
      end
      alias to_hash to_h

      def self.json(value, status: 200, headers: {})
        merged = Headers.new(headers)
        merged.set("Content-Type", "application/json; charset=utf-8") unless merged.include?("content-type")
        new(status: status, headers: merged, body: JSON.generate(value))
      end

      private

      def body_enumerable?(value)
        value.respond_to?(:each) && !value.is_a?(String) && !value.is_a?(Hash)
      end
    end
  end
end
