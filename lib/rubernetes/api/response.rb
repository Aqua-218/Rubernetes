# frozen_string_literal: true

require "json"

module Rubernetes
  module API
    # Transport-neutral response value. The body remains decoded so callers can
    # use the API core without committing to Rack, WEBrick, or an HTTP client.
    class Response
      attr_reader :status, :headers, :body, :upgrade, :encoded_body

      # +encoded_body+: the exact bytes of +body+ already serialized, for a
      # large document served unchanged many times (the OpenAPI specs); the
      # HTTP layer sends them instead of generating the JSON again, while
      # in-process callers still read the decoded +body+.
      def initialize(status: 200, headers: {}, body: nil, stream: nil, upgrade: nil, unbounded: false, encoded_body: nil)
        @encoded_body = encoded_body
        @status = Integer(status)
        @headers = normalize_headers(headers).freeze
        @body = body
        @stream = stream.nil? ? body_enumerable?(@body) : !!stream
        # A watch runs until the client hangs up, so no response byte budget
        # applies to it; see Transport::Response#unbounded?.
        @unbounded = !!unbounded
        @upgrade = upgrade
        raise ArgumentError, "upgrade must respond to call" if @upgrade && !@upgrade.respond_to?(:call)
      end

      # The transport reports the size it encoded a decoded body to
      # (apiserver_response_sizes), without the API layer encoding it twice.
      def on_body_encoded(&block)
        @on_body_encoded = block
        self
      end

      def body_encoded(bytes)
        @on_body_encoded&.call(bytes)
      rescue StandardError
        nil
      end

      def success?
        status >= 200 && status < 300
      end

      alias status_code status

      def with_header(name, value)
        self.class.new(status: status, headers: headers.merge(name.to_s.downcase => value.to_s), body: body,
                       stream: stream?, upgrade: @upgrade, unbounded: unbounded?, encoded_body: @encoded_body)
      end

      def header(name)
        headers[name.to_s.downcase]
      end

      def json
        body
      end

      def body_json
        encoded_body || JSON.generate(body)
      end

      alias json_body body_json

      def content_type
        header("content-type")
      end

      def unbounded?
        @unbounded
      end

      def stream?
        @stream
      end

      def upgrade?
        !@upgrade.nil?
      end

      def to_h
        payload = {status: status, headers: headers, body: body}
        payload[:stream] = stream? if stream?
        payload[:upgrade] = upgrade if upgrade?
        payload
      end

      # Convert to a Rack triple when an HTTP adapter is desired.
      def to_rack
        return [status, headers, body] if stream? && body.respond_to?(:each)

        payload = if body.respond_to?(:each_json_line)
                    body.each_json_line.to_a.join
                  else
                    [body_json]
                  end
        [status, headers.merge("content-type" => "application/json"), payload]
      end

      private

      def body_enumerable?(value)
        value.respond_to?(:each) && !value.is_a?(String) && !value.is_a?(Hash)
      end

      def normalize_headers(headers)
        headers.each_with_object({}) { |(key, value), normalized| normalized[key.to_s.downcase] = value.to_s }
      end
    end
  end
end
