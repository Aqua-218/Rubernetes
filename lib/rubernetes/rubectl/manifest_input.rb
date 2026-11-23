# frozen_string_literal: true

require "base64"
require "json"
require "pathname"
require_relative "../client/errors"

module Rubernetes
  module Rubectl
    # Local context for a write. Only the resource is passed to the client.
    class ManifestInput
      class Invalid < Client::ManifestError
        attr_reader :input

        def initialize(message, input)
          @input = input
          super(message)
        end
      end

      class Rejected < Client::APIError
        attr_reader :input

        def initialize(error, input)
          @input = input
          super(error.message, response: error.response, status_object: error.status_object)
        end
      end

      STATUS_IDENTIFIERS = %w[apiVersion kind status reason code].freeze

      attr_reader :resource

      def initialize(resource, filename, line)
        @resource = resource
        @filename = filename
        @line = line
      end

      def request
        yield @resource
      rescue Client::APIError => error
        raise Rejected.new(error, self)
      end

      def declaration
        return unless @line.is_a?(Integer) && @line.positive?

        "#{source_location}: #{display(@resource["kind"])}/#{display(@resource.dig("metadata", "name"))}"
      end

      def source_location
        return "<stdin>" if @filename == "-"

        path = display(Pathname.new(File.expand_path(@filename)).relative_path_from(Pathname.pwd))
        @line.is_a?(Integer) && @line.positive? ? "#{path}:#{@line}" : path
      end

      def redact_error(value)
        return value if @resource["kind"] != "Secret"

        secrets = secret_values
        secrets.empty? ? value : redact(value, Regexp.union(secrets))
      end

      private

      def display(value)
        value.to_s.scrub.gsub(/[[:cntrl:]]/) { |character| character.dump[1...-1] }
      end

      def secret_values
        encoded = strings_in(@resource["data"])
        plain = strings_in(@resource["stringData"]) + encoded.filter_map { |value| decode_secret(value) }
        values = encoded + plain + plain.map { |value| Base64.strict_encode64(value) }
        values.flat_map { |value| secret_tokens(value) }.uniq.sort_by { |value| -value.bytesize }
      end

      def secret_tokens(value)
        text = value.dup.force_encoding(Encoding::UTF_8)
        return [] if text.empty? || !text.valid_encoding?

        [text.b, JSON.generate(text)[1...-1].b]
      end

      def strings_in(value)
        value.is_a?(Hash) ? value.values.grep(String) : []
      end

      def decode_secret(value)
        Base64.strict_decode64(value.delete("\r\n"))
      rescue ArgumentError
        nil
      end

      def redact(value, pattern)
        case value
        when Hash
          value.to_h { |key, child| [key, STATUS_IDENTIFIERS.include?(key) ? child : redact(child, pattern)] }
        when Array
          value.map { |child| redact(child, pattern) }
        when String
          value.b.gsub(pattern, "[REDACTED]".b).force_encoding(value.encoding)
        else
          value
        end
      end
    end
  end
end
