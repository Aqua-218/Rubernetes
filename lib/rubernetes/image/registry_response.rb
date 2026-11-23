# frozen_string_literal: true

require_relative "errors"

module Rubernetes
  module Image
    # Small response value used by both the stdlib transport and injected test transports.
    class RegistryResponse
      attr_reader :status, :headers, :body

      def initialize(status:, headers: {}, body: "")
        @status = Integer(status)
        @headers = headers.each_with_object({}) { |(key, value), result| result[key.to_s.downcase] = value.to_s }.freeze
        @body = body.nil? ? "".b : body.to_s.b
        freeze
      rescue ArgumentError, TypeError => error
        raise RegistryError.new("registry transport returned an invalid response: #{error.message}", cause: error), cause: error
      end

      def success?
        (200..299).cover?(status)
      end

      def [](name)
        headers[name.to_s.downcase]
      end
    end
  end
end
