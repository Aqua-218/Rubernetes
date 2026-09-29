# frozen_string_literal: true

module Rubernetes
  module Transport
    # Base error for failures at the HTTP transport boundary.
    class Error < StandardError; end

    # Raised when a transport configuration cannot be used safely.
    class ConfigurationError < Error; end

    # Raised for a malformed or unsupported HTTP request.
    class RequestError < Error
      attr_reader :status, :code

      def initialize(message, status: 400, code: "BadRequest")
        @status = Integer(status)
        @code = String(code)
        super(message)
      end
    end

    class BadRequest < RequestError
      def initialize(message = "request is malformed")
        super(message, status: 400, code: "BadRequest")
      end
    end

    class RequestTimeout < RequestError
      def initialize(message = "request timed out")
        super(message, status: 408, code: "RequestTimeout")
      end
    end

    class PayloadTooLarge < RequestError
      def initialize(message = "request body exceeds the configured limit")
        super(message, status: 413, code: "RequestEntityTooLarge")
      end
    end

    class HeaderTooLarge < RequestError
      def initialize(message = "request headers exceed the configured limit")
        super(message, status: 431, code: "RequestHeaderFieldsTooLarge")
      end
    end

    class NotImplemented < RequestError
      def initialize(message = "request transfer encoding is not supported")
        super(message, status: 501, code: "NotImplemented")
      end
    end

    class HTTPVersionNotSupported < RequestError
      def initialize(message = "HTTP version is not supported")
        super(message, status: 505, code: "HTTPVersionNotSupported")
      end
    end

    # Raised when a response cannot be framed without violating HTTP rules.
    class ResponseError < Error; end

    # Raised when a response cannot be delivered before the write deadline.
    # This is deliberately separate from RequestTimeout: once response bytes
    # may have been sent, emitting a second HTTP error response would corrupt
    # the connection's framing.
    class ResponseTimeout < ResponseError; end

    class ResponseTooLarge < ResponseError
      attr_reader :partial

      def initialize(message = "response exceeds the configured limit", partial: false)
        @partial = !!partial
        super(message)
      end

      def partial?
        partial
      end
    end
  end
end
