# frozen_string_literal: true

module Rubernetes
  module Client
    # Base error for failures that occur while constructing or using a Kubernetes client.
    class Error < StandardError
      attr_reader :cause

      def initialize(message, cause: nil)
        @cause = cause
        super(message)
      end
    end

    # Raised when a kubeconfig cannot be safely loaded or validated.
    class ConfigurationError < Error; end

    # Raised when a requested kubeconfig context is not present.
    class ContextNotFoundError < ConfigurationError; end

    # Raised when a kubeconfig asks for a credential mechanism that this client cannot isolate.
    class UnsupportedCredentialError < ConfigurationError; end

    # Raised when a manifest is malformed or exceeds the CLI safety limits.
    class ManifestError < Error; end

    # Raised for Ruby manifest files because evaluating arbitrary Ruby requires a separate sandbox.
    class RubyManifestIsolationError < ManifestError; end

    # Raised when a REST response has a non-success HTTP status.
    class APIError < Error
      attr_reader :response, :status, :status_object

      def initialize(message, response:, status_object: nil)
        @response = response
        @status = response.status
        @status_object = status_object
        super(message)
      end
    end

    # Raised for transport-level failures that do not produce an HTTP response.
    class TransportError < Error; end

    # Raised when a watch response is not a bounded, valid JSON event stream.
    class WatchStreamError < Error; end

    # Raised when a watch response exceeds one of the configured stream limits.
    class WatchLimitError < WatchStreamError; end

    # Raised when a CLI argument or command is invalid.
    class UsageError < Error; end
  end
end
