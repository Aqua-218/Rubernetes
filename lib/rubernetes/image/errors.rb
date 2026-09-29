# frozen_string_literal: true

module Rubernetes
  # OCI image acquisition and unpacking primitives.
  module Image
    # Base error for all image subsystem failures.
    class Error < StandardError
      attr_reader :cause

      def initialize(message = nil, cause: nil)
        @cause = cause
        super(message)
      end
    end

    class ReferenceError < Error; end
    class DigestError < Error; end
    class DigestMismatch < DigestError; end
    class RegistryError < Error; end
    # imagePullPolicy Never and the image is not (usable) on the node:
    # the kubelet's ErrImageNeverPull.
    class NeverPullError < Error; end
    class AuthenticationError < RegistryError; end
    class ManifestError < RegistryError; end
    class StoreError < Error; end
    class LayerError < Error; end
    class SecurityError < LayerError; end
    class LimitError < LayerError; end
    class UnsupportedMediaType < LayerError; end
  end
end
