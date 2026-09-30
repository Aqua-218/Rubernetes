# frozen_string_literal: true

require_relative "../common/errors"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # Every MicroVM failure is a Runtime::Error so the common lifecycle
      # façade rolls back or marks the operation unknown exactly as for the
      # Native backend.
      class Error < ::Rubernetes::Runtime::Error; end
      class ArtifactError < Error; end
      class FramingError < Error; end
      class ProtocolError < Error; end

      class APIError < Error
        attr_reader :status

        def initialize(message, status: nil)
          super(message)
          @status = status
        end
      end

      class JailerError < Error; end
      class VsockError < Error; end
      class IdentityError < Error; end
      class PolicyError < Error; end
      class GateError < Error; end
      class VerityError < Error; end
      class NetworkError < Error; end
      # The snapshot pause ACK did not arrive: the VM may or may not be
      # quiesced.  It must never be resumed, re-snapshotted, or have its
      # workspace reused; only stop confirmation and cleanup are allowed.
      class SnapshotPauseUnknown < ::Rubernetes::Runtime::AmbiguousResult; end
      class SnapshotCorruption < ::Rubernetes::Runtime::SnapshotCorruption; end
      # A response-less remote operation (vsock disconnect mid-request).
      class ResponseLost < ::Rubernetes::Runtime::AmbiguousResult; end
    end
  end
end
