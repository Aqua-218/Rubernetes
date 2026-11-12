# frozen_string_literal: true

# The idempotent-operation envelope shared by Controller and Node: reserve the
# token in the operation ledger under the volume lock, run the effect once, and
# record the outcome as succeeded, failed or (when the effect may have
# happened) unknown.
module Rubernetes
  module Volume
    module OperationSupport
      # What one execute_operation call knows so far; the rescue paths read it
      # to decide between "failed" and "unknown".
      Attempt = Struct.new(:token, :entry, :durable_payload, :effect_started)

      private

      # An Unknown volume still permits Cleanup, and every teardown operation
      # is one: the CSI teardown calls are all required to be idempotent and to
      # succeed on a volume that is already gone.  Fencing them is what makes a
      # Pod unremovable, so the fence is decided by what the operation is.
      CLEANUP_OPERATIONS = /\A(?:delete|unstage|unpublish|controller-unpublish|delete-snapshot)(?::|\z)/

      def cleanup_operation?(operation)
        CLEANUP_OPERATIONS.match?(operation.to_s)
      end

      def execute_operation(key:, operation:, token:, payload:)
        attempt = Attempt.new(token, nil, nil, false)
        @manager.with_volume_lock(key) do
          reserve_operation(attempt, key, operation, payload)
          next Types.deep_copy(attempt.entry.result) if attempt.entry.status == "succeeded"

          ensure_executable!(attempt.entry, key, operation)
          result = yield(effect_boundary_for(attempt, key, operation))
          @manager.operations.finish!(key: key, operation: operation, token: attempt.token,
                                      result: @manager.sanitize_for_persistence(result))
          result
        end
      rescue OperationUnknown => error
        record_unknown_outcome(attempt, key, operation, error) if attempt.entry && attempt.entry.status != "unknown"
        raise
      rescue StandardError => error
        raise if error.is_a?(StateUnknownError)

        if attempt.entry && (attempt.effect_started || ambiguous_error?(error))
          record_unknown_outcome(attempt, key, operation, error)
          raise OperationUnknown.new("operation #{operation} for #{key} has an ambiguous result"), cause: error
        end
        if attempt.entry
          @manager.operations.fail!(key: key, operation: operation, token: attempt.token,
                                    error: @manager.persistence_error(error))
        end
        raise
      end

      # Fences an Unknown volume, then durably reserves the token for this
      # payload.
      def reserve_operation(attempt, key, operation, payload)
        if (record = @manager.volume_store[key.to_s])
          @manager.ensure_known!(record, action: cleanup_operation?(operation) ? "Cleanup" : "Mutate")
        end
        attempt.token = Types.identifier(attempt.token, "operation token")
        fingerprint = Types.digest(payload)
        attempt.durable_payload = @manager.operation_payload(payload)
        attempt.entry = @manager.operations.begin!(key: key, operation: operation, token: attempt.token,
                                                   fingerprint: fingerprint, payload: attempt.durable_payload)
      end

      def ensure_executable!(entry, key, operation)
        # A teardown whose outcome is unknown must be RETRIED, not fenced.
        # That is the CSI contract for every teardown call and what the
        # kubelet volume reconciler does: it keeps calling UnmountVolume and
        # UnmountDevice until one succeeds (pkg/kubelet/volumemanager/
        # reconciler).  Fencing instead made the first ambiguous unstage
        # permanent -- the volume could never be released, so the Pod holding
        # it stayed Terminating in the API for ever.
        retryable = cleanup_operation?(operation)
        case entry.status
        when "pending", "effecting", "unknown"
          raise OperationUnknown, "operation #{operation} for #{key} is #{entry.status}; recover before retrying" unless retryable
        when "new"
          # The ledger has just durably reserved this token for this payload.
          # Execute the effect exactly once and finalize the reservation below.
          nil
        when "failed"
          # "failed" is only ever recorded when the effect had NOT started (an
          # error at or after the effect boundary becomes "unknown"), so a retry
          # replays nothing.  kubelet retries a failed mount on every sync; a
          # fenced publish kept a Pod whose subPath target is created by an
          # earlier init container (GitLab's configure -> secrets.yml) failing
          # for ever with "previously failed".
          nil
        end
      end

      # The callable an effect invokes when it is about to touch the outside
      # world; :compensated / :rejected take the mark back.
      def effect_boundary_for(attempt, key, operation)
        lambda do |state = :start|
          if %i[compensated rejected].include?(state)
            attempt.effect_started = false
          elsif !attempt.effect_started
            @manager.operations.effecting!(key: key, operation: operation, token: attempt.token)
            attempt.effect_started = true
          end
          true
        end
      end

      def record_unknown_outcome(attempt, key, operation, error)
        persisted_error = @manager.persistence_error(error)
        @manager.operations.unknown!(key: key, operation: operation, token: attempt.token,
                                     error: persisted_error)
        @manager.mark_unknown(key, operation: operation, payload: attempt.durable_payload,
                                   details: Capability.detailed?(persisted_error) ? persisted_error.details : nil)
      end

      def ambiguous_error?(error)
        return false if error.is_a?(StateUnknownError)
        return true if error.is_a?(OperationUnknown)
        return true if Capability.reports_ambiguity?(error) && error.ambiguous?

        return true if error.class.name.to_s.match?(/Unknown|Ambiguous|Timeout|EOF|ConnectionReset|BrokenPipe/)

        cause = error.cause
        cause && cause != error ? ambiguous_error?(cause) : false
      end
    end
  end
end
