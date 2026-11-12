# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      # The runtime's use of the durable ownership ledger: idempotent request
      # records for container operations, resource claims and releases, and
      # the stable identities those records are keyed by.
      module LedgerRequests
        private

        # Return nil for a newly-created request and a durable record for an
        # existing request.  Pending records are never replayed because the
        # original process may have lost its response after the kernel effect.
        def begin_native_request(request_id, operation:, input:)
          request = String(request_id)
          raise ConfigurationError, "request id must not be empty" if request.empty? || request.include?("\0")

          config_digest = digest(input)
          existing = @ledger.request(request)
          return replay_native_request(request, existing, operation, config_digest) if existing

          owner = input["sandbox_id"] || input[:sandbox_id]
          @ledger.begin_request(request_id: request, operation: operation, config_digest: config_digest,
                                owner: owner ? String(owner) : nil)
          nil
        end

        def replay_native_request(request, existing, operation, config_digest)
          existing_digest = ledger_value(existing, :config_digest)
          existing_operation = ledger_value(existing, :operation)
          unless existing_digest == config_digest && existing_operation.to_s == operation.to_s
            raise OwnershipConflict, "request #{request} was replayed with different intent"
          end

          state = ledger_value(existing, :state).to_s
          return existing if state == "Completed"

          if state == "Failed"
            error = ledger_value(existing, :error)
            raise FailClosed,
                  "request #{request} previously failed: #{error.is_a?(Hash) ? error.fetch("message", "unknown failure") : error}"
          end
          # A cleanup request remains replayable after a transient cleanup
          # failure. The resource and its durable ownership record stay live
          # until a later attempt confirms cleanup, so retrying the same
          # request is safe and does not repeat an already-confirmed removal.
          return nil if state == "CleanupPending"

          raise RecoveryRequired, "request #{request} is pending durable reconciliation"
        end

        def complete_native_request(request_id, state:, result: nil, error: nil)
          @ledger.complete_request(request_id: String(request_id), state: state, result: result, error: error)
          true
        end

        def error_payload(error)
          {"class" => error.class.name.to_s, "message" => error.message.to_s}
        end

        def claim(operation, kind:, id:, identity:, metadata: {})
          @ledger.claim(operation_id: operation.id, kind: kind, id: id, identity: identity, metadata: metadata)
        end

        def container_resource_id(sandbox, container)
          "#{sandbox.id}:#{reference_id(container)}"
        end

        def process_identity_for(sandbox, container, process)
          pid = process["workload_pid"] || process[:workload_pid] || process["pid"] || process[:pid]
          start_time = process["workload_start_time"] || process[:workload_start_time]
          executable_digest = process["workload_executable_digest"] || process[:workload_executable_digest] ||
                              process["executable_digest"] || process[:executable_digest]
          "process:#{sandbox.id}:#{container.id}:#{pid}:#{start_time || "unknown"}:#{executable_digest || "unknown"}"
        end

        def ledger_resource_for(operation, kind, id)
          @ledger.resources(owner: operation.owner, include_released: true).find do |resource|
            ledger_value(resource, :kind).to_s == kind.to_s && ledger_value(resource, :id).to_s == id.to_s
          end
        end

        # Releases the claim on +kind+/+id+ unless it is absent or already
        # released.  force: this is the teardown path (see
        # OwnershipLedger#release).
        def release_ledger_claim(operation, kind, id)
          resource = ledger_resource_for(operation, kind, id)
          return nil unless resource && ledger_value(resource, :state).to_s != "Released"

          @ledger.release(operation_id: operation.id, kind: kind, id: ledger_value(resource, :id),
                          identity: ledger_value(resource, :identity), force: true)
        end

        def release_process_resource(operation, sandbox, container, _process)
          return unless operation

          release_ledger_claim(operation, "process", container_resource_id(sandbox, container))
        end

        def release_container_resource(operation, sandbox, container, process)
          return unless operation

          id = container_resource_id(sandbox, container)
          [["process", id], ["cgroup", id], ["workspace", "#{sandbox.id}.#{container.id}"]].each do |kind, resource_id|
            release_ledger_claim(operation, kind, resource_id)
          end
          process
        end

        # The ledger hands out immutable operation/request values and
        # hash-shaped resource snapshots, keyed by symbol or by string.
        # Read a field from either without calling Object#id on a Hash
        # during replay; a field the record does not have is nil.
        def ledger_value(value, name)
          fields = value.to_h
          fields.fetch(name) { fields[name.to_s] }
        end
      end
    end
  end
end
