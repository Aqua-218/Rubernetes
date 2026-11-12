# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      # Giving a sandbox's resources back: rollback after a failed creation
      # and cleanup on stop/remove release them in exact reverse order of
      # acquisition, and whatever cannot be released is left claimed and
      # marked CleanupPending in the ledger for a later attempt.
      module Teardown
        private

        def rollback_sandbox(sandbox, operation, original_error:)
          primary_error = error_payload(original_error)
          record(:rollback_started, sandbox_id: sandbox.id, error: "#{original_error.class}: #{original_error.message}",
                                    primary_error: primary_error)
          cleanup_failed = false
          begin
            sandbox.transition(:rolling_back) unless %i[rolling_back stopped removed].include?(sandbox.state)
            @ledger.transition(operation_id: operation.id, to: "RollingBack") unless operation.state == "RollingBack"
          rescue StandardError => error
            record(:rollback_transition_error, sandbox_id: sandbox.id, error: "#{error.class}: #{error.message}")
          end
          begin
            cleanup_errors = cleanup_sandbox_resources(sandbox, operation, primary_error: original_error)
          rescue StandardError => error
            cleanup_failed = true
            cleanup_errors = attached_cleanup_errors(error)
            preserve_cleanup_errors(original_error, cleanup_errors)
            payload = {sandbox_id: sandbox.id, error: "#{error.class}: #{error.message}",
                       primary_error: primary_error}
            payload[:cleanup_errors] = cleanup_errors unless cleanup_errors.empty?
            record(:rollback_cleanup_error, **payload)
          end
          if cleanup_failed
            begin
              sandbox.transition(:cleanup_pending) if sandbox.state == :rolling_back
              @ledger.transition(operation_id: operation.id, to: "CleanupPending") if @ledger.operation(operation.id)&.state == "RollingBack"
            rescue StandardError => error
              record(:rollback_pending_error, sandbox_id: sandbox.id, error: "#{error.class}: #{error.message}")
            end
            return
          end
          begin
            sandbox.transition(:stopped) if sandbox.state == :rolling_back
            @ledger.transition(operation_id: operation.id, to: "Stopped") if @ledger.operation(operation.id)&.state == "RollingBack"
            @mutex.synchronize do
              @sandboxes.delete(sandbox.id)
              @requests.delete_if { |_request, sandbox_id| sandbox_id == sandbox.id }
            end
          rescue StandardError => error
            record(:rollback_finalize_error, sandbox_id: sandbox.id, error: "#{error.class}: #{error.message}")
          end
        end

        def cleanup_sandbox_resources(sandbox, operation, primary_error: nil)
          cleanup_errors = []
          blocked_by = nil
          sandbox.containers.reverse_each do |container_hash|
            remove_container(container_hash.fetch("id"))
          rescue StandardError => error
            cleanup_errors << cleanup_error_entry(
              resource: "container:#{container_hash.fetch("id")}", error: error
            )
            blocked_by ||= "container:#{container_hash.fetch("id")}"
          end

          # Sandbox acquisition is workspace -> namespace -> cgroup.  Rollback
          # must release the exact reverse sequence.  A lower resource may depend
          # on the upper owner still holding a live kernel object, so cleanup
          # stops at the first failed release and records every dependent resource
          # as pending instead of destructively touching it.
          {"cgroup" => sandbox.cgroup, "namespace" => sandbox.namespace, "workspace" => sandbox.workspace}.each do |kind, resource|
            next unless resource
            next if ledger_resource_released?(operation, kind, sandbox.id)

            blocked_by = if blocked_by
                           defer_blocked_release(sandbox, operation, kind, blocked_by, cleanup_errors)
                         else
                           release_sandbox_kernel_resource(sandbox, operation, kind, resource, cleanup_errors)
                         end
          end

          cleanup_payload = {sandbox_id: sandbox.id, errors: cleanup_errors.freeze}
          cleanup_payload[:primary_error] = error_payload(primary_error) if primary_error
          record(:cleanup, **cleanup_payload)
          unless cleanup_errors.empty?
            error_messages = cleanup_errors.map do |entry|
              "#{entry.fetch("resource")}: #{entry.fetch("error")}"
            end
            error = ResourceError.new(
              "sandbox cleanup failed: #{error_messages.join("; ")}",
              cleanup_errors: cleanup_error_details(cleanup_errors)
            )
            mark_cleanup_pending(sandbox, operation, error, primary_error: primary_error)
            raise error
          end
          sandbox.mark_resources_cleaned
          true
        end

        # A resource below a failed release is not touched: it is recorded as
        # pending behind the resource that blocks it.  Returns that blocker.
        def defer_blocked_release(sandbox, operation, kind, blocked_by, cleanup_errors)
          cleanup_errors << cleanup_error_entry(
            resource: "#{kind}:#{sandbox.id}",
            error: "cleanup blocked by #{blocked_by}",
            blocked_by: blocked_by
          )
          mark_resource_cleanup_pending(
            operation, kind, sandbox.id, blocked_by: blocked_by, cleanup_errors: cleanup_errors
          )
          blocked_by
        end

        # Releases one sandbox resource in the kernel and then in the ledger.
        # Returns nil when it is gone, or -- after recording the failure and
        # marking the claim pending -- the key that now blocks the resources
        # beneath it.
        def release_sandbox_kernel_resource(sandbox, operation, kind, resource, cleanup_errors)
          result = case kind
                   when "cgroup" then @cgroup.remove(resource, force: true)
                   when "namespace" then @namespace.destroy(resource)
                   else @filesystem.cleanup(resource)
                   end
          raise ResourceError, "#{kind} cleanup returned false" if result == false

          release_user_namespace_range(sandbox) if kind == "namespace"
          release_sandbox_resource(operation, kind, sandbox.id)
          nil
        rescue StandardError => error
          resource_key = "#{kind}:#{sandbox.id}"
          cleanup_errors << cleanup_error_entry(resource: resource_key, error: error)
          mark_resource_cleanup_pending(
            operation, kind, sandbox.id, blocked_by: nil, cleanup_errors: cleanup_errors
          )
          resource_key
        end

        def release_sandbox_resource(operation, kind, id)
          resource = ledger_resource_for(operation, kind, id)
          return true unless resource && ledger_value(resource, :state).to_s != "Released"

          released = @ledger.release(operation_id: operation.id, kind: kind, id: id,
                                     identity: ledger_value(resource, :identity), force: true)
          raise ResourceError, "ledger #{kind} release returned false" if released == false

          true
        rescue StandardError => error
          raise ResourceError, "ledger #{kind} release failed: #{error.message}"
        end

        def mark_container_cleanup_pending(sandbox, container, operation:, error:)
          return unless operation

          cleanup_errors = []
          mark_resource_cleanup_pending(
            operation, "cgroup", container_resource_id(sandbox, container), blocked_by: nil,
                                                                            cleanup_errors: cleanup_errors
          )
          record(:container_cleanup_pending, sandbox_id: sandbox.id, container_id: container.id,
                                             error: "#{error.class}: #{error.message}", cleanup_errors: cleanup_errors.freeze)
        rescue StandardError => cleanup_error
          record(:container_cleanup_pending_error, sandbox_id: sandbox.id, container_id: container.id,
                                                   error: "#{cleanup_error.class}: #{cleanup_error.message}")
        end

        def mark_resource_cleanup_pending(operation, kind, id, blocked_by:, cleanup_errors:)
          resource = ledger_resource_for(operation, kind, id)
          return true unless resource && ledger_value(resource, :state).to_s != "Released"

          metadata = ledger_value(resource, :metadata).to_h.transform_keys(&:to_s)
          metadata["cleanup_pending"] = true
          if blocked_by
            metadata["blocked_by"] = String(blocked_by)
          else
            metadata.delete("blocked_by")
          end
          claimed = @ledger.claim(
            operation_id: operation.id,
            kind: kind,
            id: id,
            identity: ledger_value(resource, :identity),
            metadata: metadata
          )
          raise ResourceError, "ledger #{kind} cleanup_pending metadata update returned false" if claimed == false

          true
        rescue StandardError => error
          cleanup_errors << cleanup_error_entry(resource: "ledger:#{kind}:#{id}", error: error)
          false
        end

        def ledger_resource_released?(operation, kind, id)
          ledger_value(ledger_resource_for(operation, kind, id), :state).to_s == "Released"
        end

        def mark_cleanup_pending(sandbox, operation, error, primary_error: nil)
          begin
            sandbox.transition(:rolling_back) if sandbox.state == :stopping
            sandbox.transition(:cleanup_pending) if %i[rolling_back stopped].include?(sandbox.state)
          rescue Sandbox::Error => transition_error
            record(:cleanup_pending_transition_error, sandbox_id: sandbox.id,
                                                      error: "#{transition_error.class}: #{transition_error.message}")
          end
          current = @ledger.operation(operation.id)
          begin
            if current&.state == "Running"
              # A stop that failed before the durable Stopping record leaves the
              # workload liveness unknown; the model permits only
              # Running -> StateUnknown here.
              @ledger.transition(operation_id: operation.id, to: "StateUnknown")
              current = @ledger.operation(operation.id)
            end
            if current&.state == "StateUnknown"
              @ledger.transition(operation_id: operation.id, to: "CleanupPending")
              current = @ledger.operation(operation.id)
            end
            if current&.state == "Stopping"
              @ledger.transition(operation_id: operation.id, to: "RollingBack")
              current = @ledger.operation(operation.id)
            end
            @ledger.transition(operation_id: operation.id, to: "CleanupPending") if current && %w[RollingBack Stopped].include?(current.state)
            cleanup_errors = attached_cleanup_errors(error)
            cleanup_errors = [{"resource" => "sandbox:#{sandbox.id}", "error" => error.message}] if cleanup_errors.empty?
            pending_payload = {sandbox_id: sandbox.id, errors: cleanup_errors.freeze}
            pending_payload[:primary_error] = error_payload(primary_error) if primary_error
            record(:cleanup_pending, **pending_payload)
          rescue StandardError => ledger_error
            record(:cleanup_pending_ledger_error, sandbox_id: sandbox.id,
                                                  error: "#{ledger_error.class}: #{ledger_error.message}")
          end
        end
      end
    end
  end
end
