# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Releases what a stopped Pod owns in reverse acquisition order
      # (containers, claims, network, sandbox, volumes, images), keeping every
      # failed step durable for a retry.
      module Cleanup
        # A Pod whose release failed is CleanupPending: it still owns mounts,
        # a sandbox or an address, and its record and API object wait for the
        # next attempt.  That attempt only ever came from another sync of the
        # Pod -- and a Pod already deleted from the API is synced by nobody, so
        # one unmount the kernel answered ambiguously left its ledger entries
        # in place for the rest of the node's life and every later mount that
        # drew the same kernel mount id was refused.  kubelet's volume
        # reconciler retries a failed unmount on every loop; this retries the
        # whole cleanup with a short backoff from the relist thread.  Returns
        # the uids retried.
        CLEANUP_RETRY_INITIAL_SECONDS = 5.0
        CLEANUP_RETRY_MAX_SECONDS = 60.0

        def retry_pending_cleanups(now: nil)
          moment = now || monotonic_clock.call
          pending = @mutex.synchronize do
            @records.values.select { |record| record[:state] == "CleanupPending" }.map { |record| record[:uid] }
          end
          retried = []
          pending.each do |uid|
            attempt = (@cleanup_retries ||= {})[uid.to_s]
            next if attempt && moment < attempt[:next_at]

            record = @records[uid]
            next unless record && record[:state] == "CleanupPending"
            next if @mutex.synchronize { @terminating.key?(uid.to_s) }

            count = (attempt ? attempt[:count] : 0) + 1
            delay = [CLEANUP_RETRY_INITIAL_SECONDS * (2**(count - 1)), CLEANUP_RETRY_MAX_SECONDS].min
            @cleanup_retries[uid.to_s] = {count: count, next_at: moment + delay}
            event(record, "cleanup.retry", attempt: count, errors: Array(record[:cleanup_errors]).map(&:to_s))
            retried << uid
            result = terminate(record[:pod], request_id: record[:request_id], reason: record[:reason] || "PodTerminating")
            @cleanup_retries.delete(uid.to_s) if result.nil? || result.state != "CleanupPending"
          rescue StandardError => error
            event(record, "cleanup.retry_failed", error: Helpers.failure_message(error)) if record
          end
          retried
        end

        private

        # Reverse acquisition order.  Each step answers whether it failed; the
        # first failure ends the sweep, so nothing a later step depends on is
        # released under it, and the record keeps what is still owned.
        CLEANUP_STEPS = %i[
          cleanup_containers cleanup_dynamic_resources cleanup_network cleanup_sandbox cleanup_volume release_images cleanup_pod_logs
        ].freeze

        def cleanup_resources(record)
          record[:cleanup_completed] ||= {}
          CLEANUP_STEPS.find { |step| send(step, record) }
          persist_state!
        end

        def cleanup_containers(record)
          failed = false
          record[:containers].reverse_each do |entry|
            key = "container:#{entry[:id]}"
            next if record[:cleanup_completed][key]

            begin
              event(record, "container.remove", name: entry[:name], container_id: entry[:id])
              @container_manager&.post_stop(entry[:id])
              invoke(@runtime, :remove_container, entry[:id])
              record[:cleanup_completed][key] = true
              clear_cleanup_error(record, key)
            rescue StandardError => error
              # A container the runtime no longer knows is removed by
              # definition (kubelet: a NotFound on RemoveContainer is success);
              # recording it as a failure kept a Pod whose sandbox recovery had
              # released CleanupPending for the life of the node.
              if lost_container_error?(error)
                event(record, "container.remove.already_gone", name: entry[:name], container_id: entry[:id],
                                                               message: Helpers.failure_message(error))
                record[:cleanup_completed][key] = true
                clear_cleanup_error(record, key)
                next
              end

              record_cleanup_error(record, key, "container #{entry[:name]} cleanup failed: #{Helpers.failure_message(error)}")
              failed = true
            end
          end
          failed
        end

        # Claims are unprepared after every container has stopped and before
        # the Pod is reported terminal (kubelet killPod -> UnprepareDynamicResources).
        def cleanup_dynamic_resources(record)
          return false unless record[:dra_prepared] && @dra_manager && !record[:cleanup_completed]["dra"]

          @dra_manager.unprepare_resources(Helpers.string_keys(record[:pod]))
          record[:cleanup_completed]["dra"] = true
          clear_cleanup_error(record, "dra")
          false
        rescue StandardError => error
          record_cleanup_error(record, "dra", "dynamic resources cleanup failed: #{Helpers.failure_message(error)}")
          true
        end

        def cleanup_network(record)
          return false unless @network && !record[:network].nil?

          key = "network:#{record[:sandbox_id]}"
          return false if record[:cleanup_completed][key]

          event(record, "network.delete")
          delete_sandbox_network(record)
          record[:cleanup_completed][key] = true
          clear_cleanup_error(record, key)
          false
        rescue StandardError => error
          record_cleanup_error(record, key, "network cleanup failed: #{Helpers.failure_message(error)}")
          true
        end

        def delete_sandbox_network(record)
          sandbox = network_sandbox_context(record)
          invoke(@network, :delete, sandbox)
        rescue SandboxGone => error
          # A persisted holder PID and FD cannot be used after recovery.
          # The network ledger can still release the sandbox's host resources.
          event(record, "network.delete.sandbox_gone", message: error.message)
          invoke(@network, :delete, record.fetch(:sandbox_id), namespace_gone: true)
        end

        def cleanup_sandbox(record)
          return false unless record[:sandbox_id]

          key = "sandbox:#{record[:sandbox_id]}"
          return false if record[:cleanup_completed][key]

          begin
            event(record, "sandbox.remove", sandbox_id: record[:sandbox_id])
            invoke(@runtime, :remove_sandbox, record[:sandbox_id])
          rescue StandardError => error
            # The runtime finished removing it (an earlier attempt, or a
            # concurrent one), or no longer knows it at all (startup
            # recovery released it): the record is clean on that step, as
            # kubelet treats a NotFound on RemovePodSandbox.
            unless sandbox_already_removed?(record[:sandbox_id]) || Helpers.failure_message(error).include?("unknown sandbox")
              record_cleanup_error(record, key, "sandbox cleanup failed: #{Helpers.failure_message(error)}")
              return true
            end

            event(record, "sandbox.already_removed", sandbox_id: record[:sandbox_id], message: Helpers.failure_message(error))
          end
          record[:cleanup_completed][key] = true
          clear_cleanup_error(record, key)
          false
        end

        def cleanup_volume(record)
          return false if @volume.nil? || record[:volume].nil? || record[:cleanup_completed]["volume"]
          return false if preserve_sandbox_volume?(record)

          event(record, "volume.release")
          if @pod_volumes && record[:volume].is_a?(Hash)
            @pod_volumes.release(record[:pod], record[:volume], token: "release-#{record[:uid]}")
          else
            invoke(@volume, :release, record[:volume])
          end
          record[:cleanup_completed]["volume"] = true
          clear_cleanup_error(record, "volume")
          false
        rescue StandardError => error
          record_cleanup_error(record, "volume", "volume cleanup failed: #{Helpers.failure_message(error)}")
          true
        end

        def cleanup_pod_logs(record)
          return false unless record[:source_gone] && runtime_supports?(:remove_pod_logs)

          @runtime.remove_pod_logs(Helpers.string_keys(record[:pod]))
          clear_cleanup_error(record, "pod_logs")
          false
        rescue StandardError => error
          record_cleanup_error(record, "pod_logs", "Pod log cleanup failed: #{Helpers.failure_message(error)}")
          true
        end

        # The runtime's own word that a sandbox's removal completed.
        def sandbox_already_removed?(sandbox_id)
          return false if sandbox_id.nil? || !runtime_supports?(:sandbox_removed?)

          # Asked only to explain a failed removal; a runtime that cannot
          # answer leaves that failure standing.
          best_effort(false) { @runtime.sandbox_removed?(sandbox_id) == true }
        end

        def release_images(record)
          failed = false
          return if @image_resolver.nil?

          volume_images = record[:volume_image_handles] unless preserve_sandbox_volume?(record)
          handles = Array(record[:images]).map { |image| ["image", image] } +
                    Array(volume_images).map { |image| ["volume-image", image] }
          handles.each_with_index do |(prefix, image), index|
            key = "#{prefix}:#{index}"
            next if record[:cleanup_completed][key]

            begin
              invoke(@image_resolver, :release, image)
              record[:cleanup_completed][key] = true
              clear_cleanup_error(record, key)
            rescue StandardError => error
              record_cleanup_error(record, key, "image cleanup failed: #{Helpers.failure_message(error)}")
              failed = true
            end
          end
          failed
        end

        def record_cleanup_error(record, key, message)
          record[:cleanup_errors].reject! { |entry| entry.start_with?("#{key}: ") }
          record[:cleanup_errors] << "#{key}: #{message}"
        end

        def clear_cleanup_error(record, key)
          record[:cleanup_errors].reject! { |entry| entry.start_with?("#{key}: ") }
        end
      end
    end
  end
end
