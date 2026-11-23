# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      class PodLogFiles
        # Installed by the host agent. Standalone and guest runtimes still
        # use their original supervisor and private raw logs.
        module RuntimeHooks
          attr_writer :pod_log_files

          private

          def spawn_gated_workload(sandbox, container, spec, command, rootfs, hook_options)
            process = super
            begin
              if @pod_log_files.prepare(process.id, sandbox.config.fetch("metadata", {}), spec["name"], container.id)
                process = @process_supervisor.share_combined_log(process)
              end
            rescue StandardError => error
              record(:pod_log_setup_failed, container_id: container.id, error: error_payload(error))
            end
            process
          end

          def remove_container_logs(sandbox_id, container_ids)
            container_ids.each do |id|
              key = process_log_key(sandbox_id, id)
              @process_supervisor.discard_deferred_output(key)
              @pod_log_files.remove(key)
            end
            super
          end
        end

        module ProcessHooks
          attr_writer :pod_log_files

          def share_combined_log(handle)
            @mutex.synchronize { @handles[handle.id] = handle_with_shared_log(handle) }
          end

          def discard_deferred_output(id)
            log = retained_combined_log(id)
            @pod_log_files.with_writer(id) { log.discard } if log
          end

          def logs(handle, **)
            id = handle.is_a?(Platform::Linux::ProcessSupervisor::Handle) ? handle.id : String(handle)
            log = retained_combined_log(id)
            pending = log&.retained_handle
            pending ? drain_logs(pending) : log&.resume
            super
          end

          private

          def retained_combined_log(id)
            log = @mutex.synchronize { @closed_logs.dig(id, :combined) }
            log if log.is_a?(CombinedLog)
          end

          def handle_with_shared_log(handle)
            log = CombinedLog.new(handle.combined_log, stdout: handle.stdout_log, stderr: handle.stderr_log)
            handle.with(combined_log: log)
          end

          def recovered_handle(...)
            handle = super
            @pod_log_files.shared_combined?(handle.id) ? handle_with_shared_log(handle) : handle
          end

          def recovered_log_files(id)
            logs = super
            return logs unless @pod_log_files.shared_combined?(id)

            logs.merge(combined: CombinedLog.new(logs.fetch(:combined), stdout: logs.fetch(:stdout), stderr: logs.fetch(:stderr)))
          end

          def drain_logs(handle)
            combined = handle.combined_log if handle.combined_log.is_a?(CombinedLog)
            @pod_log_files.with_writer(handle.id) do |writer|
              next if combined&.discarded?

              handle = combined&.retained_handle || handle
              raise CombinedLog::DeferredPromotion if combined && !combined.resume

              super(writer || combined ? tee_logs(handle, writer, combined) : handle)
              combined&.close_retained_streams
            rescue CombinedLog::DeferredPromotion
              combined.retain_streams(handle) unless @mutex.synchronize { @handles.key?(handle.id) }
            end
          end

          def tee_logs(handle, writer, combined)
            handle.with(stdout_log: Writer::Tee.new(handle.stdout_log, writer, "stdout", combined),
                        stderr_log: Writer::Tee.new(handle.stderr_log, writer, "stderr", combined),
                        combined_log: combined ? nil : handle.combined_log)
          end
        end
      end
    end
  end
end
