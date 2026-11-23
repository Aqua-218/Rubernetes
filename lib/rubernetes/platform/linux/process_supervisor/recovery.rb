# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      class ProcessSupervisor
        # Recover the same process and streams after an agent restart. The
        # caller has already matched the durable sandbox and cgroup identity.
        module Recovery
          def finish_stdin(handle)
            @mutex.synchronize do
              current = @handles[handle.id]
              return if current&.stdin.nil? || current.stdin.closed?

              begin
                if current.durable&.fetch("stdin_once", false)
                  @pidfd_adapter.send_signal(pidfd: current.pidfd, signal: DurableProcess::STDIN_EOF_SIGNAL, resource_id: "process:#{current.id}:stdin")
                end
              rescue Linux::Error => error
                raise unless error.errno == Errno::ESRCH::Errno
              ensure
                current.stdin.close
              end
            end
          end

          # Re-adopt a live process discovered during startup reconciliation.
          # The caller must supply the durable start time and workload PID; a
          # numeric PID alone is never sufficient because it may have been
          # reused after the agent crashed.
          def adopt(metadata:, cgroup: nil)
            value = metadata.to_h.transform_keys(&:to_s)
            id = String(value.fetch("id") { raise Error, "process adoption requires an id" })
            existing = @mutex.synchronize { @handles[id] }
            return existing if existing

            pid = Integer(value.fetch("pid") { value.fetch("workload_pid") })
            workload_pid = Integer(value.fetch("workload_pid", pid))
            expected_start = value["workload_start_time"] || value["start_time"]
            raise Error, "process #{id} adoption requires a start time" if expected_start.nil?

            actual_start = process_start_time(workload_pid)
            raise Error, "process #{id} start time changed during adoption" unless actual_start == Integer(expected_start)

            expected_digest = value["workload_executable_digest"] || value["executable_digest"]
            raise Error, "process #{id} adoption requires an executable digest" if expected_digest.nil?

            # pid and start time identify the process.  The recorded digest is
            # of the file it was started from; after an exec it runs another
            # one, so the digest is kept as recorded and not compared.  It is
            # part of the claim's durable identity, which the adopted handle
            # must reproduce.
            actual_digest = String(expected_digest).downcase

            streams = DurableProcess.reopen(pid, value["durable"])
            pidfd = @pidfd_adapter ? open_pidfd(pid, "process:adopt:#{id}") : value["pidfd"]
            workload_pidfd = if @pidfd_adapter && workload_pid != pid
                               open_pidfd(workload_pid, "process:adopt:#{id}:workload")
                             else
                               pidfd
                             end
            handle = recovered_handle(value, id: id, pid: pid, pidfd: pidfd, workload_pid: workload_pid, workload_pidfd: workload_pidfd,
                                             actual_start: actual_start, actual_digest: actual_digest, streams: streams, cgroup: cgroup)
            registered = @mutex.synchronize { @handles[id] ||= handle }
            close_adoption_streams(streams, pidfd, workload_pidfd) unless registered.equal?(handle)
            registered
          rescue ArgumentError, TypeError, SystemCallError, IOError, Error, Linux::Error => error
            close_adoption_streams(streams, pidfd, workload_pidfd)
            gone = error.is_a?(Errno::ENOENT) || error.is_a?(Errno::ESRCH)
            raise (gone ? ProcessGone : Error), "process adoption failed: #{error.message}"
          end

          private

          def recovered_log_files(id)
            directory = File.join(@log_directory, id)
            raise Error, "unknown process handle #{id}" unless id.match?(/\Aprocess-[A-Za-z0-9_.-]+\z/) && File.lstat(directory).directory?

            {stdout: "stdout", stderr: "stderr", combined: "container"}.transform_values do |name|
              LogRotator.new(path: File.join(directory, "#{name}.log"), max_bytes: @max_log_bytes, max_files: @max_log_files, create_directory: false)
            end
          rescue Errno::ENOENT
            raise Error, "unknown process handle #{id}"
          end

          def recovered_handle(value, id:, pid:, pidfd:, workload_pid:, workload_pidfd:, actual_start:, actual_digest:, streams:, cgroup:)
            log_root = File.join(@log_directory, id)
            Handle.new(
              id: id.freeze,
              pid: pid,
              pidfd: pidfd && Integer(pidfd),
              workload_pid: workload_pid,
              workload_pidfd: workload_pidfd && Integer(workload_pidfd),
              workload_start_time: actual_start,
              workload_executable_digest: actual_digest,
              workload_creation_method: value["workload_creation_method"],
              workload_clone_flags: value["workload_clone_flags"],
              workload_security: value["workload_security"],
              command: Array(value["command"]).map(&:to_s).freeze,
              started_at: value["started_at"] && Time.iso8601(String(value["started_at"])).utc,
              gate: nil,
              stdin: streams[:stdin],
              stdout: streams[:stdout],
              stderr: streams[:stderr],
              stdout_log: LogRotator.new(path: File.join(log_root, "stdout.log"), max_bytes: @max_log_bytes, max_files: @max_log_files),
              stderr_log: LogRotator.new(path: File.join(log_root, "stderr.log"), max_bytes: @max_log_bytes, max_files: @max_log_files),
              combined_log: LogRotator.new(path: File.join(log_root, "container.log"), max_bytes: @max_log_bytes, max_files: @max_log_files),
              state: value["state"].to_s == "stopped" ? :stopped : :running,
              exit_status: value["exit_status"],
              term_signal: value["term_signal"],
              cgroup: cgroup,
              durable: value["durable"]
            )
          end

          def close_adoption_streams(streams, *descriptors)
            streams&.each_value(&:close)
            descriptors.compact.uniq.each { |descriptor| @pidfd_adapter.close(pidfd: descriptor) } if @pidfd_adapter
          end

          def await_durable_exit(handle, timeout:, resource_id:)
            return unless IO.for_fd(handle.pidfd, autoclose: false).wait_readable(timeout)

            native = reap_durable_wrapper(handle, resource_id)
            return native if native&.term_signal

            basename = handle.durable.fetch("exit_file")
            raise Error, "invalid wrapper exit record name" unless basename.match?(/\Aexit-[0-9a-f]{24}\.json\z/)

            DurableProcess.exit_status(File.join(@log_directory, handle.id, basename)) || native
          end

          def reap_durable_wrapper(handle, resource_id)
            @pidfd_adapter.wait(pidfd: handle.pidfd, timeout: 0, resource_id: resource_id || "process:#{handle.id}")
          rescue Linux::Error => error
            raise unless error.errno == Errno::ECHILD::Errno

            nil
          end
        end
      end
    end
  end
end
