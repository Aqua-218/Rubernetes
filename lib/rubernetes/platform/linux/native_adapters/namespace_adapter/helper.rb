# frozen_string_literal: true

require "timeout"

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # Short-lived helpers that run a block inside a holder's namespaces.
        class NamespaceAdapter
          # Run a Ruby block inside the holder's namespaces and return its
          # JSON-serializable result.  The block runs in a fresh clone3 child
          # (single task, so setns(2) on a mount namespace is legal) created
          # from a forked, single-Ruby-thread intermediary; the caller's own
          # namespaces are never changed, even when the block raises.
          def within_namespaces(handle, only: [:mount], timeout: HELPER_TIMEOUT, &)
            value = handle.is_a?(Handle) ? handle : lookup(handle)
            descriptors = open_namespace_descriptors(value, only: only)
            reader, writer = IO.pipe
            helper_pid = nil
            # A caller can time out while waiting. Register the child PID
            # before allowing that interrupt so the ensure can reap it.
            Thread.handle_interrupt(Timeout::Error => :never) do
              helper_pid = Process.fork do
                reader.close
                supervise_namespace_helper(value, descriptors, writer, timeout, &)
              end
            end
            writer.close
            descriptors.each_value(&:close)
            # A concurrent fork can inherit the writer and keep it open for
            # the lifetime of its sandbox. Read one reply instead of waiting
            # for EOF. Leave time for the supervisor's five-second kill wait.
            reader.timeout = Float(timeout) + 6.0
            payload = reader.gets("\n")
            reader.close
            _pid, status = Process.waitpid2(helper_pid)
            helper_pid = nil
            namespace_helper_value(payload, status)
          rescue IO::TimeoutError
            raise EffectError, "namespace helper timed out"
          rescue JSON::ParserError, Errno::ECHILD => error
            raise EffectError, "namespace helper returned an invalid result: #{error.message}"
          ensure
            Process.detach(helper_pid) if helper_pid
            reader&.close unless reader&.closed?
            writer&.close unless writer&.closed?
            descriptors&.each_value { |io| io.close unless io.closed? }
          end

          # Run a mount-only operation in the holder mount namespace.
          def with_mount_namespace(handle, &)
            within_namespaces(handle, only: [:mount], &)
            true
          end

          # The holder is already a slave of the host. Share precisely these
          # EmptyDir mounts among the Pod's namespaces; the host remains the
          # upstream master of the new local peer group.
          def share_local_volume_mounts(handle, sources)
            with_mount_namespace(handle) do
              raise EffectError, "cannot share a Pod-local volume in the initial mount namespace" if @mount.initial_mount_namespace?

              sources.each do |source|
                path = File.expand_path(source)
                raise EffectError, "Pod-local volume is not a dedicated directory: #{source.inspect}" if path == "/" || !File.directory?(path)

                @mount.ensure_shared_self_bind(target: path, recursive_bind: true, resource_id: "sandbox-volume:#{path}")
              end
              true
            end
          end

          private

          # The forked intermediary.  It clone3s the helper and turns the helper's
          # end into its own exit status: the helper's, 124 when it timed out, 125
          # when the intermediary itself failed.  Never returns.
          def supervise_namespace_helper(value, descriptors, writer, timeout, &)
            resource_id = "#{value.identity}:helper"
            clone_result = @clone3.call(args: Clone3::Args.new(flags: Clone3::CLONE_PIDFD), resource_id: resource_id)
            run_in_namespaces(value, descriptors, writer, &) if clone_result.child?
            writer.close
            wait = @pidfd.wait(pidfd: clone_result.pidfd, timeout: timeout, resource_id: resource_id)
            unless wait
              @pidfd.send_signal(pidfd: clone_result.pidfd, signal: SIGKILL, resource_id: resource_id)
              @pidfd.wait(pidfd: clone_result.pidfd, timeout: 5.0, resource_id: resource_id)
              exit!(124)
            end
            exit!(wait.exit_status || (128 + wait.term_signal.to_i))
          rescue StandardError
            exit!(125)
          end

          # The helper, in the clone3 child: join, run the block, report its
          # result on the pipe.  Never returns.
          def run_in_namespaces(value, descriptors, writer)
            # Ordered join: the user namespace first when present so the mount
            # namespace join is authorized by it, then the remaining namespaces.
            ordered = descriptors.keys.sort_by { |name| name == :user ? 0 : 1 }
            ordered.each do |name|
              @setns.setns(fd: descriptors.fetch(name), name: name, resource_id: "#{value.identity}:#{name}")
            end
            descriptors.each_value(&:close)
            result = yield
            writer.puts(JSON.generate("ok" => true, "value" => result))
            writer.flush
            exit!(0)
          rescue StandardError => error
            writer.puts(JSON.generate("ok" => false, "error" => "#{error.class}: #{error.message}",
                                      "errno" => NativeAdapters.errno_of(error)))
            writer.flush
            exit!(127)
          end

          def namespace_helper_value(payload, status)
            document = payload.to_s.empty? ? nil : JSON.parse(payload)
            raise EffectError, "namespace helper timed out" if status.exitstatus == 124
            unless status.success? && document && document["ok"] == true
              raise EffectError,
                    "namespace helper failed: #{document ? document["error"] : "exit #{status.exitstatus || (128 + status.termsig.to_i)}"}"
            end

            document["value"]
          end
        end
      end
    end
  end
end
