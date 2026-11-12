# frozen_string_literal: true

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
            helper_pid = Process.fork do
              reader.close
              supervise_namespace_helper(value, descriptors, writer, timeout, &)
            end
            writer.close
            descriptors.each_value(&:close)
            payload = reader.read
            reader.close
            _pid, status = Process.waitpid2(helper_pid)
            namespace_helper_value(payload, status)
          rescue JSON::ParserError, Errno::ECHILD => error
            raise EffectError, "namespace helper returned an invalid result: #{error.message}"
          ensure
            reader&.close unless reader&.closed?
            writer&.close unless writer&.closed?
            descriptors&.each_value { |io| io.close unless io.closed? }
          end

          # Run a mount-only operation in the holder mount namespace.
          def with_mount_namespace(handle, &)
            within_namespaces(handle, only: [:mount], &)
            true
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
            writer.write(JSON.generate("ok" => true, "value" => result))
            writer.flush
            exit!(0)
          rescue StandardError => error
            writer.write(JSON.generate("ok" => false, "error" => "#{error.class}: #{error.message}",
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
