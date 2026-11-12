# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        class Unsupported < StandardError; end
        class EffectError < StandardError; end

        # The errno an error carries, when it carries one: Linux::Error and
        # SystemCallError do, a plain StandardError does not.
        def self.errno_of(error)
          case error
          when Linux::Error, SystemCallError then error.errno
          end
        end

        module CapabilityContract
          def native_capabilities
            @native_capabilities ||= capabilities_snapshot
          end

          private

          def capabilities_snapshot
            {}.freeze
          end

          def require_capability!(value, message)
            raise Unsupported, message unless value

            true
          end
        end

        # Shared low-level helpers for processes that must prove their own
        # identity across a PID namespace boundary.
        module ProcessIdentity
          module_function

          def process_start_time(pid, proc_root: "/proc")
            stat = File.read(File.join(proc_root, Integer(pid).to_s, "stat"))
            suffix = stat[(stat.rindex(")") + 1)..]
            Integer(suffix.split.fetch(19))
          rescue SystemCallError, ArgumentError, IndexError
            raise Linux::Error.new(errno: Errno::ESRCH::Errno, operation: "procfs(start_time)", resource_id: "process:#{pid}")
          end

          # NSpid lists the PID in every namespace from the outermost (host)
          # to the innermost.  The host PID is the only value the agent can
          # correlate with a pidfd and with cgroup.procs.
          def host_pid_from_status(status)
            line = String(status).lines.find { |entry| entry.start_with?("NSpid:") }
            line ? line.split.drop(1).first.to_i : 0
          end

          def kernel_process_id
            File.basename(File.readlink("/proc/self")).to_i
          rescue SystemCallError
            Process.pid
          end
        end
      end
    end
  end
end
