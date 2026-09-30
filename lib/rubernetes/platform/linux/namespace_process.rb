# frozen_string_literal: true

require "rubernetes_linux"
require_relative "clone3"
require_relative "error"
require_relative "pidfd"

module Rubernetes
  module Platform
    module Linux
      class NamespaceProcess
        Spawn = Data.define(:pid, :pidfd, :error_fd)
        Result = Data.define(:pid, :pidfd, :wait_result)
        MAX_ARGUMENTS = 4096
        FAILURE_OPERATIONS = {
          1 => "prctl(PR_SET_PDEATHSIG)",
          2 => "mount(MS_PRIVATE)",
          3 => "mount(proc)",
          4 => "dup2(output)",
          5 => "execve"
        }.freeze

        def spawn(command:, output_fd:, resource_id:, proc_target: "/proc", flags: Clone3::NAMESPACE_FLAGS)
          unless command.length.between?(1, MAX_ARGUMENTS)
            raise ArgumentError, "command must contain between 1 and #{MAX_ARGUMENTS} arguments"
          end

          flags = Integer(flags)
          raise ArgumentError, "flags must be exactly CLONE_PIDFD | CLONE_NEWNS | CLONE_NEWPID" unless flags == Clone3::NAMESPACE_FLAGS

          values = Rubernetes::LinuxNative.clone3_exec(
            flags,
            command.map { |argument| String(argument) },
            String(proc_target),
            Integer(output_fd)
          )
          Spawn.new(pid: values.fetch(0), pidfd: values.fetch(1), error_fd: values.fetch(2))
        rescue SystemCallError => error
          raise Linux::Error.wrap(error, operation: "clone3_exec", resource_id: resource_id), cause: error
        end

        # The child's failure pipe is owned EXACTLY ONCE.  Wrapping a raw
        # descriptor in an autoclosing IO and letting it become garbage means
        # the GC closes that descriptor NUMBER at an arbitrary later moment --
        # long after the ensure below already closed it, and long after the
        # kernel handed the number to something else.  That is a
        # use-after-close on whatever now owns it: on 2026-09-14 it closed the
        # node agent's streaming listener at 15:07 and then glibc's netlink
        # socket at 15:18, and glibc answers EBADF on its netlink descriptor by
        # aborting the process ("Unexpected error 9 on netlink descriptor
        # 164."), taking the whole node agent down mid-conformance-run.
        def wait(spawn:, timeout:, resource_id:)
          error_io = error_descriptor_io(spawn)
          wait_result = Pidfd.new.wait(pidfd: spawn.pidfd, timeout: timeout, resource_id: resource_id)
          unless wait_result
            Pidfd.new.send_signal(
              pidfd: spawn.pidfd,
              signal: Signal.list.fetch("KILL"),
              resource_id: resource_id
            )
            Pidfd.new.wait(pidfd: spawn.pidfd, timeout: 5.0, resource_id: resource_id)
            raise Linux::Error.new(
              errno: Errno::ETIMEDOUT::Errno,
              operation: "waitid(P_PIDFD)",
              resource_id: resource_id
            )
          end

          failure = error_io ? error_io.read : "".b
          unless failure.empty?
            stage, errno = failure.unpack("l2")
            raise Linux::Error.new(
              errno: errno,
              operation: FAILURE_OPERATIONS.fetch(stage, "namespace_child"),
              resource_id: resource_id,
              details: {stage: stage}
            )
          end
          Result.new(pid: spawn.pid, pidfd: spawn.pidfd, wait_result: wait_result)
        ensure
          error_io.close if error_io && !error_io.closed?
        end

        private

        # ONE wrapper owns the descriptor, and the ensure closes it once.  The
        # wrapper must be autoclosing (an autoclose: false IO does not close
        # the descriptor on #close at all, which would leak it instead), and
        # because it is the only wrapper, a later finalisation finds it already
        # closed and does nothing.  The bug was ever making a SECOND wrapper
        # for the same descriptor.
        def error_descriptor_io(spawn)
          descriptor = spawn && spawn.error_fd
          return nil if descriptor.nil?

          IO.for_fd(Integer(descriptor))
        rescue SystemCallError
          nil
        end
      end
    end
  end
end
