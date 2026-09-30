# frozen_string_literal: true

require "fiddle"
require_relative "abi_manifest"
require_relative "error"
require_relative "syscall"

module Rubernetes
  module Platform
    module Linux
      class Pidfd
        WaitResult = Data.define(:code, :exit_status, :term_signal)

        P_PIDFD = 3
        WEXITED = 0x0000_0004
        CLD_EXITED = 1
        CLD_KILLED = 2
        CLD_DUMPED = 3
        SIGINFO_SIZE = 128
        WAITID = Fiddle::Function.new(
          Fiddle::Handle::DEFAULT["waitid"],
          [Fiddle::TYPE_INT, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT],
          Fiddle::TYPE_INT
        )

        def initialize(manifest: ABIManifest.load)
          @manifest = manifest
        end

        def open(pid:, flags: 0, resource_id: "pid:#{pid}")
          result = Syscall.call(@manifest.syscall("pidfd_open"), Integer(pid), Integer(flags))
          raise Linux::Error.new(errno: result.errno, operation: "pidfd_open", resource_id: resource_id) if result.value == -1

          Integer(result.value)
        end

        def send_signal(pidfd:, signal:, flags: 0, resource_id: "pidfd:#{pidfd}")
          result = Syscall.call(
            @manifest.syscall("pidfd_send_signal"),
            Integer(pidfd),
            Integer(signal),
            0,
            Integer(flags)
          )
          raise Linux::Error.new(errno: result.errno, operation: "pidfd_send_signal", resource_id: resource_id) if result.value == -1

          true
        end

        def wait(pidfd:, timeout: nil, resource_id: "pidfd:#{pidfd}")
          descriptor = Integer(pidfd)
          io = IO.for_fd(descriptor, autoclose: false)
          return nil unless IO.select([io], nil, nil, timeout)

          storage = Fiddle::Pointer.malloc(SIGINFO_SIZE, Fiddle::RUBY_FREE)
          storage[0, SIGINFO_SIZE] = "\0" * SIGINFO_SIZE
          value = WAITID.call(P_PIDFD, descriptor, storage, WEXITED)
          # R-1.2: waitid may fail after readiness; errno belongs to this exact call.
          errno = Fiddle.last_error
          raise Linux::Error.new(errno: errno, operation: "waitid(P_PIDFD)", resource_id: resource_id) if value == -1

          code = storage[8, 4].unpack1("l")
          status = storage[24, 4].unpack1("l")
          WaitResult.new(
            code: code,
            exit_status: code == CLD_EXITED ? status : nil,
            term_signal: [CLD_KILLED, CLD_DUMPED].include?(code) ? status : nil
          )
        rescue SystemCallError => error
          raise Linux::Error.wrap(error, operation: "waitid(P_PIDFD)", resource_id: resource_id), cause: error
        end

        # pidfds are pollable process identities.  A readable descriptor means
        # the process has exited; unlike kill(0, pid), this cannot be confused
        # with a recycled numeric PID.
        def alive?(pidfd:)
          descriptor = Integer(pidfd)
          io = IO.for_fd(descriptor, autoclose: false)
          IO.select([io], nil, nil, 0).nil?
        rescue Errno::EBADF
          false
        end
      end
    end
  end
end
