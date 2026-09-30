# frozen_string_literal: true

require "fiddle"
require_relative "abi_manifest"
require_relative "error"
require_relative "syscall"

module Rubernetes
  module Platform
    module Linux
      class Clone3
        SIGCHLD = Signal.list.fetch("CHLD")
        Args = Data.define(
          :flags,
          :exit_signal,
          :stack,
          :stack_size,
          :tls,
          :set_tid,
          :set_tid_size,
          :cgroup
        ) do
          def initialize(
            flags:,
            exit_signal: SIGCHLD,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: 0
          )
            super(
              flags: Integer(flags),
              exit_signal: Integer(exit_signal),
              stack: Integer(stack),
              stack_size: Integer(stack_size),
              tls: Integer(tls),
              set_tid: Integer(set_tid),
              set_tid_size: Integer(set_tid_size),
              cgroup: Integer(cgroup)
            )
          end
        end
        Result = Data.define(:pid, :pidfd, :child) do
          def child?
            child
          end
        end

        # Values come from include/uapi/linux/sched.h and are checked by the ABI manifest.
        CLONE_PIDFD = 0x0000_1000
        CLONE_NEWNS = 0x0002_0000
        CLONE_NEWPID = 0x2000_0000
        NAMESPACE_FLAGS = CLONE_PIDFD | CLONE_NEWNS | CLONE_NEWPID

        def initialize(manifest: ABIManifest.load)
          @manifest = manifest
          @manifest.verify_ruby_layouts!
        end

        def call(args:, resource_id:, structure_size: nil)
          pidfd_storage = Fiddle::Pointer.malloc(4, Fiddle::RUBY_FREE)
          pidfd_storage[0, 4] = [-1].pack("l")
          fields = [
            args.flags,
            (args.flags & CLONE_PIDFD).zero? ? 0 : pidfd_storage.to_i,
            0,
            0,
            args.exit_signal,
            args.stack,
            args.stack_size,
            args.tls,
            args.set_tid,
            args.set_tid_size,
            args.cgroup
          ]
          bytes = fields.pack("Q*")
          pointer = Fiddle::Pointer[bytes]
          size = structure_size || @manifest.structure("clone_args").fetch("size")
          result = Syscall.call(@manifest.syscall("clone3"), pointer, size)
          raise Linux::Error.new(errno: result.errno, operation: "clone3", resource_id: resource_id) if result.value == -1

          child = result.value.zero?
          pidfd = child || (args.flags & CLONE_PIDFD).zero? ? nil : pidfd_storage[0, 4].unpack1("l")
          Result.new(pid: Integer(result.value), pidfd: pidfd, child: child)
        end
      end
    end
  end
end
