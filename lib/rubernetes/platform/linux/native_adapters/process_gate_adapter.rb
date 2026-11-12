# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # Gate-aware clone3 workload adapter. A small Ruby management wrapper
        # owns pipes and wait/reap duties, but the production workload itself
        # is always created with clone3(CLONE_PIDFD) and runs the trusted
        # bootstrap in-process until execveat(2).  Fork is never reported as
        # workload creation capability.
        class ProcessGateAdapter
          include CapabilityContract
          include ProcessIdentity

          # Values from include/uapi/linux/prctl.h.
          PR_SET_PDEATHSIG = 1
          PR_SET_CHILD_SUBREAPER = 36
          SIGKILL = Signal.list.fetch("KILL")
          DUP2 = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["dup2"], [Fiddle::TYPE_INT, Fiddle::TYPE_INT], Fiddle::TYPE_INT
          )
          GETPPID = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["getppid"], [], Fiddle::TYPE_INT
          )
          IMMEDIATE_EXIT = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["_exit"], [Fiddle::TYPE_INT], Fiddle::TYPE_VOID
          )
          PRCTL = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["prctl"], [Fiddle::TYPE_LONG] * 5, Fiddle::TYPE_INT
          )
          # Namespaces a workload joins from the holder, in join order.  The
          # user namespace is joined last by the bootstrap after the rootfs is
          # built (see SecurityAdapter#join_user_namespace).
          HOLDER_JOIN_ORDER = %i[mount network uts ipc].freeze
          CONTAINER_JOIN_ORDER = %i[mount network uts ipc cgroup].freeze

          SETSID = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["setsid"], [], Fiddle::TYPE_INT
          )
          IOCTL = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["ioctl"], [Fiddle::TYPE_INT, Fiddle::TYPE_ULONG, Fiddle::TYPE_INT], Fiddle::TYPE_INT
          )
          TIOCSCTTY = 0x540E
          # Values from include/uapi/linux/ptrace.h.
          PTRACE_TRACEME = 0
          PTRACE_CONT = 7
          PTRACE_DETACH = 17
          SIGTRAP = Signal.list.fetch("TRAP")
          PTRACE = Fiddle::Function.new(
            Fiddle::Handle::DEFAULT["ptrace"], [Fiddle::TYPE_LONG, Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
            Fiddle::TYPE_LONG
          )

          def initialize(namespace_adapter:, security: nil, clone3: Clone3.new, setns: Setns.new)
            @namespace_adapter = namespace_adapter
            @security = security
            @clone3 = clone3
            @setns = setns
            @pidfd = Pidfd.new
          end

          attr_writer :security

          def security_applied_in_child?
            true
          end

          # OCI hooks run at their stage: the in-container ones in the
          # bootstrap, the runtime-namespace ones through the gate.
          def runs_container_hooks? = true

          def native_capabilities
            {
              process_gate: File.directory?("/proc/self/fd"),
              clone3: true,
              clone_pidfd: true,
              pdeathsig: true,
              subreaper: true,
              child_exec: true
            }.freeze
          end

          def validate_native_capabilities!
            require_capability!(native_capabilities.fetch(:process_gate), "clone3/process gate is unavailable")
            require_capability!(native_capabilities.fetch(:clone3), "clone3 process creation is unavailable")
            require_capability!(native_capabilities.fetch(:clone_pidfd), "CLONE_PIDFD process ownership is unavailable")
            require_capability!(native_capabilities.fetch(:pdeathsig), "parent-death signal is unavailable")
            require_capability!(native_capabilities.fetch(:subreaper), "child subreaper is unavailable")
            true
          end

          # Workload children can be moved into their cgroup at their execve
          # (+cgroup_procs+, see NamespaceConnector#spawn_stream).
          def join_cgroup_at_exec? = true

          def release_gate(gate)
            gate.release
          end

          def wait(pid:, timeout: nil)
            deadline = timeout && (Process.clock_gettime(Process::CLOCK_MONOTONIC) + Float(timeout))
            loop do
              result = Process.waitpid2(Integer(pid), Process::WNOHANG)
              return result && result.last if result
              return nil if deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

              sleep 0.01
            end
          rescue Errno::ECHILD
            nil
          end

          # signal() names exactly one process.  Sending to the negated pid
          # instead reaches every member of that process group -- including
          # this agent whenever the workload never got its own session -- so
          # the two are separate methods, never aliases of each other.
          def signal(pid:, signal:)
            Process.kill(Integer(signal), Integer(pid))
            true
          end

          def signal_group(pid:, signal:)
            Process.kill(Integer(signal), -Integer(pid))
            true
          end
        end
      end
    end
  end
end
