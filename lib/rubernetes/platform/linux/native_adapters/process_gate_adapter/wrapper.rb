# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # The wrapper process: a fork of the agent that owns one workload.  It
        # waits on the gate, clone3s the workload, tells the agent which process
        # that is, and from then on only waits for it and passes its exit code on.
        class ProcessGateAdapter
          # The workload traced itself (PTRACE_TRACEME) before its security
          # steps, so its successful execve stops it with SIGTRAP: the old
          # address space -- the fork of this agent -- is already gone, and
          # not one instruction of the new program has run.  Move it into the
          # container's cgroup now and let it go.  Tearing that address space
          # down inside the cgroup is what made every exec under a small CPU
          # limit take seconds; runc's small init process never has one to
          # tear down.  Other signals that stop the tracee before its execve
          # are passed on.  Returns the Process::Status when the workload
          # exited instead (a failed exec), nil once it runs in the cgroup.
          def join_cgroup_at_exec_stop(pid, cgroup_procs)
            loop do
              _, status = Process.waitpid2(pid)
              return status unless status.stopped?

              signal = status.stopsig
              unless signal == SIGTRAP
                PTRACE.call(PTRACE_CONT, pid, nil, signal)
                next
              end
              begin
                cgroup_procs.syswrite(pid.to_s)
              rescue SystemCallError
                # Never let the command run outside the container's cgroup.
                Process.kill(SIGKILL, pid)
                PTRACE.call(PTRACE_DETACH, pid, nil, nil)
                _, status = Process.waitpid2(pid)
                return status
              ensure
                cgroup_procs.close unless cgroup_procs.closed?
              end
              PTRACE.call(PTRACE_DETACH, pid, nil, nil)
              return nil
            end
          end

          # Fork a child that disables GC first, and return only once it has
          # (see #spawn): GC.disable finishes a GC already in progress, and
          # any page that touches must be charged before the caller moves the
          # child into a container's cgroup, not after.
          def fork_without_gc(&)
            reader, writer = IO.pipe
            pid = Process.fork do
              GC.disable
              reader.close
              writer.write("g")
              writer.close
              yield
            end
            writer.close
            reader.read(1)
            pid
          ensure
            reader&.close unless reader.nil? || reader.closed?
            writer&.close unless writer.nil? || writer.closed?
          end

          private

          # Never returns.
          def run_wrapper(launch, pipes)
            Process.setsid
            pipes.close_agent_ends
            # This wrapper lives as long as its workload, and fork gave it a
            # copy of EVERY descriptor the agent had open: the pipes of every
            # other container's stdio and of every exec in flight.  A pipe
            # whose write end sits in a long-lived wrapper never reaches EOF
            # for its reader, so "kubectl exec ss-2 -- mv ..." -- whose
            # pipes were created 5 s before ss-2's own wrapper forked --
            # hung for 24 h, until the suite timed out.  Close what is not
            # ours before waiting on the gate.
            close_inherited_descriptors(keep: pipes.wrapper_ends + [launch.cgroup_procs].compact)
            begin
              set_parent_death_signal(expected_parent_pid: launch.agent_pid, expected_parent_start_time: launch.agent_start_time)
              set_child_subreaper
              pipes.gate_reader.read(1) if launch.gate
              pipes.gate_reader.close
              namespace_descriptors = wrapper_namespace_descriptors(launch)
              workload = clone_workload(launch, pipes, namespace_descriptors)
              hand_over_workload(workload.pid, pipes, namespace_descriptors)
              exit_code = workload_exit_code(workload, launch.cgroup_procs)
              pipes.stderr_writer.close
              exit!(exit_code)
            rescue StandardError => error
              report_wrapper_failure(pipes, error)
              exit!(127)
            ensure
              pipes.close_wrapper_ends
            end
          end

          # Namespace descriptors are opened and verified in the wrapper so the
          # raw clone3 child only performs setns(2) on descriptors whose identity
          # has already been checked.
          def wrapper_namespace_descriptors(launch)
            descriptors = if launch.join
                            open_process_namespaces(launch.join)
                          elsif launch.namespace_handle
                            wanted = HOLDER_JOIN_ORDER + [:user] + (launch.shared_pid? ? [:pid] : [])
                            @namespace_adapter.open_namespace_descriptors(launch.namespace_handle, only: wanted)
                          else
                            {}
                          end
            # PID namespace membership is inherited only by children, so the
            # wrapper joins it (when sharing) before clone3.
            if descriptors[:pid]
              @setns.setns(fd: descriptors[:pid], name: :pid, resource_id: "process:workload:pid")
              descriptors[:pid].close
              descriptors.delete(:pid)
            end
            descriptors
          end

          # clone3 the workload.  The child runs the trusted bootstrap and never
          # returns; the wrapper gets the clone result.
          def clone_workload(launch, pipes, namespace_descriptors)
            wrapper_pid = kernel_process_id
            bootstrap = workload_bootstrap(launch, pipes, namespace_descriptors)
            workload = @clone3.call(args: Clone3::Args.new(flags: launch.clone_flags), resource_id: "process:workload")
            return workload unless workload.child?

            bootstrap.run(expected_parent_pid: wrapper_pid)
            IMMEDIATE_EXIT.call(127)
          end

          def workload_bootstrap(launch, pipes, namespace_descriptors)
            plan = launch.security_plan
            context = plan.context
            hooks = launch.container_hooks
            pipes.status_writer.close_on_exec = false
            WorkloadBootstrap.new(
              security: launch.security, setns: @setns,
              command: launch.command, env: launch.env, cwd: launch.cwd, rootfs: launch.rootfs,
              plan: plan.with(context: context.with(fd_allowlist: context.fd_allowlist + pipes.workload_descriptors)),
              namespace_descriptors: namespace_descriptors,
              build_rootfs: launch.build_rootfs?, unshare_mount: launch.private_mount_namespace?,
              unshare_cgroup: launch.unshare_cgroup?,
              mounts: launch.mounts,
              status_writer: pipes.status_writer,
              stdio: pipes.workload_stdio,
              controlling_tty: !pipes.pty_slave.nil?,
              trace_exec: !launch.cgroup_procs.nil?,
              hooks: hooks ? hooks["hooks"] : nil,
              hook_state: hooks ? hooks["state"] : nil,
              hook_reply: pipes.hook_reply_reader, clone3: @clone3
            )
          end

          # After clone3: tell the agent which process the workload is, and drop
          # every descriptor that is now the workload's alone.
          def hand_over_workload(workload_pid, pipes, namespace_descriptors)
            namespace_descriptors.each_value { |io| io.close unless io.closed? }
            pipes.hook_reply_reader&.close
            pipes.identity_writer.write([workload_pid].pack("Q<"))
            pipes.identity_writer.flush
            pipes.identity_writer.close
            # Only the workload child may hold the readiness writer.  If the
            # wrapper retains a copy, Gate#release blocks until the workload
            # exits instead of returning immediately after exec.
            pipes.status_writer.close
            pipes.stdin_reader.close
            pipes.stdout_writer.close
          end

          # The workload's exit code is the wrapper's exit code; nothing is
          # written to the container's stderr (a kubelet never adds its own lines
          # to a container's log or an exec's output).
          def workload_exit_code(workload, cgroup_procs)
            reaped = cgroup_procs ? join_cgroup_at_exec_stop(workload.pid, cgroup_procs) : nil
            status = reaped ? nil : @pidfd.wait(pidfd: workload.pidfd, timeout: nil, resource_id: "process:workload")
            IO.for_fd(workload.pidfd).close if workload.pidfd
            return reaped.exitstatus || (128 + reaped.termsig.to_i) if reaped

            status&.exit_status || (128 + status&.term_signal.to_i)
          end

          def report_wrapper_failure(pipes, error)
            report_on(pipes.status_writer, "E#{error.class}: #{error.message}")
            report_on(pipes.stderr_writer, "rubernetes process wrapper failed: #{error.class}: #{error.message}\n")
          end

          def report_on(io, text)
            io.write(text)
            io.flush
          rescue IOError
            nil
          end

          # Open the namespaces of a live container process.  The start time is
          # checked before and after the descriptors are opened so a recycled
          # PID cannot be joined.
          def open_process_namespaces(join)
            pid = join.fetch("pid")
            expected = join.fetch("start_time")
            raise EffectError, "container process identity changed before exec" unless process_start_time(pid) == expected

            descriptors = (CONTAINER_JOIN_ORDER + %i[user pid]).each_with_object({}) do |name, result|
              link = File.readlink("/proc/#{pid}/ns/#{Setns::NAMESPACE_TYPES.fetch(name).fetch(1)}")
              # The user namespace is only joined when it differs from ours.
              next if name == :user && link == File.readlink("/proc/self/ns/user")

              result[name] = @setns.open_namespace(pid: pid, name: name, expected_link: link, resource_id: "process:join:#{name}")
            end
            raise EffectError, "container process identity changed while joining" unless process_start_time(pid) == expected

            descriptors
          rescue SystemCallError => error
            raise EffectError, "container namespaces could not be opened: #{error.message}"
          end

          # Close every pipe, socket and anonymous inode (pidfd, eventfd,
          # epoll) this forked child inherited except the ones it was handed.
          # Regular files and devices are left alone: they cannot hold a
          # reader hostage and the log file is among them.
          INHERITED_CLOSE_KINDS = %w[pipe: socket: anon_inode:].freeze

          def close_inherited_descriptors(keep: [])
            keep_fds = Array(keep).compact.reject(&:closed?).map(&:fileno)
            Dir.children("/proc/self/fd").each do |entry|
              fd = Integer(entry, exception: false)
              next if fd.nil? || fd <= 2 || keep_fds.include?(fd)

              target = begin
                File.readlink("/proc/self/fd/#{fd}")
              rescue SystemCallError
                next
              end
              next unless INHERITED_CLOSE_KINDS.any? { |kind| target.start_with?(kind) }

              begin
                IO.for_fd(fd).close
              rescue SystemCallError, IOError, ArgumentError
                nil
              end
            end
          rescue SystemCallError
            nil
          end

          def set_parent_death_signal(expected_parent_pid: nil, expected_parent_start_time: nil)
            result = PRCTL.call(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)
            errno = Fiddle.last_error
            raise Linux::Error.new(errno: errno, operation: "prctl(PR_SET_PDEATHSIG)", resource_id: "process") if result == -1

            if expected_parent_pid && kernel_parent_id != Integer(expected_parent_pid)
              raise Linux::Error.new(errno: Errno::ESRCH::Errno, operation: "prctl(PR_SET_PDEATHSIG)", resource_id: "process")
            end
            if expected_parent_start_time && process_start_time(expected_parent_pid) != Integer(expected_parent_start_time)
              raise Linux::Error.new(errno: Errno::ESRCH::Errno, operation: "prctl(PR_SET_PDEATHSIG)", resource_id: "process")
            end

            true
          end

          def set_child_subreaper
            result = PRCTL.call(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
            errno = Fiddle.last_error
            raise Linux::Error.new(errno: errno, operation: "prctl(PR_SET_CHILD_SUBREAPER)", resource_id: "process") if result == -1
          end

          def kernel_parent_id
            line = File.read("/proc/self/status").lines.find { |entry| entry.start_with?("PPid:") }
            value = line ? line.split.last.to_i : 0
            value.zero? ? Process.ppid : value
          rescue SystemCallError
            Process.ppid
          end
        end
      end
    end
  end
end
