# frozen_string_literal: true

require_relative "../../durable_process"

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # Spawning a workload, on the agent's side: what to launch, the pipes
        # between agent, wrapper and workload, and the handles the caller gets.
        class ProcessGateAdapter
          # Everything one spawn decided before it forked: what runs, where, and
          # which namespaces the workload joins or creates.
          Launch = Data.define(:command, :env, :cwd, :rootfs, :gate, :security_plan, :security, :namespace_handle, :join,
                               :mounts, :cgroup_procs, :container_hooks, :agent_pid, :agent_start_time, :durable_exit, :stdin_once, :oom_score_adj) do
            def plan_namespaces
              namespace_handle ? Array(namespace_handle.namespaces) : []
            end

            def shared_pid?
              !namespace_handle.nil? && Array(namespace_handle.plan.shared).include?(:pid)
            end

            # A rootfs is only ever mounted in a private copy of a mount
            # namespace: the holder's when the sandbox has one, otherwise a
            # fresh unshare(CLONE_NEWNS) by the single-threaded child.  The
            # agent's own mount table is never modified either way.
            def private_mount_namespace?
              join.nil? && (!rootfs.nil? || plan_namespaces.include?(:mount))
            end

            # A private PID namespace per container is the §5.8.6 default;
            # shareProcessNamespace and exec/attach join an existing one via
            # setns(2) in the wrapper before clone3 instead.
            def clone_flags
              private_pid = plan_namespaces.include?(:pid) && !shared_pid? && join.nil?
              Clone3::CLONE_PIDFD | (private_pid ? Clone3::CLONE_NEWPID : 0)
            end

            def build_rootfs?
              !rootfs.nil? && join.nil?
            end

            def unshare_cgroup?
              join.nil? && plan_namespaces.include?(:cgroup)
            end

            def join_cgroup_at_exec? = !join.nil? && !cgroup_procs.nil?

            def cgroup_procs_before_setup
              cgroup_procs unless join_cgroup_at_exec?
            end
          end

          # The descriptors of one spawn.  The agent keeps one end of each pipe,
          # the wrapper (and through it the workload) the other.
          Pipes = Struct.new(:gate_reader, :gate_writer, :status_reader, :status_writer, :identity_reader, :identity_writer,
                             :hook_reply_reader, :hook_reply_writer, :stdin_reader, :stdin_writer, :stdout_reader, :stdout_writer,
                             :stderr_reader, :stderr_writer, :pty_master, :pty_slave, :owner, :wrapper) do
            def open(stdin:, tty:, hooks:, durable:)
              self.gate_reader, self.gate_writer = IO.pipe
              self.status_reader, self.status_writer = IO.pipe
              self.identity_reader, self.identity_writer = IO.pipe
              self.hook_reply_reader, self.hook_reply_writer = IO.pipe if hooks
              open_stdin(stdin || tty)
              self.stdout_reader, self.stdout_writer = IO.pipe
              self.stderr_reader, self.stderr_writer = IO.pipe
              self.owner, self.wrapper = UNIXSocket.pair if durable
              open_pty if tty
              # Ruby opens pipes O_NONBLOCK for its own scheduler; the flag lives
              # on the open file description the child inherits, so a workload
              # would see EAGAIN on a full stdout or an empty stdin.  The
              # child's ends are made blocking; the agent's ends keep the flag.
              [stdin_reader, stdout_writer, stderr_writer].each { |io| io.nonblock = false }
              self
            end

            # What the wrapper keeps across its sweep of inherited descriptors.
            def wrapper_ends
              [gate_reader, status_writer, identity_writer, stdin_reader, stdout_writer, stderr_writer, pty_master, pty_slave,
               hook_reply_reader, wrapper, *(wrapper ? retained_streams.values : [])].compact
            end

            def retained_streams
              {"stdin" => stdin_writer, "stdout" => stdout_reader, "stderr" => stderr_reader}
            end

            # In the wrapper: the ends that are the agent's.
            def close_agent_ends
              streams = wrapper ? [] : retained_streams.values
              [gate_writer, status_reader, identity_reader, hook_reply_writer, owner, *streams].each { |io| io&.close }
            end

            # In the agent: the ends that are the wrapper's.
            def close_wrapper_ends
              [gate_reader, status_writer, identity_writer, stdin_reader, stdout_writer, stderr_writer, hook_reply_reader, wrapper].each do |io|
                io&.close
              end
            end

            # The workload's descriptors 0..2: the pty slave for a tty session.
            def workload_stdio
              pty_slave ? [pty_slave.fileno] * 3 : [stdin_reader.fileno, stdout_writer.fileno, stderr_writer.fileno]
            end

            # The descriptors the workload's close step must leave open.
            def workload_descriptors
              [status_writer.fileno, stdin_reader.fileno, stdout_writer.fileno, stderr_writer.fileno] + (pty_slave ? [pty_slave.fileno] : [])
            end

            def close
              each do |io|
                io.close unless io.nil? || io.closed?
              rescue IOError
                nil
              end
            end

            private

            # Without `stdin: true` a container's stdin is /dev/null, as the
            # CRI gives it.  A pipe nobody ever writes to left `sh` -- busybox's
            # default command, the init container of "[sig-node] Pods Extended
            # pod generation should start at 1" -- blocked in read(2) for ever
            # instead of exiting at EOF, and the Pod never left Pending.
            def open_stdin(piped)
              if piped
                self.stdin_reader, self.stdin_writer = IO.pipe
              else
                self.stdin_reader = File.open(File::NULL, File::RDONLY)
              end
            end

            # A tty session (kubectl exec -it) gets a real pseudo-terminal:
            # the workload's stdio is the pty slave and its controlling
            # terminal, the caller reads and writes the master.  Pipes with a
            # tty flag would leave isatty(3) false and job control off.
            def open_pty
              self.pty_master, self.pty_slave = PTY.open
              pty_master.sync = true
              pty_slave.nonblock = false
            end
          end

          # `join_process` (exec/attach) names a live container process whose
          # namespaces the new process enters instead of building a rootfs.
          def spawn(command:, env: {}, cwd: nil, rootfs: nil, gate: true, security_plan: nil,
                    namespace: nil, cgroup: nil, tty: false, join_process: nil, mounts: [], stdin: false,
                    cgroup_procs: nil, container_hooks: nil, durable_exit: nil, stdin_once: false, oom_score_adj: nil, **_options)
            validate_native_capabilities!
            launch = plan_launch(command: command, env: env, cwd: cwd, rootfs: rootfs, gate: gate, security_plan: security_plan,
                                 namespace: namespace, join_process: join_process, mounts: mounts, cgroup_procs: cgroup_procs,
                                 container_hooks: container_hooks, durable_exit: durable_exit, stdin_once: stdin && stdin_once && !tty,
                                 oom_score_adj: oom_score_adj)
            prepare_sandbox_shared_volumes(launch)
            pipes = Pipes.new
            pipes.open(stdin: stdin, tty: tty, hooks: container_hooks, durable: !durable_exit.nil?)
            # The eventual workload is a fork of the agent until exec. Disable
            # GC before attaching either fork to avoid charging Ruby's marked
            # heap pages to the workload's memory limit.
            child_pid = fork_without_gc { run_wrapper(launch, pipes) }
            pipes.close_wrapper_ends
            spawn_result(child_pid, launch, pipes, cgroup)
          rescue SystemCallError => error
            pipes&.close
            raise EffectError, "process spawn failed: #{error.message}"
          end

          private

          def prepare_sandbox_shared_volumes(launch)
            sources = launch.mounts.filter_map { |spec| spec.fetch("source") if spec["sandbox_shared_volume"] == true }.uniq
            return if sources.empty?

            unless launch.private_mount_namespace? && launch.namespace_handle && launch.security_plan.context.privileged?
              raise EffectError, "bidirectional EmptyDir mount requires a privileged workload in a sandbox mount namespace"
            end

            @namespace_adapter.share_local_volume_mounts(launch.namespace_handle, sources)
          end

          def plan_launch(command:, env:, cwd:, rootfs:, gate:, security_plan:, namespace:, join_process:, mounts:, cgroup_procs:,
                          container_hooks:, durable_exit:, stdin_once:, oom_score_adj:)
            bind_mounts = Array(mounts).map { |mount| mount.to_h.transform_keys(&:to_s) }
            raise EffectError, "bind mounts require a rootfs" if !bind_mounts.empty? && rootfs.nil?
            raise EffectError, "production process adapter requires a security plan" unless security_plan
            raise EffectError, "production process adapter has no security applier" unless @security

            bootstrap_security = bootstrap_security_adapter
            raise EffectError, "production process adapter has no rootfs/security transition helper" unless bootstrap_security

            agent_pid = Process.pid
            Launch.new(
              command: Array(command).map { |item| String(item) },
              env: env.to_h.each_with_object({}) { |(key, value), result| result[String(key)] = value.nil? ? nil : String(value) },
              cwd: cwd, rootfs: rootfs && String(rootfs), gate: gate, security_plan: security_plan, security: bootstrap_security,
              namespace_handle: namespace&.adapter_handle, join: normalize_join(join_process), mounts: bind_mounts,
              cgroup_procs: cgroup_procs, container_hooks: container_hooks,
              agent_pid: agent_pid, agent_start_time: process_start_time(agent_pid), durable_exit: durable_exit, stdin_once: stdin_once,
              oom_score_adj: oom_score_adj
            )
          end

          # What the caller gets: the wrapper's pid, the gate, and its ends of the
          # workload's stdio.
          def spawn_result(child_pid, launch, pipes, cgroup)
            hooks = launch.container_hooks
            result = {pid: child_pid, pidfd: nil,
                      workload_creation_method: "clone3", workload_clone_flags: launch.clone_flags,
                      gate: Gate.new(writer: pipes.gate_writer, status_reader: pipes.status_reader, identity_reader: pipes.identity_reader,
                                     hook_reply: pipes.hook_reply_writer, hook_handler: hooks && hooks["runtime"], owner: pipes.owner),
                      stdin: pipes.stdin_writer, stdout: pipes.stdout_reader,
                      stderr: pipes.stderr_reader, cgroup: cgroup}
            if launch.durable_exit
              result[:durable] = DurableProcess.capture(child_pid, pipes.retained_streams).merge(
                "exit_file" => File.basename(launch.durable_exit), "stdin_once" => launch.stdin_once
              )
            end
            pipes.pty_master ? pty_session(result, pipes) : result
          end

          # A tty session reads and writes the pty master instead of the pipes.
          def pty_session(result, pipes)
            master = pipes.pty_master
            pipes.pty_slave.close
            pipes.stdin_writer&.close
            pipes.stdout_reader.close
            result.merge(stdin: PtyInput.new(master), stdout: master, pty: master,
                         resize: ->(width, height) { master.winsize = [Integer(height), Integer(width)] })
          end

          def normalize_join(value)
            return nil if value.nil?

            hash = value.to_h.transform_keys(&:to_s)
            pid = Integer(hash.fetch("pid") { hash.fetch("workload_pid") })
            start_time = Integer(hash.fetch("start_time") { hash.fetch("workload_start_time") })
            {"pid" => pid, "start_time" => start_time}
          rescue KeyError, ArgumentError, TypeError => error
            raise EffectError, "join_process requires pid and start_time: #{error.message}"
          end

          # The security applier is Linux::Security wrapping the kernel adapter,
          # or that adapter itself.  Only the kernel adapter can build a rootfs
          # and so bootstrap a workload; a recording adapter cannot.
          def bootstrap_security_adapter
            adapter = @security.is_a?(Linux::Security) ? @security.adapter : @security
            adapter if adapter.is_a?(SecurityAdapter)
          end
        end
      end
    end
  end
end
