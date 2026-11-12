# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # exec and port-forward: commands started inside a live container, and
        # the streams the caller talks to them through.
        class NamespaceConnector
          def exec(sandbox:, container:, command:, tty: false, **_options)
            process = container.process
            join = if process && process.workload_pid && process.workload_start_time
                     {"pid" => process.workload_pid, "start_time" => process.workload_start_time}
                   end
            raise EffectError, "exec requires a live container process to join" unless join

            # CRI exec (runc exec) runs the command with the container's own
            # process environment.  Spawning it with an empty one left every
            # exec -- kubectl exec and exec probes alike -- without the Pod's
            # env vars, PATH included: the Job pod failure policy spec's
            # readiness probe `cat /data/foo-$JOB_COMPLETION_INDEX` read
            # /data/foo- and never succeeded, so its Pods never became Ready.
            spawn_stream(
              sandbox: sandbox,
              container: container,
              command: Array(command),
              cwd: container.spec["cwd"],
              rootfs: nil,
              tty: tty,
              join_process: join,
              env: container.spec["env"] || {}
            )
          end

          def port_forward(sandbox:, container:, ports:, timeout:, **_options)
            validate_native_capabilities!
            values = Array(ports).map { |port| Integer(port) }
            raise EffectError, "port-forward requires between 1 and 128 ports" unless values.length.between?(1, 128)

            timeout_seconds = Float(timeout)
            raise EffectError, "port-forward timeout must be positive" unless timeout_seconds.positive?

            streams = values.map do |port|
              spawn_stream(
                sandbox: sandbox,
                container: container,
                command: [
                  busybox_path,
                  "sh",
                  "-c",
                  "i=0; while [ $i -lt 50 ]; do #{busybox_path} nc -w 1 127.0.0.1 #{port} && exit $?; " \
                  "i=$((i+1)); #{busybox_path} sleep 0.02; done; exit 111"
                ],
                cwd: nil,
                rootfs: nil,
                tty: false
              )
            end
            multiplexed = PortForwardMultiplexer.new(streams)
            {stdin: multiplexed, stdout: multiplexed, stderr: nil, status: multiplexed.status}.freeze
          end

          private

          def spawn_stream(sandbox:, container:, command:, cwd:, rootfs:, tty:, join_process: nil, env: {})
            procs = late_cgroup_procs(container)
            process = @process.spawn(
              command: command,
              env: env,
              cwd: cwd,
              rootfs: rootfs,
              namespace: sandbox.namespace,
              cgroup: container.cgroup,
              security_plan: container.security_plan,
              tty: tty,
              # An exec/attach session always owns its input pipe; the
              # /dev/null default is for the container's own process.
              stdin: true,
              join_process: join_process,
              cgroup_procs: procs
            )
            procs&.close
            @cgroup.attach(container.cgroup, pid: process.fetch(:pid)) if container.cgroup && procs.nil?
            @process.release_gate(process.fetch(:gate))
            stream(process, tty: tty)
          rescue StandardError
            abandon_stream(process) if process
            raise
          end

          # The helper that execs the command is a fork of this agent, and
          # everything it does before execve -- closing inherited
          # descriptors, entering namespaces, the security steps, each
          # copy-on-write fault on the agent's heap -- used to run inside
          # the container's cgroup, attached right after fork.  Under a
          # small CPU limit (10m: 1 ms per 100 ms) that alone took 5-15 s
          # per exec ("Pod InPlace Resize" execs cat on cgroup files a
          # dozen times per spec).  runc exec does the same setup in a few
          # milliseconds.  Here the workload is moved into the cgroup at the
          # stop that follows its execve (see ProcessGateAdapter#spawn,
          # +cgroup_procs+), through a cgroup.procs descriptor opened now.
          def late_cgroup_procs(container)
            @cgroup.open_procs(container.cgroup) if container.cgroup && @process.join_cgroup_at_exec?
          end

          def stream(process, tty:)
            wrapper_pid = process.fetch(:pid)
            status = exit_status_queue(wrapper_pid)
            workload_pid = process.fetch(:gate).workload_pid
            {
              stdin: process.fetch(:stdin),
              stdout: process.fetch(:stdout),
              stderr: tty ? nil : process.fetch(:stderr),
              status: status,
              resize: process[:resize],
              terminate: terminator(workload_pid, wrapper_pid),
              pid: workload_pid
            }.freeze
          end

          # A queue that receives the wrapper's exit status, or the error that
          # kept it from being read.
          def exit_status_queue(pid)
            status = Queue.new
            Thread.new do
              result = @process.wait(pid: pid, timeout: nil)
              status << result
            rescue StandardError => error
              status << error
            end
            status
          end

          def terminator(*pids)
            lambda do |signal = Signal.list.fetch("KILL")|
              pids.compact.uniq.each do |target|
                @process.signal(pid: target, signal: signal)
              rescue SystemCallError
                # Already gone: there is nothing left to signal.
                nil
              end
              true
            end
          end

          # A stream that failed after its wrapper started leaves no wrapper.
          def abandon_stream(process)
            @process.signal(pid: process.fetch(:pid), signal: Signal.list.fetch("KILL"))
            @process.wait(pid: process.fetch(:pid), timeout: 1.0)
          rescue SystemCallError
            nil
          end
        end
      end
    end
  end
end
