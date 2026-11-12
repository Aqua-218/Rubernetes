# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      # Starting a container: the workload is spawned behind a gate, placed in
      # its cgroup and secured while it waits, and only then released.  A
      # start that does not reach the release leaves no process behind.
      module ContainerStart
        def start_container(value, request_id: nil)
          sandbox, container = find_container(value)
          spec = container.spec
          request = request_id || spec["request_id"] || "start:#{sandbox.id}:#{container.id}"
          request_state = begin_native_request(request, operation: "container.start", input: {
                                                 "sandbox_id" => sandbox.id, "container_id" => container.id, "spec" => spec
                                               })
          return sandbox.container(container.id) if request_state&.state == "Completed"

          unless container.state == :created
            error = InvalidState.new("container #{container.id} is not startable")
            complete_native_request(request, state: "Failed", error: error_payload(error))
            raise error
          end
          launch_container(sandbox, container, request, startable_command(spec))
        rescue StandardError => error
          raise error if error.is_a?(FailClosed) || error.is_a?(RecoveryRequired) || error.is_a?(OwnershipConflict)

          raise FailClosed, "container start failed before workload gate release: #{error.message}"
        end

        private

        def startable_command(spec)
          command = spec["command"] || spec["argv"]
          return command unless command.nil?
          raise FailClosed, "container image config did not provide an executable command" if config.host_profile? || spec["image"] || spec["resolved_image"]

          ["/bin/true"]
        end

        # Spawn behind the gate, prepare the waiting wrapper, release, record.
        # Whatever fails on the way stops the process and is reported as
        # FailClosed with the start request settled as Failed.
        def launch_container(sandbox, container, request, command)
          spec = container.spec
          process = nil
          gate_released = false
          resolved_rootfs = workload_rootfs(sandbox, spec, container: container)
          command = resolve_executable(command, rootfs: resolved_rootfs, env: spec["env"] || {})
          # CDI container edits may carry OCI hooks.  A supervisor that builds
          # the container in a child runs the in-container stages there and
          # calls back for the runtime-namespace ones once the namespaces
          # exist; otherwise (no container namespaces) every pre-start stage
          # runs here, before the gate.
          hooks = container_hooks(spec)
          hook_plan = hooks.empty? ? nil : prepare_hook_bundle(sandbox, container, spec, command, resolved_rootfs, hooks)
          hooks_in_child = hook_plan && @process_supervisor.runs_container_hooks?
          hook_options = hooks_in_child ? child_hook_options(hooks, hook_plan) : {}
          process = spawn_gated_workload(sandbox, container, spec, command, resolved_rootfs, hook_options)
          prepare_gated_workload(sandbox, container, spec, process)
          run_hooks(hooks, Hooks::RUNTIME_CREATE + Hooks::IN_CONTAINER, hook_plan, pid: process.pid) if hook_plan && !hooks_in_child
          started = @process_supervisor.release_gate(process)
          gate_released = true
          running = record_started_container(sandbox, container, request, started)
          if hook_plan
            started_process = started.to_h
            run_post_hooks(sandbox, running, hooks, hook_plan, "poststart", pid: started_process["workload_pid"] || started_process["pid"])
          end
          running
        rescue StandardError => error
          abandon_failed_start(sandbox, container, request, process, error)
          raise FailClosed, "container start failed before workload gate release: #{error.message}"
        ensure
          # A forked workload waiting on its gate must never outlive a start
          # that did not release it.  The rescue above covers exceptions, but
          # a pod worker killed or timed out mid-start (Thread#kill, Timeout)
          # unwinds through ensure only -- and left a pre-exec child sleeping
          # on the gate for good: a full copy of the agent (2.7 GB RSS)
          # parked in select for 40 hours on worker-1.
          stop_ungated_process(process) if process && !gate_released
        end

        # What the supervisor's child needs to run the in-container hook
        # stages itself and to call back for the runtime-namespace ones.
        def child_hook_options(hooks, hook_plan)
          {
            container_hooks: {
              "hooks" => hooks.slice(*Hooks::IN_CONTAINER), "state" => hook_plan[:state],
              "runtime" => ->(pid) { run_hooks(hooks, Hooks::RUNTIME_CREATE, hook_plan, pid: pid) }
            }
          }
        end

        def spawn_gated_workload(sandbox, container, spec, command, rootfs, hook_options)
          @process_supervisor.spawn(
            command: command,
            env: spec["env"] || {},
            cwd: spec["cwd"],
            rootfs: rootfs,
            mounts: rootfs ? Array(spec["mounts"]) : [],
            security_plan: container.security_plan,
            namespace: sandbox.namespace,
            resource_id: "process:#{sandbox.id}:#{container.id}",
            id: "process-#{sandbox.id}-#{container.id}",
            cgroup: container.cgroup,
            # v1.Container stdin: without it the process reads /dev/null.
            stdin: spec["stdin"] == true,
            **hook_options
          )
        end

        def prepare_gated_workload(sandbox, container, spec, process)
          # Attach the wrapper before releasing the gate.  The production
          # ProcessGateAdapter forks the final workload only after the gate;
          # cgroup inheritance therefore places the actual workload in this
          # exact cgroup before its first instruction executes.
          @cgroup.attach(container.cgroup, pid: process.pid) if container.cgroup
          apply_oom_score_adj(process, spec)
          record_oom_baseline(sandbox, container)
          @security.apply(container.security_plan, probe: @security_probe) unless @process_supervisor.security_applied_in_child?
        end

        def record_started_container(sandbox, container, request, started)
          # release_gate returns only once the bootstrap's close-on-exec status
          # pipe reached EOF, which happens exactly when execve succeeded: the
          # interpreter's pages are gone and what remains charged to this
          # cgroup is the workload itself.
          apply_deferred_memory_limits(sandbox, container)
          running = sandbox.update_container(container, process: started, state: :running)
          operation = @ledger.operation(sandbox.id)
          process_hash = started.to_h
          process_identity = process_identity_for(sandbox, container, process_hash)
          claim(operation, kind: "process", id: container_resource_id(sandbox, container), identity: process_identity,
                           metadata: process_hash.merge("managed_by" => "rubernetes-native", "live" => true))
          if sandbox.state == :workload_stopped
            sandbox.transition(:running)
            @ledger.transition(operation_id: sandbox.id, to: "Running") if operation&.state == "WorkloadStopped"
          end
          complete_native_request(request, state: "Completed", result: {
                                    "container_id" => running.id, "process_id" => process_identity
                                  })
          record(:container_started, sandbox_id: sandbox.id, container_id: running.id,
                                     pid: process_hash["workload_pid"] || process_hash["pid"],
                                     wrapper_pid: process_hash["pid"])
          running
        end

        def abandon_failed_start(sandbox, container, request, process, error)
          @process_supervisor.stop(process, timeout: 1.0) if process
          begin
            operation = @ledger.operation(sandbox.id)
            release_ledger_claim(operation, "process", container_resource_id(sandbox, container)) if operation
          rescue StandardError => ledger_error
            record(:container_start_ledger_cleanup_error, sandbox_id: sandbox.id, container_id: container.id,
                                                          error: "#{ledger_error.class}: #{ledger_error.message}")
          end
          complete_native_request(request, state: "Failed", error: error_payload(error)) unless error.is_a?(RecoveryRequired)
        end

        # The last line of defence against a child parked on its gate.  By
        # now the process has usually been stopped already (the failure path
        # ran first) or cannot be signalled or waited for any more; neither
        # may replace the failure that is unwinding, or interrupt a killed
        # worker on its way out.
        def stop_ungated_process(process)
          @process_supervisor.stop(process, timeout: 1.0)
        rescue *PROCESS_ERRORS
          nil
        end

        def workload_rootfs(sandbox, spec, container: nil)
          return nil unless config.host_profile?
          return nil unless spec["rootfs_path"] || spec[:rootfs_path]

          root = (container && container.workspace&.root) || sandbox.workspace&.root
          raise FailClosed, "resolved image rootfs is unavailable at workload start" unless root && File.directory?(root) && !File.symlink?(root)

          root
        end

        # runc's process.oomScoreAdj: set on the gated wrapper, which the
        # workload is forked from after the gate, so it inherits the value.
        def apply_oom_score_adj(process, spec)
          value = spec["oom_score_adj"] || spec[:oom_score_adj]
          return if value.nil? || process.pid.nil?

          path = "/proc/#{Integer(process.pid)}/oom_score_adj"
          return unless File.exist?(path)

          File.write(path, Integer(value).clamp(-1000, 1000).to_s)
        rescue SystemCallError, IOError => error
          record(:oom_score_adj_failed, pid: process.pid, error: "#{error.class}: #{error.message}")
        end
      end
    end
  end
end
