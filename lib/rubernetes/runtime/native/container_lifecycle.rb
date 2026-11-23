# frozen_string_literal: true

require_relative "../../container_stop_signals"

module Rubernetes
  module Runtime
    class Native
      # Container lifecycle around the start (see ContainerStart): creating a
      # container with its cgroup, device filter and root filesystem, stopping
      # and removing it, and reporting its status and exit.  Every operation
      # is an idempotent request in the ledger.
      module ContainerLifecycle
        EXIT_WAIT_SLICE = 0.1
        RUNNING_EXIT_STATUS = {"state" => "running", "exitCode" => nil}.freeze

        def create_container(sandbox_value, spec, id: nil, request_id: nil)
          sandbox = sandbox(sandbox_value)
          raise InvalidState, "container creation requires a WorkloadStopped or Running sandbox" unless %i[workload_stopped running].include?(sandbox.state)

          input = resolve_container_spec(normalize_hash(spec), sandbox: sandbox)
          command = input["command"] || input[:command] || input["argv"] || input[:argv]
          validate_command!(command) if command
          input["mounts"] = normalize_mounts(input["mounts"] || input[:mounts]) if input["mounts"] || input[:mounts]
          # Container ids are node-unique (kubelet/CRI semantics): a bare
          # "container-1" repeated in every sandbox let a log or exec request
          # for one Pod reach another Pod's container.
          # Never derive the id from the LIVE COUNT: a restart removes the old
          # container first, so the count falls back and the new container takes
          # the removed one's id -- and with it the removed one's create-request
          # identity in the ledger, which answered the retry with a container
          # that no longer exists ("unknown container ...").  The sandbox's own
          # sequence only moves forward.
          container_id = String(id || input["id"] || input[:id] || sandbox.next_container_id)
          request = request_id || input["request_id"] || input[:request_id] || "create:#{sandbox.id}:#{container_id}"
          request_state = begin_native_request(request, operation: "container.create", input: {
                                                 "sandbox_id" => sandbox.id, "container_id" => container_id, "spec" => input
                                               })
          if request_state&.state == "Completed"
            recorded_id = request_state.result.is_a?(Hash) ? (request_state.result["container_id"] || request_state.result[:container_id]) : nil
            return sandbox.container(recorded_id || container_id)
          end

          build_container(sandbox, input, container_id, request)
        end

        def stop_container(value, timeout: 5.0, request_id: nil, release_process: true)
          sandbox, container = find_container(value)
          container.exit_lock.synchronize do
            stop_current_container(sandbox, sandbox.container(container.id), timeout: timeout, request_id: request_id, release_process: release_process)
          end
        end

        def stop_current_container(sandbox, container, timeout:, request_id:, release_process:)
          request = request_id || "stop:#{sandbox.id}:#{container.id}"
          request_state = begin_native_request(request, operation: "container.stop", input: {
                                                 "sandbox_id" => sandbox.id, "container_id" => container.id, "timeout" => timeout
                                               })
          return sandbox.container(container.id) if request_state&.state == "Completed"

          if container.state == :stopped
            complete_native_request(request, state: "Completed", result: {"container_id" => container.id, "state" => "stopped"})
            return container
          end
          unless container.process
            # A container that did start and then lost its process handle may
            # still be running: that stays fail-closed and goes to recovery.
            if container_started?(sandbox, container)
              error = InvalidState.new("container #{container.id} has not started")
              complete_native_request(request, state: "Failed", error: error_payload(error))
              raise error
            end

            # Nothing has ever run under this id, so there is nothing to stop
            # yet -- but a container created moments before its start may be
            # started right after this call.  Recording either a failure or a
            # success would settle the request forever and make every later stop
            # replay that verdict, so the pod could never reach a terminal
            # phase.  Leave it replayable, exactly as a pending cleanup is.
            complete_native_request(request, state: "CleanupPending")
            return container
          end

          stop_container_process(sandbox, container, request, timeout: timeout, release_process: release_process)
        end
        private :stop_current_container

        def remove_container(value, request_id: nil, preserve_logs: false)
          begin
            sandbox, container = find_container(value)
          rescue Error
            # CRI RemoveContainer is idempotent: "This call is idempotent, and
            # must not return an error if the container has already been
            # removed" (cri-api runtime.proto).  Treating a container that is
            # already gone as a cleanup failure left the Pod in CleanupPending,
            # which stops the final delete: the Pod stayed Terminating in the API
            # for ever and every spec that waits for it to disappear timed out.
            return true
          end
          request = request_id || "remove:#{sandbox.id}:#{container.id}"
          request_state = begin_native_request(request, operation: "container.remove", input: {
                                                 "sandbox_id" => sandbox.id, "container_id" => container.id
                                               })
          return true if request_state&.state == "Completed"

          begin
            release_container(sandbox, container, request, preserve_logs: preserve_logs)
            complete_native_request(request, state: "Completed", result: {"container_id" => container.id, "removed" => true})
            true
          rescue StandardError => error
            mark_container_cleanup_pending(sandbox, container, operation: @ledger.operation(sandbox.id), error: error)
            complete_native_request(request, state: "CleanupPending", error: error_payload(error)) unless error.is_a?(RecoveryRequired)
            raise
          end
        end

        def container_status(value)
          sandbox, container = find_container(value)
          # A workload that exits on its own is still recorded as running until
          # someone reaps it.  Status is where that is noticed: without this the
          # runtime reports a finished container as running forever, so its Pod
          # never reaches a confirmed stop and the node re-creates it on every
          # sync.  A non-blocking wait is proof of exit, never a guess.
          reap_exited(sandbox, container)
          sandbox, container = find_container(value)
          status = container.to_h.merge("oom_killed" => @mutex.synchronize { @oom_reported.key?(container_resource_id(sandbox, container)) })
          status["stopSignal"] = effective_stop_signal(container.spec).first
          if container.state == :stopped && container.process
            process = container.process
            exit_code = process.exit_status
            exit_code = 128 + Integer(process.term_signal) if exit_code.nil? && process.term_signal
            status["exitCode"] = exit_code
            status["terminated"] = {"exitCode" => exit_code, "signal" => process.term_signal,
                                    "reason" => status["oom_killed"] ? "OOMKilled" : nil}.compact
          end
          status
        end

        def container_stop_signal(value)
          _sandbox, container = find_container(value)
          effective_stop_signal(container.spec).first
        end

        # Status must stay readable whatever the reap runs into -- the
        # container or its handle went away under the query, the process
        # cannot be waited for, the ledger refuses the release: the next
        # status query, or the stop that follows, meets the same condition on
        # a path that reports it.
        def reap_exited(sandbox, container)
          return unless container.state == :running && container.process

          try_wait_for_container_exit(sandbox, container, timeout: 0)
        rescue Error, Support::Error, *PROCESS_ERRORS
          nil
        end

        def wait_container(value, timeout: nil)
          sandbox, container = find_container(value)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + Float(timeout) unless timeout.nil?
          loop do
            remaining = deadline ? [deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC), 0.0].max : EXIT_WAIT_SLICE
            result = try_wait_for_container_exit(sandbox, container, timeout: [remaining, EXIT_WAIT_SLICE].min)
            return result if result && result["state"] == "terminated"
            return RUNNING_EXIT_STATUS if deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

            # An explicit wait must leave another thread a chance to stop the
            # workload. The relist only ever tries to take the lock.
            result ? Thread.pass : sleep([remaining, 0.01].min)
          end
        end

        def try_wait_for_container_exit(sandbox, container, timeout:)
          return unless container.exit_lock.try_lock

          begin
            wait_for_container_exit(sandbox, sandbox.container(container.id), timeout: timeout)
          ensure
            container.exit_lock.unlock
          end
        end
        private :try_wait_for_container_exit

        def wait_for_container_exit(sandbox, container, timeout:)
          if container.state == :stopped && (process = container.process)
            oom_killed = @mutex.synchronize { @oom_reported.key?(container_resource_id(sandbox, container)) }
            return container_exit(process.exit_status, process.term_signal, oom_killed ? "OOMKilled" : nil)
          end

          raise InvalidState, "wait requires a running container" unless container.state == :running

          process = container.process
          raise InvalidState, "container #{container.id} has no process handle" unless process

          result = @process_supervisor.wait(process, timeout: timeout, resource_id: "process:#{sandbox.id}:#{container.id}")
          return RUNNING_EXIT_STATUS unless result

          oom_reason = detect_oom(sandbox, container)
          # The container keeps the handle that carries the exit: the
          # supervisor's own copy is closed below, and status readers (the node's
          # relist, stop confirmation) need the exit code afterwards.
          exited = process.with(state: :stopped, exit_status: result.exit_status, term_signal: result.term_signal)
          stopped = sandbox.update_container(container, state: :stopped, process: exited)
          process_hash = process.to_h
          operation = @ledger.operation(sandbox.id)
          release_process_resource(operation, sandbox, stopped, process_hash)
          @process_supervisor.close(process)
          status = container_exit(result.exit_status, result.term_signal, oom_reason)
          record(:container_waited, sandbox_id: sandbox.id, container_id: stopped.id, exit_code: status["exitCode"], reason: oom_reason)
          status
        end
        private :wait_for_container_exit

        def container_exit(exit_status, signal, reason)
          exit_code = exit_status.nil? ? (128 + Integer(signal) if signal) : Integer(exit_status)
          {"state" => "terminated", "exitCode" => exit_code, "signal" => signal, "reason" => reason}.freeze
        end
        private :container_exit

        private

        # OCI image StopSignal takes effect unless the Pod supplies an override.
        # Linux uses the libc range (34..64) for named real-time signals.
        def effective_stop_signal(spec)
          if (custom = spec["stop_signal"])
            number = linux_signal_number(custom) if ContainerStopSignals.cri_name(custom)
            return [custom, number] if number
          end

          image = spec.dig("resolved_image", "config", "config", "StopSignal").to_s.upcase
          unless image.empty?
            if /\A[0-9]+\z/.match?(image)
              number = Integer(image, 10)
              if number.between?(1, 64)
                name = ContainerStopSignals::LINUX.find { |candidate| linux_signal_number(candidate) == number }
                return [name, number]
              end
            else
              name = image.start_with?("SIG") ? image : "SIG#{image}"
              number = linux_signal_number(name)
              return [name, number] if number&.positive?
            end
          end
          ["SIGTERM", Signal.list.fetch("TERM")]
        end

        def linux_signal_number(name)
          case name
          when "SIGSTKFLT" then 16
          when "SIGRTMIN" then 34
          when "SIGRTMAX" then 64
          when /\ASIGRTMIN\+(\d+)\z/ then 34 + Integer(Regexp.last_match(1), 10) if ContainerStopSignals.cri_name(name)
          when /\ASIGRTMAX-(\d+)\z/ then 64 - Integer(Regexp.last_match(1), 10) if ContainerStopSignals.cri_name(name)
          else Signal.list[name.delete_prefix("SIG")]
          end
        end

        # Builds the created container's resources in acquisition order and
        # records the answer to the create request; a failure at any step
        # gives back what was acquired before it is reported.
        def build_container(sandbox, input, container_id, request)
          container = nil
          cgroup = nil
          container = sandbox.create_container(spec: input, id: container_id)
          qos = sandbox.cgroup&.qos || normalize_qos(sandbox.config)
          limits = container_cgroup_limits(input, qos: qos, pod: sandbox.config)
          cgroup = create_container_cgroup(sandbox, container, qos, limits)
          plan, plan_digest = security_plan_for(container_security_context(input))
          attach_device_filter(sandbox, container, cgroup, input, plan)
          # Every container gets its own root filesystem from its own image.
          # The sandbox workspace overlays *all* of the Pod's images into one
          # tree, so a Pod mixing images (agnhost + a glibc image) ran each
          # container on a union where the busybox `sh` met the wrong
          # dynamic loader: "No such file or directory - execveat".
          workspace = prepare_container_workspace(sandbox, container, input)
          result = sandbox.update_container(container, cgroup: cgroup, security_plan: plan, workspace: workspace)
          record(:container_created, sandbox_id: sandbox.id, container_id: result.id, qos: qos, limits: limits)
          claim_container_cgroup(sandbox, result, limits, plan_digest)
          complete_native_request(request, state: "Completed", result: {"container_id" => result.id})
          result
        rescue StandardError => error
          discard_failed_container(sandbox, container, container_id, cgroup)
          complete_native_request(request, state: "Failed", error: error_payload(error)) unless error.is_a?(RecoveryRequired)
          raise
        end

        def create_container_cgroup(sandbox, container, qos, limits)
          # The memory ceiling is applied once the workload has replaced the
          # bootstrap; see #apply_deferred_memory_limits.
          initial_limits = defer_bootstrap_limits(container_resource_id(sandbox, container), limits)
          leaf = sandbox.cgroup_container_id(container.id)
          @cgroup.create(qos: qos, pod_id: sandbox.id,
                         container_id: leaf, identity: "cgroup:#{sandbox.id}:#{leaf}",
                         limits: (initial_limits.empty? ? nil : initial_limits),
                         **sandbox_cgroup_path_options(sandbox))
        end

        def claim_container_cgroup(sandbox, container, limits, plan_digest)
          operation = @ledger.operation(sandbox.id)
          claim(operation, kind: "cgroup", id: container_resource_id(sandbox, container), identity: container.cgroup.identity,
                           # The spec is what startup reconstruction rebuilds the
                           # container from; the security plan is derived from it again
                           # there (reconstruct_one_sandbox!), so only its digest is
                           # recorded: the plan itself (the whole capability probe) was
                           # 22 KB per claim and most of the journal.
                           metadata: container.cgroup.to_h.merge(
                             "container_id" => container.id,
                             "limits" => limits,
                             "spec" => container.spec,
                             "security_context" => container_security_context(container.spec),
                             "security_plan_digest" => plan_digest
                           ))
        end

        # Undoes a create that failed part-way: the cgroup (and its device
        # filter), the sandbox's record of the container, and the cgroup claim.
        # Each step is attempted whatever became of the one before; the
        # caller re-raises the failure that brought it here.
        def discard_failed_container(sandbox, container, container_id, cgroup)
          begin
            detach_device_filter(sandbox, container_id, cgroup) if cgroup
            @cgroup.remove(cgroup, force: true) if cgroup
          rescue StandardError => cleanup_error
            record(:container_create_cleanup_error, sandbox_id: sandbox.id, container_id: container_id,
                                                    error: "#{cleanup_error.class}: #{cleanup_error.message}")
          end
          begin
            sandbox.remove_container(container) if container && container.state != :running
          rescue Sandbox::Error
            # Already gone from the sandbox.
            nil
          end
          begin
            operation = @ledger.operation(sandbox.id)
            release_ledger_claim(operation, "cgroup", container_resource_id(sandbox, container)) if operation && container
          rescue StandardError => ledger_error
            record(:container_create_ledger_cleanup_error, sandbox_id: sandbox.id, container_id: container_id,
                                                           error: "#{ledger_error.class}: #{ledger_error.message}")
          end
        end

        def stop_container_process(sandbox, container, request, timeout:, release_process:)
          _, signal = effective_stop_signal(container.spec)
          result = @process_supervisor.stop(container.process, timeout: timeout, signal: signal,
                                                               resource_id: "process:#{sandbox.id}:#{container.id}")
          oom_reason = detect_oom(sandbox, container)
          @cgroup.kill(container.cgroup) if container.cgroup
          process_hash = container.process.to_h
          @process_supervisor.close(container.process)
          process = container.process.with(state: :stopped, exit_status: result.exit_status, term_signal: result.term_signal)
          stopped = sandbox.update_container(container, state: :stopped, process: process)
          operation = @ledger.operation(sandbox.id)
          release_process_resource(operation, sandbox, stopped, process_hash) if release_process
          complete_native_request(request, state: "Completed",
                                           result: {"container_id" => stopped.id, "state" => "stopped", "reason" => oom_reason}.compact)
          record(:container_stopped, sandbox_id: sandbox.id, container_id: stopped.id, reason: oom_reason)
          stopped
        rescue StandardError => error
          complete_native_request(request, state: "Failed", error: error_payload(error)) unless error.is_a?(RecoveryRequired)
          raise
        end

        # Gives back everything a container holds, in the reverse of the
        # order it was acquired; any step that fails leaves the rest claimed
        # for the retry.
        def release_container(sandbox, container, request, preserve_logs:)
          stop_container(container, request_id: "#{request}:stop") if container.state == :running
          process_hash = container.process.to_h
          @process_supervisor.close(container.process) if container.process
          if container.cgroup
            detach_device_filter(sandbox, container.id, container.cgroup)
            removed = @cgroup.remove(container.cgroup, force: false)
            raise ResourceError, "container cgroup cleanup returned false" if removed == false
          end
          run_poststop_hooks(sandbox, container)
          if container.workspace
            cleaned = @filesystem.cleanup(container.workspace)
            raise ResourceError, "container workspace cleanup returned false" if cleaned == false
          end
          operation = @ledger.operation(sandbox.id)
          release_container_resource(operation, sandbox, container, process_hash)
          remove_container_logs(sandbox.id, [container.id]) unless preserve_logs
          sandbox.remove_container(container)
        end

        def prepare_container_workspace(sandbox, container, input)
          return nil unless config.host_profile?

          image_root = input["rootfs_path"] || input[:rootfs_path]
          return nil if image_root.to_s.empty? || sandbox.workspace.nil?

          resolved = input["resolved_image"] || input[:resolved_image]
          digest = if resolved.is_a?(Hash) &&
                      (resolved["digest"] || resolved[:digest])
                     resolved["digest"] || resolved[:digest]
                   else
                     sandbox.workspace.image_digest
                   end
          identifier = "#{sandbox.id}.#{container.id}"
          namespace_spec = namespace_spec_for(sandbox.config, sandbox.identity)
          workspace = @filesystem.prepare(id: identifier, image_digest: digest, lowerdirs: [image_root],
                                          read_only: read_only_root_filesystem?(input),
                                          owner: workspace_owner_for(namespace_spec))
          operation = @ledger.operation(sandbox.id)
          claim(operation, kind: "workspace", id: identifier, identity: workspace.identity, metadata: workspace_metadata(workspace))
          @filesystem.activate(workspace, namespace: sandbox.namespace) if sandbox.namespace
          claim(operation, kind: "workspace", id: identifier, identity: workspace.identity, metadata: workspace_metadata(workspace))
          workspace
        end

        # The ledger, not the in-memory handle, is the durable record of whether
        # a container ever had a process: after a restart the handle is gone
        # while the workload may not be.
        def container_started?(sandbox, container)
          started = @ledger.request("start:#{sandbox.id}:#{container.id}")
          return false if started.nil?

          ledger_value(started, :state).to_s == "Completed"
        rescue ArgumentError
          # An id the ledger will not look up cannot prove the container never
          # ran: stay fail-closed.
          true
        end

        def find_container(value)
          # One lookup per sandbox, no exception per miss: with a node full of
          # Pods the old rescue-driven scan raised once per sandbox for every
          # status query.
          if container_reference?(value)
            @sandboxes.each_value do |sandbox|
              found = sandbox.container_if_present(value.id)
              return [sandbox, found] if found
            end
          end
          id = reference_id(value)
          @mutex.synchronize do
            @sandboxes.each_value do |sandbox|
              found = sandbox.container_if_present(id)
              return [sandbox, found] if found
            end
          end
          raise Error, "unknown container #{id}"
        end
      end
    end
  end
end
