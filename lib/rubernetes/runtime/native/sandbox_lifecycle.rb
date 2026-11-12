# frozen_string_literal: true

require "digest"
require "fileutils"
require "securerandom"

module Rubernetes
  module Runtime
    class Native
      # Sandbox lifecycle: creates a Pod sandbox effect by effect (workspace,
      # namespaces, cgroup) with every step claimed in the ledger and the
      # workload gate closed, then stops and removes it again.
      module SandboxLifecycle
        # Creates all sandbox resources while keeping the workload gate closed.
        # No process is started before the returned sandbox reaches
        # WorkloadStopped and a container explicitly calls start_container.
        def run_sandbox(sandbox_config = {}, runtime_class: nil, request_id: nil, id: nil, **options)
          runtime_class ||= config.runtime_class
          validate_runtime_class!(runtime_class)
          input = normalize_hash(sandbox_config)
          input.merge!(normalize_hash(options))
          request = String(request_id || input["request_id"] || input[:request_id] || id || "request-#{SecureRandom.hex(12)}")
          replayed = replayed_sandbox_id(request)
          return replayed if replayed

          input = resolve_images(input)
          # QoS is derived from the Pod spec exactly once (v1.36.2
          # ComputePodQOS) and pinned into the config so replays and the
          # container cgroup path agree on the class.
          input["qos"] = normalize_qos(input)
          validate_sandbox_input!(input)
          durable = durable_sandbox_id(request, input)
          return durable if durable

          sandbox_id = String(id || input["id"] || input[:id] || generated_sandbox_id(input))
          identity = "sandbox:#{sandbox_id}:#{Digest::SHA256.hexdigest(sandbox_id)[0, 16]}"
          sandbox = register_sandbox(sandbox_id, identity, input, request)
          operation = @ledger.begin_operation(operation_id: sandbox_id, owner: identity,
                                              config_digest: digest(input), request_id: request)

          advance(sandbox, operation, :validated)
          image_digest = pin_image(input)
          advance(sandbox, operation, :image_pinned)
          namespace_spec = allocate_sandbox_workspace(sandbox, operation, input, image_digest)
          create_sandbox_isolation(sandbox, operation, input, namespace_spec)
          attach_sandbox_resources(sandbox, operation, input)

          advance(sandbox, operation, :workload_stopped)
          record(:workload_gate_closed, sandbox_id: sandbox_id)
          sandbox_id
        rescue StandardError => error
          rollback_sandbox(sandbox, operation, original_error: error) if sandbox && operation
          raise
        end

        def stop_sandbox(value, timeout: 5.0)
          sandbox = sandbox(value)
          operation = @ledger.operation(sandbox.id) || raise(Error, "sandbox operation is missing")
          return stop_idle_sandbox(sandbox, operation, "CleanupPending") if sandbox.state == :cleanup_pending
          return stop_idle_sandbox(sandbox, operation, "WorkloadStopped") if sandbox.state == :workload_stopped

          sandbox.transition(:stopping) if sandbox.state == :running
          # RuntimeLifecycle.tla BeginStopping: Running -> Stopping records
          # liveProcess = FALSE with ownership unchanged.  The durable Stopping
          # transition is therefore written only after every workload process
          # has been confirmed dead (supervisor wait/pidfd), and the process
          # ledger claims stay owned until cleanup releases them in Stopped
          # (CleanupOne).  A crash between the kill and this record leaves the
          # ledger in Running with a dead process, which recovery resolves
          # through StateUnknown -> Stopping exactly as the model does.
          sandbox.containers.each do |container_hash|
            container_id = container_hash.fetch("id")
            container = sandbox.container(container_id)
            stop_container(container, timeout: timeout, release_process: false) if container.state == :running
          end
          current_operation = @ledger.operation(sandbox.id)
          @ledger.transition(operation_id: sandbox.id, to: "Stopping") if current_operation&.state == "Running"
          sandbox.transition(:stopped) if %i[stopping workload_stopped rolling_back].include?(sandbox.state)
          current_operation = @ledger.operation(sandbox.id)
          @ledger.transition(operation_id: sandbox.id, to: "Stopped") if current_operation && %w[Stopping RollingBack].include?(current_operation.state)
          record(:sandbox_stopped, sandbox_id: sandbox.id)
          true
        rescue Sandbox::Error => error
          raise InvalidState, error.message
        rescue StandardError => error
          mark_cleanup_pending(sandbox, operation, error)
          raise
        end

        def remove_sandbox(value)
          sandbox = begin
            sandbox(value)
          rescue Error => error
            # The sandbox is no longer known because an earlier removal finished
            # (the ledger records it Removed): removing it again is a no-op,
            # not a failure to retry for ever.
            return true if sandbox_removed?(value)

            raise error
          end
          stop_sandbox(sandbox) unless %i[stopped removed].include?(sandbox.state)
          return true if sandbox.state == :removed

          operation = @ledger.operation(sandbox.id) || raise(Error, "sandbox operation is missing")
          run_owed_poststop_hooks(sandbox)
          cleanup_sandbox_resources(sandbox, operation) unless sandbox.resources_cleaned?
          sandbox.transition(:removed)
          @ledger.transition(operation_id: sandbox.id, to: "Removed") unless operation.state == "Removed"
          @mutex.synchronize { @sandboxes.delete(sandbox.id) }
          remove_sandbox_logs(sandbox)
          record(:sandbox_removed, sandbox_id: sandbox.id)
          true
        end

        # True when the ledger's operation for this sandbox reached Removed.
        def sandbox_removed?(value)
          operation = @ledger.operation(String(reference_id(value)))
          !operation.nil? && operation.state.to_s == "Removed"
        rescue TypeError
          # A value that cannot name a sandbox names no removed one either.
          false
        end

        # kubelet removes /var/log/pods/<ns>_<name>_<uid> with the Pod; the
        # supervisor's per-container log directories (one per container id,
        # so a restarted container's predecessor keeps its own until here)
        # were kept for ever: 346 directories per worker after one round.
        # Every container of this sandbox is stopped and removed by now.
        def remove_sandbox_logs(sandbox)
          return unless config.log_root

          # Exact names, no glob: a glob over a log root holding hundreds of
          # directories was 4% of teardown CPU on its own.
          sandbox.container_ids_ever.each do |container_id|
            directory = File.join(config.log_root, "process-#{sandbox.id}-#{container_id}")
            FileUtils.rm_rf(directory) if File.directory?(directory)
          end
        rescue StandardError => error
          record(:sandbox_log_cleanup_error, sandbox_id: sandbox.id, error: "#{error.class}: #{error.message}")
        end

        def sandbox(value)
          id = reference_id(value)
          @mutex.synchronize { @sandboxes.fetch(String(id)) { raise Error, "unknown sandbox #{id}" } }
        end

        def network_sandbox_context(value)
          sandbox(value).network_sandbox_context
        end

        def sandboxes
          @mutex.synchronize { @sandboxes.values.map(&:to_h).freeze }
        end

        private

        # The sandbox a retried request already produced in this process, or
        # nil for a request seen for the first time.
        def replayed_sandbox_id(request)
          existing_id = @mutex.synchronize { @requests[request] }
          return nil unless existing_id

          existing = @mutex.synchronize { @sandboxes[existing_id] }
          return nil unless existing
          if %i[cleanup_pending state_unknown rolling_back stopping].include?(existing.state)
            raise RecoveryRequired, "request #{request} is waiting for durable recovery (#{existing.state})"
          end

          existing_id
        end

        # The sandbox the ledger recorded for this request before a restart,
        # or nil when the request has no durable operation.  A recorded
        # operation that cannot be answered from the ledger alone is never
        # re-executed: it goes to recovery.
        def durable_sandbox_id(request, input)
          durable = @ledger.operation_for_request(request)
          return nil unless durable

          durable_config_digest = ledger_value(durable, :config_digest)
          raise OwnershipConflict, "request #{request} was replayed with different intent" unless durable_config_digest == digest(input)

          durable_result = ledger_value(durable, :result)
          durable_id = (durable_result["sandbox_id"] || durable_result[:sandbox_id] if durable_result.is_a?(Hash))
          durable_id ||= ledger_value(durable, :target_id)
          durable_id ||= ledger_value(durable, :id)
          durable_state = ledger_value(durable, :state)
          if %w[StateUnknown CleanupPending].include?(durable_state)
            raise RecoveryRequired, "request #{request} is waiting for durable recovery (#{durable_state})"
          end
          unless durable_id && %w[WorkloadStopped Running Stopping Stopped Removed].include?(durable_state)
            raise RecoveryRequired, "request #{request} has a durable operation without a replayable result"
          end

          @mutex.synchronize { @requests[request] = durable_id }
          durable_id
        end

        def register_sandbox(sandbox_id, identity, input, request)
          sandbox = Sandbox.new(id: sandbox_id, identity: identity, config: immutable(input), clock: @clock)
          @mutex.synchronize do
            raise Error, "sandbox #{sandbox_id} already exists" if @sandboxes.key?(sandbox_id)

            @sandboxes[sandbox_id] = sandbox
            @requests[request] = sandbox_id
          end
          sandbox
        end

        # First effect: the workspace.  Returns the namespace spec the
        # isolation step creates the holder from.
        def allocate_sandbox_workspace(sandbox, operation, input, image_digest)
          # The user-namespace range is allocated before the first filesystem
          # effect so the workspace can be owned by the Pod's mapped root.
          namespace_spec = namespace_spec_for(input, sandbox.identity)
          workspace_owner = workspace_owner_for(namespace_spec)
          workspace = @filesystem.prepare(id: sandbox.id, image_digest: image_digest, lowerdirs: input["lowerdirs"] || input[:lowerdirs] || [],
                                          read_only: input["read_only_root_filesystem"] == true, owner: workspace_owner)
          claim(operation, kind: "workspace", id: sandbox.id, identity: workspace.identity,
                           metadata: workspace_metadata(workspace))
          sandbox.set_resources(workspace: workspace)
          advance(sandbox, operation, :workspace_allocated)
          namespace_spec
        end

        # Second effect: the namespace holder, the workspace mounted inside
        # it, and the sandbox's security plan.
        def create_sandbox_isolation(sandbox, operation, input, namespace_spec)
          namespace = @namespace.create(id: sandbox.id, spec: namespace_spec, identity: "namespace:#{sandbox.id}")
          claim(operation, kind: "namespace", id: sandbox.id, identity: namespace.identity, metadata: namespace.to_h)
          sandbox.set_resources(namespace: namespace)
          workspace = sandbox.workspace
          @filesystem.activate(workspace, namespace: namespace)
          # Refresh the claim after activation.  A mount syscall return value is
          # not a stable ownership proof; the adapter must read back mount ID,
          # target, and filesystem from the holder namespace before we persist
          # the workspace as owned.
          claim(operation, kind: "workspace", id: sandbox.id, identity: workspace.identity,
                           metadata: workspace_metadata(workspace))
          security_plan, = security_plan_for(input["security_context"] || input[:security_context] || config.security_context)
          sandbox.set_resources(security_plan: security_plan)
          record(:isolation_created, sandbox_id: sandbox.id, namespace: namespace.to_h, security_steps: security_plan.step_names.map(&:to_s))
          advance(sandbox, operation, :isolation_created)
        end

        # Third effect: the Pod cgroup.
        def attach_sandbox_resources(sandbox, operation, input)
          limits = input["limits"] || input[:limits] || config.limits
          pod_limits = pod_cgroup_limits(input)
          # The Pod ceiling constrains the container cgroups nested under it, so
          # it is deferred for the same reason the container ceiling is: the
          # bootstrap that sets up the first container lives in that hierarchy
          # and allocates while it works.  See #apply_deferred_memory_limits.
          initial_pod_limits = defer_bootstrap_limits("pod:#{sandbox.id}", normalize_hash(pod_limits))
          # Creation, delegation, and limit application are one adapter call so
          # a rejected limit rolls the directory back before it can be claimed.
          cgroup = @cgroup.create(qos: normalize_qos(input), pod_id: sandbox.id, container_id: "sandbox",
                                  identity: "cgroup:#{sandbox.id}",
                                  limits: (limits.nil? || limits.empty? ? nil : limits),
                                  pod_limits: (initial_pod_limits.empty? ? nil : initial_pod_limits))
          claim(operation, kind: "cgroup", id: sandbox.id, identity: cgroup.identity,
                           metadata: cgroup.to_h.merge("pod_limits" => pod_limits, "qos" => normalize_qos(input)))
          sandbox.set_resources(cgroup: cgroup)
          record(:resources_attached, sandbox_id: sandbox.id, cgroup: cgroup.to_h)
          advance(sandbox, operation, :resources_attached)
        end

        # A sandbox with no running workload skips Stopping: its resources
        # are rolled back directly from the ledger state it rests in.
        def stop_idle_sandbox(sandbox, operation, resting_state)
          sandbox.transition(:rolling_back)
          @ledger.transition(operation_id: sandbox.id, to: "RollingBack") if operation.state == resting_state
          cleanup_sandbox_resources(sandbox, operation)
          sandbox.transition(:stopped)
          @ledger.transition(operation_id: sandbox.id, to: "Stopped") if @ledger.operation(sandbox.id)&.state == "RollingBack"
          record(:sandbox_stopped, sandbox_id: sandbox.id)
          true
        end

        # Containers removed with their sandbox are deleted here: their
        # poststop hooks run now (remove_container already ran the others').
        # A hook is a warning at most, and a container that vanished meanwhile
        # owes none; neither may keep the sandbox from being removed.
        def run_owed_poststop_hooks(sandbox)
          sandbox.containers.each do |container_hash|
            run_poststop_hooks(sandbox, sandbox.container(container_hash.fetch("id")))
          rescue Error, Hooks::Error, SystemCallError, IOError, JSON::JSONError
            nil
          end
        end

        # The pod cgroup directory is named after the sandbox, and kubelet names
        # it after the Pod UID (cgroupfs "pod<uid>", systemd "kubepods-pod<uid>
        # .slice"); tooling -- the in-place resize conformance suite among it --
        # finds a Pod's cgroup by searching for its UID.
        def generated_sandbox_id(input)
          metadata = input["metadata"] || input[:metadata]
          uid = metadata.is_a?(Hash) ? (metadata["uid"] || metadata[:uid]).to_s : ""
          return "pod#{uid}-#{SecureRandom.hex(6)}" if uid.match?(/\A[A-Za-z0-9-]{1,64}\z/)

          "sandbox-#{SecureRandom.hex(12)}"
        end

        # hostUsers=false receives a durable, non-overlapping 65,536 ID range
        # bound to the sandbox identity before the holder is created (§5.8.6).
        def namespace_spec_for(input, identity)
          spec = input["namespace"] || input[:namespace] || input
          return spec unless @namespace.user_namespace_required?(spec)

          mapping = userns_allocator.allocate(identity)
          normalized = normalize_hash(spec)
          normalized["uid_base"] = mapping.uid_base
          normalized["gid_base"] = mapping.gid_base
          normalized
        end

        def workspace_owner_for(namespace_spec)
          return nil unless namespace_spec.is_a?(Hash) && namespace_spec.key?("uid_base")

          [Integer(namespace_spec.fetch("uid_base")), Integer(namespace_spec.fetch("gid_base"))]
        end

        def userns_allocator
          @userns_allocator ||= if config.pure_profile?
                                  Platform::Linux::UserNamespace::Allocator.new(path: File.join(Dir.tmpdir,
                                                                                                "rubernetes-pure-userns-#{Process.pid}.json"))
                                else
                                  Platform::Linux::UserNamespace::Allocator.new(path: config.userns_allocation_path)
                                end
        end

        def release_user_namespace_range(sandbox)
          return true unless sandbox.namespace.plan.user_mapping

          userns_allocator.release(sandbox.identity)
        rescue Platform::Linux::UserNamespace::Error => error
          raise ResourceError, "user namespace range release failed: #{error.message}"
        end

        # Adapter-owned metadata (mount ID, cgroup inode, and similar kernel
        # identities) is kept alongside the portable workspace descriptor.  A
        # restart must be able to verify those identities before reusing a path.
        def workspace_metadata(workspace)
          workspace.to_h.merge(@filesystem.resource_metadata(workspace))
        end

        def advance(sandbox, operation, target)
          state_name = target.to_s.split("_").map(&:capitalize).join
          sandbox.transition(target)
          @ledger.transition(operation_id: operation.id, to: state_name)
          record(target, sandbox_id: sandbox.id)
          invoke_effect_hook(target, sandbox, operation) if EFFECT_POINTS.include?(target.to_sym)
        end

        # Fault/crash probes observe only fully durable effect boundaries.  The
        # hook runs after both the in-memory state and the fsynced ownership WAL
        # transition agree, so a blocked or raised hook cannot fabricate a state
        # that recovery would not replay after process death.
        def invoke_effect_hook(effect_point, sandbox, operation)
          hook = @adapters[:effect_hook]
          return true unless hook

          transition = @ledger.journal.last
          hook.call(
            effect_point: effect_point.to_s,
            sandbox: sandbox,
            operation: @ledger.operation(operation.id),
            transition: transition.to_h
          )
          true
        end
      end
    end
  end
end
