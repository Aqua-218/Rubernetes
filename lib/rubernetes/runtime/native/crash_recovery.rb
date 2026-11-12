# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      # Recovery after an agent restart: compares the durable ledger with an
      # external observation of the kernel, quiesces what a dead operation
      # left running, re-adopts the sandboxes whose every identity still
      # matches, and hands the rest to Support::Recovery.  Nothing is guessed:
      # a mismatched identity is never signalled, adopted or cleaned.
      module CrashRecovery
        RECOVERY_CANDIDATE_STATES = %w[StateUnknown RollingBack CleanupPending].freeze
        RECOVERY_STOP_TIMEOUT_SECONDS = 10

        def recover(observer: nil, cleaner: nil, orphan_predicate: nil)
          # A post-crash in-memory inventory is not evidence of kernel state.
          # Recovery may release durable ownership only when an external/native
          # observer was explicitly wired (or supplied for this invocation).
          observer ||= @adapters[:observer]
          raise RecoveryRequired, "native runtime recovery requires an explicit resource observer" unless observer
          raise RecoveryRequired, "native runtime recovery requires an external resource observer" if in_process_observer?(observer)

          cleaner ||= @adapters[:cleaner] || method(:cleanup_resource)
          observed_snapshot = normalize_inventory(invoke_observer(observer))
          mark_dead_operations_for_recovery!(observed_snapshot)
          observed_snapshot = quiesce_dead_operations!(observed_snapshot, observer)
          reconstruct_sandboxes_from_observed!(observed_snapshot)
          recovery = Support::Recovery.new(
            ledger: ledger,
            observer: -> { observed_snapshot },
            cleaner: ->(resource) { invoke_cleaner(cleaner, resource) },
            orphan_predicate: orphan_predicate
          )
          result = recovery.reconcile
          record(:recovery, result: result.to_h)
          result
        end

        private

        # A complete external inventory can prove that a durable operation lost
        # one of its exact kernel identities, or that the identity remains but
        # is dead.  Persist StateUnknown before cleanup so Recovery can release
        # only the resources from that operation.  Identity mismatches are not
        # downgraded to death: they remain fatal evidence of possible PID/path
        # reuse and are never cleaned automatically.
        def mark_dead_operations_for_recovery!(observed)
          observed_by_key = observed.to_h { |entry| [resource_key(entry), entry] }
          @ledger.operations.each do |operation|
            state = String(operation.fetch("state") { operation[:state] })
            next if %w[RollingBack CleanupPending StateUnknown Stopped Removed].include?(state)

            owner = String(operation.fetch("owner") { operation[:owner] })
            resources = normalize_inventory(@ledger.resources(owner: owner, include_released: false))
            # A key collision with a different durable identity/owner on a
            # path-like resource (inode, namespace link) is reuse evidence: the
            # operation is not downgraded to a cleanup candidate; Recovery
            # surfaces the mismatch and refuses deletion.  A *process* whose pid
            # now carries another start time or executable is proof that ours
            # exited (the kernel reused the pid): the operation is dead and the
            # claim is released without ever signalling the stranger.
            identity_mismatch = resources.any? do |resource|
              observed_resource = observed_by_key[resource_key(resource)]
              observed_resource && resource["kind"] != "process" &&
                (observed_resource["identity"] != resource["identity"] ||
                 observed_resource["owner"] != resource["owner"])
            end
            next if identity_mismatch

            dead = resources.any? do |resource|
              observed_resource = observed_by_key[resource_key(resource)]
              observed_resource.nil? ||
                (resource["kind"] == "process" && observed_resource["identity"] != resource["identity"]) ||
                (observed_resource["identity"] == resource["identity"] &&
                 observed_resource["owner"] == resource["owner"] &&
                 observed_resource.dig("metadata", "live") == false)
            end
            @ledger.transition(operation_id: operation.fetch("id") { operation[:id] }, to: "StateUnknown") if dead
          end
          true
        end

        # A dead operation (its sandbox lost a namespace, a veth, a mount) may
        # still have live containers; kubelet kills the containers of a broken
        # sandbox and lets the Pod be recreated.  Stop every process Recovery
        # would otherwise refuse to touch ("live or liveness is unknown"), but
        # only after re-verifying it is ours (pid + start time + executable
        # digest through ProcessSupervisor#adopt), kill the populated cgroups
        # the same way, then observe again so the cleanup sees dead resources.
        # A pid whose identity no longer matches is never signalled.
        def quiesce_dead_operations!(observed, observer)
          observed_by_key = observed.to_h { |entry| [resource_key(entry), entry] }
          quiesced = []
          @ledger.operations.each do |operation|
            state = String(operation.fetch("state") { operation[:state] })
            next unless RECOVERY_CANDIDATE_STATES.include?(state)

            owner = String(operation.fetch("owner") { operation[:owner] })
            resources = normalize_inventory(@ledger.resources(owner: owner, include_released: false))
            resources.sort_by { |resource| resource["kind"] == "process" ? 0 : 1 }.each do |resource|
              next unless observed_live_and_ours?(observed_by_key[resource_key(resource)], resource)

              quiesced << resource_key(resource) if quiesce_resource(resource)
            end
          end
          return observed if quiesced.empty?

          record(:recovery_quiesced, resources: quiesced)
          normalize_inventory(invoke_observer(observer))
        end

        def observed_live_and_ours?(observed_resource, resource)
          return false unless observed_resource
          return false unless observed_resource["identity"] == resource["identity"] && observed_resource["owner"] == resource["owner"]

          observed_resource.dig("metadata", "live") == true
        end

        # True when the resource was stopped or killed; a kind that holds no
        # running code, or a failed attempt (recorded), is false.
        def quiesce_resource(resource)
          case resource["kind"]
          when "process" then stop_recovered_process(resource)
          when "cgroup" then kill_recovered_cgroup(resource)
          else return false
          end
          true
        rescue StandardError => error
          record(:recovery_quiesce_failed, resource: resource_key(resource), error: error_payload(error))
          false
        end

        def stop_recovered_process(resource)
          metadata = resource.fetch("metadata", {}).merge("id" => resource.fetch("id"))
          handle = @process_supervisor.handles.values.find { |entry| entry.id.to_s == resource.fetch("id") } ||
                   @process_supervisor.adopt(metadata: metadata)
          @process_supervisor.stop(handle, timeout: RECOVERY_STOP_TIMEOUT_SECONDS, resource_id: "process:#{resource.fetch("id")}")
          @process_supervisor.close(handle)
        end

        def kill_recovered_cgroup(resource)
          metadata = resource.fetch("metadata", {})
          handle = @cgroup.lookup(metadata["path"] || resource.fetch("id"))
          raise Platform::Linux::CgroupV2::Error, "cgroup #{resource_key(resource)} identity changed" unless handle.identity == resource.fetch("identity")

          @cgroup.kill(handle)
        end

        # Rebuild only resources whose durable identity is present in the
        # external kernel inventory.  Missing or mismatched resources are left
        # to Recovery, which can release ledger ownership only after the same
        # identity checks; it never guesses a replacement PID, mount, or cgroup.
        def reconstruct_sandboxes_from_observed!(observed)
          return true unless namespace_adoption_supported?

          observed_by_key = observed.to_h { |entry| [resource_key(entry), entry] }
          @ledger.operations.each do |operation|
            state = String(operation.fetch("state") { operation[:state] })
            next if state == "Removed"

            sandbox_id = String(operation.fetch("id") { operation[:id] })
            next if @mutex.synchronize { @sandboxes.key?(sandbox_id) }

            owner = String(operation.fetch("owner") { operation[:owner] })
            resources = @ledger.resources(owner: owner, include_released: false).map { |resource| normalize_hash(resource) }
            sandbox_resources = resources.select do |resource|
              metadata = resource["metadata"] || {}
              resource_id = resource["id"].to_s
              resource_id == sandbox_id || resource_id.start_with?("#{sandbox_id}:") || metadata["parent"].to_s == sandbox_id
            end
            next if sandbox_resources.empty?
            next unless sandbox_resources.all? do |resource|
              observed_resource = observed_by_key[resource_key(resource)]
              observed_resource && observed_resource["identity"] == resource["identity"] && observed_resource.dig("metadata", "live") != false
            end

            reconstruct_one_sandbox!(operation, sandbox_resources)
          end
          true
        rescue StandardError => error
          raise RecoveryRequired, "native startup reconstruction failed closed: #{error.message}"
        end

        def reconstruct_one_sandbox!(operation, resources)
          sandbox_id = String(operation.fetch("id") { operation[:id] })
          owner = String(operation.fetch("owner") { operation[:owner] })
          workspace_resource = resources.find { |resource| resource["kind"] == "workspace" && resource["id"] == sandbox_id }
          namespace_resource = resources.find { |resource| resource["kind"] == "namespace" && resource["id"] == sandbox_id }
          cgroup_resource = resources.find { |resource| resource["kind"] == "cgroup" && resource["id"] == sandbox_id }
          return unless workspace_resource && namespace_resource && cgroup_resource

          namespace = adopt_namespace(sandbox_id, namespace_resource)
          cgroup = adopt_cgroup(cgroup_resource)
          workspace = adopt_workspace(workspace_resource, namespace)
          sandbox = Sandbox.new(id: sandbox_id, identity: owner, config: {}, clock: @clock)
          sandbox.set_resources(namespace: namespace, workspace: workspace, cgroup: cgroup)

          container_cgroups = resources.select do |resource|
            resource["kind"] == "cgroup" && resource["id"].to_s.start_with?("#{sandbox_id}:")
          end
          process_resources = resources.select do |resource|
            resource["kind"] == "process" && resource["id"].to_s.start_with?("#{sandbox_id}:")
          end
          container_cgroups.each do |resource|
            process_resource = process_resources.find { |candidate| candidate["id"] == resource["id"] }
            reconstruct_container!(sandbox, resource, process_resource)
          end
          restore_sandbox_state!(sandbox, String(operation.fetch("state") { operation[:state] }))
          @mutex.synchronize { @sandboxes[sandbox_id] = sandbox }
        end

        def adopt_namespace(sandbox_id, namespace_resource)
          namespace_metadata = namespace_resource.fetch("metadata")
          plan_data = namespace_metadata.fetch("plan")
          plan = Namespace::Plan.new(
            namespaces: Array(plan_data.fetch("namespaces")).map(&:to_sym).freeze,
            shared: Array(plan_data.fetch("shared", [])).map(&:to_sym).freeze,
            host: Array(plan_data.fetch("host", [])).map(&:to_sym).freeze,
            user_mapping: plan_data["user_mapping"], hostname: plan_data["hostname"]
          )
          @namespace.adopt(id: sandbox_id, identity: namespace_resource.fetch("identity"),
                           plan: plan, metadata: namespace_metadata)
        end

        def adopt_workspace(workspace_resource, namespace)
          workspace_data = workspace_resource.fetch("metadata")
          workspace_fields = %w[id root upper work identity image_digest].to_h do |field|
            [field.to_sym, workspace_data.fetch(field)]
          end
          workspace = Filesystem::Workspace.new(**workspace_fields)
          @filesystem.adopt(workspace, namespace: namespace, metadata: workspace_resource.fetch("metadata", {}))
          workspace
        end

        # One container of a reconstructed sandbox, from its cgroup claim (the
        # durable spec) and, when it was running, its process claim.
        def reconstruct_container!(sandbox, resource, process_resource)
          container_id = resource.fetch("id").to_s.delete_prefix("#{sandbox.id}:")
          process_metadata = process_resource && process_resource.fetch("metadata")
          container_metadata = resource.fetch("metadata", {})
          persisted_spec = container_metadata["spec"]
          raise RecoveryRequired, "container #{sandbox.id}:#{container_id} has no durable spec" unless mapping?(persisted_spec)

          spec = persisted_spec.to_h.transform_keys(&:to_s).merge("id" => container_id)
          spec["command"] = Array(process_metadata["command"]) if process_metadata && process_metadata["command"]
          container = sandbox.create_container(spec: spec, id: container_id)
          container_cgroup = adopt_cgroup(resource)
          security_context = container_security_context(spec)
          security_plan, = security_plan_for(security_context)
          process = (@process_supervisor.adopt(metadata: process_metadata, cgroup: container_cgroup) if process_metadata)
          sandbox.update_container(container, cgroup: container_cgroup,
                                              process: process,
                                              security_plan: security_plan,
                                              state: process ? :running : :created)
        end

        def adopt_cgroup(resource)
          metadata = resource.fetch("metadata")
          path = metadata.fetch("path")
          handle = @cgroup.lookup(path)
          unless handle.identity == resource.fetch("identity")
            raise RecoveryRequired,
                  "cgroup #{resource_key(resource)} identity changed during adoption"
          end

          expected_inode = metadata["cgroup_inode"] || metadata["cgroup_id"]
          if expected_inode
            actual_inode = File.stat(handle.path).ino
            unless actual_inode == Integer(expected_inode)
              raise RecoveryRequired,
                    "cgroup #{resource_key(resource)} kernel identity changed during adoption"
            end
          end

          handle
        end

        def restore_sandbox_state!(sandbox, state)
          target = state.to_s.downcase.to_sym
          return if target == :new

          if target == :state_unknown
            sandbox.transition(:state_unknown)
            return
          end
          if target == :cleanup_pending
            sandbox.transition(:state_unknown)
            sandbox.transition(:cleanup_pending)
            return
          end
          base_states = %i[validated image_pinned workspace_allocated isolation_created resources_attached workload_stopped]
          base_states.each do |step|
            sandbox.transition(step)
            break if step == target
          end
          return if sandbox.state == target

          case target
          when :running
            sandbox.transition(:running)
          when :stopping
            sandbox.transition(:running)
            sandbox.transition(:stopping)
          when :stopped
            sandbox.transition(:rolling_back)
            sandbox.transition(:stopped)
          when :rolling_back
            sandbox.transition(:rolling_back)
          else
            raise RecoveryRequired, "unsupported sandbox state #{state.inspect} during reconstruction"
          end
        end
      end
    end
  end
end
