# frozen_string_literal: true

require_relative "../native_observer"

module Rubernetes
  module Network
    class Interface
      # A failed ADD has a durable failure result only after the independently
      # observed kernel effects and all sandbox-owned references are gone.
      module AddRollback
        private

        # A saved fd number is meaningful only inside the transaction that
        # opened it. Recovery has no fresh lease for a failed native ADD.
        def unverified_add_rollbacks(records)
          return [] unless @require_observer

          records.filter_map do |record|
            next unless record["state"] == "unknown" && record["effect_intent"] && record.dig("error", "rollback_errors")

            record.fetch("id")
          end
        end

        def retained_add_allocations(unverified)
          unverified.empty? ? {} : {retained_operations: unverified}
        end

        def failed_add_recovery_error(id)
          {"component" => "failed_add_rollback", "operation_id" => id,
           "error" => "retained unverified ADD; recovery requires a fresh namespace lease or confirmed sandbox teardown"}
        end

        def rollback_failed_add(operation_id, error, resources:, leases:, namespace_lease:, rollback_plan:, bridge_plan:, sysctl_acquired:)
          operation = @mutex.synchronize { operation_for_id(operation_id) }
          sandbox_id = operation.fetch("sandbox_id")
          failures = []
          rollback_step(failures, "topology") { @topology.rollback(rollback_plan, operation_id: operation_id) } if rollback_plan

          attempted = !operation["effect_cursor"].nil?
          proof = if @require_observer && attempted && failures.empty?
                    rollback_step(failures, "kernel verification") { verify_add_rollback(operation, namespace_lease) }
                  end

          # A native ADD whose effects cannot be accounted for must retain
          # its allocation and claims. Never let the next Pod take that IP.
          if proof || !@require_observer || (!attempted && rollback_plan.nil?)
            rollback_step(failures, "IPAM") { @ipam&.release(leases, operation_id: operation_id, stopped: true) }
            rollback_step(failures, "bridge") { @topology.release_bridge(bridge_plan, owner: sandbox_id) } if bridge_plan
            rollback_step(failures, "sysctl") { @sysctl_manager.release(owner: sandbox_id, operation_id: operation_id) } if sysctl_acquired
            release_resources(operation.merge("resources" => resources), force: true, errors: failures)
            rollback_step(failures, "release verification") { verify_add_releases(operation) } if proof && failures.empty?
          end

          failure = {"class" => error.class.name, "message" => error.message, "rollback_errors" => failures}
          if proof && failures.empty?
            result = {"sandbox_id" => sandbox_id, "operation_id" => operation_id, "state" => "removed"}
            operation = update_operation(operation_id, "state" => "removed", "result" => result, "error" => failure,
                                                       "resources" => [], "effect_intent" => nil, "rollback_verified" => proof)
            @mutex.synchronize { prune_removed_operations! }
          else
            operation = update_operation(operation_id, "state" => "unknown", "resources" => resources, "error" => failure)
          end
          raise_failed_add(operation, cause: error)
        end

        def rollback_step(failures, component)
          yield
        rescue StandardError => error
          failures << "#{component}: #{error.class}: #{error.message}"
          false
        end

        def raise_failed_add(operation, cause: nil)
          failure = operation.fetch("error")
          errors = failure.fetch("rollback_errors")
          detail = errors.empty? ? "" : " (rollback: #{errors.join("; ")})"
          raise EffectError.new("network add failed for sandbox #{operation.fetch("sandbox_id")}: #{failure.fetch("message")}#{detail}",
                                operation: operation.fetch("id"), cause_error: cause)
        end

        def verify_add_rollback(operation, lease)
          unless @store && @observer.is_a?(NativeObserver) && @observer.external_observer?
            raise OwnershipError, "failed ADD lacks durable intent or independent kernel readback"
          end

          saved = @durable_state.fetch("operations").fetch(operation.fetch("id"))
          raise OwnershipError, "network effect intent is not durable" unless saved == operation

          plan = plan_from_record(saved.fetch("plan"))
          metadata = plan.metadata
          host_inode = File.stat(Netlink::THREAD_NAMESPACE_PATH).ino
          unless host_inode == saved.fetch("host_netns_inode") && metadata.fetch("sandbox_id") == saved.fetch("sandbox_id")
            raise OwnershipError, "failed ADD host namespace or sandbox does not match the durable plan"
          end

          verify_rollback_namespace!(metadata, lease, host_inode)
          effects, pending = attempted_veth_effects(saved, plan, lease.fileno)
          verify_rolled_back_effects!(saved, effects, metadata, lease, host_inode)
          {"host_netns_inode" => host_inode, "netns_inode" => lease.inode,
           "effect_cursor" => saved.fetch("effect_cursor"), "applied_count" => saved.fetch("applied_count"),
           "effect_intent" => pending}
        end

        def verify_rollback_namespace!(metadata, lease, host_inode)
          unless lease && !lease.closed? && lease.inode != host_inode &&
                 metadata.values_at("netns_handle", "netns_pid", "netns_pidfd", "netns_start_time", "netns_inode", "namespace_fd") ==
                 [lease.handle, lease.pid, lease.pidfd, lease.start_time, lease.inode, lease.fileno] &&
                 File.stat("/proc/self/fd/#{lease.fileno}").ino == lease.inode
            raise OwnershipError, "failed ADD namespace no longer matches its pinned lease"
          end
        end

        def attempted_veth_effects(operation, plan, namespace_fd)
          cursor = operation.fetch("effect_cursor")
          applied = operation.fetch("applied_count")
          unless cursor.is_a?(Integer) && cursor.between?(0, plan.operations.length - 1) && [cursor, cursor + 1].include?(applied)
            raise OwnershipError, "failed ADD cursor is inconsistent with its durable plan"
          end

          effects = plan.operations.take(cursor + 1)
          pending = operation.fetch("effect_intent")
          unless pending == effects.last.to_h && private_veth_effects?(effects, plan.metadata, namespace_fd)
            raise OwnershipError, "failed ADD includes a kernel effect outside its provable veth scope"
          end

          [effects, pending]
        end

        def private_veth_effects?(effects, metadata, namespace_fd)
          host, peer = metadata.values_at("host_ifname", "pod_ifname")
          return false unless host && peer

          first, *remaining = effects
          parameters = first.parameters
          return false unless first.action == "link_add" && parameters.values_at("kind", "name", "peer", "namespace_fd") ==
                                                            ["veth", host, peer, namespace_fd]

          remaining.all? do |effect|
            params = effect.parameters
            case effect.action
            when "link_set"
              params.values_at("name", "namespace_fd", "namespace") == [host, nil, nil] ||
                params.values_at("name", "namespace_fd") == [peer, namespace_fd]
            when "address_add", "route_add"
              params.values_at("interface", "namespace_fd") == [peer, namespace_fd]
            else
              false
            end
          end
        end

        def verify_rolled_back_effects!(operation, effects, metadata, lease, host_inode)
          host_links = @observer.resources(kinds: ["link"])
          pod_resources = @observer.netlink.with_namespace(lease.fileno, operation: "failed_network_add_readback") do
            raise OwnershipError, "failed ADD observer entered the wrong namespace" unless File.stat(Netlink::THREAD_NAMESPACE_PATH).ino == lease.inode

            @observer.resources(kinds: %w[link address route])
          end
          scopes = {host_inode => host_links, lease.inode => pod_resources}
          scope_names = {host_inode => metadata.fetch("host_ifname"), lease.inode => metadata.fetch("pod_ifname")}
          claims = operation.fetch("resources")
          if claims.any? { |resource| !scopes.key?(resource.dig("metadata", "netns_inode")) }
            raise OwnershipError, "failed ADD has a claim outside its verified namespaces"
          end

          scopes.each do |inode, entries|
            names = scope_names.fetch(inode)
            owned = claims.select { |resource| resource.dig("metadata", "netns_inode") == inode }
            if entries.any? { |entry| entry.dig("metadata", "netns_inode") != inode || rollback_resource_present?(entry, names, owned) }
              raise OwnershipError, "failed ADD still has a kernel resource in namespace #{inode}"
            end
          end

          return unless pod_resources.any? { |entry| effects.any? { |effect| rollback_effect_present?(effect, entry) } }

          raise OwnershipError, "failed ADD address or route is still present in the pinned namespace"
        end

        # Unlike successful ADD readback, this inventory includes tentative
        # and DAD-failed addresses.
        def rollback_effect_present?(effect, entry)
          params = effect.parameters
          metadata = entry.fetch("metadata")
          case [effect.action, entry.fetch("kind")]
          when %w[address_add address]
            metadata.values_at("address", "prefix") == params.values_at("address", "prefix")
          when %w[route_add route]
            fields = %w[destination table metric protocol scope route_type]
            metadata.values_at(*fields) == params.values_at(*fields) && metadata["gateway"] == params["via"]
          else
            false
          end
        end

        def rollback_resource_present?(entry, name, claims)
          observed = entry.fetch("metadata")
          return true if observed["ifname"] == name

          claims.any? do |claim|
            entry.fetch("identity") == claim.fetch("identity") ||
              (entry.fetch("kind") == "link" && observed["ifindex"] == claim.dig("metadata", "ifindex"))
          end
        end

        def verify_add_releases(operation)
          id = operation.fetch("id")
          sandbox_id = operation.fetch("sandbox_id")
          if @ipam
            lease_operation = @ipam.operations.find { |entry| entry.fetch("operation_id") == id }
            unless lease_operation && lease_operation.values_at("state", "sandbox_id", "config_digest") ==
                                      ["released", sandbox_id, operation.fetch("config_digest")] &&
                   @ipam.leases(operation_id: id).empty?
              raise OwnershipError, "failed ADD IPAM allocation is not confirmed released"
            end
          end
          bridge = operation.dig("plan", "metadata", "bridge")
          raise OwnershipError, "failed ADD still owns a bridge reference" if @topology.bridge_manager.referenced_by?(bridge, sandbox_id)

          if @sysctl_manager
            sysctls = @sysctl_manager.snapshot
            unless %w[active inactive].include?(sysctls.fetch("state")) && !sysctls.fetch("owners").include?(sandbox_id)
              raise OwnershipError, "failed ADD still owns a sysctl reference"
            end
          end
          verify_add_ledger_release(operation) if @ledger
        end

        def verify_add_ledger_release(operation)
          id = operation.fetch("id")
          owner = operation.fetch("owner")
          held = @ledger.operation(id)
          unless held && held.owner == owner && @ledger.resources(owner: owner, include_released: false).empty?
            raise OwnershipError, "failed ADD still has unconfirmed ledger claims"
          end

          finish_resource_operation(id)
          return if @ledger.operation(id)&.state == "Removed"

          raise OwnershipError, "failed ADD ledger operation is not finished"
        end
      end
    end
  end
end
