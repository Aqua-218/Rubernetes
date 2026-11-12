# frozen_string_literal: true

# Resolving operations whose outcome was lost (ledger status "unknown") from
# what recovery observed: the driver's volumes and snapshots and the kernel's
# mounts.  Each operation is either completed, classified retryable, or left
# fenced because nothing authoritative was observed.
module Rubernetes
  module Volume
    class Manager
      module OperationResolution
        private

        def reconcile_unknown_operations(csi_volume_entries:, snapshot_entries:, observations:, errors:)
          volumes = index_csi_entries(csi_volume_entries, "volumeId")
          snapshots = index_csi_entries(
            snapshot_entries && AdapterSupport.result_hash(snapshot_entries)["entries"], "snapshotId"
          )
          mounts = Array(observations).each_with_object({}) do |entry, result|
            hash = Capability.hash_like?(entry) ? entry.to_h.transform_keys(&:to_s) : entry
            target = hash && (hash["target"] || hash["mountpoint"])
            result[File.expand_path(target.to_s)] = hash if Types.present?(target)
          end
          resolved = []
          operations.unknown_entries.each do |entry|
            outcome = resolve_unknown_operation(entry, volumes: volumes, snapshots: snapshots, mounts: mounts,
                                                       csi_observed: !csi_volume_entries.nil?,
                                                       snapshots_observed: !snapshot_entries.nil?)
            resolved << {"key" => entry.key, "operation" => entry.operation, "outcome" => outcome} if outcome
          rescue StandardError => error
            errors << {"kind" => "operation-resolve", "key" => entry.key,
                       "operation" => entry.operation, "error" => redact_secret_text(error.message.to_s)}
          end
          resolved
        end

        def resolve_unknown_operation(entry, volumes:, snapshots:, mounts:, csi_observed:, snapshots_observed:)
          payload = entry.payload || {}
          record = volume_store[entry.key]
          case entry.operation
          when "create" then resolve_unknown_create(entry, record, volumes, csi_observed)
          when "delete" then resolve_unknown_delete(entry, record, volumes, csi_observed)
          when /\Acontroller-publish:/ then resolve_unknown_controller_publish(entry, record, payload, volumes, csi_observed)
          when /\Acontroller-unpublish:/ then resolve_unknown_controller_unpublish(entry, record, payload, volumes, csi_observed)
          when "expand" then resolve_unknown_expand(entry, record, payload, csi_observed)
          when "snapshot" then resolve_unknown_snapshot(entry, record, payload, snapshots, snapshots_observed)
          when "delete-snapshot" then resolve_unknown_delete_snapshot(entry, payload, snapshots, snapshots_observed)
          else
            # Mountinfo can describe the local effect, but a failed CSI
            # observation still cannot authorize follow-up NodeExpand or local
            # unfencing of a remote operation.
            return nil if record&.backend.to_s.casecmp?("csi") && !csi_observed

            resolve_unknown_node_operation(entry, record, payload, mounts)
          end
        end

        # -- controller operations ---------------------------------------------

        def resolve_unknown_create(entry, record, volumes, csi_observed)
          # A failed ListVolumes observation is not permission to replay a
          # mutating CSI RPC.  Keep the operation and record Unknown until a
          # later recovery pass has authoritative driver state.
          return nil unless record&.backend.to_s == "csi" && csi_observed

          backend = backends.fetch(record.id)
          driver_id = csi_driver_id(record)
          result = if driver_id && volumes.key?(driver_id)
                     volumes.fetch(driver_id)
                   else
                     backend.provision(token: entry.token)
                   end
          durable_result = sanitize_for_persistence(result)
          durable_spec = record.spec.merge("backendResult" => durable_result)
          volume_store[record.id] = record.with(state: "Provisioned", spec: durable_spec,
                                                operation: nil, generation: record.generation + 1)
          backends[record.id] = build_backend(record.id, durable_spec)
          finish_resolved_operation(entry, record.id)
        end

        def resolve_unknown_delete(entry, record, volumes, csi_observed)
          return nil unless record && csi_observed

          driver_id = csi_driver_id(record)
          if driver_id && !volumes.key?(driver_id)
            mount_ledger.remove_volume(record.id)
            volume_store.delete(record.id)
            backends.delete(record.id)
            forget_csi_secrets(record.id)
            finish_resolved_operation(entry, true)
          else
            resolve_operation_as_retryable(entry, record, "CSI volume still exists after DeleteVolume")
          end
        end

        def resolve_unknown_controller_publish(entry, record, payload, volumes, csi_observed)
          return nil unless record && csi_observed

          node = Types.key(payload, "node") || entry.operation.split(":", 3)[1]
          observed = volumes[csi_driver_id(record)]
          published_nodes = csi_published_nodes(observed)
          if published_nodes && !published_nodes.include?(node.to_s)
            return resolve_operation_as_retryable(entry, record,
                                                  "CSI volume is not published to #{node}")
          end

          backend = backends.fetch(record.id)
          context = context_for_node(record, node, {})
          result = sanitize_for_persistence(AdapterSupport.result_hash(backend.attach(node: node, context: context)))
          attachments = Types.deep_copy(record.attachments)
          attachments[node.to_s] = {
            "node" => node.to_s, "pods" => [],
            "publishContext" => Types.deep_copy(result["publishContext"] || {}),
            "volumeContext" => Types.deep_copy(context["volumeContext"] || {}),
            "accessModes" => Types.deep_copy(context["accessModes"] || []),
            "volumeMode" => context["volumeMode"].to_s,
            "backendResult" => sanitize_for_persistence(result)
          }
          volume_store[record.id] = record.with(state: "Attached", attachments: attachments,
                                                operation: nil, generation: record.generation + 1)
          finish_resolved_operation(entry, sanitize_for_persistence(result))
        end

        def resolve_unknown_controller_unpublish(entry, record, payload, volumes, csi_observed)
          return nil unless record && csi_observed

          node = Types.key(payload, "node") || entry.operation.split(":", 3)[1]
          observed = volumes[csi_driver_id(record)]
          published_nodes = csi_published_nodes(observed)
          if published_nodes.nil? || published_nodes.include?(node.to_s)
            backends.fetch(record.id).detach(node: node,
                                             context: context_for_node(record, node,
                                                                       {}))
          end
          attachments = Types.deep_copy(record.attachments)
          attachments.delete(node.to_s)
          state = attachments.empty? && record.stages.empty? ? "Detached" : restored_state(record, "Attached")
          volume_store[record.id] = record.with(state: state, attachments: attachments,
                                                operation: nil, generation: record.generation + 1)
          finish_resolved_operation(entry, true)
        end

        def resolve_unknown_expand(entry, record, payload, csi_observed)
          return nil unless record && csi_observed

          desired = Types.parse_capacity(Types.key(payload, "capacity"))
          expansion = backends.fetch(record.id).expand(capacity_bytes: desired, token: entry.token,
                                                       node_paths: expansion_paths(record))
          record = record_expansion_result(record, expansion)
          result = Types.key(expansion, "capacityBytes", desired)
          volume_store[record.id] = record.with(state: restored_state(record, "Provisioned"), capacity_bytes: desired,
                                                operation: nil, generation: record.generation + 1)
          finish_resolved_operation(entry, result)
        end

        def resolve_unknown_snapshot(entry, record, payload, snapshots, snapshots_observed)
          return nil unless record && snapshots_observed

          name = Types.key(payload, "name")
          existing = snapshot_manager.list.find do |snapshot|
            snapshot.source_id == record.id && (name.nil? || snapshot.name.to_s == name.to_s) && snapshots.key?(snapshot.id)
          end
          existing ||= snapshot_manager.create(record.id, token: entry.token, name: name)
          restore_known_record(record, default_state: "Provisioned")
          finish_resolved_operation(entry, existing.id)
        end

        def resolve_unknown_delete_snapshot(entry, payload, snapshots, snapshots_observed)
          snapshot_id = Types.key(payload, "snapshotId") || entry.key.delete_prefix("snapshot-")
          return nil unless snapshots_observed

          if snapshots.key?(snapshot_id.to_s)
            snapshot = snapshot_manager.store[snapshot_id.to_s]
            return nil unless snapshot

            backends.fetch(snapshot.source_id).delete_snapshot(snapshot_id, token: entry.token)
          end
          snapshot_manager.store.delete(snapshot_id.to_s)
          finish_resolved_operation(entry, true)
        end

        # -- node operations ---------------------------------------------------

        def resolve_unknown_node_operation(entry, record, payload, mounts)
          return nil unless record

          target = Types.key(payload, "path", Types.key(payload, "target"))
          target = File.expand_path(target.to_s) if Types.present?(target)
          observed = target && mounts[target]
          case entry.operation
          when /\Astage:/ then adopt_observed_stage(entry, record, payload, target, observed)
          when /\Apublish:/ then adopt_observed_publish(entry, record, payload, target, observed)
          when /\Aunpublish:/ then observed ? nil : confirm_unpublished(entry, record, payload, target)
          when /\Aunstage:/ then observed ? nil : confirm_unstaged(entry, record, target)
          end
        end

        def adopt_observed_stage(entry, record, payload, target, observed)
          return resolve_operation_as_retryable(entry, record, "stage mount is absent") unless observed
          return nil if unsafe_lease_observation?(entry)

          result = sanitize_for_persistence(observed).merge("target" => target, "node" => Types.key(payload, "node").to_s)
          record = expand_node_after_adoption(entry, record, target)
          register_mount_identity(volume_id: record.id, identity: result, target: target,
                                  owner: "volume:#{record.id}", stage_path: target,
                                  generation: record.generation, secret: false)
          stages = Types.deep_copy(record.stages).merge(target => result)
          volume_store[record.id] = record.with(state: "Staged", stages: stages, operation: nil,
                                                generation: record.generation + 1)
          finish_resolved_operation(entry, result)
        end

        def adopt_observed_publish(entry, record, payload, target, observed)
          return resolve_operation_as_retryable(entry, record, "published mount is absent") unless observed
          return nil if unsafe_lease_observation?(entry)

          pod = Types.key(payload, "pod").to_s
          result = sanitize_for_persistence(observed).merge("target" => target, "pod" => pod,
                                                            "node" => Types.key(payload, "node").to_s)
          record = expand_node_after_adoption(entry, record, target)
          stage_path = record.stages.values.first && record.stages.values.first["target"]
          register_mount_identity(volume_id: record.id, identity: result, target: target,
                                  owner: "pod:#{pod}", stage_path: stage_path,
                                  generation: record.generation, secret: false)
          publishes = Types.deep_copy(record.publishes).merge("#{pod}\0#{target}" => result)
          volume_store[record.id] = record.with(state: "Published", publishes: publishes, operation: nil,
                                                generation: record.generation + 1)
          finish_resolved_operation(entry, result)
        end

        def confirm_unpublished(entry, record, payload, target)
          pod = Types.key(payload, "pod").to_s
          publishes = Types.deep_copy(record.publishes)
          removed = publishes.delete("#{pod}\0#{target}")
          mount_ledger.remove(identity: mount_ledger.identity_for(removed), expected: removed) if removed
          state = publishes.empty? ? "Staged" : "Published"
          volume_store[record.id] = record.with(state: state, publishes: publishes, operation: nil,
                                                generation: record.generation + 1)
          finish_resolved_operation(entry, true)
        end

        def confirm_unstaged(entry, record, target)
          stages = Types.deep_copy(record.stages)
          removed = stages.delete(target)
          mount_ledger.remove(identity: mount_ledger.identity_for(removed), expected: removed) if removed
          state = record.attachments.empty? ? "Detached" : "Attached"
          volume_store[record.id] = record.with(state: state, stages: stages, operation: nil,
                                                generation: record.generation + 1)
          finish_resolved_operation(entry, true)
        end

        # An adopted CSI mount still owes the NodeExpandVolume a controller
        # expansion left pending.  Returns the (possibly updated) record.
        def expand_node_after_adoption(entry, record, target)
          return record unless backends.fetch(record.id).is_a?(RemoteBackend) && node_expansion_required?(record)

          backends.fetch(record.id).expand_node(path: target, capacity_bytes: record.capacity_bytes,
                                                token: "#{entry.token}:node-expand")
          record_node_expanded(record, target)
        end

        # A post-effect lease verification failure can leave a real mount
        # reachable only through the old descriptor path. After restart that fd
        # no longer exists, so adopting a same-path observation would turn an
        # unproven rename/replacement into durable ownership. Keep the operation
        # fenced until an operator or a later authoritative observation resolves
        # it; an absent mount remains safe to classify as retryable above.
        def unsafe_lease_observation?(entry)
          details = entry.error
          details = Capability.hash_like?(details) ? details.to_h : {}
          nested = details["details"] || details[:details] || details
          Capability.hash_like?(nested) &&
            Types.present?(nested["leaseIdentity"] || nested[:lease_identity])
        end

        # -- outcomes ----------------------------------------------------------

        def finish_resolved_operation(entry, result)
          operations.finish!(key: entry.key, operation: entry.operation, token: entry.token, result: result)
          "succeeded"
        end

        def resolve_operation_as_retryable(entry, record, message)
          operations.fail!(key: entry.key, operation: entry.operation, token: entry.token,
                           error: ConflictError.new(message))
          restore_known_record(record, default_state: "Provisioned")
          "retryable"
        end

        def restore_known_record(record, default_state:)
          volume_store[record.id] = record.with(state: restored_state(record, default_state), operation: nil,
                                                generation: record.generation + 1)
        end

        def restored_state(record, default_state)
          Types.key(record.operation || {}, "previousState", default_state).to_s
        end
      end
    end
  end
end
