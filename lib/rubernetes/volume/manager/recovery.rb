# frozen_string_literal: true

# Reconciling durable volume state with what the node actually has after a
# restart: the recover pass (mount ledger, interrupted operations, CSI and
# snapshot observation), retracting mount claims the kernel no longer backs,
# and the constructor's force-clean of Unknown volumes.
module Rubernetes
  module Volume
    class Manager
      module Recovery
        def recover(observed_mounts: nil, observed_devices: nil)
          observations = observed_mounts || (Capability.lists_mounts?(mount_adapter) ? mount_adapter.list_mounts : [])
          reconciliation = mount_ledger.reconcile(observations)
          errors = []
          redaction_ready, redaction_errors = prime_csi_secret_redactions!
          errors.concat(redaction_errors)
          actions = []
          fence_interrupted_operations
          observe_devices(observed_devices, actions)
          csi_volume_entries = observe_csi_volumes(redaction_ready, actions, errors)
          snapshot_entries = reconcile_snapshots(redaction_ready, actions, errors)
          resolved = reconcile_unknown_operations(csi_volume_entries: csi_volume_entries,
                                                  snapshot_entries: snapshot_entries,
                                                  observations: observations, errors: errors)
          actions << {"kind" => "operation-resolve", "count" => resolved.length} unless resolved.empty?
          reconciled_missing = reconcile_missing_mounts(reconciliation["missing"], errors: errors)
          unless reconciled_missing.empty?
            actions << {"kind" => "missing-mount-reconcile", "count" => reconciled_missing.length,
                        "entries" => reconciled_missing}
          end
          unknown = still_unknown
          actions << {"kind" => "observe", "count" => unknown.length} unless unknown.empty?
          RecoveryReport.new(owned: reconciliation["owned"], orphans: reconciliation["orphans"], missing: reconciliation["missing"],
                             identity_mismatches: reconciliation["identityMismatches"], unknown: unknown,
                             actions: actions, errors: errors)
        end

        private

        # An operation that was in flight when the node stopped has an unknown
        # outcome; its volume is fenced until an observation resolves it.
        def fence_interrupted_operations
          operations.pending_entries.each do |entry|
            operations.unknown!(key: entry.key, operation: entry.operation, token: entry.token,
                                error: OperationUnknown.new("operation was pending when the node restarted"))
            mark_unknown(entry.key, operation: entry.operation, payload: entry.payload) if volume_store[entry.key]
          end
          operations.unknown_entries.each do |entry|
            mark_unknown(entry.key, operation: entry.operation, payload: entry.payload) if volume_store[entry.key]
          end
        end

        def observe_devices(observed_devices, actions)
          return unless observed_devices || Capability.lists_devices?(device_adapter) || Capability.lists_devices?(mount_adapter)

          device_source = Capability.lists_devices?(device_adapter) ? device_adapter : mount_adapter
          devices = observed_devices || device_source.list_devices
          actions << {"kind" => "device-observe", "count" => Array(devices).length}
        end

        # The driver's ListVolumes entries, or nil when the driver was not (or
        # could not be) observed -- nil is what keeps CSI operations fenced.
        def observe_csi_volumes(redaction_ready, actions, errors)
          return nil unless redaction_ready && @csi && Capability.lists_volumes?(@csi)

          csi_volumes = list_csi_volumes
          csi_volume_entries = Array(AdapterSupport.result_hash(csi_volumes)["entries"] ||
                                     AdapterSupport.result_hash(csi_volumes)["volumes"] || csi_volumes)
          actions << {"kind" => "csi-list-volumes", "count" => csi_volume_entries.length}
          csi_volume_entries
        rescue StandardError => error
          errors << {"kind" => "csi-list-volumes", "error" => redact_secret_text(error.message.to_s)}
          nil
        end

        # Reconciles the snapshot catalog against ListSnapshots and returns the
        # listed entries (nil when the driver was not observed).
        def reconcile_snapshots(redaction_ready, actions, errors)
          return nil unless @snapshot_manager

          unless redaction_ready
            snapshot_report = @snapshot_manager.reconcile(
              error: CSIUnavailable.new("CSI recovery secret redaction preflight failed")
            )
            actions << {"kind" => "snapshot-reconcile", "unknown" => Array(snapshot_report["unknown"]).length,
                        "observed" => 0}
            return nil
          end

          snapshot_entries = nil
          begin
            snapshot_entries = list_csi_snapshots if @csi && Capability.lists_snapshots?(@csi)
            snapshot_report = @snapshot_manager.reconcile(entries: snapshot_entries)
            actions << {"kind" => "snapshot-reconcile", "unknown" => Array(snapshot_report["unknown"]).length,
                        "observed" => Array(snapshot_report["observed"]).length,
                        "resolved" => Array(snapshot_report["resolved"]).length}
          rescue StandardError => error
            snapshot_report = @snapshot_manager.reconcile(error: error)
            errors << {"kind" => "snapshot-reconcile", "error" => redact_secret_text(error.message.to_s)}
            actions << {"kind" => "snapshot-reconcile", "unknown" => Array(snapshot_report["unknown"]).length,
                        "observed" => 0}
          end
          snapshot_entries
        end

        def still_unknown
          unknown = operations.unknown_entries.map(&:to_h)
          snapshot_manager.list.each do |snapshot|
            next unless Types.key(snapshot.metadata, "state") == "Unknown"

            unknown << {"kind" => "snapshot", "id" => snapshot.id, "state" => "Unknown"}
          end
          unknown
        end

        # Durable mount claims that the kernel no longer backs (the node came back
        # in a fresh mount namespace, or the mounts were torn down with it) are
        # retracted from the volume record so the lifecycle can be re-driven
        # from kernel truth: a publish/stage entry without a kernel mount is
        # dropped together with its ledger row, and a backend whose provisioned
        # source mount is gone may re-establish it (emptyDir Memory tmpfs).
        # Records fenced as Unknown are left for operation resolution.
        def reconcile_missing_mounts(missing, errors:)
          outcomes = []
          entries = Array(missing).map { |entry| Capability.hash_like?(entry) ? entry.to_h.transform_keys(&:to_s) : entry }
          entries = entries.grep(Hash)
          # Publishes ride on stages, stages on the source: retract in that order.
          rank = lambda { |entry|
            if entry["owner"].to_s.start_with?("pod:")
              0
            else
              (entry["stagePath"].to_s == entry["target"].to_s ? 2 : 1)
            end
          }
          entries.sort_by { |entry| rank.call(entry) }.each do |entry|
            volume_id = entry["volumeId"].to_s
            record = volume_store[volume_id]
            next unless record
            next if record.state == "Unknown"

            target = File.expand_path(entry["target"].to_s)
            outcome = retract_missing_mount(record, entry, target)
            outcomes << {"volumeId" => volume_id, "target" => target, "owner" => entry["owner"], "outcome" => outcome} if outcome
          rescue StandardError => error
            errors << {"kind" => "missing-mount-reconcile", "volumeId" => entry["volumeId"], "target" => entry["target"],
                       "error" => redact_secret_text(error.message.to_s)}
          end
          outcomes
        end

        def retract_missing_mount(record, entry, target)
          publish_key, publish_entry = record.publishes.find { |_key, value| File.expand_path(value["target"].to_s) == target }
          return retract_missing_publish(record, entry, target, publish_key, publish_entry) if publish_key
          return retract_missing_stage(record, entry, target) if record.stages.key?(target)

          restore_missing_source_mount(record, entry, target)
        end

        def retract_missing_publish(record, entry, target, publish_key, publish_entry)
          id = record.id
          mount_ledger.remove(identity: entry)
          publishes = Types.deep_copy(record.publishes)
          publishes.delete(publish_key)
          attachments = Types.deep_copy(record.attachments)
          pod_id = publish_entry["pod"].to_s
          node_key = publish_entry["node"].to_s
          attachments[node_key]["pods"] = Array(attachments[node_key]["pods"]) - [pod_id] if attachments[node_key]
          state = publishes.empty? ? "Staged" : "Published"
          volume_store[id] = record.with(state: state, publishes: publishes, attachments: attachments,
                                         generation: record.generation + 1)
          operations.retract!(key: id, operation: "publish:#{pod_id}:#{target}")
          "publish-retracted"
        end

        def retract_missing_stage(record, entry, target)
          id = record.id
          mount_ledger.remove(identity: entry)
          stages = Types.deep_copy(record.stages)
          stages.delete(target)
          state = if !record.publishes.empty?
                    record.state
                  elsif stages.empty?
                    record.attachments.empty? ? "Detached" : "Attached"
                  else
                    "Staged"
                  end
          volume_store[id] = record.with(state: state, stages: stages, generation: record.generation + 1)
          operations.retract!(key: id, operation: "stage:#{target}")
          "stage-retracted"
        end

        # The missing mount is the backend's own provisioned source: let the
        # backend re-establish it (Backend#restore_source_mount!; nil when it
        # cannot) and record the new identity.
        def restore_missing_source_mount(record, entry, target)
          id = record.id
          backend = backends[id]
          return nil unless backend && File.expand_path(backend.source_path.to_s) == target

          restored = backend.restore_source_mount!
          return nil unless restored

          mount_ledger.remove(identity: entry)
          identity = sanitize_for_persistence(Capability.hash_like?(restored) ? restored.to_h : restored)
          backend_result = Types.deep_copy(Types.key(record.spec, "backendResult", {}))
          backend_result["mountIdentity"] = identity
          record_backend_mount(id, backend_result)
          volume_store[id] = record.with(spec: record.spec.merge("backendResult" => backend_result),
                                         generation: record.generation + 1)
          "source-mount-restored"
        end

        # kubelet's reconstruction fallback: a volume whose backend could not
        # be rebuilt (state Unknown) still has mount points on the node; they
        # are unmounted and forgotten so the Pod directory can go
        # (force_cleaned_failed_volume_operations_total counts every such
        # cleanup, _errors_total the ones that failed).
        def force_clean_unknown_publishes(records, stats)
          return unless Capability.unmounts?(@mount_adapter)

          records.each do |record|
            next unless record.state.to_s == "Unknown" && !record.publishes.to_h.empty?

            remaining = force_unmount_publishes(record, stats)
            next if remaining == record.publishes

            @volume_store[record.id] = record.with(publishes: remaining, generation: record.generation + 1)
          end
        end

        # Unmounts every published target of +record+ and returns the publishes
        # that could not be cleaned.  A target the adapter reports as "not
        # present" is already gone, which is the outcome wanted.
        def force_unmount_publishes(record, stats)
          remaining = Types.deep_copy(record.publishes)
          record.publishes.each do |key, publish|
            target = Types.key(publish, "target")
            next if target.to_s.empty?

            stats[:force_cleaned] += 1
            begin
              present = !Capability.finds_mounts?(@mount_adapter) || @mount_adapter.find_mount(target)
              AdapterSupport.call(@mount_adapter, :unmount, target: target) if present
              remaining.delete(key)
            rescue StandardError => error
              if error.class.name.to_s.end_with?("MountIdentityError") && error.message.to_s.include?("not present")
                remaining.delete(key)
              else
                stats[:force_clean_errors] += 1
              end
            end
          end
          remaining
        end
      end
    end
  end
end
