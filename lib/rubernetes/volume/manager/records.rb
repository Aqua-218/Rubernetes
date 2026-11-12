# frozen_string_literal: true

# The durable volume record as the manager edits it: fencing a record as
# Unknown, deriving the CSI node context from it, noting expansion results,
# and registering the mounts it owns in the mount identity ledger.
module Rubernetes
  module Volume
    class Manager
      module Records
        def mark_unknown(id, operation: nil, payload: nil, details: nil)
          record = volume_store[id.to_s]
          return nil unless record

          if record.state == "Unknown"
            return record unless operation && !Types.present?(Types.key(record.operation || {}, "name"))

            updated = record.with(operation: Types.deep_copy(record.operation || {}).merge(
              "name" => operation, "payload" => operation_payload(payload || {}),
              "details" => sanitize_for_persistence(details)
            ))
            volume_store[id] = updated
            return updated
          end

          updated = record.with(state: "Unknown", generation: record.generation + 1,
                                operation: {
                                  "status" => "unknown", "reason" => "effect response was ambiguous",
                                  "name" => operation, "payload" => operation_payload(payload || {}),
                                  "previousState" => record.state,
                                  "details" => sanitize_for_persistence(details)
                                })
          volume_store[id] = updated
          updated
        end

        # Build the complete CSI node context from durable CreateVolume and
        # per-node ControllerPublish results.  Node calls must not depend on a
        # caller replaying an ephemeral publishContext after restart.
        def context_for_node(record, node, context = {})
          spec = record.spec
          backend_result = Types.key(spec, "backendResult", {})
          volume_context = Types.key(spec, "volumeContext", {}).to_h.merge(
            Types.key(backend_result, "volumeContext", Types.key(backend_result, "volume_context", {})).to_h
          )
          attachment = record.attachments[node.to_s] || record.attachments[node] || {}
          Types.deep_copy(context).merge(
            "volumeContext" => volume_context,
            "publishContext" => Types.deep_copy(Types.key(attachment, "publishContext", {})),
            "secrets" => Types.deep_copy(Types.key(spec, "secrets", {})),
            "accessModes" => Array(Types.key(spec, "accessModes", ["ReadWriteOnce"])),
            "volumeMode" => Types.key(spec, "volumeMode", "Filesystem").to_s,
            "volumeCapability" => Types.deep_copy(Types.key(spec, "volumeCapability", {})),
            "node" => node.to_s
          )
        end

        def expansion_paths(record)
          stages = record.stages.values.map { |entry| Types.key(entry, "target") }
          publishes = record.publishes.values.map { |entry| Types.key(entry, "target") }
          (stages + publishes).select { |path| Types.present?(path) }.map { |path| File.expand_path(path.to_s) }.uniq
        end

        def node_expansion_required?(record)
          backend_result = Types.key(record.spec, "backendResult", {})
          Types.key(backend_result, "nodeExpansionRequired", false) == true
        end

        def record_expansion_result(record, expansion)
          result = sanitize_for_persistence(AdapterSupport.result_hash(expansion))
          required = Types.key(result, "nodeExpansionRequired", false) == true
          expanded = Array(Types.key(result, "nodeExpandedPaths", []))
          backend_result = Types.deep_copy(Types.key(record.spec, "backendResult", {})).merge(result)
          backend_result["nodeExpansionRequired"] = required && expanded.empty?
          record.with(spec: record.spec.merge("backendResult" => backend_result))
        end

        def record_node_expanded(record, path)
          backend_result = Types.deep_copy(Types.key(record.spec, "backendResult", {}))
          paths = Array(Types.key(backend_result, "nodeExpandedPaths", [])) | [File.expand_path(path.to_s)]
          backend_result["nodeExpandedPaths"] = paths
          backend_result["nodeExpansionRequired"] = false
          record.with(spec: record.spec.merge("backendResult" => backend_result))
        end

        def fetch_record(id)
          volume_store.fetch(id) { raise NotFoundError, "volume #{id} does not exist" }
        end

        def record_backend_mount(id, provisioned)
          identity = provisioned && (provisioned["mountIdentity"] || provisioned[:mount_identity])
          return true unless identity

          hash = Capability.hash_like?(identity) ? identity.to_h : identity
          register_mount_identity(
            volume_id: id,
            identity: hash,
            target: hash["target"] || hash[:target] || provisioned["source"],
            owner: "volume:#{id}",
            stage_path: provisioned["source"],
            generation: nil,
            secret: provisioned["backend"].to_s == "secret"
          )
        end

        # Forgets any recorded mount at `target`.  The caller has established
        # that nothing is mounted there any more (an attempt that died left the
        # path behind); the record would otherwise block the next mount.
        def forget_mount_target(target)
          @mount_ledger.remove_target(target)
        end

        # Keep the manager compatible with both the current ledger and the
        # stricter identity ledger used by native profiles. Optional identity
        # fields are passed only when the ledger advertises their keyword.
        def register_mount_identity(volume_id:, identity:, target:, owner:, stage_path:, generation:, secret:)
          hash = Capability.hash_like?(identity) ? identity.to_h : identity
          arguments = {
            volume_id: volume_id,
            source: hash["source"] || hash[:source],
            target: target,
            mount_id: hash["mountId"] || hash[:mount_id],
            filesystem_uuid: hash.key?("filesystemUuid") ? hash["filesystemUuid"] : hash[:filesystem_uuid],
            device_id: hash["deviceId"] || hash[:device_id],
            owner: owner,
            stage_path: stage_path,
            generation: generation,
            secret: secret
          }
          keyword_names = @mount_ledger.method(:register).parameters.filter_map do |kind, name|
            name if %i[key keyreq].include?(kind)
          end
          bind = hash.key?("bind") ? hash["bind"] == true : hash[:bind] == true
          optional = {
            root: hash["root"] || hash[:root],
            source_identity: hash["sourceIdentity"] || hash[:source_identity] || hash["source"] || hash[:source],
            filesystem_uuid_available: hash.key?("filesystemUuidAvailable") ? hash["filesystemUuidAvailable"] : hash[:filesystem_uuid_available],
            filesystem: hash["filesystem"] || hash[:filesystem] || hash["fsType"] || hash[:fs_type],
            # A bind mount rides on another superblock; the ledger must not
            # treat its device as a second attachment of that block device.
            bind: bind
          }
          optional.each { |key, value| arguments[key] = value if keyword_names.include?(key) }
          @mount_ledger.register(**arguments)
        end
      end
    end
  end
end
