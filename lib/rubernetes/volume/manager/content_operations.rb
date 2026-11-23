# frozen_string_literal: true

# Operations on a volume's content rather than its mounts: refreshing a
# projection, rotating a projected token, and filling a new volume from a
# snapshot or a clone source -- compensating the create when the fill fails.
module Rubernetes
  module Volume
    class Manager
      module ContentOperations
        def update_projection(id, data:, token:, binary_data: {}, sources: nil)
          run_manager_operation(id, "projection-update", token, {"data" => data, "binaryData" => binary_data, "sources" => sources}) do
            backend = backends.fetch(id.to_s)
            raise UnsupportedError, "volume #{id} does not support projection updates" unless Capability.updatable?(backend)

            if sources
              backend.update(sources: sources)
            else
              backend.update(data: data, binary_data: binary_data)
            end
          end
        end

        def rotate_token(id, token:, now: @clock.call)
          run_manager_operation(id, "token-rotate:#{token}", token, {"now" => now.to_s}) do
            backend = backends.fetch(id.to_s)
            raise UnsupportedError, "volume #{id} does not expose token rotation" unless Capability.rotates_token?(backend)

            backend.rotate_token(now: now)
          end
        end

        def restore_snapshot_volume(spec, snapshot:, token:)
          expected_digests = Types.key(snapshot.metadata, "contentSha256")
          # Integrity is checked before any volume exists so a corrupted
          # catalog never yields a half-restored, Provisioned volume.
          Backend.verify_content_integrity!(snapshot.content, expected_digests, volume_id: snapshot.id)
          id = create_volume(spec, token: token)
          backend = backends.fetch(id)
          # CSI restore is performed by CreateVolume(volume_content_source).  A
          # second generic restore would write local files beside a remote
          # volume and could report success without restoring the CSI object.
          return id if backend.is_a?(RemoteBackend)

          write_restored_content(id, backend, snapshot, expected_digests)
          id
        rescue StandardError => error
          error = compensate_failed_restore(id, token, error) if id
          sanitized = persistence_error(error)
          raise sanitized, cause: nil
        end

        def clone_volume(source_id:, spec:, token:)
          source = backends.fetch(source_id.to_s)
          id = create_volume(spec, token: token)
          destination = backends.fetch(id)
          # CSI clone is encoded in CreateVolume's content source.  Do not run
          # the local Backend#clone_from path for a remote destination.
          return id if destination.is_a?(RemoteBackend)

          destination.clone_from(source_backend: source)
          id
        rescue StandardError => error
          if id
            begin
              delete_volume(id, token: "clone-compensate-#{token}")
            rescue StandardError => cleanup_error
              mark_unknown(id)
              error = OperationUnknown.new("volume clone cleanup is ambiguous for #{id}: #{cleanup_error.message}")
            end
          end
          raise error
        end

        private

        def write_restored_content(id, backend, snapshot, expected_digests)
          # The volume exists durably before its bytes do.  Fence it as Unknown
          # with a named restore operation until every file is written and
          # re-verified, so a crash mid-restore leaves a record that refuses
          # attach/publish instead of a Provisioned volume with partial content.
          record = fetch_record(id)
          volume_store[id] = record.with(state: "Unknown", generation: record.generation + 1,
                                         operation: {"status" => "restoring", "name" => "restore",
                                                     "payload" => {"snapshotId" => snapshot.id},
                                                     "previousState" => record.state,
                                                     "reason" => "snapshot content is being written"})
          restored = backend.restore(content: snapshot.content, content_sha256: expected_digests)
          written = AdapterSupport.result_hash(backend.snapshot)["content"]
          Backend.verify_content_integrity!(written, expected_digests, volume_id: id) unless written.nil?
          record = fetch_record(id)
          durable_spec = record.spec.merge(
            "backendResult" => Types.key(record.spec, "backendResult", {}).to_h.merge(
              "restoredFrom" => snapshot.id, "contentDigest" => AdapterSupport.result_hash(restored)["contentDigest"]
            )
          )
          volume_store[id] = record.with(state: "Provisioned", spec: durable_spec, operation: nil,
                                         generation: record.generation + 1)
        end

        # Deletes the half-restored volume.  Returns the error to report: the
        # original one, or an OperationUnknown when the delete itself failed.
        def compensate_failed_restore(id, token, error)
          # An in-process failure is deterministic: unfence before the
          # compensating delete so it is not refused as Unknown.
          if (fenced = volume_store[id]) && fenced.state == "Unknown" &&
             Types.key(fenced.operation || {}, "name") == "restore"
            volume_store[id] = fenced.with(state: "Provisioned", operation: nil, generation: fenced.generation + 1)
          end
          delete_volume(id, token: "restore-compensate-#{token}")
          error
        rescue StandardError => cleanup_error
          mark_unknown(id)
          safe_cleanup = persistence_error(cleanup_error)
          OperationUnknown.new(
            "snapshot restore cleanup is ambiguous for #{id}: #{safe_cleanup.message}"
          )
        end

        def durable_content_result(operation, result)
          return Types.deep_copy(result) unless operation.start_with?("token-rotate:") && result.is_a?(Hash)

          sanitize_for_persistence(result.except("value", :value))
        end

        def run_manager_operation(id, operation, token, payload)
          key = Types.identifier(id, "volume id")
          token = Types.identifier(token, "operation token")
          entry = nil
          effect_applied = false
          with_volume_lock(key) do
            entry = operations.begin!(key: key, operation: operation, token: token, fingerprint: Types.digest(payload))
            return Types.deep_copy(entry.result) if entry.status == "succeeded"
            raise OperationUnknown, "operation #{operation} for #{key} is #{entry.status}" unless entry.status == "new"

            result = yield
            effect_applied = true
            operations.finish!(key: key, operation: operation, token: token, result: durable_content_result(operation, result))
            result
          end
        rescue StandardError => error
          raise if error.is_a?(StateUnknownError)

          ambiguous = effect_applied || error.is_a?(OperationUnknown) ||
                      (!error.is_a?(StateUnknownError) && error.class.name.to_s.match?(/Timeout|Unknown|EOF|Connection/)) ||
                      (Capability.reports_ambiguity?(error) && error.ambiguous?)
          if entry && ambiguous
            operations.unknown!(key: key, operation: operation, token: token, error: error)
            mark_unknown(key)
          end
          operations.fail!(key: key, operation: operation, token: token, error: error) if entry && !ambiguous
          raise
        end
      end
    end
  end
end
