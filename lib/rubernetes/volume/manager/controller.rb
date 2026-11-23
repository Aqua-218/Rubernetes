# frozen_string_literal: true

# The controller side of the volume lifecycle (CSI Controller service shape):
# create and delete volumes, attach and detach them to nodes, snapshot and
# expand them -- each as one idempotent, ledgered operation.
module Rubernetes
  module Volume
    class Controller
      include OperationSupport

      def initialize(manager = nil, **options)
        @manager = manager || options.delete(:manager) || Manager.new(**options)
      end

      def identity
        @manager.identity
      end

      def capabilities
        @manager.capabilities
      end

      def create_volume(spec, token:)
        normalized = @manager.normalize_spec(spec)
        normalized = @manager.resolve_csi_content_sources(normalized)
        id = @manager.volume_id_for(normalized)
        @manager.remember_csi_secrets(id, normalized)
        execute_operation(key: id, operation: "create", token: token, payload: normalized) do |effect_boundary|
          raise ConflictError, "volume #{id} already exists" if @manager.volume_store[id]

          persisted_spec = @manager.persisted_spec(normalized)
          backend_spec = Types.key(normalized, "backend").to_s.casecmp?("csi") ? persisted_spec : normalized
          backend = @manager.build_backend(id, backend_spec)
          record = VolumeRecord.new(id: id, spec: persisted_spec, backend: backend.type, state: "Declared",
                                    capacity_bytes: Types.key(normalized, "capacityBytes", Types.key(normalized, "capacity")))
          @manager.volume_store[id] = record
          @manager.backends[id] = backend
          begin
            provision_declared_volume(id, record, backend, persisted_spec, token, effect_boundary)
          rescue StandardError => error
            abandon_failed_create(id, backend, error, normalized, token, effect_boundary)
            raise
          end
        end
      end

      def delete_volume(id, token:)
        id = Types.identifier(id, "volume id")
        execute_operation(key: id, operation: "delete", token: token, payload: {"id" => id}) do |effect_boundary|
          record = @manager.fetch_record(id)
          raise ConflictError, "volume #{id} has active published consumers" unless record.publishes.empty?
          raise ConflictError, "volume #{id} has active attachments or stages" unless record.attachments.empty? && record.stages.empty?

          @manager.ensure_known!(record, action: "Cleanup")
          # An Unknown volume may still be torn down, but only when there is a
          # backend to tear it down WITH.  A record whose backend could not be
          # reconstructed after a restart has nothing to delete, and saying so
          # is the honest answer -- a bare `fetch` raised KeyError instead,
          # which told the caller nothing.
          backend = @manager.backends[id]
          unless backend
            raise StateUnknownError,
                  "volume #{id} is #{record.state} and its backend could not be reconstructed; recover before deleting"
          end
          raise ConflictError, "volume #{id} must be detached before delete" unless %w[Provisioned Detached Declared].include?(record.state)

          if backend.is_a?(RemoteBackend)
            backend.delete(token: token, effect_boundary: effect_boundary)
          else
            backend.delete
          end
          @manager.mount_ledger.remove_volume(id)
          @manager.volume_store.delete(id)
          @manager.backends.delete(id)
          @manager.forget_csi_secrets(id)
          true
        end
      end

      alias delete delete_volume

      # ControllerPublishVolume / ControllerUnpublishVolume semantics.
      def publish(id, node, token:)
        id = Types.identifier(id, "volume id")
        node = Types.identifier(node, "node")
        current = @manager.fetch_record(id)
        @manager.ensure_known!(current)
        if (existing = current.attachments[node])
          return Types.deep_copy(existing["backendResult"] || existing)
        end

        operation = "controller-publish:#{node}:#{current.generation}"
        execute_operation(key: id, operation: operation, token: token,
                          payload: {"id" => id, "node" => node, "generation" => current.generation}) do |effect_boundary|
          record = @manager.fetch_record(id)
          @manager.ensure_known!(record)
          enforce_attach_policy!(record, node: node, pod: nil)
          if (existing = record.attachments[node])
            return Types.deep_copy(existing["backendResult"] || existing)
          end

          backend = @manager.backends.fetch(id)
          context = attachment_context(record, node)
          result = if backend.is_a?(RemoteBackend)
                     AdapterSupport.result_hash(backend.attach(node: node, context: context,
                                                               effect_boundary: effect_boundary))
                   else
                     AdapterSupport.result_hash(backend.attach(node: node, context: context))
                   end
          durable_result = if backend.is_a?(RemoteBackend)
                             @manager.sanitize_for_persistence(result)
                           else
                             Types.deep_copy(result)
                           end
          attachments = Types.deep_copy(record.attachments)
          attachments[node] = {
            "node" => node, "generation" => record.generation + 1, "pods" => [],
            "publishContext" => Types.deep_copy(durable_result["publishContext"] || {}),
            "volumeContext" => Types.deep_copy(context["volumeContext"] || {}),
            "accessModes" => Types.deep_copy(context["accessModes"] || []),
            "volumeMode" => context["volumeMode"].to_s,
            "backendResult" => durable_result
          }
          attachments[node]["pods"] = Array(attachments[node]["pods"]).uniq
          new_state = record.state == "Detached" ? "Attached" : record.state
          new_state = "Attached" if %w[Provisioned Declared].include?(new_state)
          record = record.with(state: new_state, attachments: attachments, generation: record.generation + 1)
          @manager.volume_store[id] = record
          durable_result || {"volumeId" => id, "node" => node}
        end
      end

      def unpublish(id, node, token:)
        id = Types.identifier(id, "volume id")
        node = Types.identifier(node, "node")
        @manager.with_volume_lock(id) do
          record = @manager.fetch_record(id)
          @manager.ensure_known!(record, action: "Cleanup")
          attachment = record.attachments[node]
          next true unless attachment

          generation = attachment["generation"] || legacy_detach_generation(record, node, token)
          execute_operation(key: id, operation: "controller-unpublish:#{node}:#{generation}", token: token,
                            payload: {"id" => id, "node" => node, "generation" => generation}) do |effect_boundary|
            detach_attachment(record, node, attachment, effect_boundary)
          end
        end
      end

      alias controller_publish publish
      alias controller_unpublish unpublish

      def create_snapshot(id, token:, name: nil)
        execute_operation(key: id.to_s, operation: "snapshot", token: token,
                          payload: {"id" => id.to_s, "name" => name}) do |effect_boundary|
          @manager.snapshot_manager.create(id, token: token, name: name, effect_boundary: effect_boundary).id
        end
      end

      alias snapshot create_snapshot

      def delete_snapshot(snapshot_id, token:)
        snapshot_id = Types.identifier(snapshot_id, "snapshot id")
        execute_operation(key: "snapshot-#{snapshot_id}", operation: "delete-snapshot", token: token,
                          payload: {"snapshotId" => snapshot_id}) do |effect_boundary|
          @manager.snapshot_manager.delete(snapshot_id, token: token, effect_boundary: effect_boundary)
        end
      rescue OperationUnknown => error
        @manager.snapshot_manager.mark_unknown(snapshot_id, reason: error)
        raise
      end

      def expand(id, capacity, token:)
        id = Types.identifier(id, "volume id")
        execute_operation(key: id, operation: "expand", token: token, payload: {"id" => id, "capacity" => capacity}) do |effect_boundary|
          record = @manager.fetch_record(id)
          @manager.ensure_known!(record)
          bytes = Types.parse_capacity(capacity)
          current = record.capacity_bytes || 0
          raise CapacityError, "volume expansion must increase capacity" unless bytes > current

          class_name = Types.key(record.spec, "storageClassName", Types.key(record.spec, "storageClass", "")).to_s
          storage_class = class_name.empty? ? nil : @manager.binder.find_storage_class(class_name)
          if storage_class && !storage_class.allow_volume_expansion
            raise UnsupportedError, "online expansion is disabled for storage class #{class_name.inspect}"
          end

          backend = @manager.backends.fetch(id)
          result = if backend.is_a?(RemoteBackend)
                     expansion = backend.expand(capacity_bytes: bytes, token: token,
                                                node_paths: @manager.expansion_paths(record),
                                                effect_boundary: effect_boundary)
                     record = @manager.record_expansion_result(record, expansion)
                     Types.key(expansion, "capacityBytes", bytes)
                   else
                     backend.expand(capacity_bytes: bytes)
                   end
          @manager.volume_store[id] = record.with(capacity_bytes: bytes, generation: record.generation + 1)
          result
        end
      end

      alias controller_expand expand

      def ensure_attach_policy(record, node:, pod: nil)
        enforce_attach_policy!(record, node: node, pod: pod)
      end

      private

      # Stage cleanup can advance the volume generation between detach
      # attempts. Old records recover the generation already reserved for
      # this attachment from their operation token.
      def legacy_detach_generation(record, node, token)
        attempt = @manager.operations.fetch_token(key: record.id, token: token)
        can_resume = attempt && attempt.status != "succeeded" && attempt.operation.start_with?("controller-unpublish:#{node}:")
        return attempt.payload.fetch("generation") if can_resume

        record.generation
      end

      def detach_attachment(record, node, attachment, effect_boundary)
        published = record.publishes.values.any? { |entry| entry["node"].to_s == node }
        raise ConflictError, "volume #{record.id} still has published consumers on #{node}" if published

        backend = @manager.backends.fetch(record.id)
        context = attachment_context(record, node, attachment: attachment)
        if backend.is_a?(RemoteBackend)
          backend.detach(node: node, context: context, effect_boundary: effect_boundary)
        else
          backend.detach(node: node, context: context)
        end
        attachments = record.attachments.except(node)
        state = attachments.empty? && record.stages.empty? ? "Detached" : record.state
        @manager.volume_store[record.id] = record.with(state: state, attachments: attachments, generation: record.generation + 1)
        true
      end

      def provision_declared_volume(id, record, backend, persisted_spec, token, effect_boundary)
        provisioned = if backend.is_a?(RemoteBackend)
                        backend.provision(token: token, effect_boundary: effect_boundary)
                      else
                        backend.provision
                      end
        @manager.record_backend_mount(id, provisioned)
        durable_result = @manager.sanitize_for_persistence(provisioned)
        durable_spec = persisted_spec.merge("backendResult" => durable_result)
        record = record.with(state: "Provisioned", generation: record.generation + 1,
                             spec: durable_spec)
        @manager.volume_store[id] = record
        @manager.backends[id] = backend.is_a?(RemoteBackend) ? @manager.build_backend(id, durable_spec) : backend
        id
      end

      # A create that failed leaves either nothing (the record is dropped) or
      # an Unknown record that recovery must reconcile; which one depends on
      # whether the backend can still be proven clean.
      def abandon_failed_create(id, backend, error, normalized, token, effect_boundary)
        if backend.is_a?(RemoteBackend) && backend.driver_volume_id
          compensate_remote_create(id, backend, normalized, token, effect_boundary)
        elsif backend.is_a?(RemoteBackend) && error.is_a?(CSIUnavailable) && !ambiguous_error?(error)
          # No plugin was reached (the kubelet's "driver not found in the
          # list of registered CSI drivers"): nothing exists to fence, and
          # the create is retried once the driver registers.
          forget_volume(id)
        elsif ambiguous_error?(error) || backend.is_a?(RemoteBackend)
          @manager.mark_unknown(id)
        else
          discard_local_volume(id, backend)
        end
      end

      def compensate_remote_create(id, backend, normalized, token, effect_boundary)
        backend.delete(token: "create-compensate-#{token}")
        effect_boundary.call(:compensated)
        forget_volume(id)
      rescue StandardError
        @manager.mark_unknown(id, operation: "create", payload: @manager.operation_payload(normalized))
      end

      def discard_local_volume(id, backend)
        cleanup_failed = false
        begin
          backend.delete
        rescue StandardError
          cleanup_failed = true
        end
        if cleanup_failed
          @manager.mark_unknown(id)
        else
          forget_volume(id)
        end
      end

      def forget_volume(id)
        @manager.volume_store.delete(id)
        @manager.backends.delete(id)
      end

      def attachment_context(record, node, attachment: nil)
        spec = record.spec
        backend_result = Types.key(spec, "backendResult", {})
        volume_context = Types.key(spec, "volumeContext", {}).to_h.merge(
          Types.key(backend_result, "volumeContext", Types.key(backend_result, "volume_context", {})).to_h
        )
        attachment ||= Types.key(record.attachments, node, {})
        {
          "volumeContext" => volume_context,
          "publishContext" => Types.deep_copy(Types.key(attachment, "publishContext", {})),
          "secrets" => Types.deep_copy(Types.key(spec, "secrets", {})),
          "accessModes" => Array(Types.key(spec, "accessModes", ["ReadWriteOnce"])),
          "volumeMode" => Types.key(spec, "volumeMode", "Filesystem").to_s,
          "volumeCapability" => Types.deep_copy(Types.key(spec, "volumeCapability", {})),
          "node" => node.to_s
        }
      end

      def node_context(record, node, context)
        attachment = record.attachments[node.to_s] || record.attachments[node]
        # Caller-supplied context may add a mount path/capability, but the
        # durable controller result and CreateVolume context always win.
        Types.deep_copy(context).merge(attachment_context(record, node, attachment: attachment))
      end

      def enforce_attach_policy!(record, node:, pod:)
        modes = Array(Types.key(record.spec, "accessModes", ["ReadWriteOnce"]))
        existing_nodes = record.attachments.keys
        if modes.include?("ReadWriteOncePod") && !existing_nodes.empty? && existing_nodes.any? do |existing|
          existing.to_s != node.to_s
        end && existing_nodes.any? do |existing|
                 existing.to_s != node.to_s
               end
          raise MultiAttachError,
                "ReadWriteOncePod volume #{record.id} is already attached to another node"
        end
        if (modes & %w[ReadWriteOnce ReadWriteOncePod]).any? && existing_nodes.any? { |existing| existing.to_s != node.to_s }
          raise MultiAttachError, "volume #{record.id} with #{modes.join(", ")} cannot attach to multiple nodes"
        end
        return true unless pod
        if modes.include?("ReadWriteOncePod") && record.attachments.values.any? do |entry|
          Array(entry["pods"]).any? do |value|
            value != pod
          end
        end
          raise MultiAttachError, "ReadWriteOncePod volume #{record.id} is already used by another pod"
        end
      end
    end
  end
end
