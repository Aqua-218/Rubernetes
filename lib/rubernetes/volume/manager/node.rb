# frozen_string_literal: true

# The node side of the volume lifecycle (CSI Node service shape): stage a
# volume on the node, publish it into a Pod, and take both back -- each as one
# idempotent, ledgered operation whose mount is registered in the mount
# identity ledger and undone when it cannot be recorded.
module Rubernetes
  module Volume
    class Node
      include OperationSupport
      include SharedCSIStages

      def initialize(manager = nil, **options)
        @manager = manager || options.delete(:manager) || Manager.new(**options)
      end

      # See Manager#forget_mount_target: clears a record left behind at a
      # fixed Pod path by an attempt that died.
      def forget_mount_target(target)
        @manager.forget_mount_target(target)
      end

      def stage(id, path, token:, readonly: false, node: nil, context: {})
        id = Types.identifier(id, "volume id")
        readonly = Types.bool(readonly)
        path = secure_path(path)
        target, stage_key = stage_destination(id, path, node)
        payload = {"id" => id, "path" => path, "readonly" => readonly, "node" => node}
        if stage_key
          payload["stageTarget"] = target
          payload["sharedCSIStage"] = stage_key
        end
        execute_operation(key: id, operation: "stage:#{path}", token: token,
                          payload: payload) do |effect_boundary|
          record = @manager.fetch_record(id)
          @manager.ensure_known!(record)
          record = ensure_attached(record, node)
          raise ConflictError, "volume #{id} is not attached to node #{node}" if node && !record.attachments.key?(node.to_s)

          effective_node = node || attached_node(record)
          raise InvalidStateError, "volume #{id} must be Attached before staging (state #{record.state})" unless %w[Attached Staged].include?(record.state)

          next reusable_stage(record.stages.fetch(path), id, node) if record.stages.key?(path)

          backend = @manager.backends.fetch(id)
          modes = Array(Types.key(record.spec, "accessModes", []))
          stage_volume(backend, record, path, target: target, stage_key: stage_key, node: effective_node,
                                              readonly: readonly || modes.include?("ReadOnlyMany"), context: context,
                                              token: token, effect_boundary: effect_boundary)
        end
      end

      alias node_stage stage

      # A backend that rewrote its files (token rotation, content refresh)
      # wrote them as root; the fsGroup ownership pass runs again so the Pod
      # keeps reading them (kubelet's SetVolumeOwnership on every remount).
      def reapply_fs_group(id, pod:, stage_path:, fs_group:, readonly: false)
        return true if fs_group.nil?

        backend = @manager.backends.fetch(Types.identifier(id, "volume id"))
        # The kubelet CSI mounter applies fsGroup only at SetUp.
        return true if backend.is_a?(RemoteBackend) && !backend.csi_fs_group_mode(fs_group, readonly: readonly).nil?

        apply_security!(backend, stage_path: stage_path, pod: pod, readonly: readonly, fs_group: fs_group,
                                 selinux_label: nil, mount_propagation: nil, context: {})
        true
      end

      # Backends whose content the node itself writes into the volume
      # directory.  kubelet binds such a volume's per-Pod directory straight
      # into the container; nothing is mounted for it but the tmpfs a
      # Secret, downward API or projected volume lives on.
      DIRECT_TYPES = %w[configMap secret downwardAPI projected].freeze

      # The directory the runtime binds for a provisioned node-written
      # volume, used as it is: no stage and no publish bind.  Those two
      # mounts, their readbacks and their ledger records were most of what
      # starting a Pod with fifty ConfigMap volumes cost.  fsGroup ownership
      # is applied here, where publish applied it.
      def direct_path(id, pod:, fs_group: nil)
        id = Types.identifier(id, "volume id")
        validate_fs_group!(fs_group)
        record = @manager.fetch_record(id)
        @manager.ensure_known!(record)
        unless record.state == "Provisioned"
          raise InvalidStateError,
                "volume #{id} must be Provisioned to be used directly (state #{record.state})"
        end

        backend = @manager.backends.fetch(id)
        raise ValidationError, "#{backend.type} volume #{id} cannot be used without a publish" unless DIRECT_TYPES.include?(backend.type)

        path = backend.source_path
        apply_security!(backend, stage_path: path, pod: pod, readonly: true, fs_group: fs_group,
                                 selinux_label: nil, mount_propagation: nil, context: {})
        path
      end

      def publish(id, pod, container_path, readonly:, token:, node: nil, sub_path: nil, fs_group: nil,
                  selinux_label: nil, mount_propagation: nil, context: {})
        id = Types.identifier(id, "volume id")
        readonly = Types.bool(readonly)
        validate_mount_propagation!(mount_propagation)
        validate_fs_group!(fs_group)
        target = secure_path(container_path)
        pod_id = pod_identifier(pod)
        with_csi_publish_access(id, pod_id) do
          execute_operation(key: id, operation: "publish:#{pod_id}:#{target}", token: token,
                            payload: {"id" => id, "pod" => pod_id, "target" => target, "readonly" => readonly, "node" => node,
                                      "subPath" => sub_path, "fsGroup" => fs_group, "selinux" => selinux_label,
                                      "propagation" => mount_propagation}) do |effect_boundary|
            record = @manager.fetch_record(id)
            @manager.ensure_known!(record)
            ensure_publishable!(record, id, readonly)
            stage_path = stage_for(record, node)
            backend = @manager.backends.fetch(id)
            effective_node = node || attached_node(record)
            @manager.ensure_attach_policy!(record, node: effective_node, pod: pod_id)
            publish_key = "#{pod_id}\0#{target}"
            next reusable_publish(record.publishes.fetch(publish_key), id, readonly) if record.publishes.key?(publish_key)

            with_publish_ownership(record, backend, stage_path, fs_group, sub_path) do |local_in_use|
              publish_secured(
                record, backend, pod, target,
                stage_path: stage_path, node: effective_node, token: token, readonly: readonly, fs_group: fs_group,
                selinux_label: selinux_label, mount_propagation: mount_propagation, sub_path: sub_path,
                context: context, effect_boundary: effect_boundary, local_in_use: local_in_use
              )
            end
          end
        end
      end

      alias node_publish publish

      def expand_in_use(id, pod, container_path, capacity_bytes:, token:)
        id = Types.identifier(id, "volume id")
        target = secure_path(container_path)
        pod_id = pod_identifier(pod)
        @manager.with_volume_lock(id) do
          record = @manager.fetch_record(id)
          next nil if record.state == "Unknown"

          backend = @manager.backends[id]
          next nil unless backend.is_a?(RemoteBackend)

          existing = record.publishes["#{pod_id}\0#{target}"]
          next nil unless existing

          stage = record.stages.values.find { |entry| existing["node"].to_s.empty? || entry["node"].to_s == existing["node"].to_s }
          result = backend.kubelet_expand(target: target, stage_path: stage && stage["target"],
                                          capacity_bytes: Integer(capacity_bytes), token: token)
          if result.is_a?(Hash)
            capacity = [Integer(result["capacityBytes"] || 0), Integer(capacity_bytes)].max
            if capacity > record.capacity_bytes.to_i
              @manager.volume_store[id] =
                record.with(capacity_bytes: capacity, generation: record.generation + 1)
            end
          end
          result
        end
      end

      # csi_mounter remount for a driver with requiresRepublish.  NodePublish
      # is idempotent at the driver and the mount already exists, so this
      # goes around the operation ledger (a durable entry every sync would
      # grow the node's state without bound); the volume lock still orders it
      # against the volume's other operations.  Returns false when there is
      # nothing to republish.
      def republish(id, pod, container_path, token:)
        id = Types.identifier(id, "volume id")
        target = secure_path(container_path)
        pod_id = pod_identifier(pod)
        @manager.with_volume_lock(id) do
          record = @manager.fetch_record(id)
          next false if record.state == "Unknown"

          backend = @manager.backends[id]
          next false unless backend.is_a?(RemoteBackend) && backend.requires_republish?

          existing = record.publishes["#{pod_id}\0#{target}"]
          next false unless existing

          node = existing["node"]
          node = nil if node.to_s.empty?
          stage_path = stage_for(record, node)
          context = @manager.context_for_node(record, node || attached_node(record), {})
          backend.republish(stage_path: stage_path, target: target, pod: pod, readonly: existing["readonly"] == true,
                            context: context, token: token)
          true
        end
      end

      def unpublish(id, pod, container_path, token:)
        id = Types.identifier(id, "volume id")
        target = secure_path(container_path, teardown: true)
        pod_id = pod_identifier(pod)
        execute_operation(key: id, operation: "unpublish:#{pod_id}:#{target}", token: token,
                          payload: {"id" => id, "pod" => pod_id, "target" => target}) do |effect_boundary|
          record = @manager.fetch_record(id)
          @manager.ensure_known!(record, action: "Cleanup")
          key = "#{pod_id}\0#{target}"
          unless record.publishes.empty? || !record.publishes.key?(key)
            entry = record.publishes.fetch(key)
            transitional = record.with(state: "Unpublishing", generation: record.generation + 1)
            @manager.volume_store[id] = transitional
            backend = @manager.backends.fetch(id)
            begin
              effective_context = @manager.context_for_node(record, entry["node"], {})
              if backend.is_a?(RemoteBackend)
                backend.unpublish(target: target, identity: entry, context: effective_context,
                                  effect_boundary: effect_boundary)
              else
                backend.unpublish(target: target, identity: entry, context: effective_context)
              end
            rescue StandardError => error
              restore_after_failed_teardown(id, record, error)
              raise
            end
            @manager.mount_ledger.remove(identity: mount_identity(entry), expected: entry)
            record_unpublished(id, transitional, key, entry, pod_id)
          end
          true
        end
      end

      alias node_unpublish unpublish

      def unstage(id, path, token:, node: nil, context: {})
        id = Types.identifier(id, "volume id")
        path = secure_path(path)
        execute_operation(key: id, operation: "unstage:#{path}", token: token,
                          payload: {"id" => id, "path" => path, "node" => node}) do |effect_boundary|
          record = @manager.fetch_record(id)
          @manager.ensure_known!(record, action: "Cleanup")
          raise ConflictError, "volume #{id} still has published consumers" unless record.publishes.empty?

          entry = record.stages[path] || interrupted_shared_stage(record, path)
          if entry
            transitional = record.with(state: "Unstaged", generation: record.generation + 1)
            @manager.volume_store[id] = transitional
            begin
              teardown_stage(transitional, path, entry, context, effect_boundary)
            rescue StandardError => error
              restore_after_failed_teardown(id, record, error)
              raise
            end
          end
          true
        end
      end

      alias node_unstage unstage

      def stats(id, path: nil)
        record = @manager.fetch_record(id)
        stats_path = path || (record.stages.empty? ? @manager.backends.fetch(id).source_path : stage_for(record, nil))
        @manager.backends.fetch(id).stats(path: stats_path, capacity_bytes: record.capacity_bytes)
      end

      alias node_get_volume_stats stats

      def recover(observed_mounts: nil, observed_devices: nil)
        @manager.recover(observed_mounts: observed_mounts, observed_devices: observed_devices)
      end

      # {attempted:, errors:} of the startup reconstruction (reconstruct_volume_operations_*).
      def reconstruction_stats
        @manager.reconstruction_stats
      end

      private

      # -- stage steps ---------------------------------------------------------

      def reusable_stage(existing, id, node)
        raise ConflictError, "volume #{id} is already staged on node #{existing["node"]}" if node && existing["node"].to_s != node.to_s

        existing
      end

      def stage_on_backend(backend, path:, node:, readonly:, context:, effect_boundary:)
        if backend.is_a?(RemoteBackend)
          backend.stage(path: path, node: node, readonly: readonly, context: context, effect_boundary: effect_boundary)
        else
          backend.stage(path: path, node: node, readonly: readonly, context: context)
        end
      end

      def record_stage(id, record, backend, path, result, register: true)
        # A stage that the CSI plugin completed without a kernel mount
        # owns nothing in the mount table; only kernel identities enter
        # the ledger (spec 5.11.3).
        if register && !(result["mounted"] == false && !Types.present?(result["mountId"]))
          owner = result["sharedCSIStage"] || id
          target = result.fetch("target")
          @manager.register_mount_identity(volume_id: owner, identity: result, target: target,
                                           owner: "volume:#{owner}", stage_path: target,
                                           generation: record.generation, secret: backend.secret?)
        end
        stages = Types.deep_copy(record.stages)
        stages[path] = result
        new_state = record.state == "Attached" ? "Staged" : record.state
        @manager.volume_store[id] = record.with(state: new_state, stages: stages, generation: record.generation + 1)
        result
      end

      # -- publish steps -------------------------------------------------------

      def with_csi_publish_access(id, pod_id)
        record = @manager.volume_store[id]
        backend = @manager.backends[id]
        return yield unless backend.is_a?(RemoteBackend) && Array(record&.spec&.dig("accessModes")).include?("ReadWriteOncePod")

        identity = backend.kubelet_volume_identity
        return yield unless identity

        # Separate Pod volume records can refer to the same CSI volume.
        @manager.with_volume_lock("csi-publish:#{Types.digest(identity)}") do
          if @manager.volume_store.each_value.any? { |other| csi_published_to_another_pod?(other, identity, pod_id) }
            raise MultiAttachError, "volume uses the ReadWriteOncePod access mode and is already in use by another pod"
          end

          yield
        end
      end

      def csi_published_to_another_pod?(record, identity, pod_id)
        return false if record.publishes.empty? && record.state != "Unknown"

        backend = @manager.backends[record.id]
        return false unless backend.is_a?(RemoteBackend) && backend.kubelet_volume_identity == identity
        return true if record.publishes.each_value.any? { |entry| entry["pod"] != pod_id }

        operation = record.operation
        record.state == "Unknown" && operation && operation["name"].to_s.start_with?("publish:") &&
          operation.dig("payload", "pod") != pod_id
      end

      def with_publish_ownership(record, backend, stage_path, fs_group, sub_path)
        return yield(nil) unless backend.is_a?(LocalBackend) && sub_path.nil?

        # Separate Pod volume records can bind the same filesystem directory.
        identity = record.stages.fetch(stage_path)
        device_id, root = identity.values_at("deviceId", "root")
        source = root ? "#{device_id}:#{root}" : backend.source_path
        @manager.with_volume_lock("local-publish:#{source}") do
          yield(fs_group && @manager.mount_ledger.published_bind_of?(identity))
        end
      end

      def publish_secured(record, backend, pod, target, stage_path:, node:, token:, readonly:, fs_group:, selinux_label:,
                          mount_propagation:, sub_path:, context:, effect_boundary:, local_in_use:)
        effective_context = @manager.context_for_node(record, node, context)
        # CSI fsGroup belongs to the driver (VOLUME_MOUNT_GROUP) or runs on the
        # published target according to CSIDriver.fsGroupPolicy.
        csi_fs_group = backend.is_a?(RemoteBackend) ? backend.csi_fs_group_mode(fs_group, readonly: readonly) : nil
        effective_context = effective_context.merge("volumeMountGroup" => fs_group.to_s) if csi_fs_group == :delegate
        stage_group = fs_group unless csi_fs_group || backend.is_a?(LocalBackend)
        apply_security!(backend, stage_path: stage_path, pod: pod, readonly: readonly, fs_group: stage_group,
                                 selinux_label: selinux_label, mount_propagation: mount_propagation, context: context)
        result = publish_on_backend(backend, record: record, stage_path: stage_path, target: target, node: node, pod: pod,
                                             readonly: readonly, sub_path: sub_path, context: effective_context,
                                             effect_boundary: effect_boundary)
        record = expand_node_if_required(backend, record, target, token, effect_boundary) unless result["kubeletSubPath"]
        begin
          if csi_fs_group == :kubelet
            apply_security!(backend, stage_path: target, pod: pod, readonly: readonly, fs_group: fs_group,
                                     selinux_label: nil, mount_propagation: nil, context: context)
          end
          apply_local_ownership(backend, pod, result, fs_group, local_in_use)
          record_publish(record.id, record, backend, result, pod_id: pod_identifier(pod), target: target, stage_path: stage_path, node: node)
        rescue StandardError => error
          raise_with_cleanup(error) { backend.unpublish(target: target, identity: result, context: context) }
        end
      end

      def apply_local_ownership(backend, pod, result, fs_group, already_mounted)
        return if already_mounted.nil?

        fs_group = Integer(fs_group)
        target = result.fetch("target")
        if already_mounted
          current_group = File.stat(target).gid
          result["localFsGroupConflict"] = {"requested" => fs_group, "current" => current_group} if current_group != fs_group
        elsif !result["readonly"]
          apply_security!(backend, stage_path: target, pod: pod, readonly: false, fs_group: fs_group,
                                   selinux_label: nil, mount_propagation: nil, context: {})
        end
      end

      def validate_mount_propagation!(mount_propagation)
        return unless mount_propagation && !%w[None HostToContainer Bidirectional].include?(mount_propagation.to_s)

        raise ValidationError, "unsupported mountPropagation #{mount_propagation.inspect}"
      end

      def validate_fs_group!(fs_group)
        return unless fs_group

        begin
          raise ValidationError, "fsGroup must be non-negative" if Integer(fs_group).negative?
        rescue ArgumentError, TypeError
          raise ValidationError, "fsGroup must be an integer"
        end
      end

      def ensure_publishable!(record, id, readonly)
        raise InvalidStateError, "volume #{id} must be Staged before publishing (state #{record.state})" unless %w[Staged Published].include?(record.state)
        return unless Array(Types.key(record.spec, "accessModes", [])).include?("ReadOnlyMany") && !readonly

        raise SecurityError, "ReadOnlyMany volume #{id} cannot be published writable"
      end

      def reusable_publish(existing, id, readonly)
        if existing["readonly"] == true && !readonly
          raise SecurityError,
                "volume #{id} cannot change an existing read-only publish to writable"
        end

        existing
      end

      def publish_on_backend(backend, record:, effect_boundary:, **request)
        if backend.is_a?(RemoteBackend)
          backend.publish(**request, effect_boundary: effect_boundary, pod_publishes: record.publishes.values)
        else
          backend.publish(**request)
        end
      end

      def record_publish(id, record, backend, result, pod_id:, target:, stage_path:, node:)
        @manager.register_mount_identity(volume_id: id, identity: result, target: target,
                                         owner: "pod:#{pod_id}", stage_path: stage_path,
                                         generation: record.generation, secret: backend.secret?)
        publishes = Types.deep_copy(record.publishes)
        publishes["#{pod_id}\0#{target}"] = result.merge("pod" => pod_id, "target" => target)
        attachments = Types.deep_copy(record.attachments)
        attachments[node] ||= {"node" => node, "generation" => record.generation + 1, "pods" => []}
        attachments[node]["pods"] = (Array(attachments[node]["pods"]) + [pod_id]).uniq
        @manager.volume_store[id] = record.with(state: "Published", publishes: publishes, attachments: attachments,
                                                generation: record.generation + 1)
        result
      end

      # NodeExpandVolume owed from an earlier controller expansion is paid as
      # soon as the volume has a node path.  Returns the (possibly updated)
      # record.
      def expand_node_if_required(backend, record, path, token, effect_boundary)
        return record unless backend.is_a?(RemoteBackend) && @manager.node_expansion_required?(record)

        backend.expand_node(path: path, capacity_bytes: record.capacity_bytes,
                            token: "#{token}:node-expand", effect_boundary: effect_boundary)
        @manager.record_node_expanded(record, path)
      end

      # -- teardown steps ------------------------------------------------------

      # A teardown that failed deterministically puts the pre-teardown record
      # back; an ambiguous one fences the volume instead.
      def restore_after_failed_teardown(id, record, error)
        @manager.mark_unknown(id) if ambiguous_error?(error)
        @manager.volume_store[id] = record unless ambiguous_error?(error)
      end

      def record_unpublished(id, transitional, key, entry, pod_id)
        publishes = Types.deep_copy(transitional.publishes)
        publishes.delete(key)
        attachments = Types.deep_copy(transitional.attachments)
        node_key = entry["node"].to_s
        if attachments[node_key]
          attachments[node_key]["pods"] = Array(attachments[node_key]["pods"]) - [pod_id]
          attachments.delete(node_key) if attachments[node_key]["pods"].empty? && transitional.stages.empty?
        end
        state = publishes.empty? ? "Staged" : "Published"
        @manager.volume_store[id] = transitional.with(state: state, publishes: publishes, attachments: attachments,
                                                      generation: transitional.generation + 1)
      end

      # Undoes a mount whose bookkeeping failed and re-raises: the original
      # error when the undo succeeded, a CleanupError carrying both otherwise.
      def raise_with_cleanup(error, &)
        cleanup_errors = collect_cleanup_errors(&)
        raise @manager.with_cleanup_errors(error, cleanup_errors) unless cleanup_errors.empty?

        raise error
      end

      def collect_cleanup_errors
        result = yield
        return [] if [true, 0].include?(result)

        [CleanupError.new(
          "mount cleanup did not report success (result=#{result.inspect})",
          details: {"cleanupErrors" => [{"class" => CleanupError.name,
                                         "message" => "adapter returned #{result.inspect}"}]},
          cleanup_errors: []
        )]
      rescue StandardError => error
        [error]
      end

      # -- shared helpers ------------------------------------------------------

      def secure_path(path, teardown: false)
        value = String(path)
        raise PathSecurityError, "volume path must be absolute" unless value.start_with?("/")
        raise PathSecurityError, "volume path contains NUL" if value.include?("\0")

        components = value.split("/")
        if components.include?("..") || components.include?(".") || components.drop(1).any?(&:empty?)
          raise PathSecurityError,
                "volume path contains traversal"
        end

        security = @manager.path_security
        if teardown && security.is_a?(PathSecurity)
          security.validate_unmount_target!(value)
        else
          security.validate_target!(value)
        end
        value
      rescue TypeError
        raise PathSecurityError, "volume path must be a string"
      end

      def ensure_attached(record, node)
        return record unless node && record.attachments.key?(node.to_s)

        record
      end

      def attached_node(record)
        record.attachments.keys.first || raise(ConflictError, "volume #{record.id} is not controller-attached")
      end

      def stage_for(record, node)
        return record.stages.values.first["target"] if node.nil? && record.stages.length == 1

        value = record.stages.values.find { |entry| node.nil? || entry["node"].to_s == node.to_s }
        return value["target"] if value

        raise ConflictError, "volume #{record.id} has no stage path on node #{node}"
      end

      def mount_identity(entry)
        @manager.mount_ledger.identity_for(entry)
      end

      def pod_identifier(pod)
        return Types.identifier(pod, "pod") unless Capability.hash_like?(pod)

        metadata = Types.key(pod.to_h, "metadata", {})
        Types.identifier(Types.key(metadata, "uid", Types.key(metadata, "name", "pod")), "pod")
      end

      # PodSecurityContext.fsGroupChangePolicy: "Always" (the default) or
      # "OnRootMismatch", which skips the ownership walk when the volume root
      # already carries the desired group.
      def fs_group_change_policy(pod)
        return nil unless Capability.hash_like?(pod)

        value = Types.key(Types.key(Types.key(pod.to_h, "spec", {}), "securityContext", {}), "fsGroupChangePolicy", nil)
        value&.to_s
      end

      def apply_security!(backend, stage_path:, pod:, readonly:, fs_group:, selinux_label:, mount_propagation:, context:)
        adapter = @manager.mount_adapter
        if fs_group && Capability.applies_fs_group?(adapter)
          AdapterSupport.call(adapter, :apply_fs_group, path: stage_path, fs_group: fs_group, pod: pod,
                                                        readonly: readonly, change_policy: fs_group_change_policy(pod))
        elsif fs_group
          raise SecurityError, "fsGroup was requested but no injected adapter can apply it"
        end
        if selinux_label && Capability.applies_selinux_label?(adapter)
          AdapterSupport.call(adapter, :apply_selinux_label, path: stage_path, label: selinux_label)
        elsif selinux_label
          raise SecurityError, "SELinux label was requested but no injected adapter can apply it"
        end
        if mount_propagation && Capability.applies_mount_propagation?(adapter)
          AdapterSupport.call(adapter, :apply_mount_propagation, path: stage_path, propagation: mount_propagation)
        elsif mount_propagation
          raise SecurityError, "mountPropagation was requested but no injected adapter can apply it"
        end
        raise SecurityError, "read-only volume cannot be published writable" if backend.readonly? && !readonly

        true
      end
    end
  end
end
