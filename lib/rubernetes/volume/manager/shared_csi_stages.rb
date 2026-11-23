# frozen_string_literal: true

module Rubernetes
  module Volume
    # Kubelet stages a persistent CSI volume once on a node, and publishes
    # it separately into each Pod. Each Pod's durable volume record retains
    # its reference to the common stage until its own last publish is gone.
    module SharedCSIStages
      # Kubernetes CSI drivers are given the staging directory
      # beneath the kubelet plugin directory they mount with Bidirectional
      # propagation. The stage key remains the internal ledger identifier.
      class KubeletPaths
        attr_reader :directory

        def initialize(root)
          @directory = File.join(root, "plugins", "kubernetes.io", "csi")
        end

        def stage_path(driver, handle, block: false)
          raise ValidationError, "CSI driver name cannot be used as a plugin directory" unless driver.match?(/\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z/)

          digest = Digest::SHA256.hexdigest(handle)
          return File.join(directory, "volumeDevices", "staging", driver, digest) if block

          File.join(directory, driver, digest, "globalmount")
        end

        def stage_path?(path)
          relative = path.to_s.delete_prefix("#{directory}/")
          return false if relative == path

          relative.match?(%r{\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?/[0-9a-f]{64}/globalmount\z}) ||
            relative.match?(%r{\AvolumeDevices/staging/[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?/[0-9a-f]{64}\z})
        end
      end

      def self.references(store, stage_key, except: nil)
        store.values.flat_map do |record|
          record.stages.filter_map do |path, identity|
            [record, path, identity] if identity["sharedCSIStage"] == stage_key && [record.id, path] != except
          end
        end
      end

      private

      def stage_destination(id, path, node)
        record = @manager.fetch_record(id)
        existing = record.stages[path]
        return [existing.fetch("target"), existing["sharedCSIStage"]] if existing

        backend = @manager.backends[id]
        key = backend.shared_stage_key(node || record.attachments.keys.first) if backend.is_a?(RemoteBackend)
        return [path, nil] unless key

        previous_target = shared_stage_references(key, id, path).first&.last&.fetch("target")
        target = previous_target || shared_stage_target(backend, key)
        [secure_path(target), key]
      end

      def shared_stage_target(backend, key)
        paths = @manager.kubelet_csi_paths
        path = backend.kubelet_stage_path(paths) if paths
        path || @manager.legacy_csi_stage_path(key)
      end

      def stage_volume(backend, record, path, target:, stage_key:, node:, readonly:, context:, token:, effect_boundary:)
        return perform_stage(backend, record, path, target, node, readonly, context, token, effect_boundary) unless stage_key

        @manager.with_volume_lock(stage_key) do
          existing = shared_stage_references(stage_key, record.id, path).first&.last
          if existing
            backend.verify_shared_stage!(existing)
            record_stage(record.id, record, backend, path, existing.merge("volumeId" => record.id), register: false)
          else
            FileUtils.mkdir_p(File.dirname(target))
            perform_stage(backend, record, path, target, node, readonly, context, token, effect_boundary, stage_key: stage_key)
          end
        end
      end

      def perform_stage(backend, record, path, target, node, readonly, context, token, effect_boundary, stage_key: nil)
        effective_context = @manager.context_for_node(record, node, context)
        result = stage_on_backend(backend, path: target, node: node, readonly: readonly,
                                           context: effective_context, effect_boundary: effect_boundary)
        record = expand_node_if_required(backend, record, target, token, effect_boundary)
        result["node"] = node
        result["sharedCSIStage"] = stage_key if stage_key
        begin
          record_stage(record.id, record, backend, path, result)
        rescue StandardError => error
          raise_with_cleanup(error) do
            backend.unstage(path: target, identity: result, context: effective_context)
            @manager.mount_ledger.remove(identity: mount_identity(result), expected: result) if stage_key
          end
        end
      end

      def teardown_stage(record, path, entry, context, effect_boundary)
        stage_key = entry["sharedCSIStage"]
        unless stage_key
          unstage_on_backend(record, path, entry, context, effect_boundary)
          return forget_stage_reference(record, path)
        end

        @manager.with_volume_lock(stage_key) do
          if shared_stage_references(stage_key, record.id, path).empty?
            unstage_on_backend(record, entry.fetch("target"), entry, context, effect_boundary)
            remove_empty_stage_directory(entry.fetch("target"))
          end
          forget_stage_reference(record, path)
        end
      end

      def shared_stage_references(stage_key, id, path)
        SharedCSIStages.references(@manager.volume_store, stage_key, except: [id, path])
      end

      def interrupted_shared_stage(record, path)
        operation = @manager.operations.fetch(key: record.id, operation: "stage:#{path}")
        return unless operation && %w[effecting unknown].include?(operation.status)

        stage_key, target, node = (operation.payload || {}).values_at("sharedCSIStage", "stageTarget", "node")
        return unless stage_key && target

        backend = @manager.backends[record.id]
        return unless target == @manager.legacy_csi_stage_path(stage_key) ||
                      (backend.is_a?(RemoteBackend) && target == shared_stage_target(backend, stage_key))

        secure_path(target)

        # NodeUnstage is idempotent even if NodeStage's response was lost.
        # The backend still rejects an unknown mount at the reserved target.
        {"target" => target, "sharedCSIStage" => stage_key, "node" => node, "stage" => true, "mounted" => false}
      end

      def remove_empty_stage_directory(target)
        Dir.rmdir(target)
      rescue Errno::ENOENT, Errno::ENOTEMPTY
        nil
      end

      def unstage_on_backend(record, target, entry, context, effect_boundary)
        backend = @manager.backends.fetch(record.id)
        effective_context = @manager.context_for_node(record, entry["node"], context)
        if backend.is_a?(RemoteBackend)
          backend.unstage(path: target, identity: entry, context: effective_context, effect_boundary: effect_boundary)
        else
          backend.unstage(path: target, identity: entry, context: effective_context)
        end
        @manager.mount_ledger.remove(identity: mount_identity(entry), expected: entry)
      end

      def forget_stage_reference(record, path)
        stages = Types.deep_copy(record.stages)
        stages.delete(path)
        state = record.attachments.empty? ? "Detached" : "Attached"
        @manager.volume_store[record.id] = record.with(state: state, stages: stages, generation: record.generation + 1)
      end
    end
  end
end
