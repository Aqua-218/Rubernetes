# frozen_string_literal: true

require_relative "remote_dispatch"
require_relative "remote_mount_readback"
require_relative "remote_target_leases"

# The CSI backend: one volume served by a CSI driver.  Every lifecycle call
# becomes a CSI RPC issued through Dispatch, on a target pinned by TargetLeases
# and, where a mount results, proven by MountReadback.
module Rubernetes
  module Volume
    class RemoteBackend < Backend
      include Dispatch
      include MountReadback
      include TargetLeases

      TYPE = "csi"

      def initialize(csi:, secret_provider: nil, persistence_sanitizer: nil, error_sanitizer: nil, **)
        raise CSIUnavailable, "CSI adapter is not configured" unless csi

        super(**)
        @csi = csi
        @secret_provider = secret_provider
        @persistence_sanitizer = persistence_sanitizer
        @error_sanitizer = error_sanitizer
        backend_result = Types.key(spec, "backendResult", {})
        @driver_volume_id = Types.key(backend_result, "volumeId", Types.key(backend_result, "volume_id"))
      end

      attr_reader :driver_volume_id

      def provision(token:, effect_boundary: nil)
        request = Types.deep_copy(spec).merge("secrets" => secrets_for(:create_volume))
        result = sanitize_response(AdapterSupport.result_hash(
          invoke_remote_mutation(effect_boundary) { invoke_csi(:create_volume, request, token: token) }
        ))
        @driver_volume_id = Types.identifier(
          Types.key(result, "volumeId", Types.key(result, "volume_id")), "CSI driver volume id"
        )
        result
      end

      def remote?
        true
      end

      # csi_expander NodeExpand for a published volume (the kubelet's
      # ExpandInUseVolume): :unsupported without EXPAND_VOLUME.
      def kubelet_expand(target:, stage_path:, capacity_bytes:, token:)
        return nil unless kubelet_csi?
        return :unsupported unless @csi.supports?("EXPAND_VOLUME")

        ensure_path!(target)
        with_secure_csi_target(target, directory: nil, create: false, post_effect: :mounted) do |dispatch_path, _lease|
          sanitize_response(AdapterSupport.result_hash(
            invoke_csi(:expand_node, remote_id, dispatch_path, token: token, capacity_bytes: capacity_bytes,
                                                               volume_capability: csi_volume_capability,
                                                               secrets: secrets_for(:node_expand), staging_path: stage_path)
          ))
        end
      end

      # csi metricsCsi: NodeGetVolumeStats on a published target, or
      # :unsupported without GET_VOLUME_STATS; nil for a plugin that is not
      # a kubelet node plugin.
      def kubelet_volume_stats(path)
        return nil unless kubelet_csi?
        return :unsupported unless @csi.supports?("GET_VOLUME_STATS")

        ensure_path!(path)
        with_secure_csi_target(path, directory: nil, create: false, post_effect: :mounted) do |dispatch_path, _lease|
          sanitize_response(AdapterSupport.result_hash(invoke_csi(:stats, remote_id, path: dispatch_path)))
        end
      end

      # CSIDriver.spec.requiresRepublish: the kubelet calls NodePublishVolume
      # again periodically (fresh ServiceAccount tokens, rotated content).
      def requires_republish?
        Capability.declares_republish?(@csi) && @csi.requires_republish? == true
      end

      # The periodic remount: NodePublishVolume on the existing target, with
      # the context rebuilt as at publish.
      def republish(stage_path:, target:, pod:, token:, readonly: false, context: {})
        ensure_path!(stage_path)
        ensure_path!(target)
        remote_context = kubelet_csi_context(with_secrets(Types.deep_copy(context), :node_publish))
        remote_context["pod"] = Types.deep_copy(pod) if kubelet_csi? && pod.is_a?(Hash)
        target_directory = !Types.key(spec, "volumeMode", "Filesystem").to_s.casecmp?("Block")
        with_secure_csi_target(stage_path, directory: true, create: false, post_effect: :mounted) do |dispatch_stage, _stage_lease|
          with_secure_csi_target(target, directory: target_directory, create: false, post_effect: :mounted) do |dispatch_target, _lease|
            sanitize_response(AdapterSupport.result_hash(
              invoke_csi(:publish_node, remote_id, dispatch_stage, dispatch_target, token: token,
                                                                                    readonly: readonly || readonly?, context: remote_context)
            ))
          end
        end
      end

      # The kubelet CSI mounter's fsGroup decision for this volume: nil when
      # the adapter is not a kubelet node plugin (the stage-path pass
      # applies), otherwise :delegate, :kubelet or :none.
      def csi_fs_group_mode(fs_group, readonly:)
        return nil unless Capability.decides_fs_group?(@csi)

        @csi.fs_group_mode(fs_group: fs_group, fs_type: Types.key(spec, "fsType", "").to_s,
                           access_modes: Array(Types.key(spec, "accessModes", [])),
                           ephemeral: Types.key(spec, "ephemeral", false) == true, readonly: readonly || readonly?)
      end

      # ReadOnlyMany is a volume capability, not merely a caller hint.  Keep
      # it on the backend as well as in the ControllerPublish request so a
      # direct backend lifecycle call cannot accidentally issue a writable
      # NodePublishVolume/NodeStageVolume request.
      def readonly?
        Types.key(spec, "readOnly", Types.key(spec, "readonly", false)) == true ||
          Array(Types.key(spec, "accessModes", [])).map(&:to_s).include?("ReadOnlyMany")
      end

      def snapshot(token:, name: nil, effect_boundary: nil)
        secrets = secrets_for(:create_snapshot)
        sanitize_response(invoke_remote_mutation(effect_boundary) do
          invoke_csi(:create_snapshot, remote_id, token: token, name: name, secrets: secrets)
        end)
      end

      def delete(token:, effect_boundary: nil)
        secrets = secrets_for(:delete_volume)
        invoke_remote_mutation(effect_boundary) do
          invoke_csi(:delete_volume, remote_id, token: token, secrets: secrets)
        end
      end

      def attach(node:, context: {}, effect_boundary: nil)
        request_context = kubelet_csi_context(with_secrets(context, :controller_publish))
        sanitize_response(invoke_remote_mutation(effect_boundary) do
          invoke_csi(:publish, remote_id, node,
                     token: Types.key(context, "token", "attach-#{id}-#{node}"),
                     readonly: controller_readonly?(request_context), context: request_context)
        end)
      end

      def detach(node:, context: {}, effect_boundary: nil)
        request_context = with_secrets(context, :controller_unpublish)
        invoke_remote_mutation(effect_boundary) do
          invoke_csi(:unpublish, remote_id, node, token: Types.key(context, "token", "detach-#{id}-#{node}"),
                                                  context: request_context)
        end
      end

      def delete_snapshot(snapshot_id, token:, effect_boundary: nil)
        secrets = secrets_for(:delete_snapshot)
        invoke_remote_mutation(effect_boundary) do
          invoke_csi(:delete_snapshot, snapshot_id, token: token, secrets: secrets)
        end
      end

      def stage(path:, node:, readonly: false, context: {}, effect_boundary: nil)
        ensure_path!(path)
        request_context = kubelet_csi_context(with_secrets(context, :node_stage))
        token = Types.key(context, "token", "stage-#{id}-#{node}")
        with_secure_csi_target(
          path, directory: true, create: true, post_effect: :mounted,
                compensation: lambda do |dispatch_path, original_path|
                  compensate_stage_mount!(dispatch_path, original_path, token: token)
                end
        ) do |dispatch_path, lease|
          response = invoke_remote_mutation(effect_boundary) do
            invoke_csi(:stage, remote_id, dispatch_path,
                       token: token,
                       readonly: readonly || readonly?, context: request_context)
          end
          normalize_remote_mount(response, path, stage: true,
                                                 aliases: [dispatch_path], path_identity: lease&.identity)
        end
      end

      def unstage(path:, identity: nil, context: {}, effect_boundary: nil)
        ensure_path!(path)
        # A stage the plugin completed without a kernel mount has no mount
        # identity to verify; the target must nevertheless still be absent
        # from mountinfo, otherwise a foreign mount appeared under our path.
        if unmounted_stage_identity?(identity)
          raise MountIdentityError, "CSI stage #{path.inspect} was recorded unmounted but a mount now covers it" if remote_mount_readback(path)
        else
          verify_mount_identity!(path, identity)
        end
        with_secure_csi_target(path, directory: true, create: false, post_effect: :removed) do |dispatch_path, _lease|
          invoke_remote_mutation(effect_boundary) do
            invoke_csi(:unstage, remote_id, dispatch_path, token: Types.key(context, "token", "unstage-#{id}"))
          end
          verify_remote_absent!(path, aliases: [dispatch_path]) if @require_real_readback
        end
        true
      end

      def publish(stage_path:, target:, node:, pod:, readonly: false, sub_path: nil, context: {}, effect_boundary: nil)
        ensure_path!(stage_path)
        ensure_path!(target)
        parent_handle = nil
        handle = nil
        remote_context = Types.deep_copy(context)
        if sub_path
          raise PathSecurityError, "subPath requires openat2 descriptor validation" unless @path_security

          parent_handle = open_stage_handle(stage_path)
          begin
            # A read-only volume is never modified to satisfy a subPath.
            handle = @path_security.validate_sub_path!(parent_handle, sub_path,
                                                       create: !(readonly || readonly?))
          ensure
            parent_handle.close unless handle && parent_handle.equal?(handle)
            nil
          end
          remote_context["subPath"] = handle.path.to_s if Capability.exposes_path?(handle)
          remote_context["subPathIdentity"] = handle.identity if Capability.exposes_identity?(handle)
        end
        remote_context = kubelet_csi_context(with_secrets(remote_context, :node_publish))
        # The kubelet's CSI mounter passes the Pod's identity and the
        # ServiceAccount tokens in the volume context.
        remote_context["pod"] = Types.deep_copy(pod) if kubelet_csi? && pod.is_a?(Hash)
        target_directory = !Types.key(spec, "volumeMode", "Filesystem").to_s.casecmp?("Block")
        with_secure_csi_target(stage_path, directory: true, create: false, post_effect: :mounted) do |dispatch_stage, _stage_lease|
          with_secure_csi_target(
            target, directory: target_directory, create: true, post_effect: :mounted,
                    compensation: lambda do |dispatch_path, original_path|
                      compensate_publish_mount!(dispatch_path, original_path,
                                                token: Types.key(context, "token", "publish-#{id}-#{target}"))
                    end
          ) do |dispatch_target, target_lease|
            response = invoke_remote_mutation(effect_boundary) do
              invoke_csi(:publish_node, remote_id, dispatch_stage, dispatch_target,
                         token: Types.key(context, "token", "publish-#{id}-#{target}"),
                         readonly: readonly || readonly?, context: remote_context)
            end
            result = normalize_remote_mount(response, target, stage: false,
                                                              aliases: [dispatch_target], path_identity: target_lease&.identity)
            result["node"] = node.to_s
            result["pod"] = pod_identifier(pod)
            result
          end
        end
      ensure
        handle&.close
      end

      def unpublish(target:, identity: nil, context: {}, effect_boundary: nil)
        ensure_path!(target)
        verify_mount_identity!(target, identity)
        with_secure_csi_target(target, directory: nil, create: false, post_effect: :removed) do |dispatch_target, _lease|
          invoke_remote_mutation(effect_boundary) do
            invoke_csi(:unpublish_node, remote_id, dispatch_target,
                       token: Types.key(context, "token", "unpublish-#{id}-#{target}"))
          end
          verify_remote_absent!(target, aliases: [dispatch_target]) if @require_real_readback
        end
        true
      end

      def stats(path:, capacity_bytes: nil)
        ensure_path!(path)
        value = with_secure_csi_target(path, directory: nil, create: false, post_effect: :mounted) do |dispatch_path, _lease|
          invoke_csi(:stats, remote_id, path: dispatch_path)
        end
        hash = AdapterSupport.result_hash(value)
        Stats.new(volume_id: id, used_bytes: hash["usedBytes"] || 0, capacity_bytes: hash["capacityBytes"] || capacity_bytes || 0,
                  available_bytes: hash["availableBytes"])
      end

      def expand(capacity_bytes:, token:, node_paths: [], effect_boundary: nil)
        # ControllerExpandVolume can change remote state before NodeExpandVolume
        # runs. Acquire every node target first so a descriptor-less/raw-path
        # profile makes zero CSI calls and any parent/leaf replacement is
        # detected before the controller mutation crosses its effect boundary.
        ensure_descriptor_target_security!
        target_paths = Array(node_paths).map { |path| File.expand_path(ensure_path!(path).to_s) }.uniq
        secrets = secrets_for(:expand)
        with_target_leases(target_paths, post_effect: :mounted) do |leases|
          response = sanitize_response(invoke_remote_mutation(effect_boundary) do
            invoke_csi(:expand, remote_id, capacity_bytes, token: token, secrets: secrets,
                                                           volume_capability: csi_volume_capability)
          end)
          verify_target_leases!(leases, post_effect: :mounted)
          required = Types.key(response, "nodeExpansionRequired", Types.key(response, "node_expansion_required", false)) == true
          expanded_paths = []
          if required
            leases.each do |path, lease|
              # Same contract as with_secure_csi_target: the plugin acts on
              # the canonical path while the lease pins the inode.
              invoke_csi(:expand_node, remote_id, lease.original_path,
                         token: "#{token}:node:#{Types.digest(path)[0, 16]}",
                         capacity_bytes: capacity_bytes,
                         volume_capability: csi_volume_capability,
                         secrets: secrets_for(:node_expand))
              verify_target_leases!([[path, lease]], post_effect: :mounted)
              expanded_paths << path
            rescue OperationUnknown
              raise
            rescue StandardError => error
              raise OperationUnknown.new("CSI NodeExpandVolume failed after controller expansion: #{sanitize_error(error).message}"),
                    cause: error
            end
          end
          {
            "capacityBytes" => Types.key(response, "capacityBytes", capacity_bytes),
            "nodeExpansionRequired" => required,
            "nodeExpandedPaths" => expanded_paths
          }
        end
      end

      def expand_node(path:, capacity_bytes:, token:, effect_boundary: nil)
        ensure_path!(path)
        effect_boundary&.call
        response = perform_node_expand(path: path, capacity_bytes: capacity_bytes, token: token)
        sanitize_response(response)
      rescue StandardError => error
        raise OperationUnknown.new("CSI NodeExpandVolume result is unknown: #{sanitize_error(error).message}"), cause: error
      end

      private

      def remote_id
        return @driver_volume_id if Types.present?(@driver_volume_id)

        raise CSIUnavailable, "CSI driver volume id mapping is missing for local volume #{id}"
      end

      def csi_volume_capability
        Types.deep_copy(Types.key(spec, "volumeCapability", {
                                    "accessModes" => Array(Types.key(spec, "accessModes", ["ReadWriteOnce"])),
                                    "volumeMode" => Types.key(spec, "volumeMode", "Filesystem")
                                  }))
      end

      def controller_readonly?(context)
        modes = Array(Types.key(context, "accessModes", Types.key(spec, "accessModes", []))).map(&:to_s)
        Types.key(spec, "readOnly", Types.key(spec, "readonly", false)) == true ||
          modes.include?("ReadOnlyMany") || readonly?
      end

      def compensate_stage_mount!(dispatch_path, original_path, token:)
        invoke_csi(:unstage, remote_id, dispatch_path, token: "#{token}:compensate")
        verify_remote_absent!(original_path, aliases: [dispatch_path]) if @require_real_readback
        true
      end

      def compensate_publish_mount!(dispatch_path, original_path, token:)
        invoke_csi(:unpublish_node, remote_id, dispatch_path, token: "#{token}:compensate")
        verify_remote_absent!(original_path, aliases: [dispatch_path]) if @require_real_readback
        true
      end

      def kubelet_csi?
        Capability.declares_pod_context?(@csi) && @csi.pod_context?
      end

      # What the kubelet sends a node plugin besides the manager's context:
      # the lifecycle mode, fsType and the PV's mountOptions.
      def kubelet_csi_context(context)
        return context unless kubelet_csi?

        context["ephemeral"] = Types.key(spec, "ephemeral", false) == true
        context["fsType"] = Types.key(spec, "fsType", "").to_s
        context["mountOptions"] = Array(Types.key(spec, "mountOptions", [])).map(&:to_s)
        # SELinuxMount: the file label as a mount flag (AddSELinuxMountOption).
        label = Types.key(spec, "selinuxMountLabel", nil).to_s
        context["mountOptions"] += [SELinux.mount_option(label)] unless label.empty? || context["mountOptions"].any? do |option|
          option.start_with?("context=")
        end
        context
      end

      def perform_node_expand(path:, capacity_bytes:, token:)
        ensure_path!(path)
        with_secure_csi_target(path, directory: nil, create: false, post_effect: :mounted) do |dispatch_path, _lease|
          invoke_csi(:expand_node, remote_id, dispatch_path, token: token,
                                                             capacity_bytes: capacity_bytes,
                                                             volume_capability: csi_volume_capability,
                                                             secrets: secrets_for(:node_expand))
        end
      end
    end
  end
end
