# frozen_string_literal: true

require "digest"
require "json"
require "time"

require_relative "errors"
require_relative "types"

module Rubernetes
  module Volume
    # A CSI driver as the kubelet uses it (pkg/volume/csi, v1.36.2): the node
    # plugin registered through the plugin registry serves only Identity and
    # Node, so the kubelet never creates, deletes, ControllerPublishes or
    # ControllerUnpublishes.
    #
    #   * create_volume: the PersistentVolume's volumeHandle (or, for an
    #     inline ephemeral volume, csi-<sha256(podUID + volume name)>)
    #   * publish (attach): waits for the attach/detach controller's
    #     VolumeAttachment csi-<sha256(handle + driver + node)> to report
    #     attached, and hands its attachmentMetadata on as publish context --
    #     unless the CSIDriver says attachRequired: false, or the volume is
    #     ephemeral
    #   * stage / unstage: only with STAGE_UNSTAGE_VOLUME; otherwise skipped
    #     and NodePublishVolume gets no staging path
    #   * publish_node: the volume context gains the Pod's identity when the
    #     CSIDriver asks (podInfoOnMount), "csi.storage.k8s.io/ephemeral", and
    #     the ServiceAccount tokens the CSIDriver's tokenRequests name
    class KubernetesCSIAdapter
      POD_NAME = "csi.storage.k8s.io/pod.name"
      POD_NAMESPACE = "csi.storage.k8s.io/pod.namespace"
      POD_UID = "csi.storage.k8s.io/pod.uid"
      SERVICE_ACCOUNT = "csi.storage.k8s.io/serviceAccount.name"
      EPHEMERAL = "csi.storage.k8s.io/ephemeral"
      TOKENS = "csi.storage.k8s.io/serviceAccount.tokens"
      STAGE_UNSTAGE = "STAGE_UNSTAGE_VOLUME"
      GET_VOLUME_STATS = "GET_VOLUME_STATS"
      EXPAND_VOLUME = "EXPAND_VOLUME"
      VOLUME_MOUNT_GROUP = "VOLUME_MOUNT_GROUP"
      FS_GROUP_POLICIES = %w[ReadWriteOnceWithFSType File None].freeze
      ATTACH_TIMEOUT = 60.0
      ATTACH_POLL = 0.5

      attr_reader :driver, :bridge

      # +api+: #get(resource, name, namespace:, api_version:) and
      # #create_token(namespace, service_account, request) for tokenRequests.
      def initialize(driver:, bridge:, api:, node_name:, attach_timeout: ATTACH_TIMEOUT, sleeper: ->(seconds) { sleep(seconds) },
                     clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @driver = driver.to_s
        @bridge = bridge
        @api = api
        @node_name = node_name.to_s
        @attach_timeout = Float(attach_timeout)
        @sleeper = sleeper
        @clock = clock
        @mutex = Mutex.new
        @node_capabilities = nil
      end

      def requires_republish?
        driver_object&.dig("spec", "requiresRepublish") == true
      end

      # RemoteBackend passes the Pod and the ephemeral flag to publish_node.
      def pod_context? = true

      def identity = @bridge.identity
      def probe = @bridge.probe
      def ready? = @bridge.respond_to?(:ready?) ? @bridge.ready? : true

      def capabilities
        {"plugin" => [], "controller" => [], "node" => node_capabilities}
      end

      def supports?(capability)
        node_capabilities.any? { |value| value.casecmp?(capability.to_s) }
      end

      def node_capabilities
        @mutex.synchronize { @node_capabilities ||= @bridge.node_capabilities.map(&:to_s).freeze }
      end

      # makeVolumeHandle for inline volumes; the PV's handle otherwise.
      def self.inline_volume_handle(pod_uid, volume_name)
        "csi-#{Digest::SHA256.hexdigest("#{pod_uid}#{volume_name}")}"
      end

      def self.attachment_name(handle, driver, node_name)
        "csi-#{Digest::SHA256.hexdigest("#{handle}#{driver}#{node_name}")}"
      end

      def create_volume(spec, token: nil)
        handle = Types.key(spec, "volumeHandle").to_s
        raise CSIError.new("CSI volume for driver #{@driver} has no volumeHandle", operation: "CreateVolume") if handle.empty?

        {"volumeId" => handle, "volumeContext" => Types.deep_copy(Types.key(spec, "volumeAttributes", {}) || {}),
         "ephemeral" => ephemeral?(spec)}
      end

      def delete_volume(_id, token: nil, secrets: {})
        {}
      end

      # The attach/detach controller, not the kubelet, attaches.
      def publish(id, node, token: nil, readonly: false, context: {})
        return {"volumeId" => id.to_s, "node" => node.to_s, "publishContext" => {}} if ephemeral_context?(context) || !attach_required?

        name = self.class.attachment_name(id, @driver, node.to_s.empty? ? @node_name : node)
        deadline = @clock.call + @attach_timeout
        loop do
          attachment = begin
            @api.get("volumeattachments", name, namespace: nil, api_version: "storage.k8s.io/v1")
          rescue StandardError
            nil
          end
          status = attachment.is_a?(Hash) ? (attachment["status"] || {}) : {}
          return {"volumeId" => id.to_s, "node" => node.to_s, "publishContext" => (status["attachmentMetadata"] || {}).to_h} if status["attached"] == true

          error = status.dig("attachError", "message")
          if @clock.call >= deadline
            detail = error ? ": #{error}" : ""
            raise CSIError.new("timed out waiting for external-attacher of #{@driver} to attach volume #{id} (VolumeAttachment #{name})#{detail}",
                               operation: "ControllerPublishVolume")
          end
          @sleeper.call(ATTACH_POLL)
        end
      end

      def unpublish(_id, _node, token: nil, context: {})
        {}
      end

      # csi_attacher MountDevice: only a persistent volume of a driver with
      # STAGE_UNSTAGE_VOLUME is staged.
      def stage(id, path, token: nil, readonly: false, context: {})
        request = Types.deep_copy(context || {})
        if ephemeral_context?(request) || !supports?(STAGE_UNSTAGE)
          # Nothing is mounted at the staging path, which the backend
          # records as an unmounted stage.
          return {"volumeId" => id.to_s, "target" => path.to_s, "stage" => true, "mounted" => false, "stageSkipped" => true}
        end

        fs_group = request.delete("fsGroup")
        mount_group = fs_group && supports?(VOLUME_MOUNT_GROUP) ? fs_group.to_s : nil
        request["mount"] = mount_capability(request, mount_group)
        @bridge.stage(id, path, token: token, readonly: readonly, context: strip_kubelet_keys(request))
      end

      def unstage(id, path, token: nil)
        return {} unless supports?(STAGE_UNSTAGE)

        @bridge.unstage(id, path, token: token)
      end

      # csi_mounter SetUpAt.
      def publish_node(id, stage_path, target, token: nil, readonly: false, context: {})
        request = Types.deep_copy(context || {})
        pod = request.delete("pod")
        ephemeral = ephemeral_context?(request)
        csi_driver = driver_object
        check_lifecycle_mode!(csi_driver, ephemeral)
        fs_group_policy(csi_driver)
        volume_context = (Types.key(request, "volumeContext", {}) || {}).to_h.transform_keys(&:to_s)
        if csi_driver && csi_driver.dig("spec", "podInfoOnMount") == true && pod.is_a?(Hash)
          metadata = pod["metadata"] || {}
          volume_context[POD_NAME] = metadata["name"].to_s
          volume_context[POD_NAMESPACE] = metadata["namespace"].to_s
          volume_context[POD_UID] = metadata["uid"].to_s
          volume_context[SERVICE_ACCOUNT] = service_account(pod)
          volume_context[EPHEMERAL] = ephemeral.to_s
        end
        tokens = service_account_tokens(csi_driver, pod)
        if tokens
          if csi_driver.dig("spec", "serviceAccountTokenInSecrets") == true
            request["secrets"] = (Types.key(request, "secrets", {}) || {}).to_h.merge(TOKENS => JSON.generate(tokens))
          else
            volume_context[TOKENS] = JSON.generate(tokens)
          end
        end
        request["volumeContext"] = volume_context
        # Only a persistent volume carries publish context and mount options.
        request["publishContext"] = {} if ephemeral
        mount_group = request.delete("volumeMountGroup")
        request["mount"] = mount_capability(request, mount_group && supports?(VOLUME_MOUNT_GROUP) ? mount_group.to_s : nil)
        staging = !ephemeral && supports?(STAGE_UNSTAGE) ? stage_path : ""
        @bridge.publish_node(id, staging, target, token: token, readonly: readonly, context: strip_kubelet_keys(request))
      end

      # supportsFSGroup and the VOLUME_MOUNT_GROUP delegation: :delegate
      # (the driver applies it through volume_mount_group), :kubelet (the
      # kubelet changes the published target's ownership) or :none.
      def fs_group_mode(fs_group:, fs_type:, access_modes:, ephemeral:, readonly:)
        return :none if fs_group.nil?
        return :delegate if supports?(VOLUME_MOUNT_GROUP)

        policy = fs_group_policy(driver_object)
        return :none if policy == "None" || readonly
        return :kubelet if policy == "File"
        return :none if fs_type.to_s.empty?
        return :kubelet if ephemeral

        (Array(access_modes).map(&:to_s) & %w[ReadWriteOnce]).empty? ? :none : :kubelet
      end

      def unpublish_node(id, target, token: nil)
        @bridge.unpublish_node(id, target, token: token)
      end

      def stats(id, token: nil, path: nil)
        raise CSIUnavailable, "CSI driver #{@driver} does not report volume stats" unless supports?(GET_VOLUME_STATS)

        @bridge.stats(id, token: token, path: path)
      end

      def expand_node(id, path, token: nil, capacity_bytes: nil, volume_capability: nil, secrets: {}, staging_path: nil)
        return {} unless supports?(EXPAND_VOLUME)

        options = {token: token, capacity_bytes: capacity_bytes, volume_capability: volume_capability, secrets: secrets}
        # csi_expander: the staging path only for a driver that stages.
        options[:staging_path] = staging_path if staging_path && supports?(STAGE_UNSTAGE)
        @bridge.expand_node(id, path, **options)
      end

      private

      KUBELET_KEYS = %w[ephemeral fsType mountOptions fsGroup volumeMountGroup].freeze

      def strip_kubelet_keys(request)
        request.reject { |key, _| KUBELET_KEYS.include?(key.to_s) }
      end

      # The mount capability: fsType, the PV's mountOptions, and the fsGroup
      # when the driver applies it.
      def mount_capability(request, mount_group)
        mount = (Types.key(request, "mount", {}) || {}).to_h.transform_keys(&:to_s)
        fs_type = Types.key(request, "fsType", "").to_s
        mount["fsType"] = fs_type unless fs_type.empty? || mount.key?("fsType")
        options = Array(Types.key(request, "mountOptions", [])).map(&:to_s)
        mount["mountFlags"] = (Array(mount["mountFlags"]).map(&:to_s) + options).uniq unless options.empty?
        mount["volumeMountGroup"] = mount_group if mount_group
        mount
      end

      # supportsVolumeLifecycleMode: without a CSIDriver only persistent
      # volumes are supported; otherwise the mode must be listed.
      def check_lifecycle_mode!(csi_driver, ephemeral)
        mode = ephemeral ? "Ephemeral" : "Persistent"
        if csi_driver.nil?
          return true unless ephemeral

          raise CSIError.new("volume mode #{mode.inspect} not supported by driver #{@driver} (no CSIDriver object)",
                             operation: "NodePublishVolume")
        end
        modes = Array(csi_driver.dig("spec", "volumeLifecycleModes"))
        modes = ["Persistent"] if modes.empty?
        return true if modes.include?(mode)

        raise CSIError.new("volume mode #{mode.inspect} not supported by driver #{@driver} (only supports #{modes.inspect})",
                           operation: "NodePublishVolume")
      end

      # getFSGroupPolicy: the API defaults a CSIDriver's fsGroupPolicy, so an
      # object without one is an error; no CSIDriver means the default.
      def fs_group_policy(csi_driver)
        return "ReadWriteOnceWithFSType" if csi_driver.nil?

        policy = csi_driver.dig("spec", "fsGroupPolicy").to_s
        unless FS_GROUP_POLICIES.include?(policy)
          raise CSIError.new("expected valid fsGroupPolicy, received #{policy.empty? ? "nil value or empty string" : policy.inspect}",
                             operation: "NodePublishVolume")
        end

        policy
      end

      def ephemeral?(spec) = Types.key(spec, "ephemeral", false) == true
      def ephemeral_context?(context) = Types.key(context || {}, "ephemeral", false) == true

      def driver_object
        @api.get("csidrivers", @driver, namespace: nil, api_version: "storage.k8s.io/v1")
      rescue StandardError
        nil
      end

      # csi_attacher: a driver without a CSIDriver object needs attaching.
      def attach_required?
        object = driver_object
        return true unless object.is_a?(Hash)

        object.dig("spec", "attachRequired") != false
      end

      def service_account(pod)
        spec = pod["spec"] || {}
        (spec["serviceAccountName"] || spec["serviceAccount"] || "default").to_s
      end

      # csi_mounter podServiceAccountTokenAttrs: a token per requested
      # audience, bound to the Pod.
      def service_account_tokens(csi_driver, pod)
        requests = Array(csi_driver&.dig("spec", "tokenRequests"))
        return nil if requests.empty? || !pod.is_a?(Hash) || !@api.respond_to?(:create_token)

        metadata = pod["metadata"] || {}
        requests.to_h do |request|
          audience = request["audience"].to_s
          body = {"apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenRequest",
                  "spec" => {"audiences" => audience.empty? ? [] : [audience],
                             "boundObjectRef" => {"apiVersion" => "v1", "kind" => "Pod", "name" => metadata["name"],
                                                  "uid" => metadata["uid"]}}}
          body["spec"]["expirationSeconds"] = Integer(request["expirationSeconds"]) if request["expirationSeconds"]
          status = (@api.create_token(metadata["namespace"].to_s, service_account(pod), body) || {})["status"] || {}
          [audience, {"token" => status["token"].to_s, "expirationTimestamp" => status["expirationTimestamp"].to_s}]
        end
      end
    end

    # A volume's view of the kubelet plugin registry: every call resolves the
    # driver's currently registered node plugin, so a volume recovered before
    # its driver re-registers (or across a plugin restart) keeps a backend,
    # and an unregistered driver is a retryable CSIUnavailable at the call.
    class RegisteredCSIDriver
      METHODS = %i[identity probe ready? capabilities supports? node_capabilities create_volume delete_volume publish
                   unpublish stage unstage publish_node unpublish_node stats expand_node fs_group_mode
                   requires_republish?].freeze

      attr_reader :driver

      def initialize(registry, driver)
        @registry = registry
        @driver = driver.to_s
      end

      def pod_context? = true

      METHODS.each do |name|
        define_method(name) do |*args, **kwargs|
          target = @registry.for_driver(@driver)
          method = target.method(name)
          parameters = method.parameters
          unless parameters.any? { |kind, _| kind == :keyrest }
            kwargs = kwargs.select { |key, _| parameters.any? { |kind, param| %i[key keyreq].include?(kind) && param == key.to_sym } }
          end
          method.call(*args, **kwargs)
        end
      end
    end
  end
end
