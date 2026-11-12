# frozen_string_literal: true

module Rubernetes
  module Node
    class Agent
      # What plugs into the kubelet from outside the process: the plugin
      # registry (DRA drivers, CSI node plugins), image credential providers,
      # static Pod manifests, and the volume-side trackers that need the API.
      module Extensions
        private

        def error_handler_logger(error_handler)
          return nil unless error_handler

          Object.new.tap do |logger|
            logger.define_singleton_method(:warn) do |event, **fields|
              error_handler.call(RuntimeError.new("#{event} #{fields}"))
            end
          end
        end

        # Dynamic Resource Allocation on a real node: the kubelet plugin
        # registry (<root>/plugins_registry) and the DRA manager, whose claim
        # checkpoint lives in <root>/dra.  <root> is the parent of the Pod
        # directory, as /var/lib/kubelet is of /var/lib/kubelet/pods.
        #
        # CSI node plugins register through the same registry (type
        # CSIPlugin); the volume manager then resolves a volume's driver to
        # the registered plugin when no single CSI socket is configured.
        def initialize_plugin_registry(dra, kubelet_root, volume, dra_manager:, plugin_manager:, csi_plugins:)
          client = kubelet_root && api_client
          @dra_manager = dra_manager
          @dra_manager ||= build_dra_manager(dra, kubelet_root, client) if client && dra.fetch("enabled", true) != false
          @csi_plugins = csi_plugins
          if @csi_plugins.nil? && client && dra.fetch("csi_plugins", true) != false
            @csi_plugins = CSIPlugins.new(client: client, node_name: @node_name, error_handler: @error_handler)
          end
          volume.csi_registry = @csi_plugins if @csi_plugins && volume_manager?(volume)
          handlers = {"DRAPlugin" => @dra_manager, CSIPlugins::TYPE => @csi_plugins}.compact
          @plugin_manager = plugin_manager
          return unless @plugin_manager.nil? && !handlers.empty? && kubelet_root

          @plugin_manager = Plugins::Manager.new(directory: dra.fetch("plugins_registry", File.join(kubelet_root, "plugins_registry")),
                                                 handlers: handlers, error_handler: @error_handler)
        end

        def build_dra_manager(dra, kubelet_root, client)
          DRAManager.new(client: client, node_name: @node_name,
                         state_directory: dra.fetch("state_dir", File.join(kubelet_root, "dra")),
                         error_handler: @error_handler,
                         # ResourceHealthStatus (Beta, on): follow each driver's health stream.
                         resource_health: @feature_gates.fetch("ResourceHealthStatus", true) != false)
        end

        # The credential provider plugins, with the Pod-bound ServiceAccount
        # tokens they may ask for (TokenRequest with a Pod boundObjectRef).
        def build_credential_providers(section, api)
          section = Helpers.string_keys(section || {})
          return nil if section["config"].to_s.empty?

          client = api_client(api)
          CredentialProviders.load(config_path: section["config"], bin_dir: section["bin_dir"].to_s,
                                   token_requester: service_account_token_requester(client),
                                   service_account_reader: service_account_reader(client),
                                   sa_tokens: @feature_gates.fetch("KubeletServiceAccountTokenForCredentialProviders", true) != false)
        end

        def service_account_token_requester(client)
          lambda do |namespace, name, audience:, service_account_uid:, pod_name:, pod_uid:|
            raise "no API client for ServiceAccount tokens" unless client

            request = {"apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenRequest",
                       "metadata" => {"uid" => service_account_uid},
                       "spec" => {"audiences" => [audience],
                                  "boundObjectRef" => {"apiVersion" => "v1", "kind" => "Pod", "name" => pod_name, "uid" => pod_uid}}}
            response = client.raw("POST", "/api/v1/namespaces/#{namespace}/serviceaccounts/#{name}/token", body: JSON.generate(request),
                                                                                                           headers: {"Content-Type" => "application/json"})
            JSON.parse(response.body.to_s).dig("status", "token").to_s
          end
        end

        # The volume manager's SELinux desired-state checks (KEP-1710) on the
        # Pod volumes; CSIDriver.spec.seLinuxMount read through the node's reader.
        def attach_selinux_tracker
          pod_volumes = @lifecycle.pod_volumes
          return unless pod_volumes && pod_volumes.selinux_tracker.nil?

          pod_volumes.selinux_tracker = Volume::SELinux::Tracker.new(metrics: @kubelet_metrics, feature_gates: @feature_gates,
                                                                     csi_driver_reader: csi_driver_reader(@lifecycle.resource_reader),
                                                                     logger: @logger)
        end

        # PodCertificateRequest (feature gate, off by default): projected
        # podCertificate sources are served by the PodCertificateManager.
        def attach_pod_certificate_manager
          return unless @feature_gates.fetch("PodCertificateRequest", false) == true

          pod_volumes = @lifecycle.pod_volumes
          client = api_client
          return unless pod_volumes && client

          recorder = @event_recorder
          manager = PodCertificateManager.new(
            client: client, node_name: @node_name, logger: @logger,
            node_uid: lambda do
              node = client.get("nodes", @node_name, api_version: "v1")
              node.is_a?(Hash) ? node.dig("metadata", "uid").to_s : ""
            rescue StandardError
              ""
            end,
            events: lambda do |pod, type, reason, message|
              recorder&.record(involved_object: pod, reason: reason, message: message, type: type)
            end
          )
          pod_volumes.pod_certificates = manager
          @kubelet_metrics.pod_certificates = manager
          @pod_certificate_manager = manager.start
        end
      end
    end
  end
end
