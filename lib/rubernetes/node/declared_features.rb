# frozen_string_literal: true

require "json"

require_relative "../node_declared_features"

module Rubernetes
  module Node
    # pkg/kubelet/kubelet_node_declared_features.go: the features this node
    # declares in Node.status.declaredFeatures, discovered once at start from
    # the feature gates and the runtime's features.
    #
    # A node declares implemented features whose gates are enabled and whose
    # runtime-specific requirements match the configured runtime.
    module DeclaredFeatures
      IMPLEMENTED = {
        # node/streaming_server.rb: exec/attach/portforward over WebSocket
        # channel protocols (v5.channel.k8s.io, portforward.k8s.io v2).
        "ExtendWebSocketsToKubelet" => true,
        # node/lifecycle.rb resize_containers: init container resources are
        # resized in place like regular containers.
        "InPlacePodVerticalScalingInitContainers" => true,
        # node/lifecycle.rb restart_all_containers.
        "RestartAllContainersOnContainerExits" => true,
        # node/lifecycle.rb resize_pod + Runtime::Native#update_pod_resources:
        # pod-level resources are applied to the Pod cgroup and resized in place.
        "InPlacePodLevelResourcesVerticalScaling" => true,
        # CRI reports this only if the runtime and an available handler support it.
        "UserNamespacesHostNetworkSupport" => true
      }.freeze

      CORPUS = File.expand_path("../../../schema/kubernetes/v1.36.2-defaults/features.json", __dir__)

      module_function

      def discover_runtime_features(runtime)
        if (defined?(Runtime::Multiplexer) && runtime.is_a?(Runtime::Multiplexer)) ||
           (defined?(Runtime::CRI::Backend) && runtime.is_a?(Runtime::CRI::Backend))
          runtime.runtime_features
        else
          {}
        end
      end

      def default_gates
        @default_gates ||= if File.file?(CORPUS)
                             JSON.parse(File.read(CORPUS)).fetch("gates").transform_values { |gate| gate["default"] == true }.freeze
                           else
                             {}.freeze
                           end
      end

      # Sorted feature names to declare, or nil when NodeDeclaredFeatures is off
      # (the kubelet then publishes no declaredFeatures and runs no admit handler).
      def discover(feature_gates: {}, runtime_features: {}, framework: NodeDeclaredFeatures::DEFAULT_FRAMEWORK,
                   version: NodeDeclaredFeatures::KUBERNETES_VERSION, implemented: IMPLEMENTED)
        gates = default_gates.merge((feature_gates || {}).to_h { |name, value| [name.to_s, value == true] })
        return nil unless gates[NodeDeclaredFeatures::GATE]

        enabled = ->(name) { gates[name.to_s] == true && implemented[name.to_s] == true }
        config = NodeDeclaredFeatures::NodeConfiguration.new(feature_gates: enabled, version: version,
                                                             runtime_features: runtime_features || {})
        framework.discover_node_features(config)
      end
    end
  end
end
