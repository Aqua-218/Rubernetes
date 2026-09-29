# frozen_string_literal: true

require "json"

require_relative "../node_declared_features"

module Rubernetes
  module Node
    # pkg/kubelet/kubelet_node_declared_features.go: the features this node
    # declares in Node.status.declaredFeatures, discovered once at start from
    # the feature gates and the runtime's features.
    #
    # Upstream discovery is gate-only: a kubelet that has a feature's gate on
    # implements it.  Here a gate may be on while the behaviour behind it is
    # not built yet, and declaring such a feature would let the scheduler
    # and the API server send this node Pods it would mishandle.  A feature
    # is therefore declared only when its gate is on AND it is listed in
    # IMPLEMENTED below, with the code that provides it.
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
        # The native runtime does not report user namespaces with host
        # networking; discovery also requires the runtime feature.
        "UserNamespacesHostNetworkSupport" => false
      }.freeze

      CORPUS = File.expand_path("../../../schema/kubernetes/v1.36.2-defaults/features.json", __dir__)

      module_function

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
