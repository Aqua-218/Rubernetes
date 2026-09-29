# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# The node side of NodeDeclaredFeatures: discovery at start
# (kubelet_node_declared_features.go), Node.status.declaredFeatures,
# the declaredFeaturesAdmitHandler (reason PodFeatureUnsupported) and the
# FailedNodeDeclaredFeaturesCheck warning on an update the node cannot serve.
class NodeDeclaredFeaturesAgentTest < Minitest::Test
  Node = Rubernetes::Node
  DECLARED = %w[ExtendWebSocketsToKubelet InPlacePodLevelResourcesVerticalScaling InPlacePodVerticalScalingInitContainers
                RestartAllContainersOnContainerExits].freeze
  RESTART_ALL = [{"action" => "RestartAllContainers", "exitCodes" => {"operator" => "In", "values" => [42]}}].freeze

  class API
    attr_reader :nodes

    def initialize = @nodes = []
    def register_node(node) = (@nodes << node).last
    def renew_lease(lease) = lease
  end

  class Loop
    def start(**) = true
    def stop(**) = true
  end

  class Lifecycle
    attr_accessor :pods

    def initialize = @pods = {}
    def recover(**) = {"ready" => true, "errors" => [], "blocked" => []}
    def record(uid) = @pods.key?(uid) ? {pod: @pods[uid]} : nil
  end

  class Recorder
    attr_reader :events

    def initialize = @events = []
    def record(**event) = @events << event
  end

  def test_discovery_declares_only_implemented_features_with_gates_on
    assert_equal DECLARED, Node::DeclaredFeatures.discover
    assert_nil Node::DeclaredFeatures.discover(feature_gates: {"NodeDeclaredFeatures" => false})
    assert_equal DECLARED - %w[RestartAllContainersOnContainerExits],
                 Node::DeclaredFeatures.discover(feature_gates: {"RestartAllContainersOnContainerExits" => false})
    # A gate that is on for a feature the node does not implement declares nothing.
    refute_includes Node::DeclaredFeatures.discover(implemented: Node::DeclaredFeatures::IMPLEMENTED.merge("ExtendWebSocketsToKubelet" => false)),
                    "ExtendWebSocketsToKubelet"
    refute_includes Node::DeclaredFeatures.discover(feature_gates: {"UserNamespacesHostNetworkSupport" => true},
                                                    runtime_features: {"userNamespacesHostNetwork" => true}),
                    "UserNamespacesHostNetworkSupport"
  end

  def test_node_status_carries_declared_features
    api = API.new
    agent = Node::Agent.new(node_name: "node-a", api: api, lifecycle: Lifecycle.new, sync_loop: Loop.new, sleeper: ->(_) {})
    agent.start
    assert_equal DECLARED, api.nodes.first.dig("status", "declaredFeatures")
    assert_equal DECLARED, agent.declared_features

    api = API.new
    Node::Agent.new(node_name: "node-b", api: api, lifecycle: Lifecycle.new, sync_loop: Loop.new, sleeper: ->(_) {},
                    feature_gates: {"NodeDeclaredFeatures" => false}).start
    refute api.nodes.first.fetch("status").key?("declaredFeatures")
  ensure
    agent&.stop rescue nil
  end

  def test_admission_rejects_pod_needing_undeclared_feature
    pod = {"metadata" => {"name" => "p", "uid" => "u"},
           "spec" => {"containers" => [{"name" => "c", "restartPolicyRules" => RESTART_ALL}]}}
    admission = Node::Admission.new(node_name: "n", capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "10"},
                                    declared_features: %w[ExtendWebSocketsToKubelet])
    decision = admission.admit(pod)
    refute decision.accepted
    assert_equal "PodFeatureUnsupported", decision.reason
    assert_equal "Pod requires node features that are not available: RestartAllContainersOnContainerExits", decision.message

    declaring = Node::Admission.new(node_name: "n", capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "10"},
                                    declared_features: DECLARED)
    assert declaring.admit(pod).accepted
    # With the gate off there is no handler at all.
    assert Node::Admission.new(node_name: "n", capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "10"}).admit(pod).accepted
  end

  def test_update_needing_undeclared_feature_is_reported
    lifecycle = Lifecycle.new
    recorder = Recorder.new
    # A node that does not declare pod-level resize (its gate is off).
    agent = Node::Agent.new(node_name: "node-a", api: API.new, lifecycle: lifecycle, sync_loop: Loop.new, sleeper: ->(_) {},
                            event_recorder: recorder, feature_gates: {"InPlacePodLevelResourcesVerticalScaling" => false})
    old_pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"},
               "spec" => {"resources" => {"limits" => {"cpu" => "1"}}, "containers" => [{"name" => "c"}]}}
    lifecycle.pods["u"] = old_pod
    agent.send(:check_declared_features_update, old_pod)
    assert_empty recorder.events

    resized = Marshal.load(Marshal.dump(old_pod))
    resized["spec"]["resources"]["limits"]["cpu"] = "2"
    agent.send(:check_declared_features_update, resized)
    event = recorder.events.fetch(0)
    assert_equal "FailedNodeDeclaredFeaturesCheck", event[:reason]
    assert_equal "Warning", event[:type]
    assert_equal "Pod requires node features that are not available: InPlacePodLevelResourcesVerticalScaling", event[:message]
    assert_equal "p", event.dig(:involved_object, "name")
  end
end
