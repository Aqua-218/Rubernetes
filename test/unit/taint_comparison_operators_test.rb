# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"
require "rubernetes/controller"
require "rubernetes/scheduler"

class TaintComparisonOperatorsTest < Minitest::Test
  API = Rubernetes::API
  Scheduler = Rubernetes::Scheduler
  GATE = Rubernetes::TaintToleration::GATE
  PODS = "/api/v1/namespaces/default/pods"

  def pod(value = "5", operator = "Gt")
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "sample", "namespace" => "default", "uid" => "sample"},
     "spec" => {"containers" => [{"name" => "app", "image" => "app"}],
                "tolerations" => [{"key" => "level", "operator" => operator, "value" => value}]}}
  end

  def node(value, effect)
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "node-#{value}"},
     "spec" => {"taints" => [{"key" => "level", "value" => value, "effect" => effect}]},
     "status" => {"allocatable" => {"cpu" => "2", "memory" => "4Gi", "pods" => "10"}}}
  end

  def request(api, method, path, object)
    content_type = method == "PATCH" ? "application/merge-patch+json" : "application/json"
    api.call(API::Request.new(method: method, path: path, headers: {"content-type" => content_type},
                              identity: {"username" => "admin", "groups" => ["system:masters"]}, body: JSON.generate(object)))
  end

  def test_admission_including_persisted_pod_after_gate_disable
    store = API::MemoryStore.new
    on = API::Server.new(store: store, feature_gates: {GATE => true})
    off = API::Server.new(store: store)
    denied = request(off, "POST", PODS, pod)

    assert_equal 422, denied.status, denied.body.inspect
    assert_equal "spec.tolerations[0].operator", denied.body.dig("details", "causes", 0, "field")
    ["01", "-0", "+1", "9223372036854775808", "", "asdf"].each do |invalid|
      result = request(on, "POST", PODS, pod(invalid))

      assert_equal 422, result.status, invalid
      assert_equal "spec.tolerations[0].value", result.body.dig("details", "causes", 0, "field")
    end
    result = request(on, "POST", PODS, pod("-9223372036854775808", "Lt"))

    assert_equal 201, result.status, result.body.inspect
    result = request(off, "PATCH", "#{PODS}/sample", {"metadata" => {"labels" => {"test" => "true"}}})

    assert_equal 200, result.status, result.body.inspect
    assert_equal "Lt", result.body.dig("spec", "tolerations", 0, "operator")
  end

  def test_legacy_pod_annotation_uses_the_same_comparison_gate
    key = Rubernetes::Schema::KubernetesValidator::TOLERATIONS_ANNOTATION
    object = pod
    object["metadata"]["annotations"] = {key => JSON.generate(object.fetch("spec").delete("tolerations"))}
    off = request(API::Server.new, "POST", PODS, object)

    assert_equal 422, off.status, off.body.inspect
    assert_match(/operator/, off.body.dig("details", "causes", 0, "field"))
    enabled = request(API::Server.new(feature_gates: {GATE => true}), "POST", PODS, object)

    assert_equal 201, enabled.status, enabled.body.inspect
  end

  def test_scheduler_filters_scores_and_requeues_using_the_same_threshold
    pending = Scheduler::Pod.new(pod)
    low, high = %w[5 6].map { |n| Scheduler::Node.new(node(n, "NoSchedule")) }
    filter = Scheduler::Filters::TaintToleration.new
    on = Scheduler::CycleContext.new(nodes: [low, high], pods: [], taint_comparisons: true)

    refute_equal true, filter.call(pending, high)
    refute_equal true, filter.call(pending, low, on)
    assert_equal true, filter.call(pending, high, on)
    soft = %w[5 6].map { |n| Scheduler::Node.new(node(n, "PreferNoSchedule")) }

    assert_equal({"node-5" => 0, "node-6" => 100}, Scheduler::Scores::TaintToleration.new.score_nodes(pending, soft, on))
    [true, false].each do |enabled|
      engine = Scheduler::Framework.new(feature_gates: {GATE => enabled})
      hint = engine.queueing_strategy(pending, ["TaintToleration"], "NodeUpdateNodeTaint", low, high)

      assert_equal(enabled ? :after_backoff : :skip, hint)
    end
  end

  def test_daemonset_template_admission_and_controller_use_the_feature
    template = {"metadata" => {"labels" => {"app" => "demo"}}, "spec" => pod["spec"]}
    daemon = {"apiVersion" => "apps/v1", "kind" => "DaemonSet", "metadata" => {"name" => "daemon", "namespace" => "default"},
              "spec" => {"selector" => {"matchLabels" => {"app" => "demo"}}, "template" => template}}
    path = "/apis/apps/v1/namespaces/default/daemonsets"
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    off = request(API::Server.new(registry: registry), "POST", path, daemon)

    assert_equal 422, off.status, off.body.inspect
    assert_equal "spec.template.spec.tolerations[0].operator", off.body.dig("details", "causes", 0, "field")
    on = request(API::Server.new(registry: registry, feature_gates: {GATE => true}), "POST", path, daemon)

    assert_equal 201, on.status, on.body.inspect
    [true, false].each do |enabled|
      result = Rubernetes::Controller::DaemonSetController.new.plan(on.body, pods: [], nodes: [node("6", "NoSchedule")], feature_gates: {GATE => enabled})

      assert_equal(enabled ? 1 : 0, result.status["desiredNumberScheduled"])
    end
  end

  def test_spread_honors_only_nodes_tolerated_by_the_incoming_pod
    input = pod
    input["metadata"]["labels"] = {"app" => "demo"}
    input["spec"]["topologySpreadConstraints"] = [{"topologyKey" => "zone", "whenUnsatisfiable" => "DoNotSchedule", "maxSkew" => 1,
                                                   "nodeTaintsPolicy" => "Honor", "labelSelector" => {"matchLabels" => {"app" => "demo"}}}]
    here = node("1", "NoSchedule")
    here["metadata"]["labels"] = {"zone" => "a"}
    here["spec"]["taints"] = []
    other = node("6", "NoSchedule")
    other["metadata"]["labels"] = {"zone" => "b"}
    nodes = [here, other].map { |n| Scheduler::Node.new(n) }
    existing = Scheduler::Pod.new(input.merge("metadata" => input["metadata"].merge("name" => "other", "uid" => "other"),
                                              "spec" => {"nodeName" => here["metadata"]["name"]}))
    filter = Scheduler::Filters::PodTopologySpread.new
    [true, false].each do |enabled|
      context = Scheduler::CycleContext.new(nodes: nodes, pods: [existing], taint_comparisons: enabled)
      result = filter.call(Scheduler::Pod.new(input), nodes.first, context)

      assert_equal !enabled, result == true
    end
  end

  def test_node_admission_of_directly_bound_pods_respects_no_execute
    taints = node("6", "NoExecute").dig("spec", "taints")
    input = pod
    [true, false].each do |enabled|
      admission = Rubernetes::Node::Admission.new(node_name: "worker", node_taints: -> { taints }, features: {GATE => enabled})
      decision = admission.admit(input)

      assert_equal enabled, decision.accepted, decision.message
      assert_equal "TaintToleration", decision.reason unless enabled
    end
    taints.first["effect"] = "NoSchedule"

    assert Rubernetes::Node::Admission.new(node_name: "worker", node_taints: -> { taints }).admit(input).accepted
  end

  def test_numeric_taint_eviction
    controller = Rubernetes::Controller::TaintEvictionController.new
    running = pod
    running["spec"]["nodeName"] = "node-6"
    [true, false].each do |enabled|
      result = controller.plan(node("6", "NoExecute"), pods: [running], feature_gates: {GATE => enabled})

      assert_equal !enabled, result.operations.any?(&:delete?)
    end
    ["05", "+5", "-0", "9223372036854775808"].each do |value|
      refute Rubernetes::TaintToleration.matches?(pod.dig("spec", "tolerations", 0), {"key" => "level", "value" => value}, comparisons: true)
    end
  end
end
