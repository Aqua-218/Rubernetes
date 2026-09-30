# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"

# pkg/scheduler/framework/plugins/nodedeclaredfeatures: Filter rejects a
# Node that does not declare a feature the Pod needs, with the upstream reason
# and UnschedulableAndUnresolvable; a Pod with no requirement is unaffected.
class SchedulerNodeDeclaredFeaturesTest < Minitest::Test
  Scheduler = Rubernetes::Scheduler
  RESTART_ALL = [{"action" => "RestartAllContainers", "exitCodes" => {"operator" => "In", "values" => [42]}}].freeze

  def test_pod_with_requirement_lands_only_on_declaring_node
    result = Scheduler.new.schedule(pod("needs", rules: RESTART_ALL),
                                    [node("old", declared: nil), node("new", declared: %w[RestartAllContainersOnContainerExits])])

    assert_predicate result, :scheduled?
    assert_equal "new", result.node_name
    rejection = result.filtered.fetch("old")

    assert_equal "node(s) didn't match Pod's required features", rejection.fetch("reason")
    assert_equal "UnschedulableAndUnresolvable", rejection.fetch("code")
  end

  def test_no_declaring_node_is_unschedulable
    result = Scheduler.new.schedule(pod("needs", rules: RESTART_ALL), [node("old", declared: %w[ExtendWebSocketsToKubelet])])

    refute_predicate result, :scheduled?
  end

  def test_pod_without_requirement_ignores_declared_features
    result = Scheduler.new.schedule(pod("plain", rules: [{"action" => "Restart", "exitCodes" => {"operator" => "In", "values" => [1]}}]),
                                    [node("old", declared: nil)])

    assert_equal "old", result.node_name
  end

  def test_unknown_declared_features_are_ignored
    filter = Scheduler::Filters::NodeDeclaredFeatures.new
    typed_pod = Scheduler::Pod.new(pod("needs", rules: RESTART_ALL))

    assert_equal true,
                 filter.call(typed_pod,
                             Scheduler::Node.new(node("n", declared: %w[AFeatureFromTheFuture RestartAllContainersOnContainerExits])))
    refute_equal true, filter.call(typed_pod, Scheduler::Node.new(node("n", declared: %w[AFeatureFromTheFuture])))
  end

  def test_disabled_plugin_filters_nothing
    filter = Scheduler::Filters::NodeDeclaredFeatures.new(enabled: false)

    assert_equal true, filter.call(Scheduler::Pod.new(pod("needs", rules: RESTART_ALL)), Scheduler::Node.new(node("n", declared: nil)))
  end

  def test_host_network_user_namespace_pod_needs_runtime_backed_feature
    spec_pod = pod("userns", rules: nil)
    spec_pod["spec"]["hostNetwork"] = true
    spec_pod["spec"]["hostUsers"] = false
    result = Scheduler.new.schedule(spec_pod, [node("n", declared: %w[RestartAllContainersOnContainerExits])])

    refute_predicate result, :scheduled?
  end

  private

  def pod(name, rules:)
    container = {"name" => "c", "image" => "i"}
    container["restartPolicyRules"] = rules if rules
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"},
     "spec" => {"restartPolicy" => "Never", "containers" => [container]}}
  end

  def node(name, declared:)
    status = {"allocatable" => {"cpu" => "2", "pods" => "10"}, "conditions" => [{"type" => "Ready", "status" => "True"}]}
    status["declaredFeatures"] = declared if declared
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name}, "spec" => {}, "status" => status}
  end
end
