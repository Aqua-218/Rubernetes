# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# lifecycle/predicate.go + noderesources.Fits: the node admits a Pod only if
# it fits in what the Pods already on it leave.  The check compared each Pod
# with the whole node, so any number of Pods that each fit alone were admitted.
class NodeAdmissionFitTest < Minitest::Test
  def admission
    Rubernetes::Node::Admission.new(node_name: "n", capacity: {"cpu" => "2", "memory" => "4Gi", "pods" => "3", "example.com/gpu" => "1"})
  end

  def pod(name, cpu: nil, memory: nil, extra: {})
    requests = {}
    requests["cpu"] = cpu if cpu
    requests["memory"] = memory if memory
    requests.merge!(extra)
    {"metadata" => {"name" => name, "uid" => "#{name}-uid"},
     "spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => requests}}]}}
  end

  def test_cpu_left_by_other_pods
    decision = admission.admit(pod("new", cpu: "1500m"), other_pods: [pod("a", cpu: "1")])
    refute decision.accepted
    assert_equal "OutOfcpu", decision.reason
    assert_equal "Node didn't have enough resource: cpu, requested: 1500, used: 1000, capacity: 2000", decision.message
    assert admission.admit(pod("new", cpu: "1"), other_pods: [pod("a", cpu: "1")]).accepted
  end

  def test_memory_and_pod_count
    decision = admission.admit(pod("new", memory: "3Gi"), other_pods: [pod("a", memory: "2Gi")])
    assert_equal "OutOfmemory", decision.reason
    assert_equal "Node didn't have enough resource: memory, requested: #{3 * 1024**3}, used: #{2 * 1024**3}, capacity: #{4 * 1024**3}", decision.message
    full = admission.admit(pod("new"), other_pods: [pod("a"), pod("b"), pod("c")])
    assert_equal "OutOfpods", full.reason
    assert_equal "Node didn't have enough resource: pods, requested: 1, used: 3, capacity: 3", full.message
  end

  def test_extended_resources
    decision = admission.admit(pod("new", extra: {"example.com/gpu" => "1"}), other_pods: [pod("a", extra: {"example.com/gpu" => "1"})])
    assert_equal "OutOfexample.com/gpu", decision.reason
    # removeMissingExtendedResources: a resource the node does not have is ignored.
    assert admission.admit(pod("new", extra: {"example.com/other" => "5"}), other_pods: []).accepted
  end

  def test_the_pod_itself_is_not_counted_twice
    assert admission.admit(pod("same", cpu: "2"), other_pods: [pod("same", cpu: "2")]).accepted
  end
end
