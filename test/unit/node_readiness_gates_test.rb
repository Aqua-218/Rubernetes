# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# kubelet GeneratePodReadyCondition: a Pod is Ready only when every
# spec.readinessGates condition is also "True".  The field was validated by the
# API server and read by nobody, so a Pod with an unsatisfied gate reported
# itself Ready -- and the condition a gate names was dropped from status on
# every kubelet update, so nothing could ever satisfy one.
class NodeReadinessGatesTest < Minitest::Test
  Status = Rubernetes::Node::Status

  def aggregator
    Status.new(clock: -> { Time.at(1_700_000_000).utc })
  end

  def pod(gates: [], conditions: [])
    spec = {"nodeName" => "node-a", "containers" => [{"name" => "c", "image" => "img"}]}
    spec["readinessGates"] = gates.map { |type| {"conditionType" => type} } unless gates.empty?
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"},
     "spec" => spec,
     "status" => {"conditions" => conditions}}
  end

  def running_state
    {"containers" => {"c" => {"state" => "running", "ready" => true, "started" => true}},
     "initContainers" => {}}
  end

  def conditions_for(pod_object)
    aggregator.aggregate(pod: pod_object, state: running_state, phase: "Running",
                         reason: nil, message: nil, start_time: Time.at(1_699_999_000).utc,
                         pod_ip: "10.0.0.1", pod_ips: ["10.0.0.1"], host_ip: "10.0.0.254")
             .conditions.to_h { |entry| [entry.type, entry.status] }
  end

  def test_a_pod_without_gates_is_ready
    assert_equal "True", conditions_for(pod).fetch("Ready")
  end

  def test_an_unsatisfied_gate_keeps_the_pod_not_ready
    result = conditions_for(pod(gates: ["www.example.com/feature"]))

    assert_equal "True", result.fetch("ContainersReady")
    assert_equal "False", result.fetch("Ready"), "an unsatisfied readiness gate must block Ready"
  end

  def test_a_satisfied_gate_lets_the_pod_be_ready
    result = conditions_for(pod(gates: ["www.example.com/feature"],
                                conditions: [{"type" => "www.example.com/feature", "status" => "True"}]))

    assert_equal "True", result.fetch("Ready")
  end

  def test_a_gate_condition_set_false_blocks_ready
    result = conditions_for(pod(gates: ["www.example.com/feature"],
                                conditions: [{"type" => "www.example.com/feature", "status" => "False"}]))

    assert_equal "False", result.fetch("Ready")
  end

  def test_the_gate_condition_is_preserved_in_status
    result = conditions_for(pod(gates: ["www.example.com/feature"],
                                conditions: [{"type" => "www.example.com/feature", "status" => "True"}]))

    assert_equal "True", result.fetch("www.example.com/feature"),
                 "a condition the kubelet does not own must survive its status update"
  end

  def test_every_gate_must_be_satisfied
    result = conditions_for(pod(gates: %w[a/one b/two],
                                conditions: [{"type" => "a/one", "status" => "True"}]))

    assert_equal "False", result.fetch("Ready")
  end
end
