# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# kubelet's Generate*Condition functions (pkg/kubelet/status/generate.go): a
# Pod condition that is not True says WHY, and clients print and wait on
# exactly those reasons.  Ours labelled every false condition
# "ContainersNotReady", so "[sig-node] InitContainer should not start app
# containers and fail the pod if init containers fail on a RestartNever pod"
# read ContainersNotReady where it wanted ContainersNotInitialized.
class NodeConditionReasonsTest < Minitest::Test
  Status = Rubernetes::Node::Status

  def setup
    @aggregator = Status.new(clock: -> { Time.at(1_700_000_000).utc })
  end

  def pod(init: [])
    spec = {"nodeName" => "node-a", "containers" => [{"name" => "app", "image" => "img"}]}
    spec["initContainers"] = init unless init.empty?
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"}, "spec" => spec}
  end

  def conditions(pod_object, state, **options)
    @aggregator.aggregate(pod: pod_object, state: state, **options)
               .conditions.to_h { |entry| [entry.type, entry] }
  end

  def running(name)
    {"state" => "running", "ready" => true, "started" => true}
  end

  def test_an_unfinished_init_container_names_itself_on_initialized
    state = {"containers" => {}, "initContainers" => {"setup" => {"state" => "running", "ready" => false}}}
    initialized = conditions(pod(init: [{"name" => "setup", "image" => "img"}]), state).fetch("Initialized")

    assert_equal("False", initialized.status)
    assert_equal("ContainersNotInitialized", initialized.reason)
    assert_includes(initialized.message, "containers with incomplete status: [setup]")
  end

  def test_an_unready_container_names_itself_on_containers_ready
    state = {"containers" => {"app" => {"state" => "running", "ready" => false, "started" => true}},
             "initContainers" => {}}
    result = conditions(pod, state, phase: "Running")

    assert_equal("ContainersNotReady", result.fetch("ContainersReady").reason)
    assert_includes(result.fetch("ContainersReady").message, "containers with unready status: [app]")
  end

  # Ready mirrors ContainersReady whenever that is not True.
  def test_ready_mirrors_containers_ready
    state = {"containers" => {"app" => {"state" => "running", "ready" => false, "started" => true}},
             "initContainers" => {}}
    result = conditions(pod, state, phase: "Running")

    assert_equal(result.fetch("ContainersReady").reason, result.fetch("Ready").reason)
    assert_equal(result.fetch("ContainersReady").message, result.fetch("Ready").message)
  end

  def test_a_finished_pod_reports_pod_completed
    state = {"containers" => {"app" => {"state" => "terminated", "exitCode" => 0, "ready" => false}},
             "initContainers" => {}}
    result = conditions(pod, state, phase: "Succeeded")

    assert_equal("PodCompleted", result.fetch("ContainersReady").reason)
    assert_equal("PodCompleted", result.fetch("Ready").reason)
  end

  def test_a_ready_pod_carries_no_reason
    state = {"containers" => {"app" => running("app")}, "initContainers" => {}}
    result = conditions(pod, state, phase: "Running")

    assert_equal("True", result.fetch("Ready").status)
    assert_equal("", result.fetch("Ready").reason)
  end

  def test_an_unsatisfied_readiness_gate_still_reports_its_own_reason
    gated = pod
    gated["spec"]["readinessGates"] = [{"conditionType" => "www.example.com/feature"}]
    state = {"containers" => {"app" => running("app")}, "initContainers" => {}}
    result = conditions(gated, state, phase: "Running")

    assert_equal("ReadinessGatesNotReady", result.fetch("Ready").reason)
  end
end
