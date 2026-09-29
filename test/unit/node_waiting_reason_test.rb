# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# kubelet convertToAPIContainerStatuses (pkg/kubelet/kubelet_pods.go) seeds
# every container that has not started with a waiting state that ALWAYS carries
# a reason: PodInitializing when the Pod has init containers, ContainerCreating
# when it does not.  Ours reported a bare `waiting: {}`, so conformance read
# back no reason at all -- "container \"run1\" should have reason
# PodInitializing".
class NodeWaitingReasonTest < Minitest::Test
  Status = Rubernetes::Node::Status

  def setup
    @aggregator = Status.new(clock: -> { Time.at(1_700_000_000).utc })
  end

  def pod(init: [])
    spec = {"nodeName" => "node-a", "containers" => [{"name" => "run1", "image" => "img"}]}
    spec["initContainers"] = init unless init.empty?
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"}, "spec" => spec}
  end

  def statuses(pod_object, state)
    @aggregator.aggregate(pod: pod_object, state: state).to_h
  end

  def test_a_pod_with_init_containers_reports_pod_initializing
    result = statuses(pod(init: [{"name" => "init1", "image" => "img"}]),
                      {"containers" => {}, "initContainers" => {}})

    assert_equal("PodInitializing", result.fetch("containerStatuses").first.dig("state", "waiting", "reason"))
    assert_equal("PodInitializing", result.fetch("initContainerStatuses").first.dig("state", "waiting", "reason"))
  end

  def test_a_pod_without_init_containers_reports_container_creating
    result = statuses(pod, {"containers" => {}, "initContainers" => {}})

    assert_equal("ContainerCreating", result.fetch("containerStatuses").first.dig("state", "waiting", "reason"))
  end

  # A start that failed for a real reason keeps that reason, which is what
  # clients wait on (CreateContainerConfigError, ErrImagePull...).
  def test_an_observed_failure_reason_wins_over_the_default
    result = @aggregator.aggregate(pod: pod, state: {"containers" => {}, "initContainers" => {}},
                                   reason: "CreateContainerConfigError", message: "bad subPath").to_h

    waiting = result.fetch("containerStatuses").first.dig("state", "waiting")
    assert_equal("CreateContainerConfigError", waiting.fetch("reason"))
    assert_equal("bad subPath", waiting.fetch("message"))
  end

  def test_a_running_container_has_no_waiting_state
    state = {"containers" => {"run1" => {"state" => "running", "ready" => true, "started" => true}},
             "initContainers" => {}}
    result = statuses(pod, state)

    refute(result.fetch("containerStatuses").first.fetch("state").key?("waiting"))
  end
end
