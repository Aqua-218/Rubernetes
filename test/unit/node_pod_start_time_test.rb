# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# pkg/kubelet/status/status_manager.go updateStatusInternal stamps startTime on
# the first status it publishes for a Pod and never moves it again, and
# pkg/kubelet/status/generate.go always emits a PodReadyToStartContainers
# condition.  Ours reported neither: `status.startTime` stayed null for the
# whole life of every Pod.
class NodePodStartTimeTest < Minitest::Test
  Status = Rubernetes::Node::Status

  def setup
    @now = Time.at(1_700_000_000).utc
    @aggregator = Status.new(clock: -> { @now })
  end

  def pod(host_network: false, status: {})
    spec = {"nodeName" => "node-a", "containers" => [{"name" => "c", "image" => "img"}]}
    spec["hostNetwork"] = true if host_network
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"},
     "spec" => spec, "status" => status}
  end

  def running_state(pod_ip: "10.0.0.1")
    state = {"containers" => {"c" => {"state" => "running", "ready" => true, "started" => true}},
             "initContainers" => {}}
    state["podIP"] = pod_ip if pod_ip
    state
  end

  def aggregate(pod_object, state, **options)
    @aggregator.aggregate(pod: pod_object, state: state, **options)
  end

  def test_a_pod_without_an_observed_start_is_stamped_with_the_current_time
    snapshot = aggregate(pod, running_state)

    assert_equal(@now.iso8601(6), snapshot.to_h.fetch("startTime"))
  end

  def test_the_first_start_time_survives_later_updates
    first = aggregate(pod, running_state)
    @now = Time.at(1_700_000_600).utc
    second = aggregate(pod, running_state)

    assert_equal(first.start_time, second.start_time)
  end

  def test_a_start_time_already_published_on_the_pod_is_adopted
    published = Time.at(1_699_999_000).utc.iso8601(6)
    snapshot = aggregate(pod(status: {"startTime" => published}), running_state)

    assert_equal(published, snapshot.to_h.fetch("startTime"))
  end

  def test_an_observed_start_time_wins_over_the_clock
    observed = Time.at(1_699_999_500).utc
    snapshot = aggregate(pod, running_state, start_time: observed)

    assert_equal(observed, snapshot.start_time)
  end

  # A sandbox with networking already exists once a container has been observed
  # and the Pod holds an address.
  def test_ready_to_start_containers_follows_the_sandbox
    conditions = aggregate(pod, running_state).conditions.to_h { |entry| [entry.type, entry.status] }

    assert_equal("True", conditions.fetch("PodReadyToStartContainers"))
  end

  def test_a_pod_with_no_observed_container_is_not_ready_to_start_containers
    conditions = aggregate(pod, {"containers" => {}, "initContainers" => {}})
                 .conditions.to_h { |entry| [entry.type, entry.status] }

    assert_equal("False", conditions.fetch("PodReadyToStartContainers"))
  end

  def test_a_running_pod_without_an_address_is_not_ready_to_start_containers
    conditions = aggregate(pod, running_state(pod_ip: nil))
                 .conditions.to_h { |entry| [entry.type, entry.status] }

    assert_equal("False", conditions.fetch("PodReadyToStartContainers"))
  end

  # A host-network Pod never gets a sandbox address of its own.
  def test_a_host_network_pod_is_ready_to_start_containers_without_an_address
    conditions = aggregate(pod(host_network: true), running_state(pod_ip: nil))
                 .conditions.to_h { |entry| [entry.type, entry.status] }

    assert_equal("True", conditions.fetch("PodReadyToStartContainers"))
  end

  # The kubelet owns this condition, so it must not be echoed back as a
  # caller-supplied custom condition.
  def test_the_condition_is_not_duplicated_from_the_published_status
    published = {"conditions" => [{"type" => "PodReadyToStartContainers", "status" => "False"}]}
    types = aggregate(pod(status: published), running_state).conditions.map(&:type)

    assert_equal(1, types.count("PodReadyToStartContainers"))
  end
end
