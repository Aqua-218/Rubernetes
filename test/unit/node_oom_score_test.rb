# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# pkg/kubelet/qos/policy_test.go cases (v1.36.2) for GetContainerOOMScoreAdjust.
class NodeOOMScoreTest < Minitest::Test
  OOM = Rubernetes::Node::OOMScore
  STANDARD = 8_000_000_000
  MEM_REQUEST = (STANDARD / 8).to_s
  POD_MEM_REQUEST = (STANDARD / 4).to_s
  POD_MEM_LIMIT = (1000 + (STANDARD / 4)).to_s

  def pod(containers:, init: [], resources: nil, extra: {})
    spec = {"containers" => containers, "initContainers" => init}.merge(extra)
    spec["resources"] = resources if resources
    {"metadata" => {"name" => "p"}, "spec" => spec}
  end

  def container(name, requests: nil, limits: nil, restart_policy: nil)
    resources = {}
    resources["requests"] = requests if requests
    resources["limits"] = limits if limits
    value = {"name" => name, "resources" => resources}
    value["restartPolicy"] = restart_policy if restart_policy
    value
  end

  def adjust(pod, name, capacity)
    all = pod["spec"]["containers"] + pod["spec"]["initContainers"]
    OOM.container_adjust(pod, all.find { |entry| entry["name"] == name }, memory_capacity: capacity)
  end

  def test_qos_classes
    best_effort = pod(containers: [container("c")])

    assert_equal 1000, adjust(best_effort, "c", 4_000_000_000)
    guaranteed = pod(containers: [container("c", requests: {"cpu" => "5m", "memory" => "1Gi"}, limits: {"cpu" => "5m", "memory" => "1Gi"})])

    assert_equal(-997, adjust(guaranteed, "c", 123_456_789))
    request_no_limit = pod(containers: [container("c", requests: {"memory" => (STANDARD - 1).to_s})])

    assert_equal 3, adjust(request_no_limit, "c", STANDARD)
    tiny = pod(containers: [container("c", requests: {"cpu" => "1"})])

    assert_equal 999, adjust(tiny, "c", 4_000_000_000), "a burstable pod never ties BestEffort"
  end

  def test_node_critical
    critical = pod(containers: [container("c")], extra: {"priorityClassName" => "system-node-critical", "priority" => 2_000_001_000})

    assert_equal(-997, adjust(critical, "c", 4_000_000_000))
  end

  def test_sidecar_is_no_worse_than_the_smallest_regular_container
    small_main = pod(containers: [container("main-1", requests: {"memory" => MEM_REQUEST})],
                     init: [container("sidecar-big", requests: {"memory" => (STANDARD / 2).to_s}, restart_policy: "Always")])

    assert_equal 500, adjust(small_main, "sidecar-big", STANDARD)
    assert_equal 875, adjust(small_main, "main-1", STANDARD)
  end

  def test_pod_level_requests_are_shared_among_containers
    pod_resources = {"requests" => {"cpu" => "5m", "memory" => POD_MEM_REQUEST}, "limits" => {"cpu" => "5m", "memory" => POD_MEM_LIMIT}}
    none = pod(containers: [container("a"), container("b")], resources: pod_resources)

    assert_equal 750, adjust(none, "a", 4_000_000_000)
    assert_equal 750, adjust(none, "b", 4_000_000_000)
    equal = pod(containers: [container("a", requests: {"memory" => MEM_REQUEST}), container("b", requests: {"memory" => MEM_REQUEST})],
                resources: pod_resources)

    assert_equal 750, adjust(equal, "a", 4_000_000_000)
    unequal = pod(containers: [container("burstable", requests: {"cpu" => "3m", "memory" => MEM_REQUEST}, limits: {"cpu" => "5m", "memory" => MEM_REQUEST}),
                               container("best-effort")], resources: pod_resources)

    assert_equal 625, adjust(unequal, "burstable", 4_000_000_000)
    assert_equal 875, adjust(unequal, "best-effort", 4_000_000_000)
    guaranteed = pod(containers: [container("a"), container("b")],
                     resources: {"requests" => {"cpu" => "5m", "memory" => POD_MEM_REQUEST},
                                 "limits" => {"cpu" => "5m", "memory" => POD_MEM_REQUEST}})

    assert_equal(-997, adjust(guaranteed, "a", 4_000_000_000))
  end
end
