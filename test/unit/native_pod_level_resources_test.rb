# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/runtime"

# PodLevelResources in the Native runtime: cm.ResourceConfigForPod for the
# Pod cgroup, kuberuntime getCPULimit/getMemoryLimit for containers, and
# qos.ComputePodQOS -- pod-level resources were ignored by all three.
class NativePodLevelResourcesTest < Minitest::Test
  R = Rubernetes::Runtime::Native::Resources

  def spec(containers:, resources: nil, init: nil)
    value = {"containers" => containers.each_with_index.map { |resources_value, index| {"name" => "c#{index}", "resources" => resources_value} }}
    value["initContainers"] = init if init
    value["resources"] = resources if resources
    {"spec" => value}
  end

  def test_qos_uses_pod_level_resources
    assert_equal "guaranteed", R.qos_class(spec(containers: [{}], resources: {"requests" => {"cpu" => "1", "memory" => "1Gi"},
                                                                               "limits" => {"cpu" => "1", "memory" => "1Gi"}}))
    assert_equal "burstable", R.qos_class(spec(containers: [{"requests" => {"cpu" => "1", "memory" => "1Gi"}, "limits" => {"cpu" => "1", "memory" => "1Gi"}}],
                                               resources: {"limits" => {"cpu" => "2"}, "requests" => {"cpu" => "1"}}))
    assert_equal "besteffort", R.qos_class(spec(containers: [{}]))
    assert_equal "guaranteed", R.qos_class(spec(containers: [{"limits" => {"cpu" => "1", "memory" => "1Gi"}}]))
  end

  def test_pod_cgroup_follows_pod_level_limits
    pod = spec(containers: [{"requests" => {"cpu" => "100m"}}, {}], resources: {"requests" => {"cpu" => "500m", "memory" => "256Mi"},
                                                                                 "limits" => {"cpu" => "2", "memory" => "1Gi"}})
    limits = R.pod_cgroup_limits(pod)
    # Burstable: pod-level limits declare both CPU and memory although no container has a limit.
    assert_equal R.cpu_weight(500).to_s, limits.fetch("cpu.weight")
    assert_equal "200000 100000", limits.fetch("cpu.max")
    assert_equal (1024**3).to_s, limits.fetch("memory.max")
  end

  def test_pod_cgroup_without_pod_level_keeps_container_semantics
    pod = spec(containers: [{"requests" => {"cpu" => "100m"}, "limits" => {"cpu" => "1"}}, {"requests" => {"memory" => "64Mi"}}])
    limits = R.pod_cgroup_limits(pod)
    refute limits.key?("cpu.max"), "a container without a CPU limit leaves the Pod unbounded"
    refute limits.key?("memory.max")
    assert_equal R.cpu_weight(100).to_s, limits.fetch("cpu.weight")
  end

  def test_container_falls_back_to_pod_level_limits
    pod = spec(containers: [{}], resources: {"limits" => {"cpu" => "1500m", "memory" => "512Mi"}})["spec"]
    limits = R.container_cgroup_limits({"resources" => {"requests" => {"cpu" => "100m"}}}, qos: "burstable", pod: pod)
    assert_equal "150000 100000", limits.fetch("cpu.max")
    assert_equal (512 * 1024**2).to_s, limits.fetch("memory.max")
    own = R.container_cgroup_limits({"resources" => {"limits" => {"cpu" => "500m"}}}, qos: "burstable", pod: pod)
    assert_equal "50000 100000", own.fetch("cpu.max"), "a container's own limit wins"
    plain = R.container_cgroup_limits({"resources" => {}}, qos: "besteffort")
    assert_equal "max 100000", plain.fetch("cpu.max")
  end

  def test_sidecars_and_overhead_in_pod_requests
    pod = spec(containers: [{"requests" => {"cpu" => "500m"}, "limits" => {"cpu" => "500m"}}],
               init: [{"name" => "s", "restartPolicy" => "Always", "resources" => {"requests" => {"cpu" => "1"}, "limits" => {"cpu" => "1"}}},
                      {"name" => "i", "resources" => {"requests" => {"cpu" => "2"}, "limits" => {"cpu" => "2"}}}])
    pod["spec"]["overhead"] = {"cpu" => "250m"}
    limits = R.pod_cgroup_limits(pod)
    # max(500m + 1, 2 + 1) + 250m overhead = 3250m.
    assert_equal R.cpu_weight(3250).to_s, limits.fetch("cpu.weight")
    assert_equal "325000 100000", limits.fetch("cpu.max")
  end
end
