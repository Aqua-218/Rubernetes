# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/container_manager"
require "rubernetes/observability/metrics"
require "tmpdir"

# The CPU, memory and topology managers' metrics (pkg/kubelet/cm, v1.36.2):
# pinning requests and errors, the shared pool and exclusive CPU gauges,
# allocation per NUMA node, aligned compute resources and topology manager
# admissions.
class KubeletResourceManagerMetricsTest < Minitest::Test
  GI = 1024**3

  def machine
    nodes = [0, 1].map do |numa|
      cores = Array.new(4) do |index|
        core = numa * 4 + index
        {id: index, socket_id: numa, threads: [core, core + 8], uncore_caches: []}
      end
      {id: numa, cores: cores, memory: 8 * GI, hugepages: [], distances: [numa.zero? ? 10 : 20, numa.zero? ? 20 : 10]}
    end
    {num_cores: 16, num_sockets: 2, topology: nodes}
  end

  def pod(uid, cpu:)
    requests = {"cpu" => cpu, "memory" => "1Gi"}
    {"metadata" => {"name" => "p-#{uid}", "namespace" => "ns", "uid" => uid},
     "spec" => {"containers" => [{"name" => "app", "resources" => {"requests" => requests, "limits" => requests}}]}}
  end

  def sample(text, series)
    line = text.lines.find { |candidate| candidate.start_with?("#{series} ") }
    line&.split&.last
  end

  def test_static_policies_and_single_numa_admission
    Dir.mktmpdir do |dir|
      reserved = Rubernetes::Node::NodeAllocatable.quantities({"cpu" => "1", "memory" => "1Gi"})
      manager = Rubernetes::Node::ContainerManager.new(state_directory: dir, reservation: reserved, cpu: {"policy" => "static"},
                                                       memory: {"policy" => "Static",
                                                                "reserved_memory" => [{"numa_node" => 0, "limits" => {"memory" => "1Gi"}}]},
                                                       topology: {"policy" => "single-numa-node"}, machine: machine)
      registry = Rubernetes::Observability::Metrics.new(apiserver: false, process: false, component: "kubelet")
      manager.metrics = registry
      pods = []
      manager.start(active_pods: -> { pods }, container_statuses: ->(_p) { [] }, update_cpuset: ->(*) {})
      text = registry.render
      assert_equal "15000", sample(text, "kubelet_cpu_manager_shared_pool_size_millicores")
      assert_equal "0", sample(text, %(kubelet_container_aligned_compute_resources_count{boundary="numa_node",scope="pod"}))

      admitted = pod("a", cpu: "2")
      pods << admitted
      assert manager.admit(admitted).admit?
      refute manager.admit(pod("huge", cpu: "12")).admit?
      text = registry.render
      assert_equal "2", sample(text, "kubelet_topology_manager_admission_requests_total")
      assert_equal "1", sample(text, "kubelet_topology_manager_admission_errors_total")
      assert_equal "1", sample(text, %(kubelet_container_aligned_compute_resources_count{boundary="numa_node",scope="container"}))
      assert_equal "1", sample(text, %(kubelet_container_aligned_compute_resources_failure_count{boundary="numa_node",scope="container"}))
      assert_equal "1", sample(text, "kubelet_cpu_manager_pinning_requests_total")
      assert_equal "2", sample(text, "kubelet_cpu_manager_exclusive_cpu_allocation_count")
      assert_equal "13000", sample(text, "kubelet_cpu_manager_shared_pool_size_millicores")
      assert_equal "2", sample(text, %(kubelet_cpu_manager_allocation_per_numa{numa_node="0"}))
      assert_equal "1", sample(text, "kubelet_memory_manager_pinning_requests_total")
      assert_equal "2", sample(text, "kubelet_topology_manager_admission_duration_ms_count")

      manager.cpu_manager.policy.remove_container(manager.cpu_manager.state, "a", "app")
      text = registry.render
      assert_equal "0", sample(text, "kubelet_cpu_manager_exclusive_cpu_allocation_count")
      assert_equal "15000", sample(text, "kubelet_cpu_manager_shared_pool_size_millicores")
    end
  end
end
