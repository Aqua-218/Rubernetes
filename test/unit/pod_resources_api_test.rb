# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/observability/metrics"
require "rubernetes/node"
require "rubernetes/node/pod_resources"

# kubelet's pod resources API (v1 PodResourcesLister): List, Get and
# GetAllocatableResources answered from the device plugin, CPU and memory
# managers.  The gRPC side is exercised in test/integration/pod_resources_test.rb.
class PodResourcesAPITest < Minitest::Test
  Node = Rubernetes::Node
  CPUSet = Node::CPUManager::CPUSet

  Plugins = Struct.new(:devices) do
    def container_devices(uid, name) = devices.fetch([uid, name], {})
    def allocatable_devices = {"example.com/gpu" => %w[d1 d2]}
  end
  CPUState = Struct.new(:sets) { def cpu_set(uid, name) = sets[[uid, name]] }
  CPU = Struct.new(:state) { def allocatable_cpus = CPUSet.parse("2-5") }
  Memory = Struct.new(:blocks) do
    def memory(uid, name) = blocks[[uid, name]]
    def allocatable_memory = [{"type" => "memory", "size" => 1024, "numaAffinity" => [0]}]
  end
  Containers = Struct.new(:cpu_manager, :memory_manager)

  def subject
    pods = [{"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"},
             "spec" => {"initContainers" => [{"name" => "side", "restartPolicy" => "Always"}, {"name" => "once"}],
                        "containers" => [{"name" => "app"}]}}]
    block = Node::MemoryManager::Block.new(numa_affinity: [0], type: "memory", size: 512)
    Node::PodResources.new(directory: "/nonexistent", pods: -> { pods },
                           device_plugins: Plugins.new({%w[u app] => {"example.com/gpu" => %w[d1]}}),
                           container_manager: Containers.new(CPU.new(CPUState.new({%w[u app] => CPUSet.parse("2-3")})),
                                                             Memory.new({%w[u app] => [block]})))
  end

  def test_list_reports_each_running_container
    containers = subject.list.fetch("pod_resources").first.fetch("containers")
    assert_equal %w[side app], containers.map { |c| c["name"] }, "sidecars run for the Pod's lifetime; a finished init container does not"
    app = containers.last
    assert_equal [{"resource_name" => "example.com/gpu", "device_ids" => %w[d1]}], app["devices"]
    assert_equal [2, 3], app["cpu_ids"]
    assert_equal [{"memory_type" => "memory", "size" => 512, "topology" => {"nodes" => [{"ID" => 0}]}}], app["memory"]
  end

  def test_get_and_allocatable
    assert_equal "p", subject.get("p", "ns").dig("pod_resources", "name")
    error = assert_raises(ArgumentError) { subject.get("x", "ns") }
    assert_equal "pod x in namespace ns not found", error.message
    allocatable = subject.allocatable
    assert_equal [2, 3, 4, 5], allocatable["cpu_ids"]
    assert_equal [{"resource_name" => "example.com/gpu", "device_ids" => %w[d1 d2]}], allocatable["devices"]
    assert_equal 1024, allocatable["memory"].first["size"]
  end

  # server_v1.go: every call counts in the total and its own counter; a
  # missing Pod is a Get error.
  def test_endpoint_metrics
    registry = Rubernetes::Observability::Metrics.new(apiserver: false, process: false, component: "kubelet")
    server = subject
    server.metrics = registry
    server.list
    server.get("p", "ns")
    assert_raises(ArgumentError) { server.get("x", "ns") }
    server.allocatable
    text = registry.render
    {"requests_total" => 4, "requests_list" => 1, "requests_get" => 2, "errors_get" => 1, "requests_get_allocatable" => 1}.each do |name, count|
      assert_includes text, %(kubelet_pod_resources_endpoint_#{name}{server_api_version="v1"} #{count})
    end
  end
end

class DRAContainerClaimsTest < Minitest::Test
  def test_the_prepared_claim_devices_of_a_container_request
    manager = Rubernetes::Node::DRAManager.allocate
    manager.instance_variable_set(:@mutex, Mutex.new)
    manager.instance_variable_set(:@claims, {"ns/gpu-claim" => {
      "claim_name" => "gpu-claim", "namespace" => "ns",
      "driver_state" => {"gpu.example.com" => {"devices" => [
        {"pool_name" => "pool", "device_name" => "gpu-0", "request_names" => ["gpu"], "cdi_device_ids" => ["gpu.example.com/gpu=0"]},
        {"pool_name" => "pool", "device_name" => "nic-0", "request_names" => ["nic"], "cdi_device_ids" => []}
      ]}}
    }})
    pod = {"metadata" => {"namespace" => "ns", "name" => "p"},
           "spec" => {"resourceClaims" => [{"name" => "c", "resourceClaimName" => "gpu-claim"}]},
           "status" => {}}
    container = {"name" => "app", "resources" => {"claims" => [{"name" => "c", "request" => "gpu"}]}}
    assert_equal [{"claim_name" => "gpu-claim", "claim_namespace" => "ns",
                   "claim_resources" => [{"driver_name" => "gpu.example.com", "pool_name" => "pool", "device_name" => "gpu-0",
                                          "cdi_devices" => [{"name" => "gpu.example.com/gpu=0"}]}]}],
                 manager.container_claims(pod, container)
  end
end
