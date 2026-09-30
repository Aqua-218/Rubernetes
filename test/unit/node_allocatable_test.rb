# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/node_allocatable"
require "rubernetes/node/eviction_manager"
require "rubernetes/bootstrap"
require "tempfile"

# Node Allocatable (GetNodeAllocatableReservation + the MachineInfo setter):
# capacity less system-reserved, kube-reserved and the hard eviction
# thresholds for memory.available and nodefs.available, clamped at zero,
# memory also less the hugepage pools.  The agent reported capacity as
# allocatable, so the eviction thresholds the node enforces were schedulable.
class NodeAllocatableTest < Minitest::Test
  NA = Rubernetes::Node::NodeAllocatable
  EM = Rubernetes::Node::EvictionManager

  def capacity
    {"cpu" => "8", "memory" => "16Gi", "ephemeral-storage" => "100Gi", "pods" => "110", "hugepages-2Mi" => "1Gi", "hugepages-1Gi" => "0"}
  end

  def test_the_default_eviction_thresholds_are_reserved
    reservation = NA.reservation(capacity: capacity, hard_thresholds: EM.parse_threshold_config(allocatable_config: []))

    assert_equal({"memory" => "100Mi", "ephemeral-storage" => "10737418400"}, reservation.transform_values(&:to_s),
                 "10% as upstream's float32 fraction of the capacity")
    allocatable = NA.allocatable(capacity, reservation)

    assert_equal "8", allocatable["cpu"]
    assert_equal "15260Mi", allocatable["memory"], "16Gi - 100Mi - the 1Gi of 2Mi hugepages"
    assert_equal "96636764000", allocatable["ephemeral-storage"]
    assert_equal "1Gi", allocatable["hugepages-2Mi"]
    assert_equal "110", allocatable["pods"]
  end

  def test_system_and_kube_reserved_add_up_and_clamp_at_zero
    reservation = NA.reservation(capacity: capacity, system_reserved: {"cpu" => "500m", "memory" => "1Gi"},
                                 kube_reserved: {"cpu" => "1", "pods" => "200"})

    assert_equal({"cpu" => "1500m", "memory" => "1Gi", "pods" => "200"}, reservation.transform_values(&:to_s))
    allocatable = NA.allocatable(capacity, reservation)

    assert_equal "6500m", allocatable["cpu"]
    assert_equal "14Gi", allocatable["memory"]
    assert_equal "0", allocatable["pods"]
  end

  def test_reserved_system_cpus_replace_both_cpu_reservations
    agent = Rubernetes::Node::Agent.allocate
    agent.instance_variable_set(:@capacity, capacity)
    reservation = agent.send(:node_allocatable_reservation, {"cpu" => "250m"}, {"cpu" => "2", "memory" => "512Mi"}, "0-1,4", {},
                             host: false)

    assert_equal({"cpu" => "3", "memory" => "512Mi"}, reservation.transform_values(&:to_s))
    assert_empty agent.send(:node_allocatable_reservation, {}, {}, nil, {}, host: false), "no reservation without a real node"
  end

  def test_the_configuration_validates_the_resource_manager_settings
    {
      "    system_reserved:\n      cpu: lots\n" => "rubernetes-agent.system_reserved.cpu must be a quantity",
      "    reserved_system_cpus: 0-x\n" => "rubernetes-agent.reserved_system_cpus must be a CPU list",
      "    cpu_manager:\n      policy: dynamic\n" => "cpu_manager.policy must be none or static",
      "    cpu_manager:\n      options:\n        full-pcpus-only: true\n" => "cpu_manager.options.full-pcpus-only must be a string",
      "    memory_manager:\n      policy: static\n" => "memory_manager.policy must be None or Static",
      "    memory_manager:\n      reserved_memory:\n      - limits: {memory: 1Gi}\n" => "reserved_memory[0].numa_node must be a non-negative integer",
      "    topology_manager:\n      scope: node\n" => "topology_manager.scope must be container or pod",
      "    topology_manager:\n      surprise: 1\n" => "topology_manager has unknown fields: surprise"
    }.each do |body, message|
      Tempfile.create(["rubernetes-resources", ".yml"]) do |file|
        file.write("processes:\n  rubernetes-agent:\n    node_name: n\n#{body}")
        file.flush
        error = assert_raises(Rubernetes::Bootstrap::Config::Error, body) do
          Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent", path: file.path)
        end
        assert_includes error.message, message
      end
    end
    Tempfile.create(["rubernetes-resources", ".yml"]) do |file|
      file.write(<<~YAML)
        processes:
          rubernetes-agent:
            node_name: n
            system_reserved: {cpu: 500m, memory: 1Gi}
            kube_reserved: {cpu: 500m}
            reserved_system_cpus: "0-1"
            cpu_manager: {policy: static, options: {full-pcpus-only: "true"}, reconcile_period_seconds: 5}
            memory_manager: {policy: Static, reserved_memory: [{numa_node: 0, limits: {memory: 1Gi}}]}
            topology_manager: {policy: single-numa-node, scope: pod, options: {prefer-closest-numa-nodes: "true"}}
      YAML
      file.flush
      config = Rubernetes::Bootstrap::Config.load(process_name: "rubernetes-agent", path: file.path)

      assert_equal "static", config.process.dig("cpu_manager", "policy")
    end
  end
end
