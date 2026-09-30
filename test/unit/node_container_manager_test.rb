# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/container_manager"
require "tmpdir"

# The CPU, memory and topology managers behind the kubelet's resource
# allocation admit handler: a Guaranteed container with integral CPUs is
# pinned to exclusive CPUs (NUMA-aligned under the topology policy) and the
# rest share what is left; the assignments survive a restart through
# cpu_manager_state; the Static memory policy pins cpuset.mems.  The
# allocation algorithms themselves are checked against upstream by
# tools/differential/{cpu,memory,topology}_manager_differential.rb.
class NodeContainerManagerTest < Minitest::Test
  CM = Rubernetes::Node::CPUManager
  GI = 1024**3

  # Two sockets, one NUMA node each, 4 cores x 2 threads per socket; the
  # second thread of core c is c + 8.
  def machine
    nodes = [0, 1].map do |numa|
      cores = Array.new(4) do |index|
        core = (numa * 4) + index
        {id: index, socket_id: numa, threads: [core, core + 8], uncore_caches: []}
      end
      {id: numa, cores: cores, memory: 8 * GI, hugepages: [], distances: [numa.zero? ? 10 : 20, numa.zero? ? 20 : 10]}
    end
    {num_cores: 16, num_sockets: 2, topology: nodes}
  end

  def manager(dir, cpu: {"policy" => "static"}, memory: {}, topology: {}, reservation: {"cpu" => "1", "memory" => "1Gi"})
    reserved = Rubernetes::Node::NodeAllocatable.quantities(reservation)
    Rubernetes::Node::ContainerManager.new(state_directory: dir, reservation: reserved, cpu: cpu, memory: memory, topology: topology,
                                           machine: machine)
  end

  def pod(uid, cpu:, memory: "1Gi", guaranteed: true)
    requests = {"cpu" => cpu, "memory" => memory}
    {"metadata" => {"name" => "p-#{uid}", "namespace" => "ns", "uid" => uid},
     "spec" => {"containers" => [{"name" => "app", "resources" => {"requests" => requests, "limits" => guaranteed ? requests : {}}}]}}
  end

  def start(manager, pods)
    updates = []
    manager.start(active_pods: -> { pods }, container_statuses: lambda { |p|
      [{name: "app", id: "cid-#{p.dig("metadata", "uid")}", state: "running"}]
    },
                  update_cpuset: ->(id, cpus) { updates << [id, cpus.to_s] })
    updates
  end

  def test_a_guaranteed_container_gets_exclusive_cpus_and_the_rest_share
    Dir.mktmpdir do |dir|
      pods = []
      subject = manager(dir)
      updates = start(subject, pods)

      assert_equal "0", subject.cpu_manager.policy.reserved_cpus.to_s, "ceil(1) CPU reserved, taken by topology"

      exclusive = pod("a", cpu: "2")
      shared = pod("b", cpu: "500m")
      pods.push(exclusive, shared)

      assert_predicate subject.admit(exclusive), :admit?
      assert_predicate subject.admit(shared), :admit?
      assert_equal({"cpuset.cpus" => "1,9"}, subject.container_limits(exclusive, exclusive["spec"]["containers"][0]),
                   "a whole core, the lowest free one")
      assert_equal "0,2-8,10-15", subject.container_limits(shared, shared["spec"]["containers"][0])["cpuset.cpus"]

      subject.pre_start(exclusive, exclusive["spec"]["containers"][0], "cid-a")
      subject.cpu_manager.reconcile_state

      refute(updates.any? { |id, _| id == "cid-a" }, "an exclusive container already runs on its CPUs")
      assert_includes updates, ["cid-b", "0,2-8,10-15"], "AddContainer records only exclusive CPUs; a sharer is pinned once"
      updates.clear
      subject.cpu_manager.reconcile_state

      assert_empty updates, "nothing changed"

      pods.delete(exclusive)
      subject.cpu_manager.reconcile_state

      assert_includes updates, %w[cid-b 0-15], "released CPUs return to the shared pool and the sharers are re-pinned"
    end
  end

  def test_assignments_survive_a_restart_through_the_checkpoint
    Dir.mktmpdir do |dir|
      pods = [pod("a", cpu: "4")]
      first = manager(dir)
      start(first, pods)

      assert_predicate first.admit(pods.first), :admit?
      assigned = first.cpu_manager.exclusive_cpus("a", "app").to_s

      assert_equal "1-2,9-10", assigned
      body = JSON.parse(File.read(File.join(dir, "cpu_manager_state")))

      assert_equal({"a" => {"app" => assigned}}, body["entries"])
      assert_equal "static", body["policyName"]

      second = manager(dir)
      start(second, pods)

      assert_equal assigned, second.cpu_manager.exclusive_cpus("a", "app").to_s

      assert_raises(Rubernetes::Node::ContainerManager::Error) { start(manager(dir, cpu: {"policy" => "none"}), pods) }
    end
  end

  def test_the_restricted_topology_policy_rejects_what_cannot_be_aligned
    Dir.mktmpdir do |dir|
      pods = []
      subject = manager(dir, topology: {"policy" => "restricted"})
      start(subject, pods)
      first = pod("a", cpu: "6")
      second = pod("c", cpu: "4")
      pods.push(first, second)

      assert_predicate subject.admit(first), :admit?
      assert_equal "1-3,9-11", subject.cpu_manager.exclusive_cpus("a", "app").to_s, "all on NUMA node 0"
      assert_predicate subject.admit(second), :admit?
      assert_equal "4-5,12-13", subject.cpu_manager.exclusive_cpus("c", "app").to_s, "all on NUMA node 1"

      # 1 CPU is left on node 0 and 4 on node 1: 5 fit only across both,
      # which is not the preferred (single node) affinity.
      split = pod("b", cpu: "5")
      pods << split
      result = subject.admit(split)

      refute_predicate result, :admit?
      assert_equal "TopologyAffinityError", result.reason
      assert_equal "Resources cannot be allocated with Topology locality", result.message
    end
  end

  def test_full_pcpus_only_rejects_a_partial_core
    Dir.mktmpdir do |dir|
      subject = manager(dir, cpu: {"policy" => "static", "options" => {"full-pcpus-only" => "true"}})
      pods = [pod("a", cpu: "3")]
      start(subject, pods)
      result = subject.admit(pods.first)

      refute_predicate result, :admit?
      assert_equal "SMTAlignmentError", result.reason
      assert_equal "SMT Alignment Error: requested 3 cpus not multiple cpus per core = 2", result.message
    end
  end

  def test_the_static_memory_policy_pins_the_numa_node
    Dir.mktmpdir do |dir|
      reservation = {"cpu" => "1", "memory" => "1Gi"}
      memory = {"policy" => "Static", "reserved_memory" => [{"numa_node" => 0, "limits" => {"memory" => "1Gi"}}]}
      subject = manager(dir, memory: memory, topology: {"policy" => "single-numa-node"}, reservation: reservation)
      pods = [pod("a", cpu: "2", memory: "2Gi")]
      start(subject, pods)

      assert_predicate subject.admit(pods.first), :admit?
      limits = subject.container_limits(pods.first, pods.first["spec"]["containers"][0])

      assert_equal "0", limits["cpuset.mems"]
      assert_equal "1,9", limits["cpuset.cpus"]
      body = JSON.parse(File.read(File.join(dir, "memory_manager_state")))

      assert_equal "Static", body["policyName"]
      assert_equal [{"numaAffinity" => [0], "type" => "memory", "size" => 2 * GI}], body.dig("entries", "a", "app")
    end
  end

  def test_the_static_policy_needs_a_cpu_reservation
    Dir.mktmpdir do |dir|
      error = assert_raises(Rubernetes::Node::ContainerManager::Error) { manager(dir, reservation: {"memory" => "1Gi"}) }
      assert_equal "[cpumanager] unable to determine reserved CPU resources for static policy", error.message
    end
  end

  def test_the_none_policies_pin_nothing
    Dir.mktmpdir do |dir|
      subject = manager(dir, cpu: {})
      pods = [pod("a", cpu: "2")]
      start(subject, pods)

      assert_predicate subject.admit(pods.first), :admit?
      assert_empty subject.container_limits(pods.first, pods.first["spec"]["containers"][0])
      assert_equal "none", JSON.parse(File.read(File.join(dir, "cpu_manager_state")))["policyName"]
    end
  end
end
