# frozen_string_literal: true

require "json"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node/container_manager"

# PodLevelResourceManagers (alpha): under the pod-scope topology manager a
# Guaranteed Pod with pod-level resources gets one CPU "bubble"
# (AllocatePod), carved into exclusive sets for the containers that are
# Guaranteed on their own and a shared rest for the others; the bubble is
# checkpointed (podEntries) and released with the last container.  Off, such
# a Pod is not managed at all.
class PodLevelResourceManagersTest < Minitest::Test
  GI = 1024**3

  def machine
    nodes = [0, 1].map do |numa|
      cores = Array.new(4) { |index| {id: index, socket_id: numa, threads: [numa * 4 + index, numa * 4 + index + 8], uncore_caches: []} }
      {id: numa, cores: cores, memory: 8 * GI, hugepages: [], distances: [numa.zero? ? 10 : 20, numa.zero? ? 20 : 10]}
    end
    {num_cores: 16, num_sockets: 2, topology: nodes}
  end

  def manager(dir, pod_level: true, memory: {})
    reserved = Rubernetes::Node::NodeAllocatable.quantities({"cpu" => "1", "memory" => "1Gi"})
    Rubernetes::Node::ContainerManager.new(state_directory: dir, reservation: reserved, cpu: {"policy" => "static"}, memory: memory,
                                           topology: {"policy" => "best-effort", "scope" => "pod"}, machine: machine,
                                           pod_level_resource_managers: pod_level)
  end

  def pod(uid, pod_cpu: "4", main_cpu: "2")
    main = {"name" => "main", "resources" => {"requests" => {"cpu" => main_cpu, "memory" => "1Gi"}, "limits" => {"cpu" => main_cpu, "memory" => "1Gi"}}}
    {"metadata" => {"name" => "p-#{uid}", "namespace" => "ns", "uid" => uid},
     "spec" => {"resources" => {"requests" => {"cpu" => pod_cpu, "memory" => "4Gi"}, "limits" => {"cpu" => pod_cpu, "memory" => "4Gi"}},
                "containers" => [main, {"name" => "helper"}]}}
  end

  def start(subject, pods)
    subject.start(active_pods: -> { pods }, container_statuses: ->(_pod) { [] }, update_cpuset: ->(*) {})
  end

  def cpus(subject, pod, name) = subject.container_limits(pod, pod["spec"]["containers"].find { |c| c["name"] == name })["cpuset.cpus"]

  def test_the_pod_bubble_is_partitioned_checkpointed_and_released
    Dir.mktmpdir do |dir|
      target = pod("a")
      pods = [target]
      subject = manager(dir)
      start(subject, pods)
      assert subject.admit(target).admit?
      bubble = subject.cpu_manager.state.pod_cpu_set("a")
      assert_equal 4, bubble.size
      main = Rubernetes::Node::CPUManager::CPUSet.parse(cpus(subject, target, "main"))
      helper = Rubernetes::Node::CPUManager::CPUSet.parse(cpus(subject, target, "helper"))
      assert_equal 2, main.size
      assert_equal bubble.difference(main), helper, "the rest of the bubble is the Pod's shared pool"
      refute subject.cpu_manager.state.default_cpu_set.intersection(bubble).size.positive?, "taken from the node's shared pool"
      body = JSON.parse(File.read(File.join(dir, "cpu_manager_state")))
      assert_equal({"a" => {"cpuSet" => bubble.to_s}}, body["podEntries"])

      restarted = manager(dir)
      start(restarted, pods)
      assert_equal bubble, restarted.cpu_manager.state.pod_cpu_set("a"), "the checkpoint (checksum included) is read back"

      subject.pre_start(target, target["spec"]["containers"][0], "c-main")
      subject.pre_start(target, target["spec"]["containers"][1], "c-helper")
      subject.cpu_manager.remove_container("c-main")
      assert_equal bubble, subject.cpu_manager.state.pod_cpu_set("a"), "held while a container remains"
      subject.cpu_manager.remove_container("c-helper")
      assert_nil subject.cpu_manager.state.pod_cpu_set("a")
      assert bubble.difference(subject.cpu_manager.state.default_cpu_set).empty?, "the whole bubble is shared again"
    end
  end

  def test_a_bubble_left_without_room_for_shared_containers_is_rejected
    Dir.mktmpdir do |dir|
      target = pod("b", pod_cpu: "2", main_cpu: "2")
      subject = manager(dir)
      start(subject, [target])
      result = subject.admit(target)
      refute result.admit?
      # best-effort admits the empty hint; AllocatePod rejects it itself.
      assert_equal "EmptyPodSharedPoolError", result.reason
    end
  end

  def test_off_a_pod_level_pod_is_not_managed
    Dir.mktmpdir do |dir|
      target = pod("c")
      subject = manager(dir, pod_level: false)
      start(subject, [target])
      assert subject.admit(target).admit?
      assert_nil subject.cpu_manager.state.pod_cpu_set("c")
      assert_equal "0-15", cpus(subject, target, "main"), "the node's shared pool"
      refute JSON.parse(File.read(File.join(dir, "cpu_manager_state"))).key?("podEntries")
    end
  end

  STATIC_MEMORY = {"policy" => "Static", "reserved_memory" => [{"numa_node" => 0, "limits" => {"memory" => "1Gi"}}]}.freeze

  def memory_sizes(blocks) = Array(blocks).to_h { |block| [block.type, block.size] }

  # The memory manager's bubble: the Pod's whole memory on one NUMA node,
  # 1Gi of it exclusive to the Guaranteed container, the rest shared.
  def test_the_memory_bubble_is_partitioned_checkpointed_and_released
    Dir.mktmpdir do |dir|
      target = pod("m")
      pods = [target]
      subject = manager(dir, memory: STATIC_MEMORY)
      start(subject, pods)
      assert subject.admit(target).admit?
      state = subject.memory_manager.state
      assert_equal({"memory" => 4 * GI}, memory_sizes(state.pod_memory_blocks("m")))
      assert_equal({"memory" => GI}, memory_sizes(state.memory_blocks("m", "main")))
      assert_equal({"memory" => 3 * GI}, memory_sizes(state.memory_blocks("m", "helper")), "the rest of the bubble is shared")
      node = state.pod_memory_blocks("m").first.numa_affinity
      free = state.machine_state[node.first].memory["memory"].free
      assert_equal subject.memory_manager.state.machine_state[node.first].memory["memory"].allocatable - 4 * GI, free,
                   "the node gives up the bubble once, not per container"
      body = JSON.parse(File.read(File.join(dir, "memory_manager_state")))
      assert_equal [{"numaAffinity" => node, "type" => "memory", "size" => 4 * GI}], body.dig("podEntries", "m", "memoryBlocks")

      restarted = manager(dir, memory: STATIC_MEMORY)
      start(restarted, pods)
      assert_equal({"memory" => 4 * GI}, memory_sizes(restarted.memory_manager.state.pod_memory_blocks("m")),
                   "the checkpoint (checksum included) is read back and validates")

      subject.pre_start(target, target["spec"]["containers"][0], "c-main")
      subject.pre_start(target, target["spec"]["containers"][1], "c-helper")
      subject.memory_manager.remove_container("c-main")
      refute_nil state.pod_memory_blocks("m"), "held while a container remains"
      subject.memory_manager.remove_container("c-helper")
      assert_nil state.pod_memory_blocks("m")
      table = state.machine_state[node.first].memory["memory"]
      assert_equal table.allocatable, table.free, "the whole bubble is free again"
    end
  end

  def test_memory_off_leaves_a_pod_level_pod_unpinned
    Dir.mktmpdir do |dir|
      target = pod("n")
      subject = manager(dir, pod_level: false, memory: STATIC_MEMORY)
      start(subject, [target])
      assert subject.admit(target).admit?
      assert_nil subject.memory_manager.state.memory_blocks("n", "main")
      refute JSON.parse(File.read(File.join(dir, "memory_manager_state"))).key?("podEntries")
    end
  end
end
