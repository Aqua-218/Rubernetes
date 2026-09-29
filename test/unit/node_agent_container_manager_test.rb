# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require "tmpdir"

# The agent builds the CPU/memory/topology managers from its configuration:
# the reservation shrinks the node's allocatable, the static CPU policy
# reserves ceil(system + kube reserved) CPUs, the managers' state lives next
# to the Pod directory (/var/lib/kubelet/cpu_manager_state), and admission
# runs the allocation handler.
class NodeAgentContainerManagerTest < Minitest::Test
  Node = Rubernetes::Node

  class API
    def create_or_update_node(node) = node
    def renew_lease(**) = {}
  end

  class Lifecycle
    def admitted_pods = []
    def pods = {}
  end

  class Loop
    def start = nil
    def stop = nil
    def running? = false
  end

  def test_the_managers_are_built_from_the_configuration
    Dir.mktmpdir do |dir|
      pod_root = File.join(dir, "pods")
      FileUtils.mkdir_p(pod_root)
      agent = Node::Agent.new(node_name: "n", api: API.new, lifecycle: Lifecycle.new, sync_loop: Loop.new, sleeper: ->(_) {},
                              pod_root: pod_root, capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "110"},
                              system_reserved: {"cpu" => "500m", "memory" => "512Mi"}, kube_reserved: {"cpu" => "500m"},
                              cpu_manager: {"policy" => "static"})
      assert_equal({"cpu" => "3", "memory" => "7680Mi", "pods" => "110"}, agent.allocatable)
      manager = agent.container_manager
      assert_equal 1, manager.cpu_manager.policy.reserved_cpus.size
      assert_equal "static", JSON.parse(File.read(File.join(dir, "cpu_manager_state")))["policyName"]
      assert_equal "None", JSON.parse(File.read(File.join(dir, "memory_manager_state")))["policyName"]
      admission = agent.instance_variable_get(:@admission)
      assert_equal manager.method(:admit), admission.allocation_admit_handler
    end
  end

  def test_an_impossible_configured_policy_stops_the_agent
    Dir.mktmpdir do |dir|
      pod_root = File.join(dir, "pods")
      FileUtils.mkdir_p(pod_root)
      error = assert_raises(Node::ContainerManager::Error) do
        Node::Agent.new(node_name: "n", api: API.new, lifecycle: Lifecycle.new, sync_loop: Loop.new, sleeper: ->(_) {},
                        pod_root: pod_root, capacity: {"cpu" => "4"}, cpu_manager: {"policy" => "static"})
      end
      assert_equal "[cpumanager] unable to determine reserved CPU resources for static policy", error.message
    end
  end

  def test_a_node_shutting_down_is_not_ready_and_refuses_pods
    Dir.mktmpdir do |dir|
      pod_root = File.join(dir, "pods")
      FileUtils.mkdir_p(pod_root)
      agent = Node::Agent.new(node_name: "n", api: API.new, lifecycle: Lifecycle.new, sync_loop: Loop.new, sleeper: ->(_) {},
                              pod_root: pod_root, capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "110"},
                              shutdown: {"grace_period" => "30s", "grace_period_critical_pods" => "10s"})
      manager = agent.shutdown_manager
      assert_equal [0, 2_000_000_000], manager.periods.map(&:priority)
      ready = agent.send(:build_node, ready: true).dig("status", "conditions").find { |c| c["type"] == "Ready" }
      assert_equal ["True", "KubeletReady", "kubelet is posting ready status"], ready.values_at("status", "reason", "message")

      manager.handle_event(true)
      ready = agent.send(:build_node, ready: true).dig("status", "conditions").find { |c| c["type"] == "Ready" }
      assert_equal ["False", "KubeletNotReady", "node is shutting down"], ready.values_at("status", "reason", "message")
      decision = agent.instance_variable_get(:@admission).admit({"metadata" => {"name" => "p", "uid" => "u"}, "spec" => {"containers" => []}})
      refute decision.accepted
      assert_equal "NodeShutdown", decision.reason
      assert_equal "Pod was rejected as the node is shutting down.", decision.message
    end
    assert_nil Node::Agent.new(node_name: "n", api: API.new, lifecycle: Lifecycle.new, sync_loop: Loop.new, sleeper: ->(_) {}).shutdown_manager,
               "no grace period, no shutdown manager"
  end
end
