# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node/qos_cgroup_manager"

# kubelet node allocatable enforcement and QoS cgroup weights
# (pkg/kubelet/cm node_container_manager_linux.go, qos_container_manager_linux.go,
# helpers_linux.go MilliCPUToShares, libcontainer's shares -> cpu.weight).
class QOSCgroupManagerTest < Minitest::Test
  Manager = Rubernetes::Node::QOSCgroupManager
  FILES = %w[cpu.weight memory.max pids.max hugetlb.2MB.max].freeze

  def setup
    @dir = Dir.mktmpdir("qos-cgroups-")
    @root = File.join(@dir, "cgroup")
    @state = File.join(@dir, "state")
    base = File.join(@root, "rubernetes")
    ([base] + %w[guaranteed burstable besteffort].map { |qos| File.join(base, qos) }).each do |directory|
      FileUtils.mkdir_p(directory)
      FILES.each { |file| File.write(File.join(directory, file), "max") }
    end
    FileUtils.mkdir_p(File.join(@root, "system.slice"))
    FILES.each { |file| File.write(File.join(@root, "system.slice", file), "max") }
    @events = []
  end

  def teardown
    FileUtils.rm_rf(@dir)
  end

  def read(*path) = File.read(File.join(@root, "rubernetes", *path))

  def manager(node: "n1", capacity: {}, **)
    Manager.new(root: @root, capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "110", "hugepages-2Mi" => "4Mi"}.merge(capacity),
                node_name: node, state_dir: @state, pid_max_paths: [], event: ->(*event) { @events << event },
                error_handler: ->(error, *) { raise error }, **)
  end

  def pod(qos_cpu, uid, phase: "Running")
    resources = case qos_cpu
                when :besteffort then {}
                when Array then {"requests" => {"cpu" => qos_cpu[1]}, "limits" => {"cpu" => qos_cpu[1], "memory" => "1Gi"}}.tap do |value|
                  value["requests"]["memory"] = "1Gi"
                end
                else {"requests" => {"cpu" => qos_cpu}}
                end
    {"metadata" => {"uid" => uid}, "spec" => {"containers" => [{"name" => "c", "resources" => resources}]}, "status" => {"phase" => phase}}
  end

  def test_shares_and_weights_follow_upstream
    assert_equal 2, Manager.milli_cpu_to_shares(0)
    assert_equal 2, Manager.milli_cpu_to_shares(1)
    assert_equal 102, Manager.milli_cpu_to_shares(100)
    assert_equal 262_144, Manager.milli_cpu_to_shares(1_000_000)
    assert_equal 1, Manager.shares_to_weight(2)
    assert_equal 39, Manager.shares_to_weight(1024)
    assert_equal 10_000, Manager.shares_to_weight(262_144)
  end

  def test_pods_root_is_limited_to_capacity_less_reservations
    manager(system_reserved: {"cpu" => "500m", "memory" => "1Gi"}, kube_reserved: {"memory" => "1Gi", "pid" => "100"},
            capacity: {"pid" => "1000"}).tick([])

    assert_equal Manager.shares_to_weight(Manager.milli_cpu_to_shares(3500)).to_s, read("cpu.weight")
    assert_equal (6 * (1024**3)).to_s, read("memory.max")
    assert_equal "900", read("pids.max")
    assert_equal (4 * (1024**2)).to_s, read("hugetlb.2MB.max")
    assert_equal [["Normal", "NodeAllocatableEnforced", "Updated Node Allocatable limit across pods"]], @events
  end

  def test_without_pods_enforcement_the_root_gets_capacity
    manager(system_reserved: {"memory" => "1Gi"}, enforce_node_allocatable: []).tick([])

    assert_equal (8 * (1024**3)).to_s, read("memory.max")
  end

  def test_qos_weights_follow_the_pods_requests
    m = manager
    m.tick([pod("250m", "a"), pod("750m", "b"), pod(:besteffort, "c"), pod([:guaranteed, "2"], "d"), pod("4", "done", phase: "Succeeded")])

    assert_equal Manager.shares_to_weight(Manager.milli_cpu_to_shares(1000)).to_s, read("burstable", "cpu.weight")
    assert_equal Manager.shares_to_weight(Manager.milli_cpu_to_shares(2000)).to_s, read("guaranteed", "cpu.weight")
    assert_equal "1", read("besteffort", "cpu.weight")
  end

  # Two agents of one host share the hierarchy: both write the same
  # composition instead of overwriting each other.
  def test_agents_sharing_the_hierarchy_compose
    first = manager(node: "worker-0", system_reserved: {"memory" => "6Gi"})
    second = manager(node: "worker-1", system_reserved: {"memory" => "7Gi"})
    first.tick([pod("500m", "a")])
    second.tick([pod("1500m", "b")])

    assert_equal (3 * (1024**3)).to_s, read("memory.max"), "2Gi + 1Gi of allocatable"
    burstable = Manager.shares_to_weight(Manager.milli_cpu_to_shares(2000)).to_s

    assert_equal burstable, read("burstable", "cpu.weight")
    first.tick([pod("500m", "a")])

    assert_equal burstable, read("burstable", "cpu.weight"), "the first agent keeps the second one's Pods"
    assert_equal (3 * (1024**3)).to_s, read("memory.max")

    second.stop
    first.tick([pod("500m", "a")])

    assert_equal Manager.shares_to_weight(Manager.milli_cpu_to_shares(500)).to_s, read("burstable", "cpu.weight")
    assert_equal (2 * (1024**3)).to_s, read("memory.max"), "a stopped agent's share is gone"
  end

  def test_the_sum_never_exceeds_the_host_capacity
    manager(node: "a").tick([])
    manager(node: "b").tick([])

    assert_equal (8 * (1024**3)).to_s, read("memory.max")
  end

  def test_reserved_cgroups_are_limited_to_their_reservations
    manager(system_reserved: {"cpu" => "1", "memory" => "1Gi"}, enforce_node_allocatable: %w[pods system-reserved],
            system_reserved_cgroup: "/system.slice").tick([])

    assert_equal (1024**3).to_s, File.read(File.join(@root, "system.slice", "memory.max"))
    assert_equal "39", File.read(File.join(@root, "system.slice", "cpu.weight"))
  end

  # enforceExistingCgroup(..., compressibleResources: true): the reserved
  # cgroup gets its CPU weight only, memory and pids are left alone.
  def test_compressible_enforcement_limits_the_cpu_only
    FileUtils.mkdir_p(File.join(@root, "system.slice"))
    File.write(File.join(@root, "system.slice", "memory.max"), "max")
    manager(system_reserved: {"cpu" => "1", "memory" => "1Gi"}, enforce_node_allocatable: %w[pods system-reserved-compressible],
            system_reserved_cgroup: "/system.slice").tick([])

    assert_equal "39", File.read(File.join(@root, "system.slice", "cpu.weight"))
    assert_equal "max", File.read(File.join(@root, "system.slice", "memory.max"))
    assert_raises(Manager::Error) { manager(enforce_node_allocatable: %w[kube-reserved-compressible]) }
  end

  def test_configuration_errors
    assert_raises(Manager::Error) { manager(enforce_node_allocatable: %w[pods bogus]) }
    assert_raises(Manager::Error) { manager(enforce_node_allocatable: %w[kube-reserved]) }
    assert_raises(Manager::Error) { manager(enforce_node_allocatable: %w[none pods]) }
  end

  def test_a_failed_enforcement_is_reported_and_retried
    FileUtils.rm_rf(File.join(@root, "rubernetes"))
    errors = []
    m = manager
    m.instance_variable_set(:@error_handler, ->(error, *) { errors << error })
    m.tick([])

    assert_equal "FailedNodeAllocatableEnforcement", @events.last[1]
    refute_empty errors
    FileUtils.mkdir_p(File.join(@root, "rubernetes"))
    FILES.each { |file| File.write(File.join(@root, "rubernetes", file), "max") }
    m.tick([])

    assert_equal "NodeAllocatableEnforced", @events.last[1]
  end
end

# rubernetes-agent cgroups_per_qos / enforce_node_allocatable /
# system_reserved_cgroup / kube_reserved_cgroup, validated as the kubelet's.
class NodeAllocatableEnforcementConfigTest < Minitest::Test
  require "tempfile"
  require "json"
  require "rubernetes/bootstrap/config"
  Config = Rubernetes::Bootstrap::Config

  def load(settings)
    file = Tempfile.new(["agent", ".yml"])
    lines = settings.map { |key, value| "      #{key}: #{value.to_json}" }.join("\n")
    file.write("version: 1\nlogging:\n  level: info\nprocesses:\n  rubernetes-agent:\n    node_name: n1\n    api_server: http://127.0.0.1:1\n#{lines.gsub(
      /^      /, "    "
    )}\n")
    file.flush
    Config.load(process_name: "rubernetes-agent", path: file.path)
  ensure
    file&.close
  end

  def test_valid_settings
    config = load("enforce_node_allocatable" => %w[pods system-reserved], "system_reserved_cgroup" => "/system.slice")

    assert_equal %w[pods system-reserved], config.process["enforce_node_allocatable"]
    assert load("enforce_node_allocatable" => ["none"], "cgroups_per_qos" => false)
  end

  def test_invalid_settings
    assert_raises(Config::Error) { load("enforce_node_allocatable" => ["everything"]) }
    assert_raises(Config::Error) { load("enforce_node_allocatable" => %w[none pods]) }
    assert_raises(Config::Error) { load("enforce_node_allocatable" => ["kube-reserved"]) }
    assert_raises(Config::Error) { load("enforce_node_allocatable" => ["pods"], "cgroups_per_qos" => false) }
    assert_raises(Config::Error) { load("system_reserved_cgroup" => "system.slice") }
    assert_raises(Config::Error) { load("cgroups_per_qos" => "yes") }
  end
end
