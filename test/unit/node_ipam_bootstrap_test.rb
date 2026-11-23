# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"
require "rubernetes/cluster/cli"
require "stringio"
require "tmpdir"

class NodeIPAMBootstrapTest < Minitest::Test
  MANAGER = "rubernetes-controller-manager"
  CONTROLLER = "node-ipam-controller"

  def test_normal_controller_config_enables_dual_stack_allocation_in_pool_order
    manager = controller_manager("allocate_node_cidrs" => true, "cluster_cidrs" => %w[fd00:42::/56 10.24.0.0/16])
    allocation = manager.controllers.fetch(CONTROLLER).reconcile(node("worker"), apply: false)
    spec = allocation.operations.fetch(0).object.fetch("spec")

    assert_equal %w[fd00:42::/64 10.24.0.0/24], spec.fetch("podCIDRs")
    assert_equal "fd00:42::/64", spec.fetch("podCIDR")
  end

  def test_disabled_controller_does_not_infer_ranges_from_known_nodes
    refute controller_manager.controllers.key?(CONTROLLER)
    refute controller_manager("allocate_node_cidrs" => false, "cluster_cidrs" => ["10.24.0.0/16"]).controllers.key?(CONTROLLER)
  end

  def test_dual_stack_exhaustion_does_not_publish_a_partial_assignment
    controller = Rubernetes::Controller::NodeIPAMController.new
    occupied = node("taken", "podCIDRs" => ["fd00:42::/64"])
    allocation = controller.plan(
      node("worker"), nodes: [occupied], cluster_cidrs: %w[10.24.0.0/24 fd00:42::/64], node_cidr_mask_sizes: [24, 64]
    )

    assert_empty allocation.operations
    assert_equal "CIDRAssignmentFailed", allocation.events.fetch(0).fetch("reason")
  end

  def test_fixed_assignments_do_not_claim_a_range_already_owned_by_another_node
    section = {"allocate_node_cidrs" => true, "assignments" => {"worker" => %w[10.32.4.0/24 fd00:42:1::/64]}}
    allocator = Rubernetes::Bootstrap::NodeIPAMSettings.new(section).controller_options.fetch(:cidr_allocator)

    assert_empty allocator.call(node("unknown"), [])
    assert_empty allocator.call(node("worker"), [node("other", "podCIDR" => "10.32.0.0/16")])
    assert_equal %w[10.32.4.0/24 fd00:42:1::/64], allocator.call(node("worker"), [node("empty", "podCIDR" => "")])
  end

  def test_enabled_config_rejects_missing_pools_and_overlapping_assignments
    no_pool = assert_raises(Rubernetes::Bootstrap::Config::Error) { config("allocate_node_cidrs" => true) }
    overlap_error = assert_raises(Rubernetes::Bootstrap::Config::Error) do
      config("allocate_node_cidrs" => true, "assignments" => {"first" => ["10.32.4.0/24"], "second" => ["10.32.0.0/16"]})
    end

    assert_match(/cluster_cidrs must contain/, no_pool.message)
    assert_match(/assignments overlap/, overlap_error.message)
  end

  def test_public_cluster_up_uses_the_same_ranges_for_the_native_bridge_and_nodeipam
    Dir.mktmpdir do |root|
      cli = Rubernetes::Cluster::CLI.new(stdout: StringIO.new, stderr: StringIO.new)
      inspect_cluster = lambda do |cluster, _options|
        cluster.stub(:selected_controllers, [CONTROLLER]) do
          controller = cluster.send(:write_controller_config, "credentials", serving_port: 10_257)
          assignments = Rubernetes::Bootstrap::Config.load(process_name: MANAGER, path: controller).process
          expected = assignments.dig("node_ipam", "assignments", "worker-1")
          agent = cluster.send(:write_agent_config, "worker-1", 1, "credentials")
          network = YAML.safe_load_file(agent).dig("processes", "rubernetes-agent", "network")
          bridge = %w[ipv4 ipv6].zip(%w[node_subnet_prefix ipv6_node_prefix]).map do |family, key|
            prefix = network.fetch(key)
            "#{IPAddr.new(network.fetch("#{family}_cidr")).mask(prefix)}/#{prefix}"
          end

          assert_equal bridge, expected
          assert_equal %w[10.241.0.0/24 fd00:d8:1::/64], expected
        end
        0
      end

      cli.stub(:up, inspect_cluster) do
        assert_equal 0, cli.run(["up", "--root", root, "--workers", "2", "--ip-family", "dual", "--allocate-node-cidrs"])
      end
    end
  end

  private

  def config(settings)
    process = {"controllers" => [CONTROLLER]}
    process["node_ipam"] = settings unless settings.nil?
    data = {"version" => 1, "logging" => {"level" => "warn"}, "processes" => {MANAGER => process}}
    Rubernetes::Bootstrap::Config.new(process_name: MANAGER, data: data).process
  end

  def controller_manager(settings = nil)
    service = Rubernetes::Bootstrap::ControllerManagerService.new(
      config: config(settings), logger: Object.new, client: Object.new, store: Rubernetes::Storage::MemoryStore.new
    )
    service.send(:build_runtime!)
    service.manager
  end

  def node(name, spec = {})
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "uid" => name}, "spec" => spec}
  end
end
