# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/storage/memory_store"
require "rubernetes/watch/work_queue"

# monitorNodeHealth: the controller manager sweeps every Node on a period,
# timed as node_collector_update_all_nodes_health_duration_seconds.
class NodeHealthMonitorTest < Minitest::Test
  Manager = Rubernetes::Controller::Manager

  Elector = Struct.new(:leader) do
    def leader? = leader
  end

  class FakeNodeController
    attr_reader :seen, :name

    def initialize = (@seen = [])
    def name = "node-lifecycle-controller"
    def resource_descriptor = Rubernetes::Controller::ResourceDescriptor.parse("Node")

    def reconcile(node, **)
      @seen << node.dig("metadata", "name")
      Rubernetes::Controller::ReconcileResult.new(operations: [], status: {}, controller: name, key: node.dig("metadata", "name"))
    end
  end

  def test_the_pass_reconciles_every_node_and_records_its_duration
    store = Rubernetes::Storage::MemoryStore.new
    %w[worker-0 worker-1].each do |name|
      store.create("registry/v1/nodes/#{name}", {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name}, "spec" => {}, "status" => {}})
    end
    controller = FakeNodeController.new
    manager = Manager.allocate
    {queue: Rubernetes::Watch::WorkQueue.new, elector: Elector.new(true), store: store, store_for: nil, controller_stores: {},
     manager_mutex: Mutex.new, controllers: {"node-lifecycle-controller" => controller}, error_handler: nil}.each do |name, value|
      manager.instance_variable_set(:"@#{name}", value)
    end
    registry = Rubernetes::Observability::Metrics.new(apiserver: false, component: "kube-controller-manager")
    previous_metrics = Rubernetes::Controller.metrics
    Rubernetes::Controller.metrics = registry
    assert_equal 2, manager.node_health_pass!
    assert_equal %w[worker-0 worker-1], controller.seen.sort
    text = registry.render
    assert_match(/node_collector_update_all_nodes_health_duration_seconds_count 1/, text)
    manager.instance_variable_set(:@elector, Elector.new(false))
    assert_equal 0, manager.node_health_pass!, "a follower does not sweep"
  ensure
    Rubernetes::Controller.metrics = previous_metrics
  end
end
