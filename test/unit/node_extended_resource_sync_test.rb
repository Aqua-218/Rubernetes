# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# kubelet's MachineInfo status setter carries every resource in the Node's
# capacity into allocatable on each sync, extended resources it does not
# manage included, and drops extended resources that left capacity.  The
# agent never did, so a resource a client wrote into capacity never became
# allocatable: nothing that requested it could be scheduled, and the agent's
# own admission would have rejected it anyway.  "[sig-scheduling]
# SchedulerPreemption PreemptionExecutionPath runs ReplicaSets to verify
# preemption running path" adds example.com/fakecpu, and its ReplicaSets
# never ran.
class NodeExtendedResourceSyncTest < Minitest::Test
  RM = Rubernetes::Node::ResourceManager

  class API
    attr_reader :patches
    attr_accessor :node

    def initialize(node)
      @node = node
      @patches = []
    end

    def read_object(_resource, _name, **) = @node

    def patch_node_status(name, status)
      @patches << [name, status]
    end
  end

  def node(capacity:, allocatable:)
    {"metadata" => {"name" => "worker-0"}, "status" => {"capacity" => capacity, "allocatable" => allocatable}}
  end

  def agent_with(api, manager)
    admission = Struct.new(:resource_manager).new(manager)
    agent = Rubernetes::Node::Agent.allocate
    agent.instance_variable_set(:@api, api)
    agent.instance_variable_set(:@node_name, "worker-0")
    agent.instance_variable_set(:@capacity, {"cpu" => "4", "memory" => "8Gi", "pods" => "110"})
    agent.instance_variable_set(:@admission, admission)
    agent
  end

  def manager = RM.new(capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "110"})

  def test_an_extended_resource_in_capacity_becomes_allocatable
    api = API.new(node(capacity: {"cpu" => "4", "example.com/fakecpu" => "1k"}, allocatable: {"cpu" => "4"}))

    agent_with(api, manager).send(:sync_extended_resources)

    assert_equal [["worker-0", {"allocatable" => {"example.com/fakecpu" => "1k"}}]], api.patches
  end

  def test_the_agents_admission_admits_against_it
    rm = manager
    api = API.new(node(capacity: {"example.com/fakecpu" => "1k"}, allocatable: {}))

    agent_with(api, rm).send(:sync_extended_resources)

    assert rm.fits?({"example.com/fakecpu" => "200"}), "a Pod requesting the advertised resource must fit"
    refute rm.fits?({"example.com/fakecpu" => "2k"})
  end

  def test_an_extended_resource_gone_from_capacity_leaves_allocatable
    rm = manager
    rm.replace_extended({"example.com/fakecpu" => "1k"})
    api = API.new(node(capacity: {"cpu" => "4"}, allocatable: {"cpu" => "4", "example.com/fakecpu" => "1k"}))

    agent_with(api, rm).send(:sync_extended_resources)

    assert_equal [["worker-0", {"allocatable" => {"example.com/fakecpu" => nil}}]], api.patches
    refute rm.fits?({"example.com/fakecpu" => "1"})
  end

  def test_nothing_is_written_when_allocatable_already_matches
    api = API.new(node(capacity: {"example.com/fakecpu" => "1k"}, allocatable: {"example.com/fakecpu" => "1k"}))

    agent_with(api, manager).send(:sync_extended_resources)

    assert_empty api.patches
  end

  def test_native_and_quota_names_are_not_extended_resources
    refute RM.extended_resource?("cpu")
    refute RM.extended_resource?("kubernetes.io/batch-cpu")
    refute RM.extended_resource?("requests.example.com/foo")
    assert RM.extended_resource?("example.com/fakecpu")
  end
end
