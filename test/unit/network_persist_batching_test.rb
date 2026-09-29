# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"

# Attaching a Pod rewrote the node's whole network state once per claimed
# resource -- a veth effect claims two, host and peer -- on top of once per
# effect.  Concurrent Pod starts queued behind those writes.  One write now
# covers an effect's claims, and a claim that succeeded before a later one
# failed is still recorded.
class NetworkPersistBatchingTest < Minitest::Test
  Network = Rubernetes::Network

  class CountingStore
    attr_reader :writes

    def initialize
      @state = {}
      @writes = 0
    end

    def read = Network::Support.copy(@state)

    def replace(value)
      @writes += 1
      @state = Network::Support.copy(value)
      Network::Support.freeze_deeply(Network::Support.copy(@state))
    end
  end

  def interface_with(store, ledger: nil)
    Network::Interface.new(ipam: nil, topology: topology, state_store: store, ledger: ledger,
                           require_observer: false, observer: observer)
  end

  def topology
    plan = Struct.new(:operations, :mtu, :backend, :revision, :metadata, keyword_init: true)
    operation = Struct.new(:action, :resource, :identity, :parameters, keyword_init: true) do
      def to_h = {"action" => action, "resource" => resource, "identity" => identity, "parameters" => parameters}
    end
    operations = [operation.new(action: "link_add", resource: "link:veth0", identity: "veth0:1",
                                parameters: {"name" => "veth0", "kind" => "veth", "peer" => "eth0", "peer_resource" => "link:eth0"})]
    built = plan.new(operations: operations, mtu: 1500, backend: "bridge", revision: 1, metadata: {"bridge" => "cni0"})
    fake = Object.new
    fake.define_singleton_method(:desired) { |*, **| built }
    fake.define_singleton_method(:apply) do |plan_value, operation_id: nil, before_operation: nil, after_operation: nil|
      Array(plan_value.operations).each_with_index do |op, index|
        before_operation&.call(op, index)
        after_operation&.call(op, index)
      end
      plan_value
    end
    fake
  end

  # Two proofs for the one veth effect, as the kernel observer reports.
  def observer
    fake = Object.new
    fake.define_singleton_method(:resources_for) do |operation|
      value = operation.respond_to?(:to_h) ? operation.to_h : operation
      [{"kind" => "link", "id" => value["resource"], "identity" => "host-identity"},
       {"kind" => "link", "id" => "link:eth0", "identity" => "peer-identity"}]
    end
    fake
  end

  def test_one_effect_persists_its_claims_once
    store = CountingStore.new
    interface = interface_with(store)
    interface.add({"sandbox_id" => "sb-1", "netns" => nil}, {"node" => "worker-0", "host_network" => true})
    baseline = store.writes

    store2 = CountingStore.new
    other = interface_with(store2)
    result = other.add({"sandbox_id" => "sb-2"}, {"node" => "worker-0", "ips" => [], "default_route" => false})
    assert result
    operation = store2.read.fetch("operations").values.last
    identities = Array(operation["resources"]).map { |resource| resource["identity"] }.sort
    assert_equal %w[host-identity peer-identity], identities, "both proofs are recorded"
    assert_operator store2.writes, :<, baseline + 8, "a veth effect must not rewrite the state per claim"
  end
end
