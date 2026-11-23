# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/network"

class NetworkFailedAddRollbackTest < Minitest::Test
  Network = Rubernetes::Network
  SANDBOX = {"sandbox_id" => "failed"}.freeze
  CONFIG = {gateway: "10.244.0.1", node: "worker", operation_id: "original"}.freeze

  class RecordingAdapter
    attr_accessor :fail_bridge
    attr_reader :effects

    def initialize
      @effects = []
    end

    def apply(operation, operation_id:)
      @effects << [operation_id, operation]
      !(fail_bridge && operation.parameters["kind"] == "bridge")
    end
  end

  class ProoflessObserver
    def external_observer? = true

    def resources_for(operation)
      return [] if operation.action == "address_add"

      [{"kind" => "link", "identity" => "recording-#{operation.resource}"}]
    end
  end

  def with_network
    Dir.mktmpdir("network-failed-add") do |dir|
      adapter = RecordingAdapter.new
      ipam = Network::IPAM.new(ipv4_cidr: "10.244.0.0/16", ipv4_node_prefix: 24, state_path: File.join(dir, "ipam.json"), fsync: false)
      journal = Rubernetes::Runtime::Native::RollbackJournal.new(File.join(dir, "network.wal"), fsync: false)
      ledger = Rubernetes::Runtime::Native::OwnershipLedger.new(journal: journal)
      state_path = File.join(dir, "network.json")
      network = Network::Interface.new(adapter: adapter, ipam: ipam, ledger: ledger, observer: ProoflessObserver.new,
                                       state_path: state_path, require_observer: true, readback_timeout: 0.005, fsync: false)
      yield network, adapter, ipam, ledger, state_path
    end
  end

  def test_uncertain_native_rollback_retains_the_attempted_effect_allocation_and_claims
    with_network do |network, adapter, ipam, ledger, state_path|
      error = assert_raises(Network::EffectError) { network.add(SANDBOX, **CONFIG) }
      record = JSON.parse(File.read(state_path)).fetch("operations").fetch("original")
      inverses = adapter.effects.map { |_id, effect| effect.action }.grep(/delete/)

      assert_match(/lacks durable intent or independent kernel readback/, error.message)
      assert_equal "unknown", record.fetch("state")
      assert_equal "address_add", record.dig("effect_intent", "action")
      assert_nil record["rollback_verified"]
      assert_equal %w[address_delete link_delete], inverses
      assert_equal ["reserved"], ipam.leases(operation_id: "original").map(&:state)
      refute_empty ledger.resources(owner: "network:failed")

      recorded_effects = adapter.effects.length

      assert_raises(Network::RecoveryRequired) { network.add(SANDBOX, **CONFIG) }
      assert_raises(Network::OperationConflict) { network.add(SANDBOX, **CONFIG, operation_id: "another") }
      assert_equal recorded_effects, adapter.effects.length

      recovered = network.recover
      failed_ids = recovered.errors.map { |detail| detail.fetch("operation_id") }

      assert_equal ["original"], failed_ids
      assert_empty recovered.ipam.reclaimed
      assert_equal ["reserved"], ipam.leases(operation_id: "original").map(&:state)
      assert_equal recorded_effects, adapter.effects.length
    end
  end

  def test_bridge_failure_does_not_run_inverses_for_an_unattempted_plan
    with_network do |network, adapter, ipam, _ledger, _state_path|
      adapter.fail_bridge = true

      assert_raises(Network::EffectError) { network.add(SANDBOX, **CONFIG) }
      actions = adapter.effects.map { |_id, effect| effect.action }

      assert_equal ["link_add"], actions
      assert_nil network.operation("original")["effect_intent"]
      assert_equal "unknown", network.operation("original").fetch("state")
      assert_empty ipam.leases(operation_id: "original")
    end
  end
end
