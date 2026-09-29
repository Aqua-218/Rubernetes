# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/lifecycle"
require "rubernetes/network/interface"

# Both durable states are rewritten in full on every transition, so a state
# that only ever grows turns every Pod start into JSON churn: 250 dead Pod
# records (10.3 MB) and 241 dead network operations (1.2 MB) were measured on
# a conformance node, and network.connect alone took 11-12 s of a 17 s start.
class StatePruningTest < Minitest::Test
  def test_only_live_records_and_a_bounded_window_of_removed_ones_are_persisted
    lifecycle = Rubernetes::Node::Lifecycle.allocate
    records = {}
    40.times { |i| records["gone-#{i}"] = {uid: "gone-#{i}", state: "Removed", pod: {"metadata" => {"name" => "gone-#{i}"}}} }
    records["live"] = {uid: "live", state: "Running", pod: {"metadata" => {"name" => "live"}}}
    lifecycle.instance_variable_set(:@records, records)
    lifecycle.define_singleton_method(:serializable_record) { |record| {"uid" => record[:uid], "state" => record[:state]} }

    persisted = lifecycle.send(:persistable_records)
    states = persisted.group_by { |r| r["state"] }.transform_values(&:length)

    assert_equal 1, states["Running"], "every live record is persisted"
    assert_equal Rubernetes::Node::Lifecycle::PERSISTED_REMOVED_RECORDS, states["Removed"]
    assert_equal "gone-39", persisted.last["uid"], "the most recent removals are the ones kept"
  end

  def test_removed_network_operations_are_pruned_to_a_bounded_window
    interface = Rubernetes::Network::Interface.allocate
    operations = {}
    requests = {}
    60.times do |i|
      operations["op-#{i}"] = {"id" => "op-#{i}", "state" => "removed", "request_id" => "req-#{i}"}
      requests["req-#{i}"] = "op-#{i}"
    end
    operations["live"] = {"id" => "live", "state" => "committed", "request_id" => "req-live"}
    requests["req-live"] = "live"
    interface.instance_variable_set(:@state, {"operations" => operations, "requests" => requests})
    interface.define_singleton_method(:persist!) { |*| nil }

    interface.send(:prune_removed_operations!)
    state = interface.instance_variable_get(:@state)

    removed = state["operations"].values.count { |o| o["state"] == "removed" }
    assert_equal Rubernetes::Network::Interface::RETAINED_REMOVED_OPERATIONS, removed
    assert state["operations"].key?("live"), "a live operation is never pruned"
    assert_equal "live", state["requests"]["req-live"]
    refute state["requests"].key?("req-0"), "a pruned operation's request mapping goes with it"
    assert state["operations"].key?("op-59"), "the most recent removals are kept"
  end

  # Pruning the records left the snapshot at 1.1 MB on a conformance node:
  # 415 KB of probe state and 50 KB of restart backoff for containers of Pods
  # that were long gone.  kubelet drops both with the Pod (probeManager.RemovePod,
  # backoff GC).  Every byte here is rewritten under one lock on every state
  # transition of every Pod, so it is what made Pod starts on a node queue
  # behind each other.
  class Probes
    attr_reader :registered

    def initialize(ids) = @registered = ids.dup

    def unregister(id) = @registered.delete(id)
  end

  def restart_manager(*keys)
    manager = Rubernetes::Node::RestartManager.new
    keys.each { |key| manager.record_start(key, policy: "Always") }
    manager
  end

  def test_a_cleaned_up_pod_releases_its_probe_and_restart_state
    lifecycle = Rubernetes::Node::Lifecycle.allocate
    probes = Probes.new(%w[cid-app cid-side cid-other])
    restarts = restart_manager("dead/app", "dead/side", "alive/app")
    lifecycle.instance_variable_set(:@probes, probes)
    lifecycle.instance_variable_set(:@restarts, restarts)
    record = {uid: "dead", cleanup_errors: [],
              containers: [{id: "cid-app", name: "app"}, {id: "cid-side", name: "side"}]}

    lifecycle.send(:forget_terminated_probe_and_restart_state, record)

    assert_equal ["cid-other"], probes.registered, "only the dead Pod's probes are dropped"
    assert_equal ["alive/app"], restarts.all.map { |entry| entry["key"] || entry[:key] }
  end

  # A Pod whose cleanup failed still owns resources the next sync must retry,
  # so its state is not released.
  def test_a_pod_with_cleanup_errors_keeps_its_state
    lifecycle = Rubernetes::Node::Lifecycle.allocate
    probes = Probes.new(%w[cid-app])
    restarts = restart_manager("stuck/app")
    lifecycle.instance_variable_set(:@probes, probes)
    lifecycle.instance_variable_set(:@restarts, restarts)
    record = {uid: "stuck", cleanup_errors: ["stop: boom"], containers: [{id: "cid-app", name: "app"}]}

    lifecycle.send(:forget_terminated_probe_and_restart_state, record)

    assert_equal ["cid-app"], probes.registered
    assert_equal 1, restarts.all.length
  end
end
