# frozen_string_literal: true

require "json"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/network"

# A network state write re-encodes only what changed: sealed canonical
# subtrees from the previous write are shared, not rebuilt.
class NetworkCanonicalSharingTest < Minitest::Test
  Support = Rubernetes::Network::Support

  def test_sealed_subtrees_are_shared_and_new_parts_canonicalised
    sealed = Support.freeze_canonical(Support.canonical({"b" => 1, "a" => {"z" => 2, "y" => [3]}}))
    assert sealed.frozen?
    assert_equal %w[a b], sealed.keys
    again = Support.canonical({b: sealed, c: Time.utc(2026, 9, 23)})
    assert_same sealed, again["b"], "a sealed subtree is not rebuilt"
    assert_equal "2026-09-23T00:00:00.000000Z", again["c"]
  end

  def test_unknown_objects_become_what_json_makes_of_them
    point = Struct.new(:x).new(1)
    assert_equal JSON.parse(JSON.generate([point])).first, Support.canonical(point)
  end

  def test_working_copy_has_mutable_maps_over_sealed_records
    sealed = Support.freeze_canonical(Support.canonical({"operations" => {"o1" => {"state" => "a"}}, "requests" => {}}))
    working = Support.working_copy(sealed)
    working["operations"]["o2"] = {"state" => "b"}
    working["requests"]["r"] = "o2"
    assert_same sealed["operations"]["o1"], working["operations"]["o1"]
    assert_raises(FrozenError) { working["operations"]["o1"]["state"] = "x" }
    refute sealed["operations"].key?("o2")
  end

  def test_durable_state_replace_round_trips_and_returns_the_sealed_state
    Dir.mktmpdir do |dir|
      store = Rubernetes::Network::DurableState.new(File.join(dir, "state.json"), default: {"operations" => {}}, fsync: false)
      written = store.replace({"operations" => {"o1" => {"state" => "a"}}})
      assert written.frozen?
      next_state = Support.working_copy(written)
      next_state["operations"]["o2"] = {"state" => "b"}
      second = store.replace(next_state)
      assert_same written["operations"]["o1"], second["operations"]["o1"]
      assert_equal({"operations" => {"o1" => {"state" => "a"}, "o2" => {"state" => "b"}}}, JSON.parse(File.read(File.join(dir, "state.json"))))
    end
  end
end

# IPAM keeps the records it wrote and replaces (never edits) the one a call
# changes, so a write re-encodes only that record; a failed persist still
# rolls the whole transaction back.
class IPAMRecordSharingTest < Minitest::Test
  def ipam(path)
    Rubernetes::Network::IPAM.new(ipv4_cidr: "10.244.0.0/16", ipv4_node_prefix: 24, state_path: path, fsync: false)
  end

  def test_unchanged_leases_are_shared_across_writes
    Dir.mktmpdir do |dir|
      subject = ipam(File.join(dir, "ipam.json"))
      first = subject.reserve(node: "n", pod_uid: "a", sandbox_id: "sa")
      subject.commit(first)
      state = subject.instance_variable_get(:@durable_state)
      lease_a = state["leases"].values.first
      assert lease_a.frozen?

      second = subject.reserve(node: "n", pod_uid: "b", sandbox_id: "sb")
      subject.commit(second)
      after = subject.instance_variable_get(:@durable_state)
      assert_same lease_a, after["leases"].values.find { |lease| lease["pod_uid"] == "a" }, "pod a's lease was not rebuilt"
      assert_equal %w[committed committed], after["leases"].values.map { |lease| lease["state"] }
    end
  end

  def test_a_failed_persist_rolls_the_commit_back
    Dir.mktmpdir do |dir|
      subject = ipam(File.join(dir, "ipam.json"))
      leases = subject.reserve(node: "n", pod_uid: "a", sandbox_id: "sa")
      store = subject.instance_variable_get(:@store)
      store.define_singleton_method(:replace) { |_value| raise Rubernetes::Network::DurabilityError, "disk full" }
      assert_raises(Rubernetes::Network::DurabilityError) { subject.commit(leases) }
      assert_equal "reserved", subject.instance_variable_get(:@state)["leases"].values.first["state"]
    end
  end
end

# IPAM keeps only a window of released operations; the state does not grow
# with every Pod the node has ever run.
class IPAMReleasedOperationPruningTest < Minitest::Test
  def test_released_operations_beyond_the_window_are_dropped
    Dir.mktmpdir do |dir|
      ipam = Rubernetes::Network::IPAM.new(ipv4_cidr: "10.244.0.0/16", ipv4_node_prefix: 24,
                                           state_path: File.join(dir, "ipam.json"), fsync: false)
      window = Rubernetes::Network::IPAM::RETAINED_RELEASED_OPERATIONS
      (window + 20).times do |i|
        leases = ipam.reserve(node: "n", pod_uid: "p#{i}", sandbox_id: "s#{i}")
        ipam.release(ipam.commit(leases), stopped: true)
      end
      operations = ipam.instance_variable_get(:@state)["operations"]
      assert_equal window, operations.length
      refute operations.key?("network-s0") || operations.values.any? { |record| record["sandbox_id"] == "s0" }
      # A retried release of a pruned operation is a completed release.
      assert_empty ipam.release(operation_id: operations.keys.first.sub(/\d+\z/, "0"), stopped: true).to_a
    end
  end
end
