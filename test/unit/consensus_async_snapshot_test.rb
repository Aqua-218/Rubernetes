# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/consensus"

# Encoding a snapshot takes seconds for a store of a few thousand objects, and
# the node used to do it under the server lock that also drives heartbeats:
# every 10,000 entries the leader went silent, the followers' election timeout
# fired, and the term changed.  The node now only captures the state document
# under the lock; a writer thread encodes and persists it and reports back.
class ConsensusAsyncSnapshotTest < Minitest::Test
  C = Rubernetes::Consensus

  def setup
    @root = Dir.mktmpdir("raft-async-snapshot")
    @ca, @ca_key = C::Identity.generate_ca("t")
    @ids = %w[a b c]
    @timing = C::Node::Timing.default.with(snapshot_entries: 10, snapshot_min_interval: 0.05)
    @servers = @ids.to_h { |id| [id, build_server(id)] }
    @servers.each_value(&:start)
    @servers.each_value { |server| @servers.each { |peer_id, peer| server.add_peer(peer_id, peer.address) unless peer.equal?(server) } }
    wait_until("a leader") { @servers.values.any?(&:leader?) }
  end

  def teardown
    @servers.each_value do |server|
      server.stop
    rescue StandardError
      nil
    end
    FileUtils.rm_rf(@root)
  end

  def build_server(id)
    bundle = C::Identity.issue_node(@ca, @ca_key, cluster_id: "t", node_id: id)
    C::Server.new(id: id, cluster_id: "t", data_directory: File.join(@root, id), bundle: bundle, initial_voters: @ids,
                  timing: @timing)
  end

  def wait_until(what, timeout: 10)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      raise "timed out waiting for #{what}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.02
    end
  end

  def test_the_leader_snapshots_off_the_lock_and_compacts_its_log_afterwards
    leader = @servers.values.find(&:leader?)
    term_before = leader.status["term"]
    store = C::RaftStore.new(leader)
    30.times { |i| store.create("k/#{i}", {"metadata" => {"name" => "o#{i}"}, "spec" => {"v" => i}}) }

    # Wait for the snapshot EVENT, not a threshold: with 30 entries and a
    # 10-entry trigger a second snapshot can be in flight -- written to disk
    # but not yet compacted, or compacted while this reads the disk -- when
    # the first one has passed the threshold (3 of 200 runs under load).
    # Settled means: nothing in flight and too few new entries to start one.
    wait_until("the snapshots to settle") do
      status = leader.status
      status["snapshot_index"].to_i >= 10 && !leader.node.snapshot_in_flight? &&
        status["last_applied"] - status["snapshot_index"] < @timing.snapshot_entries
    end

    snapshot, = leader.send(:instance_variable_get, :@storage).snapshots.latest(strict: true)

    refute_nil snapshot
    assert_operator snapshot.index, :>=, 10
    assert_equal snapshot.index, leader.status["snapshot_index"]
    # The state kept serving and accepting writes throughout.
    assert_equal({"v" => 29}, store.get("k/29")["spec"])
    store.create("k/after", {"metadata" => {"name" => "after"}})

    assert_equal "after", store.get("k/after").dig("metadata", "name")
    # The term did not move: no election was caused by the snapshot.
    assert_equal term_before, leader.status["term"], "a snapshot must not cost the leader its term"
  end

  def test_a_capture_is_taken_under_the_lock_and_completed_later
    Dir.mktmpdir do |dir|
      storage = C::Storage.new(dir)
      machine = C::KVStateMachine.new
      captures = []
      node = C::Node.new(id: "n1", cluster_id: "t", log: storage.log, snapshot_store: storage.snapshots,
                         state_machine: machine, initial_membership: C::Membership.simple(%w[n1]),
                         clock: -> { 0.0 }, timing: @timing, snapshot_writer: ->(capture) { captures << capture })
      # Drive a lone voter to leadership and through 12 committed entries.
      node.tick(10.0)
      node.drain

      assert_predicate node, :leader?, "a single voter elects itself"
      12.times do |i|
        node.propose({"type" => "create", "key" => "k/#{i}", "object" => {"metadata" => {"name" => "o#{i}"}}}, now: 10.0 + i)
        node.flush(10.0 + i)
        node.drain
      end
      node.tick(30.0)

      assert_equal 1, captures.length, "the due snapshot was handed to the writer once"
      capture = captures.first

      assert_equal node.last_applied, capture.index
      assert_equal 0, storage.log.snapshot_index, "nothing is compacted until the writer reports back"
      assert_predicate node, :snapshot_in_flight?
      node.tick(31.0)

      assert_equal 1, captures.length, "no second capture while one is in flight"

      bytes = C::KVStateMachine.encode_snapshot(capture.document)
      metadata = storage.snapshots.write(state: bytes, index: capture.index, term: capture.term,
                                         membership: capture.membership, created_at: capture.created_at)
      node.complete_snapshot!(capture, metadata)

      assert_equal capture.index, storage.log.snapshot_index
      refute_predicate node, :snapshot_in_flight?
      restored = C::KVStateMachine.new
      restored.restore(storage.snapshots.read_bytes(metadata.path).then { |raw| C::SnapshotStore.decode(raw).state })

      assert_equal 12, restored.store.list("k/").items.length
      storage.close
    end
  end

  def test_an_abandoned_snapshot_is_retried_on_the_next_due_tick
    Dir.mktmpdir do |dir|
      storage = C::Storage.new(dir)
      captures = []
      node = C::Node.new(id: "n1", cluster_id: "t", log: storage.log, snapshot_store: storage.snapshots,
                         state_machine: C::KVStateMachine.new, initial_membership: C::Membership.simple(%w[n1]),
                         clock: -> { 0.0 }, timing: @timing, snapshot_writer: ->(capture) { captures << capture })
      node.tick(10.0)
      node.drain
      12.times do |i|
        node.propose({"type" => "create", "key" => "k/#{i}", "object" => {"metadata" => {"name" => "o#{i}"}}}, now: 10.0 + i)
        node.flush(10.0 + i)
        node.drain
      end
      node.tick(30.0)

      assert_equal 1, captures.length

      node.abandon_snapshot!(captures.first, RuntimeError.new("disk hiccup"))
      node.tick(31.0)

      assert_equal 2, captures.length, "a failed write is retried once the interval passes"
      assert_equal 0, storage.log.snapshot_index
      storage.close
    end
  end
end
