# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require_relative "../support/raft_simulation"
require "rubernetes/consensus"

# A write paid the leader's WAL fsync and then the followers' receive, append
# and fsync one after the other.  The leader now sends its AppendEntries
# first and syncs while they travel (Node#flush defer_sync:), as etcd does --
# without ever counting its own unsynced entries toward the commit quorum.
class ConsensusOverlappedLeaderSyncTest < Minitest::Test
  C = Rubernetes::Consensus

  class CountingDevice
    attr_reader :fsyncs

    def initialize(path)
      @inner = C::WAL::FileDevice.new(path)
      @fsyncs = 0
    end

    def size = @inner.size
    def write(bytes) = @inner.write(bytes)
    def truncate(length) = @inner.truncate(length)
    def close = @inner.close

    def fsync
      @fsyncs += 1
      @inner.fsync
    end
  end

  def test_an_unsynced_append_is_synced_once_and_reads_back_as_a_reopen_would
    Dir.mktmpdir do |dir|
      path = File.join(dir, "wal")
      device = nil
      wal = C::WAL.new(path, device_factory: ->(p) { device = CountingDevice.new(p) })
      base = device.fsyncs
      wal.append([C::WAL::TYPE_ENTRY, {"index" => 1, "term" => 1, "command" => {"b" => 1, "a" => [:x]}}], sync: false)

      assert_equal base, device.fsyncs
      wal.sync
      wal.sync

      assert_equal base + 1, device.fsyncs, "one fsync covers the deferred append; a second sync is free"
      in_process = wal.records.map { |record| [record.type, record.payload, record.offset, record.bytes] }
      wal.close
      reopened = C::WAL.new(path).records.map { |record| [record.type, record.payload, record.offset, record.bytes] }

      assert_equal reopened, in_process
    end
  end

  def test_the_leader_does_not_count_itself_until_its_batch_is_durable
    cluster = RaftSimulation::Cluster.new(%w[n1], seed: 5)
    cluster.run(1.0)
    leader = cluster.leader.first
    committed = leader.commit_index
    leader.propose({"type" => "create", "key" => "k/1", "object" => {"metadata" => {"name" => "o"}},
                    "request_uid" => "r1", "leader_time" => cluster.now})
    leader.flush(cluster.now, defer_sync: true)

    assert_predicate leader, :local_sync_pending?
    assert_equal committed, leader.commit_index, "a lone leader must not commit what it has not synced"
    assert leader.sync_local!
    refute_predicate leader, :local_sync_pending?
    assert_equal committed + 1, leader.commit_index
    refute leader.sync_local!, "nothing left to sync"
  ensure
    cluster&.cleanup
  end

  def test_followers_commit_while_the_leader_sync_is_still_owed_and_the_next_input_settles_it
    cluster = RaftSimulation::Cluster.new(%w[n1 n2 n3], seed: 7)
    cluster.run(1.0)
    leader = cluster.leader.first
    committed = leader.commit_index
    leader.propose({"type" => "create", "key" => "k/1", "object" => {"metadata" => {"name" => "o"}},
                    "request_uid" => "r1", "leader_time" => cluster.now})
    leader.flush(cluster.now, defer_sync: true)
    cluster.route(leader.drain)

    assert_predicate leader, :local_sync_pending?

    # The followers' acknowledgements are a quorum without the leader; the
    # first of them to arrive also makes the leader sync before handling it.
    cluster.run(0.2)

    refute_predicate leader, :local_sync_pending?
    assert_equal committed + 1, leader.commit_index
    cluster.processes.each_value { |process| assert_equal committed + 1, process.node.commit_index }
  ensure
    cluster&.cleanup
  end
end
