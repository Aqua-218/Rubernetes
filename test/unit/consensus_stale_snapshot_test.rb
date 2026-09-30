# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/raft_simulation"

# A follower can apply far past its own last snapshot through the log.  The
# InstallSnapshot handler only compared the incoming snapshot with the
# follower's SNAPSHOT index, so a snapshot older than what the follower had
# already applied went on to install_snapshot_bytes, which refused it by
# raising.  The raise killed the inbound thread before any reply went out, the
# leader never learned the transfer was over, and it streamed the same
# snapshot again -- 3561 times in one conformance round -- while that
# apiserver lagged and answered its clients "503 read index timed out".
# Raft figure 13 and etcd's restore() ignore such a snapshot and reply anyway.
class ConsensusStaleSnapshotTest < Minitest::Test
  C = Rubernetes::Consensus

  def propose(node, cluster, count, start)
    count.times do |offset|
      index = start + offset
      node.propose({"type" => "create", "key" => "k/#{index}", "object" => {"metadata" => {"name" => "o#{index}"}},
                    "request_uid" => "r#{index}", "leader_time" => cluster.now})
    end
  end

  # A cluster in which a snapshot is taken and captured, and every follower
  # then applies well past it through the log.
  def settled_cluster
    timing = C::Node::Timing.default.with(snapshot_entries: 10_000, snapshot_min_interval: 0.1)
    cluster = RaftSimulation::Cluster.new(%w[n1 n2 n3], seed: 7, timing: timing)
    cluster.run(1.0)
    leader = cluster.leader.first
    propose(leader, cluster, 30, 0)
    cluster.run(0.5)
    leader.snapshot!(force: true)
    snapshot, = leader.snapshot_store.latest(strict: true)
    captured = {index: snapshot.index, term: snapshot.term, bytes: leader.snapshot_store.read_bytes(snapshot.path)}
    propose(leader, cluster, 20, 100)
    cluster.run(0.5)
    [cluster, leader, captured]
  end

  def stale_snapshot_message(leader, follower, captured)
    bytes = captured[:bytes]
    C::Messages::InstallSnapshot.new(cluster_id: leader.cluster_id, from: leader.id, to: follower.id,
                                     term: leader.current_term, request_id: "stale-1",
                                     last_included_index: captured[:index], last_included_term: captured[:term],
                                     offset: 0, data: [bytes].pack("m0"), done: true, total_bytes: bytes.bytesize)
  end

  def test_a_snapshot_the_follower_already_passed_is_acknowledged_not_raised
    cluster, leader, captured = settled_cluster
    follower = cluster.processes.values.map(&:node).find { |node| node.id != leader.id }
    applied = follower.last_applied
    message = stale_snapshot_message(leader, follower, captured)

    assert_operator message.last_included_index, :<, applied, "precondition: the snapshot is behind the follower"
    follower.drain

    outbound = follower.handle(message, cluster.now)

    reply = Array(outbound).find { |sent| sent.is_a?(C::Messages::InstallSnapshotResponse) }

    refute_nil reply, "the follower must answer, or the leader streams the snapshot for ever"
    assert reply.success, "a snapshot already passed is ignored and acknowledged"
    assert_equal applied, follower.last_applied, "the follower must not move backwards"
  ensure
    cluster&.cleanup
  end

  def test_the_leader_returns_to_log_replication_after_the_acknowledgement
    cluster, leader, = settled_cluster
    follower = cluster.processes.values.map(&:node).find { |node| node.id != leader.id }
    propose(leader, cluster, 5, 200)
    cluster.run(0.5)

    assert_equal leader.commit_index, follower.commit_index
  ensure
    cluster&.cleanup
  end
end
