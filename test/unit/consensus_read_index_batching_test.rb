# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/raft_simulation"

# Every linearizable read used to start its own heartbeat round: two messages
# out and two acknowledgements handled under the leader's lock for every GET
# a follower forwarded.  Reads that arrive while a round is in flight now
# wait for the next round and share it, the way etcd batches ReadIndex.
class ConsensusReadIndexBatchingTest < Minitest::Test
  C = Rubernetes::Consensus

  module HeartbeatCounter
    attr_accessor :heartbeats

    def send(message, now)
      self.heartbeats = (heartbeats || 0) + 1 if message.is_a?(C::Messages::AppendEntries) && message.entries.empty?
      super
    end
  end

  def settled_cluster
    cluster = RaftSimulation::Cluster.new(%w[n1 n2 n3], seed: 11)
    cluster.run(1.0)
    leader = cluster.leader.first
    leader.propose({"type" => "create", "key" => "k/0", "object" => {"metadata" => {"name" => "o"}},
                    "request_uid" => "r0", "leader_time" => cluster.now})
    cluster.run(0.3)
    [cluster, cluster.leader.first]
  end

  def test_reads_arriving_during_a_round_share_the_next_one
    cluster, leader = settled_cluster
    cluster.network.singleton_class.prepend(HeartbeatCounter)
    results = []
    8.times { leader.read_index(now: cluster.now) { |index, error| results << [index, error] } }
    cluster.run(0.02)

    assert_equal 8, results.length, "every read settles"
    assert(results.all? { |_, error| error.nil? })
    assert(results.all? { |index, _| index == leader.commit_index })
    # Two rounds of two peers each, plus at most one periodic heartbeat pair;
    # a round per read would have been sixteen.
    assert_operator cluster.network.heartbeats, :<=, 6, "heartbeats: #{cluster.network.heartbeats}"
  end

  def test_a_lone_read_still_gets_its_round_at_once
    cluster, leader = settled_cluster
    cluster.network.singleton_class.prepend(HeartbeatCounter)
    result = nil
    leader.read_index(now: cluster.now) { |index, error| result = [index, error] }
    cluster.run(0.002)

    assert_includes [2, 4], cluster.network.heartbeats, "one round for the lone read (plus at most a periodic pair)"
    cluster.run(0.02)

    assert_equal [leader.commit_index, nil], result
  end

  def test_queued_reads_fail_when_leadership_is_lost
    cluster, leader = settled_cluster
    errors = []
    leader.read_index(now: cluster.now) { |_index, error| errors << error }
    leader.read_index(now: cluster.now) { |_index, error| errors << error }
    leader.__send__(:become_follower, leader.current_term + 1, leader: nil, now: cluster.now)

    assert_equal 2, errors.length
    assert(errors.all? { |error| error.is_a?(C::NotLeader) })
  end
end
