# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/raft_simulation"

# A linearizable read settles once a quorum has acknowledged the leader at or
# after the read's epoch, and the epoch of an acknowledgement was looked up in
# the leader's in-flight AppendEntries records.  Those records are expired as
# lost after election_timeout_min (150 ms) so pipelining cannot wedge -- and a
# response that arrived after its record had expired no longer counted as an
# acknowledgement at all.  With followers answering in more than 150 ms, which
# a loaded Ruby apiserver does routinely, no heartbeat ever proved leadership:
# every read on the cluster hung while writes kept committing.  A conformance
# round caught it in thread dumps -- controller-manager workers all waiting on
# apiserver replies, the follower apiserver's request threads all in
# forward_read -- and nothing reconciled for twelve minutes.
class ConsensusReadIndexSlowAcksTest < Minitest::Test
  C = Rubernetes::Consensus

  def propose(node, cluster, count)
    count.times do |index|
      node.propose({"type" => "create", "key" => "k/#{index}", "object" => {"metadata" => {"name" => "o#{index}"}},
                    "request_uid" => "r#{index}", "leader_time" => cluster.now})
    end
  end

  def slow_cluster(one_way_delay)
    cluster = RaftSimulation::Cluster.new(%w[n1 n2 n3], seed: 21)
    cluster.run(1.0)
    leader = cluster.leader.first
    propose(leader, cluster, 3)
    cluster.run(0.3)
    cluster.network.min_delay = one_way_delay
    cluster.network.max_delay = one_way_delay
    cluster.run(1.0)
    [cluster, cluster.leader.first]
  end

  def test_a_read_settles_when_every_acknowledgement_is_slower_than_the_inflight_expiry
    cluster, leader = slow_cluster(0.1) # 200 ms round trip, past the 150 ms expiry

    refute_nil leader, "precondition: the cluster keeps a leader on a slow network"
    settled = nil

    leader.read_index { |index, error| settled = [index, error] }
    cluster.run(2.0)

    refute_nil settled, "a read must settle even when acknowledgements arrive after the in-flight expiry"
    assert_nil settled[1]
  ensure
    cluster&.cleanup
  end

  def test_a_read_still_settles_on_a_fast_network
    cluster, leader = slow_cluster(0.002)
    settled = nil

    leader.read_index { |index, error| settled = [index, error] }
    cluster.run(0.5)

    refute_nil settled
  ensure
    cluster&.cleanup
  end
end
