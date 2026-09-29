# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/raft_simulation"

# A follower appending entries past the end of its log is not resolving a
# conflict: it must not rescan the whole log for membership.  Treating "no
# entry at this index" as a term conflict made every append rescan, a
# quarter of a follower's CPU once its log was long.
class ConsensusFollowerAppendScanTest < Minitest::Test
  C = Rubernetes::Consensus

  def test_ordinary_appends_do_not_rescan_the_log
    cluster = RaftSimulation::Cluster.new(%w[n1 n2 n3], seed: 3)
    cluster.run(1.0)
    leader = cluster.leader.first
    followers = cluster.processes.values.map(&:node).reject { |node| node.id == leader.id }
    scans = Hash.new(0)
    followers.each do |node|
      node.define_singleton_method(:membership_from_log) { |fallback| scans[id] += 1; super(fallback) }
    end
    20.times do |index|
      leader.propose({"type" => "create", "key" => "k/#{index}", "object" => {"metadata" => {"name" => "o#{index}"}},
                      "request_uid" => "r#{index}", "leader_time" => cluster.now})
      cluster.run(0.05)
    end
    cluster.run(0.3)
    followers.each { |node| assert_equal 21, node.commit_index }
    assert_equal({}, scans.to_h, "no follower rescanned its log for plain appends")
  ensure
    cluster&.cleanup
  end
end
