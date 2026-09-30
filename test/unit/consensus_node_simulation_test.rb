# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/raft_simulation"

class ConsensusNodeSimulationTest < Minitest::Test
  C = Rubernetes::Consensus

  def propose(node, cluster, count, start)
    count.times do |offset|
      index = start + offset
      node.propose({"type" => "create", "key" => "k/#{index}", "object" => {"metadata" => {"name" => "o#{index}"}},
                    "request_uid" => "r#{index}", "leader_time" => cluster.now})
    end
  end

  def test_three_nodes_elect_one_leader_and_replicate
    cluster = RaftSimulation::Cluster.new(%w[n1 n2 n3], seed: 3)
    cluster.run(1.0)

    assert_equal 1, cluster.leader.length
    leader = cluster.leader.first
    propose(leader, cluster, 5, 0)
    cluster.run(0.3)
    cluster.processes.each_value do |process|
      assert_equal 6, process.node.commit_index, process.id
      assert_equal 5, process.state_machine.store.list("k/").items.length
    end
  ensure
    cluster.cleanup
  end

  def test_leader_crash_loses_no_committed_entry_and_a_partitioned_leader_cannot_commit
    cluster = RaftSimulation::Cluster.new(%w[n1 n2 n3], seed: 11)
    cluster.run(1.0)
    leader = cluster.leader.first
    propose(leader, cluster, 3, 0)
    cluster.run(0.2)
    committed = leader.commit_index
    # Partition the leader away; it must not commit anything new.
    others = %w[n1 n2 n3] - [leader.id]
    others.each do |other|
      cluster.network.cut(leader.id, other)
      cluster.network.cut(other, leader.id)
    end
    propose(leader, cluster, 2, 10)
    cluster.run(1.0)

    assert_equal committed, leader.commit_index
    new_leader = cluster.leader.find { |candidate| candidate.id != leader.id }

    refute_nil new_leader
    propose(new_leader, cluster, 2, 20)
    cluster.run(0.3)
    cluster.network.heal
    cluster.run(1.0)

    assert_equal 1, cluster.leader.length
    ids = cluster.processes.values.map { |p| p.state_machine.store.list("k/").items.map { |o| o["metadata"]["name"] }.sort }.uniq

    assert_equal 1, ids.length
    assert_includes ids.first, "o20"
    refute_includes ids.first, "o10", "entries proposed by the partitioned leader were never committed"
  ensure
    cluster.cleanup
  end

  def test_crash_and_restart_recovers_from_wal_and_snapshot
    timing = C::Node::Timing.default.with(snapshot_entries: 10, snapshot_min_interval: 0.1)
    cluster = RaftSimulation::Cluster.new(%w[n1 n2 n3], seed: 5, timing: timing)
    cluster.run(1.0)
    leader = cluster.leader.first
    propose(leader, cluster, 30, 0)
    cluster.run(0.5)
    victim = (%w[n1 n2 n3] - [leader.id]).first
    cluster.crash(victim)
    propose(leader, cluster, 30, 100)
    cluster.run(0.5)
    cluster.restart(victim)
    cluster.run(1.5)
    node = cluster.node(victim)

    assert_equal leader.commit_index, node.commit_index
    assert_equal 60, cluster.processes[victim].state_machine.store.list("k/").items.length
    assert_operator node.status["snapshot_index"], :>, 0
  ensure
    cluster.cleanup
  end

  def test_joint_consensus_membership_change_with_leader_loss
    cluster = RaftSimulation::Cluster.new(%w[n1 n2 n3], seed: 9)
    cluster.run(1.0)
    leader = cluster.leader.first
    base = C::Membership.simple(%w[n1 n2 n3])
    cluster.add_process("n4", membership: base)
    cluster.add_process("n5", membership: base)
    leader.propose_membership(%w[n1 n2 n3 n4 n5])
    cluster.run(0.05)
    cluster.crash(leader.id)
    cluster.run(2.0)
    cluster.restart(leader.id)
    cluster.run(1.0)
    leaders = cluster.leader

    assert_equal 1, leaders.length
    assert_equal({"voters" => %w[n1 n2 n3 n4 n5], "learners" => []}, leaders.first.membership.to_h)
    leaders.first.propose_membership(%w[n3 n4 n5])
    cluster.run(2.0)
    final = cluster.leader.first

    assert_includes %w[n3 n4 n5], final.id
    assert_equal({"voters" => %w[n3 n4 n5], "learners" => []}, final.membership.to_h)
  ensure
    cluster.cleanup
  end

  def test_clock_jump_and_asymmetric_partition_preserve_safety
    cluster = RaftSimulation::Cluster.new(%w[n1 n2 n3 n4 n5], seed: 21)
    cluster.run(1.0)
    leaders_by_term = {}
    30.times do |round|
      leader = cluster.leader.first
      propose(leader, cluster, 2, round * 2) if leader
      cluster.processes["n2"].clock_offset += 3.0 if round == 5
      cluster.network.cut("n1", "n3") if round == 10
      cluster.network.heal if round == 20
      cluster.run(0.2)
      cluster.leader.each do |candidate|
        previous = leaders_by_term[candidate.current_term]

        assert(previous.nil? || previous == candidate.id, "two leaders in term #{candidate.current_term}")
        leaders_by_term[candidate.current_term] = candidate.id
      end
    end
    cluster.run(1.0)
    applied = cluster.processes.values.map { |p| p.node.last_applied }.uniq

    assert_equal 1, applied.length
  ensure
    cluster.cleanup
  end
end
