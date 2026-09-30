# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/consensus"
require "tmpdir"
require "securerandom"

# Every proposal used to flush its own batch: a WAL fsync and an AppendEntries
# per write, serialised behind the server's monitor, so eight concurrent
# writes took eight times as long as one.  A proposer that finds other
# proposers queued for the monitor now leaves the batch to the tick loop,
# which flushes everything that accumulated in one go; a lone proposer still
# flushes at once.
class ConsensusGroupCommitTest < Minitest::Test
  C = Rubernetes::Consensus

  module FlushCounter
    attr_reader :flushes

    def flush_batch(now, **options)
      @flushes = (@flushes || 0) + 1 unless @pending_batch.empty?
      super
    end
  end

  def start_cluster(root)
    ca, ca_key = C::Identity.generate_ca("gc")
    ids = %w[a b c]
    servers = ids.to_h do |id|
      bundle = C::Identity.issue_node(ca, ca_key, cluster_id: "gc", node_id: id)
      [id, C::Server.new(id: id, cluster_id: "gc", data_directory: File.join(root, id), bundle: bundle, initial_voters: ids)]
    end
    servers.each_value(&:start)
    servers.each_value { |server| servers.each { |peer_id, peer| server.add_peer(peer_id, peer.address) unless peer.equal?(server) } }
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
    sleep 0.02 until servers.values.any?(&:leader?) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
    sleep 0.2
    servers
  end

  def command(index)
    {"type" => "create", "key" => "registry/things/ns/t#{index}", "object" => {"metadata" => {"name" => "t#{index}"}},
     "request_uid" => SecureRandom.uuid, "leader_time" => Time.now.to_f}
  end

  def test_concurrent_proposals_share_batches_and_all_apply
    Dir.mktmpdir("group-commit") do |root|
      servers = start_cluster(root)
      leader = servers.values.find(&:leader?)
      leader.node.singleton_class.prepend(FlushCounter)
      results = Queue.new
      threads = 16.times.map do |index|
        Thread.new { results << leader.propose(command(index)) }
      end
      threads.each(&:join)
      applied = Array.new(16) { results.pop }

      assert applied.all? { |result| result["ok"] }, applied.reject { |result| result["ok"] }.inspect
      assert_operator leader.node.flushes, :<, 16, "16 concurrent proposals must not each flush alone"
      store = C::RaftStore.new(leader)

      assert_equal 16, store.list("registry/things/").items.length
      servers.each_value(&:stop)
    end
  end

  def test_a_lone_proposal_flushes_without_waiting_for_the_tick_loop
    Dir.mktmpdir("group-commit") do |root|
      servers = start_cluster(root)
      leader = servers.values.find(&:leader?)
      leader.node.singleton_class.prepend(FlushCounter)
      leader.propose(command(0))

      assert_equal 1, leader.node.flushes
      servers.each_value(&:stop)
    end
  end
end

# Forwarded proposals join the leader's group commit as well: the leader used
# to flush its batch for every ForwardProposal message it handled, a WAL
# fsync per forwarded write, so a follower-fronted controller manager paid
# the serialised cost twice over.
class ConsensusForwardedGroupCommitTest < Minitest::Test
  C = Rubernetes::Consensus

  def test_forwarded_proposals_share_a_flush_and_are_answered_after_it
    require_relative "../support/raft_simulation"
    cluster = RaftSimulation::Cluster.new(%w[n1 n2 n3], seed: 5)
    cluster.run(1.0)
    leader = cluster.leader.first
    follower = cluster.processes.values.find { |process| process.alive && !process.node.leader? }.node
    leader.singleton_class.prepend(ConsensusGroupCommitTest::FlushCounter)
    3.times do |index|
      message = C::Messages::ForwardProposal.new(cluster_id: cluster.cluster_id, from: follower.id, to: leader.id, term: leader.current_term,
                                                 request_id: "fwd-#{index}",
                                                 command: {"type" => "create", "key" => "k/#{index}", "object" => {"metadata" => {"name" => "o#{index}"}},
                                                           "request_uid" => "u#{index}", "leader_time" => cluster.now})
      cluster.route(leader.handle(message, cluster.now))
    end

    assert_nil leader.flushes, "handling a forwarded proposal must not flush on its own"
    cluster.run(0.01)

    assert_equal 1, leader.flushes, "one flush for the three forwarded proposals"
    cluster.run(0.05)

    assert_operator leader.commit_index, :>=, 3
    assert_operator follower.log.last_index, :>=, 3, "the batch reached the follower"
  end
end
