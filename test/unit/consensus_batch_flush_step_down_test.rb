# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/consensus"

# A proposer that left its entry to the group-commit batch wakes after the
# tick loop flushed it.  If the leader stepped down in between, the entry
# is in the log under the old term and its fate is decided by the new
# leader.  The server used to answer "not leader" to that proposer, which
# proposed again: the same create appended twice, the second applied as
# AlreadyExists, and the client got 409 for a create that had succeeded.
class ConsensusBatchFlushStepDownTest < Minitest::Test
  C = Rubernetes::Consensus

  def start_cluster(root)
    ca, ca_key = C::Identity.generate_ca("bf")
    ids = %w[a b c]
    servers = ids.to_h do |id|
      bundle = C::Identity.issue_node(ca, ca_key, cluster_id: "bf", node_id: id)
      [id, C::Server.new(id: id, cluster_id: "bf", data_directory: File.join(root, id), bundle: bundle, initial_voters: ids)]
    end
    servers.each_value(&:start)
    servers.each_value { |server| servers.each { |peer_id, peer| server.add_peer(peer_id, peer.address) unless peer.equal?(server) } }
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
    sleep 0.02 until servers.values.any?(&:leader?) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
    sleep 0.2
    servers
  end

  def test_the_proposer_waits_for_its_appended_entry_after_a_step_down
    Dir.mktmpdir("batch-flush") do |root|
      servers = start_cluster(root)
      leader = servers.values.find(&:leader?)
      node = leader.node
      command = {"type" => "create", "key" => "registry/things/ns/raced", "object" => {"metadata" => {"name" => "raced"}},
                 "request_uid" => nil, "leader_time" => Time.now.to_f}
      position = leader.synchronize do
        node.propose(command, request_id: "r1")
        node.flush
        leader.send(:flush_outbox)
        appended = node.proposal_position("r1")
        # Step down before the proposer's await_batch_flush runs.
        node.__send__(:become_follower, node.current_term + 1, leader: nil, now: Process.clock_gettime(Process::CLOCK_MONOTONIC))

        refute_predicate node, :leader?
        [appended, leader.send(:await_batch_flush, "r1", 1.0)]
      end
      appended, awaited = position

      refute_nil appended
      assert_equal appended, awaited, "the proposer gets the position its entry was appended at, not nil"
      # The entry commits under the next leader and every replica holds it once.
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
      all_applied = -> { servers.values.all? { |server| server.node.last_applied >= appended[:index] } }
      until all_applied.call || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
        sleep 0.02
      end
      servers.each_value do |server|
        assert_operator server.node.last_applied, :>=, appended[:index], "#{server.id} applied the entry"
        assert_equal 1, C::RaftStore.new(server).list("registry/things/").items.length
      end
      servers.each_value(&:stop)
    end
  end

  def test_an_entry_that_never_left_the_batch_is_proposed_again
    Dir.mktmpdir("batch-flush") do |root|
      servers = start_cluster(root)
      leader = servers.values.find(&:leader?)
      node = leader.node
      command = {"type" => "create", "key" => "registry/things/ns/unflushed", "object" => {"metadata" => {"name" => "unflushed"}},
                 "request_uid" => nil, "leader_time" => Time.now.to_f}
      awaited = leader.synchronize do
        node.propose(command, request_id: "r2")
        node.__send__(:become_follower, node.current_term + 1, leader: nil, now: Process.clock_gettime(Process::CLOCK_MONOTONIC))
        leader.send(:await_batch_flush, "r2", 1.0)
      end

      assert_nil awaited, "nothing was appended, so the proposal is retried"
      servers.each_value(&:stop)
    end
  end
end
