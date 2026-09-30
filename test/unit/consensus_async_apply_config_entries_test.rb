# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/consensus"

# Node#apply_pending! (the async apply loop's entry point) must hand only
# configuration entries back to the server.  It handed every entry back,
# so Server#apply_loop's after_async_apply read "membership" from a create
# on the leader, raised KeyError, and slept 10 ms in its error path after
# every apply -- the reason RUBERNETES_RAFT_ASYNC_APPLY=1 measured 10 ms
# per lone proposal and was left off.
class ConsensusAsyncApplyConfigEntriesTest < Minitest::Test
  C = Rubernetes::Consensus

  class Recorder
    attr_reader :events

    def initialize = @events = []
    %w[debug info warn error].each { |level| define_method(level) { |event, **fields| @events << [level, event, fields] } }
  end

  def single_node(root)
    storage = C::Storage.new(File.join(root, "n1"), fsync: false)
    machine = C::KVStateMachine.new
    node = C::Node.new(id: "n1", cluster_id: "t", log: storage.log, snapshot_store: storage.snapshots, state_machine: machine,
                       initial_membership: C::Membership.simple(%w[n1]), clock: -> { 0.0 })
    node.async_apply = -> {}
    node.tick(1.0)
    [node, machine, storage]
  end

  def test_apply_pending_returns_only_configuration_entries
    Dir.mktmpdir("async-apply") do |root|
      node, machine, storage = single_node(root)

      assert_predicate node, :leader?
      node.propose({"type" => "create", "key" => "k/a", "object" => {"metadata" => {"name" => "a"}}, "leader_time" => 0.0},
                   request_id: "r1")
      node.flush(1.0)

      assert_operator node.commit_index, :>=, node.last_applied + 1, "committed but not yet applied (async)"
      applied, configuration_entries = node.apply_pending!

      assert applied
      assert_empty configuration_entries, "a create is not a configuration entry"
      assert_equal "a", machine.store.get("k/a")["metadata"]["name"]
      node.after_async_apply(configuration_entries)
      storage.close
    end
  end

  def test_the_server_apply_loop_logs_no_error_and_answers_promptly
    previous = C::Server.async_apply?
    C::Server.async_apply = true
    Dir.mktmpdir("async-apply") do |root|
      logger = Recorder.new
      ca, ca_key = C::Identity.generate_ca("aa")
      bundle = C::Identity.issue_node(ca, ca_key, cluster_id: "aa", node_id: "n1")
      server = C::Server.new(id: "n1", cluster_id: "aa", data_directory: File.join(root, "n1"), bundle: bundle,
                             initial_voters: %w[n1], logger: logger)
      server.start
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
      sleep 0.01 until server.leader? || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      latencies = Array.new(10) do |i|
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result = server.propose({"type" => "create", "key" => "k/#{i}", "object" => {"metadata" => {"name" => "x"}}, "leader_time" => 0.0})

        assert result["ok"]
        Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
      end

      assert_empty(logger.events.select { |(level, _event, _fields)| level == "error" }.map { |event| event[1..] })
      assert_operator latencies.min, :<, 0.008, "no 10 ms error-path sleep in the apply loop: #{latencies.map { |l| (l * 1000).round(1) }}"
      server.stop
    end
  ensure
    C::Server.async_apply = previous
  end
end
