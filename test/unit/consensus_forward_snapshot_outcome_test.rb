# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/consensus"

# A follower forwards a write, the leader appends it at index i, and before
# the follower applies i itself it installs a snapshot covering i.  The
# follower then holds no apply result for i.  The server used to register a
# future nothing could resolve, time the forward out after 2 s, retry with
# the same request id, be told the same position, and fail the write only
# at the 10 s deadline.  It now reports the unknown outcome at once.
class ConsensusForwardSnapshotOutcomeTest < Minitest::Test
  C = Rubernetes::Consensus

  class FakeTransport
    attr_reader :sent

    def initialize
      @sent = []
    end

    def send(message)
      @sent << message
      true
    end

    def start = self
    def stop = self
    def address = "127.0.0.1:0"
    def stats = {}
    def on_message(&_block) = self
    def add_peer(*) = nil
  end

  def build_server(root)
    ca, ca_key = C::Identity.generate_ca("fso")
    bundle = C::Identity.issue_node(ca, ca_key, cluster_id: "fso", node_id: "b")
    server = C::Server.new(id: "b", cluster_id: "fso", data_directory: File.join(root, "b"), bundle: bundle, initial_voters: %w[a b c])
    server.instance_variable_set(:@transport, FakeTransport.new)
    server
  end

  def snapshot_applied(index, term)
    C::Node::Applied.new(index: index, term: term, command: {"type" => "snapshot"}, result: nil)
  end

  def test_waiting_for_an_index_below_an_installed_snapshot_fails_at_once
    Dir.mktmpdir("fso") do |root|
      server = build_server(root)
      server.send(:applied_hook, snapshot_applied(50, 3))
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      error = assert_raises(C::AppliedThroughSnapshot) { server.send(:wait_for, 30, 2, "r1", 2.0) }
      assert_match(/applied through a snapshot/, error.message)
      assert_raises(C::AppliedThroughSnapshot) { server.send(:wait_for, 50, 3, "r2", 2.0) }
      assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.5
      assert_kind_of C::ProposalDropped, error, "callers mapping ProposalDropped to 503 keep working"
    end
  end

  def test_a_waiter_for_exactly_the_snapshot_index_gets_the_unknown_outcome_not_a_nil_result
    Dir.mktmpdir("fso") do |root|
      server = build_server(root)
      waiter = Thread.new do
        Thread.current.report_on_exception = false
        server.send(:wait_for, 50, 3, "r1", 5.0)
      end
      sleep 0.05 until server.instance_variable_get(:@pending).key?([50, 3])
      server.send(:applied_hook, snapshot_applied(50, 3))
      assert_raises(C::AppliedThroughSnapshot) { waiter.value }
    end
  end

  def test_a_waiter_registered_before_the_install_is_dropped_by_the_install
    Dir.mktmpdir("fso") do |root|
      server = build_server(root)
      waiter = Thread.new do
        Thread.current.report_on_exception = false
        server.send(:wait_for, 30, 2, "r1", 5.0)
      end
      sleep 0.05 until server.instance_variable_get(:@pending).key?([30, 2])
      server.send(:applied_hook, snapshot_applied(50, 3))
      error = assert_raises(C::AppliedThroughSnapshot) { waiter.value }
      assert_match(/applied through a snapshot/, error.message)
    end
  end

  def test_a_forwarded_proposal_reports_the_unknown_outcome_instead_of_retrying_until_the_deadline
    Dir.mktmpdir("fso") do |root|
      server = build_server(root)
      node = server.node
      node.instance_variable_set(:@leader_id, "a")
      transport = server.instance_variable_get(:@transport)
      # The leader answers every forward with the same, already covered position.
      answerer = Thread.new do
        loop do
          forward = transport.sent.find { |message| message.is_a?(C::Messages::ForwardProposal) }
          if forward
            transport.sent.delete(forward)
            server.send(:inbound, C::Messages::ForwardProposalResponse.new(cluster_id: "fso", from: "a", to: "b", term: 3,
                                                                           request_id: forward.request_id, accepted: true,
                                                                           index: 30, entry_term: 2, leader_id: "a"))
          end
          sleep 0.005
        end
      end
      server.send(:applied_hook, snapshot_applied(50, 3))
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      assert_raises(C::AppliedThroughSnapshot) do
        server.propose({"type" => "create", "key" => "k/x", "object" => {}}, request_id: "r1", timeout: 10.0)
      end
      assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 2.0, "must not wait for the 10 s deadline"
      answerer.kill
    end
  end
end
