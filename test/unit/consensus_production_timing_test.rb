# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/consensus"

# The apiservers ran raft with the simulation's timing: a 50 ms heartbeat and
# a 150-300 ms election timeout.  A Ruby apiserver with a multi-GB heap pauses
# for longer than that under load.  Each pause made the followers call an
# election, and the round reached term 124 in two hours.  Every election
# stalled reads and forwarded proposals.  Production uses etcd's timing
# instead.
class ConsensusProductionTimingTest < Minitest::Test
  Timing = Rubernetes::Consensus::Node::Timing

  def test_production_timing_follows_etcd_defaults
    timing = Timing.production.validate!

    assert_equal 0.100, timing.heartbeat_interval
    assert_equal 1.0, timing.election_timeout_min
    assert_equal 2.0, timing.election_timeout_max
  end

  def test_a_pause_of_half_a_second_does_not_reach_the_election_timeout
    assert_operator Timing.production.election_timeout_min, :>, 0.5
  end

  def test_the_apiserver_uses_production_timing_unless_configured
    source = File.read(File.expand_path("../../lib/rubernetes/bootstrap/api_server_service.rb", __dir__))

    assert_includes source, "timing = Consensus::Node::Timing.production"
  end
end
