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

  def test_production_timing_keeps_the_heartbeat_and_a_long_election_timeout
    timing = Timing.production.validate!

    assert_in_delta(0.100, timing.heartbeat_interval)
    assert_in_delta(5.0, timing.election_timeout_min)
    assert_in_delta(10.0, timing.election_timeout_max)
  end

  # On the demo VM a healthy leader with a 3.5 GB heap went silent for up to
  # 2.8 s and a follower took over every 1-2 minutes.
  def test_a_pause_of_three_seconds_does_not_reach_the_election_timeout
    assert_operator Timing.production.election_timeout_min, :>, 3.0
  end

  def test_the_apiserver_uses_production_timing_unless_configured
    source = File.read(File.expand_path("../../lib/rubernetes/bootstrap/api_server_service.rb", __dir__))

    assert_includes source, "timing = Consensus::Node::Timing.production"
  end
end
