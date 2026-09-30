# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# The agent persists the probe snapshot on every change of any Pod; it was
# rebuilt for every container each time.  Unchanged containers now reuse
# their serialized state, and a change is still reflected at once.
class NodeProbeSnapshotCacheTest < Minitest::Test
  Node = Rubernetes::Node

  def manager
    Node::ProbeManager.new(runtime: nil, clock: -> { Time.at(0).utc })
  end

  def test_unchanged_containers_reuse_their_snapshot_and_changes_show_up
    probes = manager
    probes.register("c1", probes: {"livenessProbe" => {"exec" => {"command" => ["true"]}}})
    probes.register("c2", probes: {"readinessProbe" => {"exec" => {"command" => ["true"]}}})
    first = probes.snapshot

    second = probes.snapshot

    assert_same first.dig("states", "c1"), second.dig("states", "c1")

    probes.send(:apply_result, "c1", "liveness", false, "Failure", "boom", Time.at(1).utc, action: "exec", deferred: false)
    third = probes.snapshot

    refute_same second.dig("states", "c1"), third.dig("states", "c1")
    assert_equal 1, third.dig("states", "c1", "liveness", "failure_count")
    assert_same second.dig("states", "c2"), third.dig("states", "c2")

    probes.unregister("c2")

    refute probes.snapshot.fetch("states").key?("c2")
  end
end
