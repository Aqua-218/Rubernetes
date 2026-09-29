# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# The garbage collector's sweep lists its corpus kind by kind.  A Pod read
# before an orphaning delete released it, together with its owner read after
# the owner was gone, looked like a dependent of a deleted owner, and the stale
# copy was collected.  That deleted Pods the delete had just promised to keep
# ("[sig-api-machinery] Garbage collector should orphan pods created by rc if
# delete options say so" kept 60 of 100).  attemptToDeleteItem re-reads the
# dependent first, and so does this collector now.
class GcLiveDependentRecheckTest < Minitest::Test
  GC = Rubernetes::Controller::GarbageCollector

  def pod(name, owner_uid: "rc-uid")
    metadata = {"name" => name, "namespace" => "ns", "uid" => "uid-#{name}"}
    if owner_uid
      metadata["ownerReferences"] = [{"apiVersion" => "v1", "kind" => "ReplicationController",
                                      "name" => "rc", "uid" => owner_uid, "controller" => true}]
    end
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata, "spec" => {}}
  end

  # The owner is gone for the live lookup.
  def owner_gone = ->(_reference, _namespace) { false }

  def collect(stale, live_by_name)
    collector = GC.new(owner_lookup: owner_gone, known_kinds: %w[Pod ReplicationController],
                       dependent_lookup: ->(object) { live_by_name[object.dig("metadata", "name")] })
    collector.plan(stale, deleted: []).operations.map { |operation| operation.object.dig("metadata", "name") }
  end

  def test_a_dependent_released_since_the_sweep_read_it_is_kept
    stale = [pod("released"), pod("still-owned")]
    live = {"released" => pod("released", owner_uid: nil), "still-owned" => pod("still-owned")}

    assert_equal %w[still-owned], collect(stale, live)
  end

  def test_a_dependent_already_gone_is_not_deleted_again
    assert_empty collect([pod("gone")], {})
  end

  def test_a_recreated_object_with_the_same_name_is_not_collected
    recreated = pod("p")
    recreated["metadata"]["uid"] = "a-different-uid"

    assert_empty collect([pod("p")], {"p" => recreated})
  end

  def test_without_a_live_lookup_the_swept_copy_decides_as_before
    collector = GC.new(owner_lookup: owner_gone, known_kinds: %w[Pod ReplicationController])

    names = collector.plan([pod("p")], deleted: []).operations.map { |operation| operation.object.dig("metadata", "name") }

    assert_equal %w[p], names
  end
end
