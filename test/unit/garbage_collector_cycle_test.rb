# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# An ownership cycle is REPORTED, not fatal: the objects inside it keep each
# other alive, but everything else in the cluster must still be collected.
# Refusing the whole plan meant one deliberate cycle -- "[sig-api-machinery]
# Garbage collector should not be blocked by dependency circle" creates one --
# stopped garbage collection cluster-wide for the rest of the run, so orphaned
# EndpointSlices, ReplicaSets and Pods were never reclaimed.
class GarbageCollectorCycleTest < Minitest::Test
  Controller = Rubernetes::Controller

  def object(kind, name, uid:, owners: [])
    metadata = {"name" => name, "namespace" => "ns", "uid" => uid}
    unless owners.empty?
      metadata["ownerReferences"] = owners.map do |owner|
        {"apiVersion" => "v1", "kind" => owner.fetch("kind"),
         "name" => owner.dig("metadata", "name"), "uid" => owner.dig("metadata", "uid")}
      end
    end
    {"apiVersion" => "v1", "kind" => kind, "metadata" => metadata}
  end

  def collector = Controller::GarbageCollector.new

  def test_an_orphan_is_collected_even_while_a_cycle_exists_elsewhere
    left = object("ConfigMap", "left", uid: "left")
    right = object("ConfigMap", "right", uid: "right")
    left["metadata"]["ownerReferences"] = [{"apiVersion" => "v1", "kind" => "ConfigMap",
                                            "name" => "right", "uid" => "right"}]
    right["metadata"]["ownerReferences"] = [{"apiVersion" => "v1", "kind" => "ConfigMap",
                                             "name" => "left", "uid" => "left"}]
    orphan = object("EndpointSlice", "slice", uid: "slice",
                                              owners: [{"kind" => "Service", "metadata" => {"name" => "gone", "uid" => "gone-uid"}}])

    result = collector.plan([left, right, orphan])

    assert_equal(%w[slice], result.operations.map { |operation| operation.object.dig("metadata", "name") })
    assert_equal("OwnerReferenceCycle", result.events.first.fetch("reason"))
  end

  # Breaking the cycle by deleting one member lets the rest be collected on the
  # next sweep, which is exactly what the conformance spec waits for.
  def test_removing_one_member_of_a_cycle_frees_the_others
    a = object("ConfigMap", "a", uid: "a")
    b = object("ConfigMap", "b", uid: "b")
    a["metadata"]["ownerReferences"] = [{"apiVersion" => "v1", "kind" => "ConfigMap", "name" => "b", "uid" => "b"}]
    b["metadata"]["ownerReferences"] = [{"apiVersion" => "v1", "kind" => "ConfigMap", "name" => "a", "uid" => "a"}]

    assert_empty(collector.plan([a, b]).operations)
    assert_equal(%w[b], collector.plan([b]).operations.map { |operation| operation.object.dig("metadata", "name") })
  end

  def test_an_object_with_a_live_owner_is_kept
    owner = object("Service", "svc", uid: "svc-uid")
    slice = object("EndpointSlice", "slice", uid: "slice", owners: [owner])

    assert_empty(collector.plan([owner, slice]).operations)
  end
end
