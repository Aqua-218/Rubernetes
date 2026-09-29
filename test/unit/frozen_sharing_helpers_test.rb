# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"
require "rubernetes/controller"
require "rubernetes/watch"

# The scheduler, the controller runtime and the informers all defended
# themselves by deep-copying and deep-freezing every value they handed out.
# A Pod snapshot's accessors did it on every call -- per plugin, per node,
# per cycle -- and normalisation alone was a third of the scheduler's CPU.
# A value this module already froze all the way down cannot be mutated by
# anyone, so it is shared; anything else is still copied.
class FrozenSharingHelpersTest < Minitest::Test
  MODULES = {
    "scheduler" => [Rubernetes::Scheduler::Support, :snapshot],
    "controller" => [Rubernetes::Controller::Support, :immutable_copy],
    "watch" => [Rubernetes::Watch::Support, :immutable_copy]
  }.freeze

  def object
    {"metadata" => {"name" => "p", "labels" => {"a" => "b"}}, "spec" => {"containers" => [{"name" => "c", "env" => [{"n" => 1}]}]}}
  end

  def test_a_value_the_module_froze_is_returned_as_is
    MODULES.each do |label, (mod, method)|
      frozen = mod.public_send(method, object)
      assert frozen.frozen?, label
      assert frozen.dig("spec", "containers", 0).frozen?, label
      assert_same frozen, mod.public_send(method, frozen), label
      assert mod.deep_frozen?(frozen), label
    end
  end

  def test_the_callers_own_object_is_copied_not_aliased
    MODULES.each do |label, (mod, method)|
      mine = object
      frozen = mod.public_send(method, mine)
      refute_same mine, frozen, label
      mine["spec"]["containers"] << {"name" => "d"}
      assert_equal 1, frozen.dig("spec", "containers").length, label
      assert_raises(FrozenError, label) { frozen["spec"]["containers"] << {} }
    end
  end

  def test_a_foreign_frozen_object_is_still_copied
    MODULES.each do |label, (mod, method)|
      shallow = {"metadata" => {"name" => "n"}}.freeze
      result = mod.public_send(method, shallow)
      refute_same shallow, result, label
      assert result["metadata"].frozen?, label
    end
  end

  def test_a_pod_snapshots_accessors_return_the_same_frozen_objects
    pod = Rubernetes::Scheduler::Pod.new(object.merge("apiVersion" => "v1", "kind" => "Pod"))
    assert_same pod.spec, pod.spec
    assert_same pod.metadata, pod.metadata
    assert_same pod.containers, pod.containers
    assert_equal "c", pod.containers.first["name"]
    assert_equal({"a" => "b"}, pod.metadata["labels"])
  end
end

# Filter and score plugins ask for the same sub-objects of a Pod snapshot
# over and over: affinity terms, spread constraints, selectors, resource
# maps.  Re-normalising each one on every request was most of a scheduling
# cycle, and everything this module freezes has already been normalised.
class SchedulerNormalizeShortCircuitTest < Minitest::Test
  Support = Rubernetes::Scheduler::Support

  def test_a_frozen_snapshot_is_not_renormalised
    snapshot = Support.snapshot({"a" => {"b" => [{"c" => 1}]}})
    assert_same snapshot, Support.object_hash(snapshot)
    assert_same snapshot, Support.normalize(snapshot)
    inner = snapshot["a"]
    assert_same inner, Support.object_hash(inner), "sub-objects are shared too"
  end

  def test_symbol_keys_are_still_stringified
    result = Support.object_hash({a: 1, "b" => {c: 2}})
    assert_equal({"a" => 1, "b" => {"c" => 2}}, result)
    assert_equal({"x" => [{"y" => 3}]}, Support.normalize({x: [{y: 3}]}))
  end

  def test_an_object_that_responds_to_to_h_is_converted
    struct = Struct.new(:one).new(1)
    assert_equal({"one" => 1}, Support.object_hash(struct))
    assert_raises(TypeError) { Support.object_hash(42) }
  end

  def test_a_pods_resource_view_is_stable_and_correct
    pod = Rubernetes::Scheduler::Pod.new(
      "apiVersion" => "v1", "kind" => "Pod",
      "metadata" => {"name" => "p", "namespace" => "ns", "labels" => {"app" => "x"}},
      "spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => {"cpu" => "500m", "memory" => "1Gi"}}}]}
    )
    assert_equal({"app" => "x"}, pod.labels)
    requests = Support.requests_for(pod)
    assert_in_delta 0.5, requests["cpu"].to_f, 0.001
    assert_same pod.spec, pod.spec
  end
end
