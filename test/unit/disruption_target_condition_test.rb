# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# A Pod that is taken away from its owner is told why before it goes:
# eviction.go addConditionAndDeletePod sets DisruptionTarget on an evicted Pod,
# and preemption.go PrepareCandidate sets it on a preemption victim.  Both
# deleted the Pod silently here, so nothing downstream could tell an
# involuntary disruption from the Pod's own failure: "[sig-scheduling]
# SchedulerPreemption validates pod disruption condition is added to the
# preempted pod" found a victim with no condition at all, and "[sig-apps] Job
# should allow to use a pod failure policy to ignore failure matching on
# DisruptionTarget condition" had nothing to match, so every eviction counted
# as a real failure.
class DisruptionTargetConditionTest < Minitest::Test
  Server = Rubernetes::API::Server

  class Store
    attr_reader :updated, :deleted

    def initialize(pod)
      @pod = pod
      @updated = []
      @deleted = []
    end

    def get(resource:, namespace: nil, name: nil, **) = @pod

    def list(resource:, **) = {"items" => []}

    def update(resource:, namespace:, name:, object:, **)
      @updated << object
      @pod = object
    end

    def delete(resource:, namespace:, name:, **)
      @deleted << name
      @pod
    end
  end

  def pod
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "victim", "namespace" => "ns", "resourceVersion" => "7"},
     "status" => {"phase" => "Running",
                  "conditions" => [{"type" => "Ready", "status" => "True"}]}}
  end

  def server_for(store)
    subject = Server.allocate
    subject.instance_variable_set(:@store, store)
    subject.instance_variable_set(:@clock, -> { Time.utc(2026, 1, 1) })
    subject.define_singleton_method(:after_commit) { |*| nil }
    subject
  end

  def evict(store)
    server_for(store).send(:mark_evicted, "pods", "ns", "victim", store.get(resource: nil))
  end

  def condition_of(object)
    Array(object.dig("status", "conditions")).find { |c| c["type"] == "DisruptionTarget" }
  end

  def test_an_evicted_pod_is_marked_with_the_eviction_api_reason
    store = Store.new(pod)

    evict(store)

    assert_equal 1, store.updated.length
    condition = condition_of(store.updated.first)
    refute_nil condition, "the evicted Pod must carry DisruptionTarget"
    assert_equal "True", condition["status"]
    assert_equal "EvictionByEvictionAPI", condition["reason"]
    assert_equal "Eviction API: evicting", condition["message"]
  end

  def test_marking_keeps_the_conditions_the_pod_already_had
    store = Store.new(pod)

    evict(store)

    types = Array(store.updated.first.dig("status", "conditions")).map { |c| c["type"] }
    assert_includes types, "Ready"
    assert_equal 1, types.count("DisruptionTarget"), "the condition is set, never duplicated"
  end

  def test_marking_an_already_marked_pod_replaces_rather_than_appends
    marked = pod
    marked["status"]["conditions"] << {"type" => "DisruptionTarget", "status" => "False", "reason" => "Stale"}
    store = Store.new(marked)

    evict(store)

    conditions = Array(store.updated.first.dig("status", "conditions")).select { |c| c["type"] == "DisruptionTarget" }
    assert_equal 1, conditions.length
    assert_equal "EvictionByEvictionAPI", conditions.first["reason"]
  end

  # A Pod that vanished under us must not stop the eviction it was chosen for.
  def test_a_pod_that_disappears_does_not_fail_the_eviction
    store = Store.new(pod)
    store.define_singleton_method(:update) { |**| raise Rubernetes::API::MemoryStore::NotFound, "gone" }

    result = evict(store)

    assert_equal "victim", result.dig("metadata", "name")
  end
end
