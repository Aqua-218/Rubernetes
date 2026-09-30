# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"

# Runtime regressions for the M3 scheduler extension-point contracts.
# Specification: spec/control-plane/scheduler.md §5.6.1, §5.6.3, §5.6.5,
# and §5.6.6. These tests cover observable queue order, post-filter dispatch,
# trace provenance, and exact preemption-budget failure semantics.
class M3SchedulerRuntimeRegressionTest < Minitest::Test
  Scheduler = Rubernetes::Scheduler

  def test_registered_queue_sort_override_controls_schedule_next_and_is_traced
    scheduler = Scheduler.new do
      queue_sort "PrioritySort" do |left, right|
        # Deliberately reverse names so the registry override is observable.
        right.name <=> left.name
      end
    end

    scheduler.enqueue(pod("alpha", priority: 100))
    scheduler.enqueue(pod("zulu", priority: 0))

    result = scheduler.schedule_next(nodes: [node("worker")])

    assert_predicate result, :scheduled?
    assert_equal "zulu", result.pod.name
    queue_events = result.trace.events.select { |event| event.fetch("phase") == "queue_sort" }

    refute_empty queue_events
    assert_equal ["PrioritySort"], queue_events.map { |event| event.fetch("plugin") }.uniq
    assert(queue_events.all? { |event| event.fetch("output").is_a?(Integer) })
    assert(queue_events.all? { |event| event.fetch("input_snapshot_sha256").match?(/\A[0-9a-f]{64}\z/) })
  end

  def test_registered_post_filter_override_is_invoked_instead_of_hardcoded_evaluator
    low = pod("victim", priority: 1, requests: {"cpu" => "1"}, node_name: "worker")
    pending = pod("pending", priority: 10, requests: {"cpu" => "1500m"})
    custom_node = Scheduler::Node.new(node("worker"))
    custom_victim = Scheduler::Pod.new(low)
    calls = 0
    registry = Scheduler::PluginRegistry.new
    registry.register(Scheduler::Plugin.new(
      name: "DefaultPreemption",
      kind: :post_filter,
      phase: :post_filter,
      block: lambda do |_pod, _node|
        calls += 1
        Scheduler::Preemption::Result.new(node: custom_node, victims: [custom_victim],
                                          reason: "custom post-filter")
      end
    ))
    deleted = []
    scheduler = Scheduler.new(plugins: registry, delete_pod: ->(victim) { deleted << victim.name })

    result = scheduler.schedule(pending, [node("worker")], pods: [low])

    assert_predicate result, :unschedulable?
    assert_equal "worker", result.nominated_node
    assert scheduler.wait_for_preemptions
    assert_equal ["victim"], deleted
    assert_equal 1, calls
    post_filter_events = result.trace.events.select { |event| event.fetch("phase") == "post_filter" }
    # DynamicResources runs first (applyDynamicResources) and has no claim to
    # deallocate for a Pod without claims.
    assert_equal(%w[DynamicResources DefaultPreemption], post_filter_events.map { |event| event.fetch("plugin") })
    assert_equal "custom post-filter", post_filter_events.last.fetch("output").fetch("reason")
  end

  def test_preemption_budget_exhaustion_requeues_without_returning_partial_victims
    first = pod("a-victim", priority: 1, requests: {"cpu" => "1500m"}, node_name: "worker")
    second = pod("b-victim", priority: 1, requests: {"cpu" => "500m"}, node_name: "worker")
    pending = pod("high-priority", priority: 10, requests: {"cpu" => "1500m"})
    evaluator = Scheduler::Preemption::Evaluator.new(max_evaluations: 1)
    scheduler = Scheduler.new(preemption: evaluator, delete_pod: ->(_victim) { flunk "partial victim set must not be applied" })

    result = scheduler.schedule(pending, [node("worker", allocatable: {"cpu" => "2"})], pods: [first, second])

    assert_predicate result, :requeued?
    assert_instance_of Scheduler::Preemption::BudgetExceeded, result.error
    assert_empty result.victims
    # Requeued now means the Pod waits out a backoff before it can be popped
    # again; see M3SchedulerQueueStarvationRegressionTest.
    assert_equal 0, scheduler.queue.size
    assert_equal 1, scheduler.queue.backoff_size
  end

  private

  def pod(name, priority:, requests: {}, node_name: nil)
    spec = {
      "priority" => priority,
      "containers" => [{"name" => "container", "resources" => {"requests" => requests}}]
    }
    spec["nodeName"] = node_name if node_name
    {
      "apiVersion" => "v1", "kind" => "Pod",
      "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"},
      "spec" => spec
    }
  end

  def node(name, allocatable: {"cpu" => "2"})
    {
      "apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name},
      "status" => {"allocatable" => allocatable,
                   "conditions" => [{"type" => "Ready", "status" => "True"}]}
    }
  end
end
