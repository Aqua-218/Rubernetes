# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"
require "rubernetes/client/errors"

# Regression coverage for the scheduling-queue starvation class found in the
# 2026-09-13 K1 conformance run (#44): a CronJob Pod was deleted between being
# queued and being bound, the bind failed with HTTP 404, and the failure path
# re-enqueued it.  The delete event that had already removed it from the queue
# never arrives twice, so the zombie stayed queued; PrioritySort orders by
# creation timestamp, so it sorted ahead of every Pod created afterwards and
# was popped on every scheduling tick.  88,501 consecutive failed attempts
# over 15.5 hours, and not one other Pod was ever scheduled.
#
# Specification: spec/control-plane/scheduler.md §5.6.1 (queue order) and
# §5.6.6 (failure handling).
class M3SchedulerQueueStarvationRegressionTest < Minitest::Test
  Scheduler = Rubernetes::Scheduler

  class GoneError < StandardError
    def status
      404
    end
  end

  def test_pod_that_no_longer_exists_is_dropped_and_never_requeued
    ghost = pod("ghost", created: "2026-09-13T15:17:00Z")
    scheduler = Scheduler.new(bind: lambda do |pod, _node|
      raise GoneError, "Kubernetes API request GET /api/v1/namespaces/default/pods/#{pod.name} " \
                       "failed with HTTP 404: pods \"#{pod.name}\" not found"
    end)

    scheduler.enqueue(ghost)
    result = scheduler.schedule_next(nodes: [node("worker")])

    assert_predicate result, :dropped?
    refute scheduler.queue.include?(Scheduler::Pod.new(ghost)), "a deleted Pod must not stay queued"
    assert_nil scheduler.schedule_next(nodes: [node("worker")]), "the queue must be empty afterwards"
  end

  def test_ghost_pod_cannot_starve_pods_created_after_it
    ghost = pod("ghost", created: "2026-09-13T15:17:00Z")
    victim = pod("victim", created: "2026-09-13T15:27:00Z")
    attempts = Hash.new(0)
    scheduler = Scheduler.new(bind: lambda do |pod, _node|
      attempts[pod.name] += 1
      next true unless pod.name == "ghost"

      raise GoneError, "Kubernetes API request POST /api/v1/namespaces/default/pods/ghost/binding " \
                       "failed with HTTP 404: pods \"ghost\" not found"
    end)

    scheduler.enqueue(ghost)
    scheduler.enqueue(victim)

    # The ghost sorts first (older creationTimestamp) and fails.
    first = scheduler.schedule_next(nodes: [node("worker")])
    assert_predicate first, :dropped?
    assert_equal "ghost", first.pod.name

    # The very next tick must schedule the Pod behind it.  Before the fix this
    # popped the ghost again, forever.
    second = scheduler.schedule_next(nodes: [node("worker")])
    assert_predicate second, :scheduled?
    assert_equal "victim", second.pod.name
    assert_equal 1, attempts["ghost"]
  end

  def test_repeated_bind_failures_go_through_exponential_backoff
    clock = 0.0
    queue = Scheduler::SchedulingQueue.new(clock: -> { clock })
    flaky = pod("flaky", created: "2026-09-13T15:17:00Z")
    scheduler = Scheduler.new(queue: queue, bind: ->(_pod, _node) { raise "transient bind failure" })

    scheduler.enqueue(flaky)
    first = scheduler.schedule_next(nodes: [node("worker")])
    assert_predicate first, :requeued?

    # Still inside the first backoff window: the loop gets nothing to do rather
    # than spinning on the same Pod.
    assert_nil scheduler.schedule_next(nodes: [node("worker")])
    assert_equal 1, queue.backoff_size

    clock += Scheduler::SchedulingQueue::INITIAL_BACKOFF_SECONDS
    assert_predicate scheduler.schedule_next(nodes: [node("worker")]), :requeued?
    assert_equal 2, queue.attempts(Scheduler::Pod.new(flaky))

    # Backoff doubles and is capped.
    clock += Scheduler::SchedulingQueue::INITIAL_BACKOFF_SECONDS
    assert_nil scheduler.schedule_next(nodes: [node("worker")])
    clock += Scheduler::SchedulingQueue::MAX_BACKOFF_SECONDS
    assert_predicate scheduler.schedule_next(nodes: [node("worker")]), :requeued?
  end

  def test_persistent_failure_leaves_the_active_rotation_for_the_unschedulable_queue
    clock = 0.0
    queue = Scheduler::SchedulingQueue.new(clock: -> { clock }, max_active_attempts: 3)
    flaky = pod("flaky", created: "2026-09-13T15:17:00Z")
    scheduler = Scheduler.new(queue: queue, bind: ->(_pod, _node) { raise "transient bind failure" })

    scheduler.enqueue(flaky)
    3.times do
      clock += Scheduler::SchedulingQueue::MAX_BACKOFF_SECONDS
      scheduler.schedule_next(nodes: [node("worker")])
    end

    assert_equal 0, queue.size
    assert_equal 0, queue.backoff_size
    assert_equal 1, queue.unschedulable_size
  end

  def test_a_404_for_a_different_object_does_not_evict_a_live_pod
    live = pod("live", created: "2026-09-13T15:17:00Z")
    scheduler = Scheduler.new(bind: lambda do |_pod, _node|
      raise GoneError, "Kubernetes API request GET /api/v1/namespaces/default/persistentvolumeclaims/data " \
                       "failed with HTTP 404: persistentvolumeclaims \"data\" not found"
    end)

    scheduler.enqueue(live)
    result = scheduler.schedule_next(nodes: [node("worker")])

    assert_predicate result, :requeued?
    assert scheduler.queue.include?(Scheduler::Pod.new(live)),
           "a Pod must survive a 404 raised for some other object"
  end

  def test_successful_bind_clears_the_failure_history
    clock = 0.0
    queue = Scheduler::SchedulingQueue.new(clock: -> { clock })
    fail_once = true
    target = pod("target", created: "2026-09-13T15:17:00Z")
    scheduler = Scheduler.new(queue: queue, bind: lambda do |_pod, _node|
      raise "transient bind failure" if fail_once

      true
    end)

    scheduler.enqueue(target)
    assert_predicate scheduler.schedule_next(nodes: [node("worker")]), :requeued?
    assert_equal 1, queue.attempts(Scheduler::Pod.new(target))

    fail_once = false
    clock += Scheduler::SchedulingQueue::INITIAL_BACKOFF_SECONDS
    assert_predicate scheduler.schedule_next(nodes: [node("worker")]), :scheduled?
    assert_equal 0, queue.attempts(Scheduler::Pod.new(target))
  end

  private

  def pod(name, created:)
    {
      "apiVersion" => "v1", "kind" => "Pod",
      "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}",
                     "creationTimestamp" => created},
      "spec" => {"containers" => [{"name" => "container",
                                   "resources" => {"requests" => {"cpu" => "10m"}}}]}
    }
  end

  def node(name, allocatable: {"cpu" => "8"})
    {
      "apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name},
      "status" => {"allocatable" => allocatable,
                   "conditions" => [{"type" => "Ready", "status" => "True"}]}
    }
  end
end
