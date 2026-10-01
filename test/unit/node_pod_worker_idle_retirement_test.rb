# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A pod worker's thread used to live as long as the process: a node that had
# run a few hundred Pods carried a few hundred idle threads, each pinning a
# glibc malloc arena (4 GB resident on a conformance node) and each making
# every fork the agent performed slower.  kubelet's pod workers end with the
# Pod.  Ours now let the thread exit after an idle timeout; the next enqueue
# starts a fresh one, and the pool drops a retired worker.
class NodePodWorkerIdleRetirementTest < Minitest::Test
  Worker = Rubernetes::Node::PodWorker
  Pool = Rubernetes::Node::PodWorkerPool

  def pod(uid = "u")
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => uid}}
  end

  def wait_until(timeout = 2.0)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      flunk "condition not met within #{timeout}s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      sleep 0.005
    end
  end

  def test_an_idle_worker_lets_its_thread_exit_and_restarts_it_on_the_next_enqueue
    seen = Queue.new
    worker = Worker.new(pod_uid: "u", idle_timeout: 0.05, reconcile: ->(_object, action: nil, request_id: nil) { seen << action })
    worker.enqueue(pod, action: "ADDED")

    assert_equal "ADDED", seen.pop
    wait_until { !worker.running? }

    assert_predicate worker, :retired?

    worker.enqueue(pod, action: "MODIFIED")

    assert_equal "MODIFIED", seen.pop
    assert_predicate worker, :running?
    worker.stop
  end

  def test_a_worker_without_idle_timeout_keeps_its_thread
    worker = Worker.new(pod_uid: "u", idle_timeout: nil, reconcile: ->(_object, action: nil, request_id: nil) {})
    worker.enqueue(pod, action: "ADDED")
    worker.drain(timeout: 1.0)
    sleep 0.05

    assert_predicate worker, :running?
    worker.stop
  end

  def test_the_pool_drops_a_retired_worker_and_builds_a_new_one_on_demand
    processed = Queue.new
    pool = Pool.new(idle_timeout: 0.05, reconcile: ->(object, action: nil, request_id: nil) { processed << object.dig("metadata", "uid") })
    pool.enqueue(pod("a"), action: "ADDED")
    pool.enqueue(pod("b"), action: "ADDED")

    assert_equal %w[a b], [processed.pop, processed.pop].sort
    wait_until { pool.workers.empty? }

    pool.enqueue(pod("a"), action: "MODIFIED")

    assert_equal "a", processed.pop
    assert_equal ["a"], pool.workers.keys
    pool.stop
  end

  def test_an_enqueue_racing_the_idle_exit_is_never_lost
    processed = Queue.new
    pool = Pool.new(idle_timeout: 0.01, reconcile: ->(_object, action: nil, request_id: nil) { processed << action })
    # Enqueue at roughly the idle timeout for a while: every task must be
    # processed whether it landed on the old thread or started a new one.
    40.times do |round|
      pool.enqueue(pod, action: "R#{round}")
      sleep(round.even? ? 0.01 : 0.012)
    end
    received = []
    received << processed.pop(timeout: 2.0) while (received.length < 40 && !processed.empty?) ||
                                                  (received.length < 40 && (sleep(0.01) || true) && received.length < 40 && processed.size.positive?)
    pool.drain(timeout: 2.0)
    received << processed.pop until processed.empty?

    assert_equal (0...40).map { |round| "R#{round}" }, received.compact
    pool.stop
  end
end
