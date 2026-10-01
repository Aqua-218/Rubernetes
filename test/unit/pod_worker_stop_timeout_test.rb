# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/pod_worker"

# A stop drains queued work, but a reconcile that never finishes must not
# hold the agent's shutdown for ever: agent-worker-0 sat in PodWorkerPool#stop
# behind a Cilium init container that never exited, and SIGTERM never ended
# the process.
class PodWorkerStopTimeoutTest < Minitest::Test
  def test_pool_stop_returns_after_the_timeout_with_a_blocked_reconcile
    started = Queue.new
    release = Queue.new
    pool = Rubernetes::Node::PodWorkerPool.new(reconcile: lambda { |_pod|
      started << true
      release.pop
    })
    pod = {"metadata" => {"uid" => "u1", "name" => "p", "namespace" => "default"}}
    pool.enqueue(pod)
    pool.start
    started.pop
    before = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    pool.stop(drain: true, join: true, timeout: 0.5)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - before

    assert_operator elapsed, :<, 3, "stop must return once the drain timeout passes (took #{elapsed.round(2)}s)"
  ensure
    release << true
  end

  def test_pool_stop_without_a_timeout_still_drains_finished_work
    done = []
    pool = Rubernetes::Node::PodWorkerPool.new(reconcile: ->(pod) { done << pod.dig("metadata", "uid") })
    pool.enqueue({"metadata" => {"uid" => "u2", "name" => "p", "namespace" => "default"}})
    pool.start
    pool.stop(drain: true, join: true)

    assert_equal ["u2"], done
  end
end
