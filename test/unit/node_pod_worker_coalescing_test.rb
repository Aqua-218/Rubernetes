# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# kubelet's pod worker keeps ONE pending update per Pod and replaces it with
# the newest one (pkg/kubelet/pod_workers.go pendingUpdate): a sync that
# arrives while the previous one is still running describes the same Pod, so
# queueing both only makes the worker fall further behind.  Without this the
# periodic housekeeping sync -- which enqueues every Pod on a short timer --
# outran a slow reconcile and the backlog grew without bound, so a Pod could
# sit Pending for minutes replaying stale syncs.
class NodePodWorkerCoalescingTest < Minitest::Test
  Worker = Rubernetes::Node::PodWorker

  def pod(name = "p")
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "ns", "uid" => "u"}}
  end

  def test_syncs_queued_behind_a_slow_reconcile_collapse_to_the_newest
    started = Queue.new
    gate = Queue.new
    seen = []
    worker = Worker.new(pod_uid: "u", reconcile: lambda { |object, action: nil, request_id: nil|
      if seen.empty?
        started << :running
        gate.pop
      end
      seen << [action, object.dig("metadata", "labels", "round")]
    })
    worker.enqueue(pod, action: "SYNC")
    started.pop # the first sync is now running and cannot be coalesced away
    5.times do |index|
      candidate = pod
      candidate["metadata"]["labels"] = {"round" => index.to_s}
      worker.enqueue(candidate, action: "SYNC")
    end
    gate << :go
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
    sleep(0.01) while seen.length < 2 && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

    assert_equal(2, seen.length, "one running sync plus one coalesced pending sync")
    assert_equal("4", seen.last.last, "the newest state wins")
  ensure
    worker&.stop(join: false)
  end

  # A sync superseded BEFORE it starts is dropped outright: only the newest
  # state is ever handed to the runtime.
  def test_a_sync_superseded_before_it_starts_never_runs
    seen = []
    worker = Worker.new(pod_uid: "u", auto_start: false,
                        reconcile: lambda { |object, action: nil, request_id: nil|
                          seen << object.dig("metadata", "labels", "round")
                        })
    3.times do |index|
      candidate = pod
      candidate["metadata"]["labels"] = {"round" => index.to_s}
      worker.enqueue(candidate, action: "SYNC")
    end
    worker.start
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
    sleep(0.01) while seen.empty? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

    assert_equal(%w[2], seen)
  ensure
    worker&.stop(join: false)
  end

  def test_a_deletion_supersedes_a_pending_sync
    seen = []
    worker = Worker.new(pod_uid: "u", auto_start: false,
                        reconcile: ->(_object, action: nil, request_id: nil) { seen << action })
    worker.enqueue(pod, action: "SYNC")
    worker.enqueue(pod, action: "MODIFIED")
    worker.enqueue(pod, action: "DELETED")
    worker.start
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
    sleep(0.01) while seen.empty? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

    assert_equal(%w[DELETED], seen)
  ensure
    worker&.stop(join: false)
  end

  def test_a_single_sync_still_runs
    seen = []
    worker = Worker.new(pod_uid: "u", reconcile: ->(_object, action: nil, request_id: nil) { seen << action })
    worker.enqueue(pod, action: "SYNC")
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
    sleep(0.01) while seen.empty? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

    assert_equal(%w[SYNC], seen)
  ensure
    worker&.stop(join: false)
  end
end
