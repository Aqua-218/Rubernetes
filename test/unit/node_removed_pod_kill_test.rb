# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# kubelet parity for a Pod deleted from the API while its containers still
# run ("[sig-scheduling] SchedulerPreemption ... with the async preemption":
# victims with a 79 s preStop hook are force-deleted, then the preemptors
# are bound to their node):
# - HandlePodRemoves drops the Pod from the pod manager at once, so admission
#   no longer counts it -- we counted it until its containers were gone and
#   refused the preemptors ("Node didn't have enough resource").
# - killContainer runs the preStop hook only within the grace period (a
#   force delete's 0 runs none); we ran it for up to 30 s.
class NodeRemovedPodKillTest < Minitest::Test
  Lifecycle = Rubernetes::Node::Lifecycle

  def pod(uid, grace: 80, deletion_grace: nil)
    metadata = {"name" => uid, "namespace" => "ns", "uid" => uid}
    metadata["deletionGracePeriodSeconds"] = deletion_grace unless deletion_grace.nil?
    {"metadata" => metadata, "spec" => {"terminationGracePeriodSeconds" => grace, "containers" => []}}
  end

  def record(uid, **fields)
    {uid: uid, state: "Running", phase: "Running", containers: [{name: "c", id: "c-#{uid}", started: true}],
     pod: pod(uid), events: [], cleanup_errors: []}.merge(fields)
  end

  def test_a_pod_removed_from_the_api_is_not_admitted_any_more
    lifecycle = Lifecycle.new(runtime: Object.new)
    records = lifecycle.instance_variable_get(:@records)
    records["running"] = record("running")
    records["removed"] = record("removed", state: "Stopping", config_removed: true)

    assert_equal ["running"], lifecycle.send(:admitted_pods).map { |item| item.dig("metadata", "uid") }
  end

  def test_the_kill_grace_period
    lifecycle = Lifecycle.new(runtime: Object.new)
    entry = record("p")
    assert_equal 80, lifecycle.send(:kill_grace_seconds, entry, pod("p"))
    assert_equal 0, lifecycle.send(:kill_grace_seconds, entry, pod("p", deletion_grace: 0))
    assert_equal 30, lifecycle.send(:kill_grace_seconds, entry, pod("p", deletion_grace: 30))
    assert_equal 5, lifecycle.send(:kill_grace_seconds, entry.merge(grace_override: 5), pod("p", deletion_grace: 30))
  end

  def test_a_prestop_hook_is_cut_off_at_the_grace_period
    slept = []
    lifecycle = Lifecycle.new(runtime: Object.new, sleeper: ->(seconds) { slept << seconds })
    entry = record("p")
    entry[:containers][0][:spec] = {"name" => "c", "lifecycle" => {"preStop" => {"sleep" => {"seconds" => 79}}}}

    lifecycle.send(:run_pre_stop_hooks, entry[:pod], entry, budget: 0)
    assert_empty slept, "a force delete runs no preStop hook"

    # runSleepHandler: cut off by the grace period, the hook fails (the
    # caller reports FailedPreStopHook and kills the container anyway).
    error = assert_raises(Lifecycle::LifecycleError) { lifecycle.send(:run_pre_stop_hooks, entry[:pod], entry, budget: 5) }
    assert_equal "container terminated before sleep hook finished", error.message
    assert_equal 1, slept.length
    assert_operator slept.first, :<=, 5

    slept.clear
    lifecycle.send(:run_pre_stop_hooks, entry[:pod], entry, budget: 80)
    assert_equal [79], slept
  end

  class Source
    def list_pods(**_options) = {"items" => [], "metadata" => {"resourceVersion" => "1"}}
    def watch_pods(**_options) = []
    def close = true
  end

  # The worker that would handle the DELETED may be busy killing the same Pod
  # (a preStop hook running out its grace period), so the watch thread tells
  # the lifecycle straight away.
  def test_the_watch_marks_a_deleted_pod_removed_before_its_worker_runs
    removed = []
    blocker = Queue.new
    sync = Rubernetes::Node::SyncLoop.new(source: Source.new, node_name: "node-a",
                                          reconcile: ->(_object, **_options) { blocker.pop },
                                          removed: ->(uid) { removed << uid }, sleeper: ->(_seconds) {})
    object = {"apiVersion" => "v1", "kind" => "Pod",
              "metadata" => {"name" => "victim", "namespace" => "ns", "uid" => "uid-victim", "resourceVersion" => "2"},
              "spec" => {"nodeName" => "node-a"}}
    sync.process_event({"type" => "ADDED", "object" => object})
    sync.process_event({"type" => "DELETED", "object" => object})
    assert_equal ["uid-victim"], removed
  ensure
    3.times { blocker&.push(true) }
  end

  def test_pod_removed_takes_the_pod_out_of_admission
    lifecycle = Lifecycle.new(runtime: Object.new)
    lifecycle.instance_variable_get(:@records)["busy"] = record("busy", state: "Stopping")
    assert_equal 1, lifecycle.send(:admitted_pods).length
    lifecycle.pod_removed("busy")
    assert_empty lifecycle.send(:admitted_pods)
  end
end
