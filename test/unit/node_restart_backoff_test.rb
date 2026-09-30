# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# kubelet holds a crash-looping container in CrashLoopBackOff and starts it
# again on the sync that finds the backoff elapsed; it never sleeps through the
# wait.  Ours slept inside the reconcile, which held the node's whole sync loop
# for every other Pod and -- worse -- left the container waiting for ever if
# anything interrupted the restart after the sleep.  Observed live on
# 2026-09-15: a Pod whose liveness probe always fails restarted exactly once
# and then sat in "back-off 10s restarting failed container" until deletion,
# so "[sig-node] Probing container should have monotonically increasing restart
# count" saw 1 restart where it wanted 5.
class NodeRestartBackoffTest < Minitest::Test
  Node = Rubernetes::Node

  class Runtime
    attr_reader :calls

    def initialize
      @calls = []
      @sequence = 0
    end

    def run_sandbox(_pod, runtime_class: nil)
      @calls << :run_sandbox
      "sandbox-1"
    end

    def create_container(_sandbox, spec)
      @sequence += 1
      @calls << [:create, spec["name"]]
      "container-#{@sequence}"
    end

    def start_container(id)
      @calls << [:start, id]
      true
    end

    def stop_container(id, timeout: nil)
      @calls << [:stop, id, timeout]
      true
    end

    def remove_container(id)
      @calls << [:remove, id]
      true
    end

    def remove_sandbox(_id) = true

    def wait_container(id)
      @calls << [:wait, id]
      {"state" => "terminated", "exitCode" => 0}
    end
  end

  def pod
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "crasher", "namespace" => "ns", "uid" => "u1"},
     "spec" => {"nodeName" => "n", "restartPolicy" => "Always",
                "containers" => [{"name" => "app", "image" => "img"}]}}
  end

  def setup
    @now = 0.0
    @runtime = Runtime.new
    @restarts = Node::RestartManager.new(clock: -> { @now }, sleeper: ->(seconds) { @now += seconds })
    @lifecycle = Node::Lifecycle.new(runtime: @runtime, restart_manager: @restarts,
                                     clock: -> { Time.at(@now).utc }, sleeper: ->(seconds) { @now += seconds })
    @lifecycle.start(pod)
  end

  def container_status
    @lifecycle.record(pod).fetch(:status).fetch("containerStatuses").first
  end

  def crash_once
    @now += 1
    @lifecycle.handle_container_exit(pod, container_name: "app", exit_code: 1, now: @now)
  end

  # kubelet restarts after the first failure at once; the backoff (and the
  # CrashLoopBackOff wait) starts with the second.
  def crash_into_backoff
    crash_once
    @lifecycle.reconcile(pod)
    crash_once
  end

  def test_the_first_failure_restarts_without_a_backoff
    crash_once

    assert_equal 0, @restarts.backoff("u1/app")
    @lifecycle.reconcile(pod)

    assert(container_status.fetch("state").key?("running"))
    assert_equal(1, container_status.fetch("restartCount"))
  end

  def test_a_crash_leaves_the_container_waiting_without_sleeping
    slept = []
    @lifecycle = Node::Lifecycle.new(runtime: @runtime, restart_manager: @restarts,
                                     clock: -> { Time.at(@now).utc }, sleeper: ->(seconds) { slept << seconds })
    @lifecycle.start(pod)
    crash_into_backoff

    assert_equal("CrashLoopBackOff", container_status.dig("state", "waiting", "reason"))
    assert_empty(slept, "the reconcile must not block the node's sync loop")
  end

  def test_a_sync_before_the_backoff_elapses_does_not_restart
    crash_into_backoff
    @lifecycle.reconcile(pod)

    assert_equal("CrashLoopBackOff", container_status.dig("state", "waiting", "reason"))
  end

  def test_the_sync_after_the_backoff_starts_the_container_again
    crash_once
    @now += @restarts.backoff("u1/app") + 1
    @lifecycle.reconcile(pod)

    assert(container_status.fetch("state").key?("running"))
    assert_equal(1, container_status.fetch("restartCount"))
  end

  # The point of the whole exercise: the count keeps climbing.
  def test_restart_count_increases_monotonically_across_crashes
    counts = []
    6.times do
      crash_once
      counts << container_status.fetch("restartCount")
      @now += @restarts.backoff("u1/app") + 1
      @lifecycle.reconcile(pod)
    end

    assert_equal(counts.sort, counts)
    assert_operator(counts.last, :>=, 5)
  end

  # A container waiting out a backoff has no live container to probe; probing
  # the old address would fail liveness again and push the backoff out for ever.
  def test_a_waiting_container_is_not_probed
    crash_into_backoff
    before = @runtime.calls.length
    @lifecycle.send(:probe_running_containers, @lifecycle.record(pod), pod)

    assert_equal(before, @runtime.calls.length)
  end
end
