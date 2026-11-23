# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require_relative "../support/node_agent_fakes"

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
    termination = container_status.dig("lastState", "terminated")

    assert_equal "container-1", termination.fetch("containerID")
    assert_equal Time.at(@now).utc.iso8601(6), termination.fetch("finishedAt")
  end

  def test_replacement_retires_only_the_prior_attempt_and_tracks_its_log
    @runtime.define_singleton_method(:retire_container) do |id, previous_id: nil, previous_log_path: nil|
      calls << [:retire, id, previous_id, previous_log_path]
      {"log_path" => "/archive/#{id}.log"}
    end
    crash_into_backoff
    @now += 60
    @lifecycle.reconcile(pod)

    assert_includes @runtime.calls, [:retire, "container-1", nil, nil]
    assert_includes @runtime.calls, [:retire, "container-2", "container-1", "/archive/container-1.log"]
    record = @lifecycle.record(pod).fetch(:containers).first

    assert_equal "container-2", record[:previous_id]
    assert_equal "/archive/container-2.log", record[:previous_log_path]
    assert_equal "container-2", record.dig(:status, "lastState", "terminated", "containerID")
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

  def test_matching_rule_restarts_and_backs_off_under_never
    workload = pod
    workload["metadata"]["uid"] = "rule-restart"
    workload["spec"]["restartPolicy"] = "Never"
    container = workload["spec"]["containers"].first
    container["restartPolicy"] = "Never"
    container["restartPolicyRules"] = [{"action" => "Restart", "exitCodes" => {"operator" => "In", "values" => [42]}}]
    @lifecycle.start(workload)
    2.times do
      @now += 1
      @lifecycle.handle_container_exit(workload, container_name: "app", exit_code: 42, now: @now)
    end
    waiting = @lifecycle.record(workload).fetch(:status)

    assert_equal "Running", waiting["phase"]
    assert_equal "CrashLoopBackOff", waiting.dig("containerStatuses", 0, "state", "waiting", "reason")
    assert_equal 1, waiting.dig("containerStatuses", 0, "restartCount")

    @now += @restarts.backoff("rule-restart/app")
    @lifecycle.reconcile(workload)

    assert_equal 2, @lifecycle.record(workload).dig(:status, "containerStatuses", 0, "restartCount")
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

  def test_agent_uses_the_kubelet_backoff_defaults_and_gate_precedence
    legacy = agent_restart_manager
    reduced = agent_restart_manager(feature_gates: {"ReduceDefaultCrashLoopBackOffDecay" => true})
    reduced_without_override = agent_restart_manager(
      feature_gates: {"ReduceDefaultCrashLoopBackOffDecay" => true, "KubeletCrashLoopBackOffMax" => false}
    )
    reduced_with_override = agent_restart_manager(
      feature_gates: {"ReduceDefaultCrashLoopBackOffDecay" => true}, crash_loop_back_off_max: 100
    )

    assert_equal [0, 10, 20, 40, 80, 160, 300, 300, 300, 300, 300, 300], backoff_delays(legacy, 12)
    assert_equal [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300], backoff_delays(reduced, 12)
    assert_equal [0, 1, 2, 4, 8, 16, 32, 60, 60, 60], backoff_delays(reduced_without_override, 10)
    assert_equal [0, 1, 2, 4, 8, 16, 32, 64, 100, 100], backoff_delays(reduced_with_override, 10)
  end

  def test_configured_maximum_clamps_the_initial_delay_and_survives_recovery
    manager = agent_restart_manager(crash_loop_back_off_max: 2.5)

    assert_equal [0, 2.5, 2.5], backoff_delays(manager, 3)
    recovered = agent_restart_manager(crash_loop_back_off_max: 2.5)
    recovered.restore(manager.snapshot)

    assert_in_delta 2.5, recovered.backoff("u1/app")
    refute recovered.restart_ready?("u1/app", now: 4.4)
    assert recovered.restart_ready?("u1/app", now: 4.5)
  end

  private

  def agent_restart_manager(**)
    Node::Agent.new(node_name: "n", api: NodeAgentFakes::API.new, runtime: @runtime, **).lifecycle.restarts
  end

  def backoff_delays(manager, attempts)
    Array.new(attempts) do |attempt|
      manager.record_exit("u1/app", exit_code: 1, at: attempt).delay_seconds
    end
  end
end
