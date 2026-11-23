# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# Each init retry keeps the existing sandbox and reports the previous run.
class InitContainerRestartCountTest < Minitest::Test
  class Runtime
    def initialize = @counter = 0

    def run_sandbox(_pod, runtime_class: nil) = "sandbox-1"

    def create_container(_sandbox, _spec)
      @counter += 1
      "container-#{@counter}"
    end

    def start_container(_id) = true
    # Every init container fails.
    def wait_container(_id) = {"state" => "terminated", "exitCode" => 1}
    def stop_container(_id, timeout:) = true
    def kill_container(_id, signal:) = true
    def remove_container(_id) = true
    def remove_sandbox(_id) = true
  end

  def pod
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "initfail", "namespace" => "ns", "uid" => "pod-1"},
     "spec" => {"nodeName" => "node-1", "restartPolicy" => "Always",
                "initContainers" => [{"name" => "init1", "image" => "example/busybox"}],
                "containers" => [{"name" => "run1", "image" => "example/pause"}]}}
  end

  def lifecycle
    @now = 0
    restarts = Rubernetes::Node::RestartManager.new(clock: -> { @now })
    Rubernetes::Node::Lifecycle.new(runtime: Runtime.new, restart_manager: restarts)
  end

  def init_status(subject)
    record = subject.send(:record, "pod-1")
    Array(record[:containers]).find { |entry| entry[:name] == "init1" }
  end

  def attempt_starts(subject, times)
    times.times do
      subject.reconcile(pod)
      @now += 30
    end
  end

  def test_the_restart_count_climbs_across_retried_starts
    subject = lifecycle
    attempt_starts(subject, 3)

    assert_operator init_status(subject)[:status]["restartCount"].to_i, :>=, 2,
                    "a repeatedly failing init container must be counted as restarting"
  end

  def test_a_retried_init_container_reports_where_it_came_from
    subject = lifecycle
    attempt_starts(subject, 2)

    last = init_status(subject)[:status]["lastState"]

    refute_nil last, "the retried container must carry its previous termination"
    assert_equal 1, last.dig("terminated", "exitCode")
  end

  def test_a_pod_waiting_to_be_started_again_keeps_its_restart_history
    subject = lifecycle
    wakeups = []
    subject.wakeup = ->(uid, delay) { wakeups << [uid, delay] }
    subject.reconcile(pod)
    subject.reconcile(pod)

    assert_equal [["pod-1", 10.0]], wakeups
    waiting = init_status(subject)

    assert_equal "CrashLoopBackOff", waiting.dig(:status, "waiting", "reason")
    assert_equal 1, waiting.dig(:status, "restartCount")
    assert_equal 1, waiting.dig(:status, "lastState", "terminated", "exitCode")
    assert_equal "sandbox-1", subject.record("pod-1").fetch(:sandbox_id)

    subject.reconcile(pod)

    assert_equal waiting[:id], init_status(subject)[:id]
    assert_equal [["pod-1", 10.0]], wakeups
  end

  def test_a_pod_that_is_really_gone_still_releases_its_restart_history
    subject = lifecycle
    subject.reconcile(pod)
    subject.terminate(pod)

    assert_empty subject.instance_variable_get(:@restarts).all
  end
end
