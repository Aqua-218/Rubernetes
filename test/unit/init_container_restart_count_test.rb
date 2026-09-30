# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# An init container that keeps failing under a restarting policy is the same
# container restarting, and kubelet numbers it that way: restartCount climbs
# and lastState carries the previous termination.  Ours rolled the Pod back and
# started it again from a fresh record, so every attempt looked like the first
# one -- restartCount 0 and no lastState, for ever.  "[sig-node] InitContainer
# should not start app containers if init containers fail on a RestartAlways
# pod" waits for restartCount 3 and a terminated lastState.
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
    Rubernetes::Node::Lifecycle.new(runtime: Runtime.new, sleeper: ->(_seconds) {})
  end

  def init_status(subject)
    record = subject.send(:record, "pod-1")
    Array(record[:containers]).find { |entry| entry[:name] == "init1" }
  end

  # Each retry is a restart of the same container, not a new first attempt.
  def attempt_starts(subject, times)
    times.times do
      subject.send(:clear_start_retry, "pod-1")
      begin
        subject.start(pod)
      rescue StandardError
        nil
      end
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
    begin
      subject.start(pod)
    rescue StandardError
      nil
    end

    assert subject.send(:start_retry_scheduled?, "pod-1"),
           "a failed start schedules a retry"
    record = subject.send(:record, "pod-1")
    subject.send(:forget_terminated_probe_and_restart_state, record)

    assert_operator subject.instance_variable_get(:@restarts).restart_count("pod-1/init1").to_i, :>=, 0
    refute_empty subject.instance_variable_get(:@restarts).all,
                 "the restart history of a Pod that is coming back must not be dropped"
  end

  def test_a_pod_that_is_really_gone_still_releases_its_restart_history
    subject = lifecycle
    begin
      subject.start(pod)
    rescue StandardError
      nil
    end
    record = subject.send(:record, "pod-1")
    subject.send(:clear_start_retry, "pod-1")

    subject.send(:forget_terminated_probe_and_restart_state, record)

    assert_empty subject.instance_variable_get(:@restarts).all
  end
end
