# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# Probes and restart backoffs are driven by per-Pod wake-ups: without them a
# liveness probe ran whenever some unrelated event reconciled its Pod.
class NodeWakeupTimerTest < Minitest::Test
  Node = Rubernetes::Node

  def test_a_wakeup_fires_once_at_its_time_and_the_earliest_request_wins
    fired = Queue.new
    timer = Node::WakeupTimer.new { |key| fired << [key, Process.clock_gettime(Process::CLOCK_MONOTONIC)] }
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    timer.schedule("pod-a", 0.3)
    timer.schedule("pod-a", 0.1)
    timer.schedule("pod-b", 0.2)
    sleep 0.45

    events = Array.new(fired.size) { fired.pop }
    assert_equal %w[pod-a pod-b], events.map(&:first)
    assert_in_delta 0.1, events.first.last - started, 0.08
    assert_empty timer.pending
  ensure
    timer&.stop
  end

  def test_a_cancelled_wakeup_does_not_fire
    fired = Queue.new
    timer = Node::WakeupTimer.new { |key| fired << key }
    timer.schedule("pod-a", 0.1)
    timer.cancel("pod-a")
    sleep 0.2

    assert_equal 0, fired.size
  ensure
    timer&.stop
  end

  class Runtime
    def initialize = @sequence = 0
    def run_sandbox(_pod, runtime_class: nil) = "sandbox-1"
    def create_container(_sandbox, _spec) = "container-#{@sequence += 1}"
    def start_container(_id) = true
    def stop_container(_id, timeout: nil) = true
    def remove_container(_id) = true
    def remove_sandbox(_id) = true
    def wait_container(_id) = {"state" => "terminated", "exitCode" => 0}
  end

  def test_a_probed_container_is_woken_at_its_initial_delay_and_then_every_period
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"},
           "spec" => {"nodeName" => "n", "containers" => [{"name" => "c", "image" => "img",
                                                           "livenessProbe" => {"httpGet" => {"path" => "/healthz", "port" => 8080},
                                                                               "initialDelaySeconds" => 5, "periodSeconds" => 7}}]}}
    lifecycle = Node::Lifecycle.new(runtime: Runtime.new)
    wakeups = []
    lifecycle.wakeup = ->(uid, delay) { wakeups << [uid, delay] }
    lifecycle.start(pod)

    assert_equal ["u1", 5.0], wakeups.first
    record = lifecycle.record("u1")
    lifecycle.send(:probe_running_containers, record, pod) rescue nil
    assert_includes wakeups, ["u1", 7.0]
  end
end
