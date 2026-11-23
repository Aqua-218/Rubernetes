# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

class NodeTerminationReadinessTest < Minitest::Test
  Lifecycle = Rubernetes::Node::Lifecycle

  class Runtime
    attr_accessor :probes_fail
    attr_reader :stopping, :release, :checks

    def initialize
      @stopping = Queue.new
      @release = Queue.new
      @checks = []
      @probes_fail = false
    end

    def run_sandbox(_pod, runtime_class: nil) = "sandbox"
    def create_container(_sandbox, _spec) = "app"
    def start_container(_id) = true
    def remove_container(_id) = true
    def remove_sandbox(_id) = true

    def stop_container(id, timeout:)
      @stopping << [id, timeout]
      @release.pop(timeout: 8)
      true
    end

    def exec(_id, command, tty: false)
      @checks << command.first
      @probes_fail ? 1 : 0
    end
  end

  def test_a_running_container_without_a_readiness_probe_stays_ready_through_grace
    during_termination(pod) do |lifecycle, runtime, object, worker, _reports|
      status = lifecycle.status.status_for(object)

      assert_equal "Running", status.fetch("phase")
      assert_equal "True", condition(status, "Ready").fetch("status")
      assert_equal "True", condition(status, "ContainersReady").fetch("status")
      assert_equal true, status.dig("containerStatuses", 0, "ready")

      runtime.release << true
      finished = worker.value.status

      assert_equal "Succeeded", finished.fetch("phase")
      assert_equal "False", condition(finished, "Ready").fetch("status")
    end
  end

  def test_readiness_can_fail_during_grace_with_no_prestop_hook
    probe = ->(command) { {"exec" => {"command" => [command]}, "periodSeconds" => 1, "failureThreshold" => 1} }
    subject = pod("readinessProbe" => probe.call("readiness"), "livenessProbe" => probe.call("liveness"))
    during_termination(subject) do |_lifecycle, runtime, _object, _worker, reports|
      initial = reports.pop(timeout: 4)

      assert_equal "True", condition(initial, "Ready").fetch("status")
      runtime.probes_fail = true
      failed = reports.pop(timeout: 4)

      assert_equal "Running", failed.fetch("phase")
      assert_equal "False", condition(failed, "Ready").fetch("status")
      assert_equal "ContainersNotReady", condition(failed, "Ready").fetch("reason")
      assert_equal %w[liveness readiness readiness], runtime.checks.take(3)
      assert_equal 1, runtime.checks.count("liveness")
    end
  end

  def test_eviction_withdraws_readiness_while_the_runtime_is_stopping
    previous = {"phase" => "Running", "reason" => "PreviousReason", "message" => "previous API status"}
    during_termination(pod.merge("status" => previous), evict: true) do |lifecycle, runtime, object, worker, _reports|
      status = lifecycle.status.status_for(object)

      assert_equal previous, status.slice(*previous.keys)
      assert_equal "False", condition(status, "Ready").fetch("status")
      assert_nil condition(status, "DisruptionTarget")

      runtime.release << true
      finished = worker.value.status

      assert_equal %w[Failed Evicted], finished.values_at("phase", "reason")
      assert_equal "fixture eviction", finished.fetch("message")
      assert_equal "TerminationByKubelet", condition(finished, "DisruptionTarget").fetch("reason")
    end
  end

  private

  def during_termination(object, evict: false)
    runtime = Runtime.new
    reports = Queue.new
    reporter = lambda do |target, status|
      reports << status if target.dig("metadata", "deletionTimestamp")
    end
    lifecycle = Lifecycle.new(runtime: runtime, reporter: reporter)
    started = lifecycle.start(object)

    assert_equal "Running", started.phase
    lifecycle.probe(object) if object.dig("spec", "containers", 0, "readinessProbe")
    deleting_metadata = object.fetch("metadata").merge("deletionTimestamp" => (Time.now.utc + 10).iso8601, "deletionGracePeriodSeconds" => 10)
    deleting = object.merge("metadata" => deleting_metadata)
    worker = Thread.new do
      if evict
        disruption = {"type" => "DisruptionTarget", "status" => "True", "reason" => "TerminationByKubelet"}
        lifecycle.evict(object, message: "fixture eviction", grace_period_seconds: 10, condition: disruption)
      else
        lifecycle.terminate(deleting)
      end
    end

    refute_nil runtime.stopping.pop(timeout: 4), "runtime did not enter its stop operation"
    yield lifecycle, runtime, deleting, worker, reports
  ensure
    runtime&.release&.push(true)
    worker&.join(4)
  end

  def condition(status, type)
    refute_nil status, "Pod status was not published"
    status.fetch("conditions").find { |entry| entry["type"] == type }
  end

  def pod(container = {})
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "app", "namespace" => "default", "uid" => "pod"},
     "spec" => {"nodeName" => "worker", "terminationGracePeriodSeconds" => 10,
                "containers" => [{"name" => "app", "image" => "fixture/app"}.merge(container)]}}
  end
end
