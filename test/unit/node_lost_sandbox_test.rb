# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# After an agent crash the runtime's recovery may release a Pod's sandbox
# while the kubelet record still says Running.  The relist used to swallow
# the runtime's "unknown container" and leave the dead Pod Running for ever.
# kubelet's PLEG: a container the runtime lost is Terminated with
# ContainerStatusUnknown (137); a lost sandbox kills the Pod, which the
# restart policy then starts again (Always/OnFailure) or ends Failed (Never).
class NodeLostSandboxTest < Minitest::Test
  class Runtime
    attr_reader :sandboxes_created, :removed_sandboxes

    def initialize
      @counter = 0
      @sandboxes_created = 0
      @removed_sandboxes = []
      @lost = false
      @names = {}
    end

    def lose! = @lost = true

    def run_sandbox(_pod, runtime_class: nil)
      @sandboxes_created += 1
      "sandbox-#{@sandboxes_created}"
    end

    def sandbox(id)
      raise "unknown sandbox #{id}" if @lost

      {"id" => id}
    end

    def create_container(_sandbox, spec)
      raise "unknown sandbox" if @lost

      @counter += 1
      @names["c#{@counter}"] = spec["name"]
      "c#{@counter}"
    end

    def start_container(_id) = true

    def container_status(id)
      raise "unknown container #{id}" if @lost

      {"state" => "running"}
    end

    def stop_container(id, timeout:)
      raise "unknown container #{id}" if @lost

      true
    end

    def remove_container(id)
      raise "unknown container #{id}" if @lost

      true
    end

    def remove_sandbox(id)
      @removed_sandboxes << id
      raise "unknown sandbox #{id}" if @lost

      true
    end
  end

  class Reporter
    attr_reader :statuses

    def initialize = @statuses = []
    def report(_pod, status) = @statuses << status.to_h
  end

  def pod(policy)
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "lost", "namespace" => "ns", "uid" => "pod-lost", "generation" => 1},
     "spec" => {"nodeName" => "node-1", "restartPolicy" => policy, "containers" => [{"name" => "main", "image" => "example/busybox"}]}}
  end

  def build(policy)
    runtime = Runtime.new
    reporter = Reporter.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, reporter: reporter, sleeper: ->(_seconds) {})
    lifecycle.reconcile(pod(policy))

    assert_equal "Running", lifecycle.record("pod-lost")[:state]
    [runtime, reporter, lifecycle]
  end

  def container_status(reporter)
    Array(reporter.statuses.last["containerStatuses"]).find { |entry| entry["name"] == "main" }
  end

  def test_a_lost_sandbox_is_reported_unknown_and_an_always_pod_starts_again
    runtime, reporter, lifecycle = build("Always")
    runtime.lose!
    lifecycle.observe_exits("pod-lost")
    status = container_status(reporter)

    assert_equal 137, status.dig("state", "terminated", "exitCode"), status.inspect
    assert_equal "ContainerStatusUnknown", status.dig("state", "terminated", "reason")
    assert_equal "Removed", lifecycle.record("pod-lost")[:state], "the dead Pod's record must not stay Running"
    assert_equal "Running", reporter.statuses.last["phase"], "an Always Pod being restarted stays Running (kubelet getPhase)"

    runtime.instance_variable_set(:@lost, false)
    lifecycle.reconcile(pod("Always"))

    assert_equal 2, runtime.sandboxes_created, "the Pod is started again on the next sync"
    assert_equal "Running", lifecycle.record("pod-lost")[:state]
  end

  def test_a_lost_sandbox_ends_a_never_pod_failed
    runtime, reporter, lifecycle = build("Never")
    runtime.lose!
    lifecycle.observe_exits("pod-lost")

    assert_equal "Failed", reporter.statuses.last["phase"], reporter.statuses.last.inspect
    assert_equal "ContainerStatusUnknown", container_status(reporter).dig("state", "terminated", "reason")
    runtime.instance_variable_set(:@lost, false)
    lifecycle.reconcile(pod("Never"))

    assert_equal 1, runtime.sandboxes_created, "a Never Pod is not started again"
  end

  def test_a_running_pod_whose_runtime_still_knows_it_is_left_alone
    runtime, _reporter, lifecycle = build("Always")

    assert_equal 0, lifecycle.observe_exits("pod-lost")
    assert_equal 1, runtime.sandboxes_created
    assert_equal "Running", lifecycle.record("pod-lost")[:state]
  end
end
