# frozen_string_literal: true

require_relative "../test_helper"
require_relative "node_lifecycle_test"
require "rubernetes/bootstrap/agent_service"

# Startup recovery on a node whose Pods lost their sandbox: the termination
# of such a Pod must finish (its namespace is gone, there is nothing to
# enter) and one Pod whose cleanup is still pending must not keep the whole
# agent down -- kubelet never refuses to start over a single leftover Pod.
class NodeRecoveryPendingPodTest < Minitest::Test
  # The runtime released the sandbox during recovery: a live lookup says so.
  class GoneSandboxRuntime < NodeLifecycleTest::Runtime
    attr_accessor :gone

    def network_sandbox_context(id)
      raise StandardError, "unknown sandbox #{id}" if gone

      {"sandbox_id" => id,
       "netns" => {"handle" => "namespace:#{id}", "path" => "/proc/4242/ns/net", "inode" => 4_026_531_842, "pid" => 4242}}
    end
  end

  def test_a_pod_whose_sandbox_is_gone_finishes_its_network_cleanup
    calls = []
    runtime = GoneSandboxRuntime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, volume: NodeLifecycleTest::Volume.new(calls),
                                                network: NodeLifecycleTest::Network.new(calls))
    object = pod
    lifecycle.start(object)
    runtime.gone = true
    result = lifecycle.terminate(object, reason: "StartupRecovery")

    assert_equal "Removed", result.state, result.inspect
    assert_empty Array(result.cleanup_errors)
    # The stored descriptor (from start) is what the teardown was given, so
    # IPAM and bridge state are still released.
    refute_empty calls.select { |call| Array(call).first == :network_delete }, calls.inspect
  end

  def test_a_pending_pod_cleanup_does_not_keep_the_agent_down
    service = Rubernetes::Bootstrap::AgentService.allocate
    report = {"ready" => true, "errors" => [], "blocked" => ["3229d668-uid"],
              "pod_errors" => {"3229d668-uid" => ["network cleanup failed"]}}

    assert_equal true, service.send(:ensure_recovery_ready!, report)
    error = assert_raises(Rubernetes::Bootstrap::AgentService::Error) do
      service.send(:ensure_recovery_ready!, {"ready" => false, "errors" => ["resource identity mismatch: cgroup:x"], "blocked" => []})
    end
    assert_match(/identity mismatch/, error.message)
  end

  private

  def pod
    NodeLifecycleTest.new("x").send(:pod)
  end
end
