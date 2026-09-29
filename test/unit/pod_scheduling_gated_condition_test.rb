# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/scheduler"

# pkg/registry/core/pod/strategy.go applySchedulingGatedCondition: a Pod
# created with scheduling gates carries PodScheduled=False/SchedulingGated.
# A PreEnqueue rejection (gates, or DynamicResources waiting for a claim)
# never enters a scheduling cycle, so the scheduler reports nothing for it.
class PodSchedulingGatedConditionTest < Minitest::Test
  def server
    server = Rubernetes::API::Server.new(registry: Rubernetes::API::Registry.new,
                                         store: Rubernetes::API::MemoryStore.new, namespace_lifecycle: true)
    server.call(method: "POST", path: "/api/v1/namespaces", body: {"metadata" => {"name" => "dev"}}, headers: {})
    server
  end

  def create(server, spec)
    body = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p#{spec.hash.abs % 1000}"},
            "spec" => {"containers" => [{"name" => "c", "image" => "busybox"}]}.merge(spec)}
    server.call(method: "POST", path: "/api/v1/namespaces/dev/pods", body: body, headers: {}).body
  end

  def test_a_gated_pod_is_created_with_the_scheduling_gated_condition
    created = create(server, "schedulingGates" => [{"name" => "example.com/wait"}])
    condition = Array(created.dig("status", "conditions")).find { |entry| entry["type"] == "PodScheduled" }
    assert_equal "False", condition["status"]
    assert_equal "SchedulingGated", condition["reason"]
    assert_equal "Scheduling is blocked due to non-empty scheduling gates", condition["message"]
  end

  def test_an_ungated_pod_has_no_condition
    created = create(server, {})
    assert_nil created.dig("status", "conditions")
  end

  def test_a_pre_enqueue_rejection_is_a_gated_result
    framework = Rubernetes::Scheduler::Framework.new
    pod = {"metadata" => {"name" => "g", "namespace" => "dev", "uid" => "u"},
           "spec" => {"schedulingGates" => [{"name" => "x"}], "containers" => [{"name" => "c", "image" => "i"}]}}
    node = {"metadata" => {"name" => "n"}, "status" => {"allocatable" => {"cpu" => "4", "memory" => "8Gi", "pods" => "110"},
                                                         "conditions" => [{"type" => "Ready", "status" => "True"}]}}
    result = framework.schedule(pod, [node])
    assert result.unschedulable?
    assert result.gated?
  end
end
