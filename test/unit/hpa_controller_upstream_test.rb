# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/observability/metrics"

# pkg/controller/podautoscaler (v1.36.2): the replica calculator over the
# resource metrics API, the controller's normalization (stabilization,
# scale-rate limits), conditions and events.  The first cases are
# horizontal_test.go's TestScaleUp / TestScaleDown numbers.
class HPAControllerUpstreamTest < Minitest::Test
  Controller = Rubernetes::Controller
  NOW = Time.utc(2026, 9, 23, 12)

  class FakeMetrics
    attr_accessor :levels, :error

    def initialize(levels) = @levels = levels

    def resource_metric(_resource, _namespace, _selector, _container)
      raise Controller::MetricsClient::MetricsError, error if error

      metrics = levels.to_h { |name, milli| [name, Controller::MetricsClient::PodMetric.new(value: milli, timestamp: NOW - 60, window: 30.0)] }
      [metrics, NOW - 60]
    end
  end

  def hpa(min: 2, max: 6, target: 30, behavior: nil)
    spec = {"scaleTargetRef" => {"apiVersion" => "apps/v1", "kind" => "Deployment", "name" => "web"}, "minReplicas" => min, "maxReplicas" => max,
            "metrics" => [{"type" => "Resource", "resource" => {"name" => "cpu", "target" => {"type" => "Utilization", "averageUtilization" => target}}}]}
    spec["behavior"] = behavior if behavior
    {"apiVersion" => "autoscaling/v2", "kind" => "HorizontalPodAutoscaler", "metadata" => {"name" => "web-hpa", "namespace" => "ns", "uid" => "h"},
     "spec" => spec, "status" => {}}
  end

  def deployment(replicas)
    {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"name" => "web", "namespace" => "ns", "uid" => "d"},
     "spec" => {"replicas" => replicas, "selector" => {"matchLabels" => {"app" => "web"}}}, "status" => {"replicas" => replicas}}
  end

  def pods(count, request: "1", phase: "Running", ready: true)
    Array.new(count) do |i|
      {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "web-#{i}", "namespace" => "ns", "labels" => {"app" => "web"}},
       "spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => {"cpu" => request}}}]},
       "status" => {"phase" => phase, "startTime" => (NOW - 3600).iso8601,
                    "conditions" => [{"type" => "Ready", "status" => ready ? "True" : "False", "lastTransitionTime" => (NOW - 3000).iso8601}]}}
    end
  end

  class Scales
    def initialize(target) = @target = target
    def get_scale(descriptor:, **) = Controller::ScaleClient.new.snapshot_for(@target, descriptor: descriptor)
    def build_update(snapshot, replicas) = Controller::ScaleClient.new.build_update(snapshot, replicas)
  end

  def controller(metrics, target, history: nil, clock: -> { NOW })
    subject = Controller::HorizontalPodAutoscalerController.new(metrics_client: metrics, scale_client: Scales.new(target), clock: clock)
    subject.instance_variable_get(:@recommendations)["ns/web-hpa"] = history unless history.nil?
    subject
  end

  def condition(result, type) = result.status["conditions"].find { |entry| entry["type"] == type }.values_at("status", "reason")

  def test_scale_up
    metrics = FakeMetrics.new("web-0" => 300, "web-1" => 500, "web-2" => 700)
    result = controller(metrics, deployment(3)).plan(hpa, pods: pods(3))

    assert_equal 5, result.operations.find { |operation| operation.action == :update }.object.dig("spec", "replicas")
    assert_equal(["SuccessfulRescale"], result.events.map { |event| event["reason"] })
    assert_equal "New size: 5; reason: cpu resource utilization (percentage of request) above target", result.events.first["message"]
    assert_equal %w[True SucceededRescale], condition(result, "AbleToScale")
    assert_equal %w[True ValidMetricFound], condition(result, "ScalingActive")
    assert_equal %w[False DesiredWithinRange], condition(result, "ScalingLimited")
    assert_equal({"type" => "Resource", "resource" => {"name" => "cpu", "current" => {"averageUtilization" => 50, "averageValue" => "500m"}}},
                 result.status["currentMetrics"].first)
    assert_equal [3, 5], result.status.values_at("currentReplicas", "desiredReplicas")
    assert result.status["lastScaleTime"]
  end

  def test_scale_down_and_its_stabilization
    metrics = FakeMetrics.new("web-0" => 100, "web-1" => 300, "web-2" => 500, "web-3" => 250, "web-4" => 250)
    result = controller(metrics, deployment(5), history: []).plan(hpa(target: 50), pods: pods(5))

    assert_equal 3, result.operations.find { |operation| operation.action == :update }.object.dig("spec", "replicas")
    assert_equal "New size: 3; reason: All metrics below target", result.events.first["message"]

    stabilized = controller(metrics, deployment(5)).plan(hpa(target: 50), pods: pods(5))

    assert_empty stabilized.operations.select { |operation|
      operation.action == :update
    }, "the initial recommendation (5) is within the window"
    assert_equal %w[True ScaleDownStabilized], condition(stabilized, "AbleToScale")
  end

  def test_missing_metrics_leave_the_scale_alone
    metrics = FakeMetrics.new({})
    metrics.error = "no metrics returned from resource metrics API"
    result = controller(metrics, deployment(3)).plan(hpa, pods: pods(3))

    assert_empty(result.operations.select { |operation| operation.action == :update })
    assert_equal(%w[FailedGetResourceMetric FailedComputeMetricsReplicas], result.events.map { |event| event["reason"] })
    assert_equal %w[False FailedGetResourceMetric], condition(result, "ScalingActive")
    message = result.status["conditions"].find { |entry| entry["type"] == "ScalingActive" }["message"]

    assert_equal "the HPA was unable to compute the replica count: failed to get cpu utilization: unable to get metrics for resource cpu: " \
                 "no metrics returned from resource metrics API", message
  end

  def test_zero_replicas_disable_scaling_and_bounds_are_enforced
    result = controller(FakeMetrics.new({}), deployment(0)).plan(hpa, pods: [])

    assert_equal %w[False ScalingDisabled], condition(result, "ScalingActive")
    assert_empty(result.operations.select { |operation| operation.action == :update })

    above = controller(FakeMetrics.new({}), deployment(9)).plan(hpa, pods: pods(9))

    assert_equal 6, above.operations.find { |operation| operation.action == :update }.object.dig("spec", "replicas")
    assert_equal "New size: 6; reason: Current number of replicas above Spec.MaxReplicas", above.events.first["message"]
  end

  def test_unready_pods_count_as_zero_when_scaling_up
    metrics = FakeMetrics.new("web-0" => 1000, "web-1" => 1000, "web-2" => 1000)
    all = pods(3)
    all[2]["status"]["conditions"][0]["status"] = "False"
    all[2]["status"]["conditions"][0]["lastTransitionTime"] = (NOW - 3599).iso8601
    result = controller(metrics, deployment(3)).plan(hpa(target: 50, max: 10), pods: all)
    # Two ready pods at 100% of request vs a 50% target (ratio 2.0); the
    # unready one counts as 0 -> 2000m / 3000m = 66% -> ceil(1.33 * 3) = 4.
    assert_equal 4, result.operations.find { |operation| operation.action == :update }.object.dig("spec", "replicas")
  end

  def test_behavior_rate_limits_a_scale_up
    behavior = {"scaleUp" => {"stabilizationWindowSeconds" => 0, "selectPolicy" => "Max",
                              "policies" => [{"type" => "Pods", "value" => 4, "periodSeconds" => 15},
                                             {"type" => "Percent", "value" => 100, "periodSeconds" => 15}]},
                "scaleDown" => {"selectPolicy" => "Max", "policies" => [{"type" => "Percent", "value" => 100, "periodSeconds" => 15}]}}
    metrics = FakeMetrics.new("web-0" => 10_000)
    result = controller(metrics, deployment(1), history: []).plan(hpa(min: 1, max: 20, target: 50, behavior: behavior), pods: pods(1))

    assert_equal 5, result.operations.find { |operation| operation.action == :update }.object.dig("spec", "replicas"), "max(1+4, 1*2)"
    assert_equal %w[True ScaleUpLimit], condition(result, "ScalingLimited")
  end

  def test_a_missing_request_is_an_error
    no_request = pods(1)
    no_request[0]["spec"]["containers"][0]["resources"] = {}
    result = controller(FakeMetrics.new("web-0" => 100), deployment(1)).plan(hpa(min: 1), pods: no_request)

    assert_includes result.status["conditions"].find { |entry| entry["type"] == "ScalingActive" }["message"],
                    "missing request for cpu in container c of Pod web-0"
  end

  # podautoscaler/monitor: reconciliations, metric computations, desired
  # replicas and the number of HPAs.
  def test_monitor_metrics
    registry = Rubernetes::Observability::Metrics.new(apiserver: false, process: false, component: "kube-controller-manager")
    Controller.metrics = registry
    Controller::HorizontalPodAutoscalerController::HPA_KEYS.clear
    metrics = FakeMetrics.new("web-0" => 300, "web-1" => 500, "web-2" => 700)
    subject = controller(metrics, deployment(3))
    subject.plan(hpa, pods: pods(3))
    metrics.error = "no metrics"
    subject.plan(hpa, pods: pods(3))
    text = registry.render

    assert_includes text, %(horizontal_pod_autoscaler_controller_reconciliations_total{action="scale_up",error="none"} 1)
    assert_includes text, %(horizontal_pod_autoscaler_controller_reconciliations_total{action="none",error="internal"} 1)
    assert_includes text,
                    %(horizontal_pod_autoscaler_controller_metric_computation_total{action="scale_up",error="none",metric_type="Resource"} 1)
    assert_includes text,
                    %(horizontal_pod_autoscaler_controller_metric_computation_total{action="none",error="internal",metric_type="Resource"} 1)
    assert_includes text, %(horizontal_pod_autoscaler_controller_desired_replicas{hpa_name="web-hpa",namespace="ns"} 5)
    assert_includes text, "horizontal_pod_autoscaler_controller_num_horizontal_pod_autoscalers 1"
    subject.plan_orphans("ns/web-hpa")

    assert_includes registry.render, "horizontal_pod_autoscaler_controller_num_horizontal_pod_autoscalers 0"
  ensure
    Controller.metrics = nil
  end
end
