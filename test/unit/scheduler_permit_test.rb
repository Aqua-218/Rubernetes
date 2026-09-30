# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"

# The Permit extension point: allow, reject, wait-then-allow, wait timeout,
# and scheduler_permit_wait_duration_seconds.
class SchedulerPermitTest < Minitest::Test
  Scheduler = Rubernetes::Scheduler

  def pod(name)
    Scheduler::Pod.new({"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"},
                        "spec" => {"containers" => [{"name" => "c", "image" => "nginx", "resources" => {"requests" => {"cpu" => "1"}}}]}})
  end

  def node(name)
    Scheduler::Node.new({"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "labels" => {}}, "spec" => {},
                         "status" => {"allocatable" => {"cpu" => "4", "memory" => "4Gi"}, "conditions" => [{"type" => "Ready", "status" => "True"}]}})
  end

  def framework(metrics, &permit)
    registry = Scheduler::PluginRegistry.new
    registry.register(Scheduler::Plugin.new(name: "Gate", phase: :permit, block: permit))
    Scheduler::Framework.new(plugins: registry, bind: ->(_pod, _node) { true }, metrics: metrics, opportunistic_batching: false)
  end

  def value(text, name, **labels)
    found = text.lines.map(&:chomp).find { |entry| entry.start_with?(name) && labels.all? { |k, v| entry.include?("#{k}=\"#{v}\"") } }
    found && Float(found.split.last)
  end

  def test_allow_and_reject
    metrics = Scheduler::Metrics.new

    assert_predicate framework(metrics) { |_pod, _node| true }.schedule(pod("a"), [node("n")]), :scheduled?
    result = framework(metrics) { |_pod, _node| false }.schedule(pod("b"), [node("n")])

    refute_predicate result, :scheduled?
    assert_kind_of Scheduler::PermitError, result.error
    text = metrics.render

    assert_in_delta(1.0,
                    value(text, "scheduler_framework_extension_point_duration_seconds_count", extension_point: "Permit", status: "Success"))
    assert_in_delta(1.0, value(text, "scheduler_framework_extension_point_duration_seconds_count", extension_point: "Permit",
                                                                                                   status: "Unschedulable"))
  end

  def test_a_waiting_pod_is_scheduled_once_allowed
    metrics = Scheduler::Metrics.new
    fw = framework(metrics) { |_pod, _node| Scheduler::Permit::Wait.new(5) }
    allower = Thread.new do
      sleep 0.05 until (waiting = fw.waiting_pod("uid-c"))
      waiting.allow("Gate")
    end
    result = fw.schedule(pod("c"), [node("n")])
    allower.join

    assert_predicate result, :scheduled?
    assert_empty fw.waiting_pods
    text = metrics.render

    assert_in_delta(1.0, value(text, "scheduler_permit_wait_duration_seconds_count", result: "Success"))
  end

  def test_a_waiting_pod_times_out_or_is_rejected
    metrics = Scheduler::Metrics.new
    fw = framework(metrics) { |_pod, _node| Scheduler::Permit::Wait.new(0.2) }
    result = fw.schedule(pod("d"), [node("n")])

    refute_predicate result, :scheduled?
    assert_match(/timeout after waiting/, result.error.message)
    rejecter = Thread.new do
      sleep 0.05 until (waiting = fw.waiting_pod("default/e"))
      waiting.reject("Gate", "quota exceeded")
    end
    fw2 = framework(metrics) { |_pod, _node| Scheduler::Permit::Wait.new(5) }
    rejecter2 = Thread.new do
      sleep 0.05 until (waiting = fw2.waiting_pod("default/e"))
      waiting.reject("Gate", "quota exceeded")
    end
    rejecter.kill
    result = fw2.schedule(pod("e"), [node("n")])
    rejecter2.join

    assert_match(/quota exceeded/, result.error.message)
    text = metrics.render

    assert_in_delta(2.0, value(text, "scheduler_permit_wait_duration_seconds_count", result: "Unschedulable"))
  end
end
