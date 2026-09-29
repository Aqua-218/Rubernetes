# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# A NoExecute taint without timeAdded (kubectl taint sets none) started every
# Pod's toleration clock at the Node's Ready transition, long in the past.
# Every tolerationSeconds had therefore already elapsed, and a Pod tolerating
# the taint for 25 s was evicted together with one tolerating it for 5 s.
# Upstream's taint manager counts from when it observed the taint, and fires
# each eviction from a timer at its deadline.  Ours set no requeue, so an
# eviction that fell due waited for whatever touched the Node next.
class TaintEvictionTolerationClockTest < Minitest::Test
  Controller = Rubernetes::Controller
  TAINT_KEY = "kubernetes.io/e2e-evict-taint-key"

  def node(taint_time: nil)
    taint = {"key" => TAINT_KEY, "value" => "evictTaintVal", "effect" => "NoExecute"}
    taint["timeAdded"] = taint_time if taint_time
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "worker-2"},
     "spec" => {"taints" => [taint]},
     "status" => {"conditions" => [{"type" => "Ready", "status" => "True",
                                    "lastTransitionTime" => "2026-01-01T00:00:00Z"}]}}
  end

  def pod(name, seconds)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "ns", "uid" => name},
     "spec" => {"nodeName" => "worker-2", "containers" => [{"name" => "c", "image" => "i"}],
                "tolerations" => [{"key" => TAINT_KEY, "value" => "evictTaintVal", "effect" => "NoExecute",
                                   "tolerationSeconds" => seconds}]},
     "status" => {"phase" => "Running"}}
  end

  def plan_at(controller, time, taint_time: nil)
    controller.plan(node(taint_time: taint_time), pods: [pod("t1", 5), pod("t2", 25)], now: time)
  end

  def evicted(result)
    result.operations.select { |op| op.action == :delete }.map { |op| Rubernetes::Controller::Support.name(op.object) }
  end

  def test_the_clock_starts_when_the_taint_is_first_seen_not_at_the_ready_transition
    controller = Controller::TaintEvictionController.new
    start = Time.utc(2026, 9, 18, 12, 0, 0)

    assert_empty evicted(plan_at(controller, start)), "nothing is evicted the moment the taint appears"
    assert_equal %w[t1], evicted(plan_at(controller, start + 6))
    assert_equal %w[t1 t2], evicted(plan_at(controller, start + 26)).sort
  end

  def test_the_next_eviction_is_scheduled_for_its_deadline
    controller = Controller::TaintEvictionController.new
    start = Time.utc(2026, 9, 18, 12, 0, 0)

    result = plan_at(controller, start)

    assert_in_delta 5.0, result.requeue_after, 0.01
  end

  def test_a_taint_that_carries_its_own_time_is_honoured
    controller = Controller::TaintEvictionController.new
    added = Time.utc(2026, 9, 18, 12, 0, 0)

    assert_equal %w[t1], evicted(plan_at(controller, added + 10, taint_time: added.iso8601))
  end

  def test_a_taint_that_goes_away_and_comes_back_starts_afresh
    controller = Controller::TaintEvictionController.new
    start = Time.utc(2026, 9, 18, 12, 0, 0)
    plan_at(controller, start)
    untainted = node
    untainted["spec"]["taints"] = []
    controller.plan(untainted, pods: [], now: start + 100)

    assert_empty evicted(plan_at(controller, start + 101))
  end
end
