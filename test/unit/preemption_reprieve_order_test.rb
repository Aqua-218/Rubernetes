# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"

# default_preemption.go selectVictimsOnNode removes every lower-priority Pod
# and then reprieves them from the most important down, evicting only the
# ones it could not keep.  Searching for the SMALLEST victim set instead
# evicted one important Pod rather than two unimportant ones.
# "[sig-scheduling] SchedulerPreemption PreemptionExecutionPath runs
# ReplicaSets to verify preemption running path" fills a node's 1000
# example.com/fakecpu with 200 (p1), 300 (p2) and 450 (p3) and brings a 500
# (p4) preemptor; upstream evicts p1 and p2 and leaves p3 alone.
class PreemptionReprieveOrderTest < Minitest::Test
  Scheduler = Rubernetes::Scheduler
  RESOURCE = "example.com/fakecpu"

  def pod(name, priority, amount, node_name: nil)
    spec = {"priority" => priority,
            "containers" => [{"name" => "c", "resources" => {"requests" => {RESOURCE => amount}}}]}
    spec["nodeName"] = node_name if node_name
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"}, "spec" => spec}
  end

  def node
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "worker-0"},
     "status" => {"allocatable" => {"cpu" => "8", "memory" => "8Gi", "pods" => "110", RESOURCE => "1k"},
                  "conditions" => [{"type" => "Ready", "status" => "True"}]}}
  end

  def test_the_least_important_pods_are_evicted_not_the_fewest
    running = [pod("rs-pod1", 1, "200", node_name: "worker-0"),
               pod("rs-pod2", 2, "300", node_name: "worker-0"),
               pod("rs-pod3", 3, "450", node_name: "worker-0")]
    deleted = []
    scheduler = Scheduler.new(delete_pod: ->(victim) { deleted << victim.name })

    scheduler.schedule(pod("pod4", 4, "500"), [node], pods: running)
    assert scheduler.wait_for_preemptions

    assert_equal %w[rs-pod1 rs-pod2], deleted.sort
  end

  def test_a_node_where_even_every_victim_would_not_make_room_is_not_used
    running = [pod("small", 1, "100", node_name: "worker-0")]
    deleted = []
    scheduler = Scheduler.new(delete_pod: ->(victim) { deleted << victim.name })

    scheduler.schedule(pod("huge", 4, "2k"), [node], pods: running)
    assert scheduler.wait_for_preemptions

    assert_empty deleted
  end
end
