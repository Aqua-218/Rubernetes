# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"

# kube-scheduler picks one of the highest-scoring nodes at random -- reservoir
# sampling in pkg/scheduler/schedule_one.go selectHost.  Choosing the first by
# name instead is invisible while nodes score differently and catastrophic the
# moment they tie, which is the normal case: a BestEffort Pod requests nothing,
# so LeastAllocated scores every node 100.  A conformance run put 23 of 27 Pods
# on worker-0 while worker-1 ran one, and the Pods queued behind each other
# there timed out waiting to start.
class SchedulerTieBreakTest < Minitest::Test
  Scheduler = Rubernetes::Scheduler

  def node(name)
    {"apiVersion" => "v1", "kind" => "Node",
     "metadata" => {"name" => name, "labels" => {"kubernetes.io/hostname" => name}},
     "status" => {"allocatable" => {"cpu" => "4", "memory" => "8Gi", "pods" => "110"},
                  "capacity" => {"cpu" => "4", "memory" => "8Gi", "pods" => "110"},
                  "conditions" => [{"type" => "Ready", "status" => "True"}]},
     "spec" => {}}
  end

  def pod(name)
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "default", "uid" => "#{name}-uid"},
     "spec" => {"containers" => [{"name" => "c", "image" => "busybox"}]},
     "status" => {"phase" => "Pending"}}
  end

  NODES = %w[worker-0 worker-1 worker-2].freeze

  def schedule_many(framework, count)
    placed = Hash.new(0)
    bound = []
    count.times do |index|
      nodes = NODES.map { |name| node(name) }
      result = framework.schedule(pod("p#{index}"), nodes, pods: bound.dup)

      assert_equal(:scheduled, result.status, "pod p#{index} was not scheduled")
      placed[result.node.name] += 1
      scheduled = pod("p#{index}")
      scheduled["spec"]["nodeName"] = result.node.name
      bound << scheduled
    end
    placed
  end

  # Every node ties at the top, so over sixty BestEffort Pods no node may take
  # all of them and every node must get some.
  def test_tied_nodes_share_the_pods
    framework = Scheduler::Framework.new(random: Random.new(20_260_915))

    placed = schedule_many(framework, 60)

    assert_equal(NODES.sort, placed.keys.sort)
    placed.each_value { |count| assert_operator(count, :>, 5, "uneven placement: #{placed.inspect}") }
  end

  # A seeded generator makes the choice reproducible for anyone debugging a
  # placement, which is what the deterministic tie-break was protecting.
  def test_the_choice_is_reproducible_for_a_given_seed
    first = schedule_many(Scheduler::Framework.new(random: Random.new(7)), 12)
    second = schedule_many(Scheduler::Framework.new(random: Random.new(7)), 12)

    assert_equal(first, second)
  end

  # A node that genuinely scores higher still wins outright: only ties are
  # broken at random.
  def test_a_higher_scoring_node_always_wins
    winner = Scheduler::Framework.new(
      random: Random.new(1),
      scores: [->(_pod, node) { node.name == "worker-2" ? 100 : 0 }]
    )

    20.times do |index|
      result = winner.schedule(pod("q#{index}"), NODES.map { |name| node(name) }, pods: [])

      assert_equal("worker-2", result.node.name)
    end
  end
end
