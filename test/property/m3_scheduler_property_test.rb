# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"

# Fixed-seed scheduler properties exercise replay determinism instead of relying
# on wall-clock timing or Ruby's process-randomized hash order.
class M3SchedulerPropertyTest < Minitest::Test
  SEEDS = [0x5EED, 0xC0FFEE, 0x515CED].freeze

  def test_seeded_cycles_have_stable_node_and_trace_results
    SEEDS.each do |seed|
      random = Random.new(seed)
      nodes = 5.times.map do |index|
        {
          "kind" => "Node", "metadata" => {"name" => format("node-%02d", index), "labels" => {"zone" => (index % 2).to_s}},
          "status" => {"allocatable" => {"cpu" => "4", "memory" => "8Gi"},
                       "conditions" => [{"type" => "Ready", "status" => "True"}]}
        }
      end
      existing = 8.times.map do |index|
        {
          "kind" => "Pod", "metadata" => {"name" => "existing-#{index}", "namespace" => "default", "uid" => "existing-#{index}",
                                          "labels" => {"app" => index.even? ? "web" : "worker"}},
          "spec" => {"nodeName" => nodes[index % nodes.length]["metadata"]["name"], "priority" => random.rand(4),
                     "containers" => [{"name" => "container", "resources" => {"requests" => {"cpu" => "250m"}}}]}
        }
      end
      pending = {
        "kind" => "Pod", "metadata" => {"name" => "pending-#{seed}", "namespace" => "default", "uid" => "pending-#{seed}",
                                        "labels" => {"app" => "web"}},
        "spec" => {"priority" => 10, "containers" => [{"name" => "container", "resources" => {"requests" => {"cpu" => "500m"}}}],
                   "topologySpreadConstraints" => [{"maxSkew" => 1, "topologyKey" => "zone", "whenUnsatisfiable" => "ScheduleAnyway",
                                                    "labelSelector" => {"matchLabels" => {"app" => "web"}}}]}
      }

      first_input = Marshal.load(Marshal.dump(pending))
      second_input = Marshal.load(Marshal.dump(pending))
      first = Rubernetes::Scheduler.new.schedule(first_input, nodes, pods: existing)
      second = Rubernetes::Scheduler.new.schedule(second_input, nodes.shuffle(random: random), pods: existing.shuffle(random: random))

      assert_equal first.status, second.status, "seed=#{seed} status diverged"
      assert_equal first.node_name, second.node_name, "seed=#{seed} node tie-break diverged"
      assert_equal first.trace.digest, second.trace.digest, "seed=#{seed} trace digest diverged"
      first.trace.events.each do |event|
        next unless event.fetch("phase") == "score"

        assert_kind_of Integer, event.fetch("output")
        assert_includes 0..100, event.fetch("output")
      end
    end
  end

  def test_seeded_queue_order_is_priority_then_identity
    queue = Rubernetes::Scheduler::SchedulingQueue.new
    %w[z a m].each_with_index do |name, index|
      queue.enqueue({"metadata" => {"name" => name}, "spec" => {"priority" => index % 2, "containers" => []}})
    end

    assert_equal(%w[a m z], 3.times.map { queue.pop.pod.name })
  end
end
