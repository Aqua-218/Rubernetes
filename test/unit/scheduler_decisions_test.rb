# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"
require "rubernetes/extension"
require "rubernetes/extension/scheduler_plugins"

# `rubectl why`: the scheduler can say, for a Pod it placed or could not
# place, which plugin turned each node away and how the others were scored.
class SchedulerDecisionsTest < Minitest::Test
  Scheduler = Rubernetes::Scheduler

  def node(name, labels = {})
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "labels" => labels.merge("kubernetes.io/hostname" => name)},
     "status" => {"allocatable" => {"cpu" => "4", "memory" => "8Gi", "pods" => "110"},
                  "capacity" => {"cpu" => "4", "memory" => "8Gi", "pods" => "110"},
                  "conditions" => [{"type" => "Ready", "status" => "True"}]},
     "spec" => {}}
  end

  def pod(name, spec = {})
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "shop", "uid" => "#{name}-uid", "labels" => {}},
     "spec" => {"containers" => [{"name" => "c", "image" => "busybox"}]}.merge(spec), "status" => {"phase" => "Pending"}}
  end

  def setup
    @framework = Scheduler::Framework.new(random: Random.new(1))
    extension = Rubernetes::Extension::Definition.compile("rules", <<~RUBY)
      filter("NoInteractive") { |_pod, node| node.labels["workload"] == "interactive" ? "node is reserved for interactive workloads" : true }
      score("PreferSsd", weight: 4) { |_pod, node| node.labels["disk"] == "ssd" ? 100 : 0 }
    RUBY
    @framework.extension_plugins = Rubernetes::Extension::SchedulerPlugins.registry([extension])
    @nodes = [node("worker-0", "workload" => "interactive"), node("worker-1", "disk" => "ssd"), node("worker-2")]
    @decisions = Scheduler::Decisions.new(clock: -> { Time.utc(2026, 11, 11, 15, 0, 0) })
  end

  def decide(pod, nodes = @nodes)
    @decisions.record(@framework.schedule(pod, nodes, pods: []), 0.0012)
  end

  def test_a_placed_pod_is_explained_node_by_node
    decide(pod("web"))
    lines = @decisions.explain("shop/web").lines.map(&:chomp)

    assert_equal "shop/web: scheduled on worker-1  (attempt 1, 1.2 ms, 2026-11-11T15:00:00.000Z)", lines.fetch(0)
    assert_match(/\A  worker-1 +\d+  .*rules\.PreferSsd 100x4/, lines.fetch(1), "the chosen node leads, with every plugin that scored it")
    assert_match(/\A  worker-2 +\d+  /, lines.fetch(2))
    refute_match(/PreferSsd/, lines.fetch(2), "a plugin that gave nothing is left out")
    assert_equal "  worker-0      -  rules.NoInteractive: node is reserved for interactive workloads", lines.fetch(3)
    assert_equal 4, lines.length, "a node that passed every filter is not also listed as ruled out"
  end

  def test_a_pod_no_node_takes_names_the_plugin_that_refused_each_node
    decide(pod("pinned", "nodeSelector" => {"kubernetes.io/hostname" => "worker-0"}))
    explanation = @decisions.explain("shop/pinned")

    assert_match(%r{\Ashop/pinned: unschedulable }, explanation)
    assert_includes explanation, "worker-0      -  rules.NoInteractive: node is reserved for interactive workloads"
    assert_includes explanation, "worker-1      -  NodeAffinity: node does not match nodeSelector"
  end

  def test_only_the_last_attempt_is_kept_and_the_attempts_are_counted
    3.times { decide(pod("pinned", "nodeSelector" => {"kubernetes.io/hostname" => "worker-0"})) }

    assert_equal 3, @decisions["shop/pinned"].fetch("attempts")
    assert_equal %w[shop/pinned], @decisions.keys
  end

  def test_the_oldest_decisions_make_room
    decisions = Scheduler::Decisions.new(limit: 2)
    %w[a b c].each { |name| decisions.record(@framework.schedule(pod(name), @nodes, pods: []), 0.001) }

    assert_equal %w[shop/b shop/c], decisions.keys
    assert_match(%r{no scheduling decision is remembered for shop/a}, decisions.explain("shop/a"))
  end
end
