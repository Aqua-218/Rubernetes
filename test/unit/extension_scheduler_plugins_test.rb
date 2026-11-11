# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/extension"
require "rubernetes/extension/scheduler_plugins"

# A filter or score block from an Extension object takes part in scheduling
# the next Pod, beside the built-in plugins, and leaves again when the object
# does -- without the scheduler restarting.
class ExtensionSchedulerPluginsTest < Minitest::Test
  E = Rubernetes::Extension
  Scheduler = Rubernetes::Scheduler

  def node(name, labels = {})
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "labels" => labels.merge("kubernetes.io/hostname" => name)},
     "status" => {"allocatable" => {"cpu" => "4", "memory" => "8Gi", "pods" => "110"},
                  "capacity" => {"cpu" => "4", "memory" => "8Gi", "pods" => "110"},
                  "conditions" => [{"type" => "Ready", "status" => "True"}]},
     "spec" => {}}
  end

  def pod(name, labels = {})
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "default", "uid" => "#{name}-uid", "labels" => labels},
     "spec" => {"containers" => [{"name" => "c", "image" => "busybox"}]}, "status" => {"phase" => "Pending"}}
  end

  def nodes
    [node("worker-0", "workload" => "interactive"), node("worker-1", "disk" => "ssd"), node("worker-2")]
  end

  def load_extensions(framework, *sources, on_failure: nil)
    extensions = sources.each_with_index.map { |source, index| E::Definition.compile("ext#{index}", source) }
    framework.extension_plugins = E::SchedulerPlugins.registry(extensions, on_failure: on_failure)
  end

  def setup
    @framework = Scheduler::Framework.new(random: Random.new(1))
  end

  def test_a_filter_rules_nodes_out_with_its_own_reason
    load_extensions(@framework, <<~RUBY)
      filter "KeepBatchOffInteractive" do |pod, node|
        pod.labels["tier"] == "batch" && node.labels["workload"] == "interactive" ? "node is reserved for interactive workloads" : true
      end
    RUBY

    20.times do |index|
      refute_equal "worker-0", @framework.schedule(pod("batch-#{index}", "tier" => "batch"), nodes, pods: []).node.name
    end
    result = @framework.schedule(pod("alone", "tier" => "batch"), [nodes.first], pods: [])

    assert_predicate result, :unschedulable?
    assert_equal "node is reserved for interactive workloads", result.filtered.fetch("worker-0").fetch("reason")
    assert_equal "ext0.KeepBatchOffInteractive", result.filtered.fetch("worker-0").fetch("plugin")
  end

  def test_a_score_moves_pods_towards_the_nodes_it_prefers
    load_extensions(@framework, 'score("PreferSsd", weight: 50) { |_pod, node| node.labels["disk"] == "ssd" ? 100 : 0 }')

    10.times { |index| assert_equal "worker-1", @framework.schedule(pod("p#{index}"), nodes, pods: []).node.name }
  end

  def test_an_empty_set_leaves_exactly_the_built_in_plugins
    built_in = @framework.plugins.map(&:name)
    load_extensions(@framework, 'filter("Nowhere") { "no" }')

    assert_predicate @framework.schedule(pod("stuck"), nodes, pods: []), :unschedulable?

    load_extensions(@framework)

    assert_equal built_in, @framework.plugins.map(&:name)
    assert_predicate @framework.schedule(pod("free"), nodes, pods: []), :scheduled?
  end

  # Two extensions may pick the same plugin name, and none can shadow a
  # built-in plugin by naming itself after it.
  def test_plugin_names_are_qualified_by_their_extension
    load_extensions(@framework, 'filter("NodeName") { true }', 'filter("NodeName") { true }')
    names = @framework.plugins.map(&:name)

    assert_includes names, "NodeName"
    assert_includes names, "ext0.NodeName"
    assert_includes names, "ext1.NodeName"
  end

  def test_a_block_that_raises_fails_the_attempt_and_is_reported
    failures = []
    load_extensions(@framework, 'filter("Broken") { |pod, _node| pod.no_such_method }',
                    on_failure: ->(extension, hook, error) { failures << [extension, hook, error.class] })

    assert_raises(Scheduler::PluginError) { @framework.schedule(pod("p"), nodes, pods: []) }
    assert_equal ["ext0", "filter:Broken", NoMethodError], failures.first
  end

  def test_a_block_that_hangs_is_cut_off
    failures = []
    block = E::SchedulerPlugins.guarded(->(_pod, _node) { sleep }, "ext", "filter:Hang", ->(*failure) { failures << failure },
                                        timeout: 0.05)

    assert_raises(Timeout::Error) { block.call(nil, nil) }
    assert_equal %w[ext filter:Hang], failures.first.first(2)
  end
end
