# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"

# OpportunisticBatching (framework/runtime/batch.go): the next Pod with the
# same signature takes the previous Pod's next-best node when the previous
# Pod filled the node it chose.  With PodTopologySpread's system default
# constraints configured -- the default -- no Pod can be signed, upstream
# and here.
class SchedulerOpportunisticBatchTest < Minitest::Test
  Scheduler = Rubernetes::Scheduler
  PLUGINS = %w[NodeUnschedulable NodeName TaintToleration NodeAffinity NodePorts NodeResourcesFit
               VolumeRestrictions NodeVolumeLimits VolumeBinding VolumeZone PodTopologySpread
               InterPodAffinity DynamicResources NodeDeclaredFeatures NodeResourcesBalancedAllocation ImageLocality].freeze

  def pod(name, spec = {})
    Scheduler::Pod.new("apiVersion" => "v1", "kind" => "Pod",
                       "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}", "labels" => {"app" => "web"}},
                       "spec" => {"containers" => [{"name" => "c", "image" => "nginx",
                                                    "resources" => {"requests" => {"cpu" => "1"}}}]}.merge(spec))
  end

  def test_default_configuration_signs_nothing
    batch = Scheduler::OpportunisticBatch.new(plugin_names: PLUGINS)
    assert_nil batch.sign(pod("web-1"))
    framework = Scheduler::Framework.new
    assert_nil framework.batch.sign(pod("web-1"))
  end

  def test_pods_that_cannot_be_signed
    batch = Scheduler::OpportunisticBatch.new(plugin_names: PLUGINS, system_default_constraints: false)
    refute_nil batch.sign(pod("plain"))
    assert_nil batch.sign(pod("spread", "topologySpreadConstraints" => [{"maxSkew" => 1}]))
    assert_nil batch.sign(pod("affinity", "affinity" => {"podAntiAffinity" => {"x" => 1}}))
    assert_nil batch.sign(pod("claims", "resourceClaims" => [{"name" => "gpu"}]))
    assert_nil Scheduler::OpportunisticBatch.new(plugin_names: PLUGINS + ["MyDSLFilter"], system_default_constraints: false)
                                            .sign(pod("custom"))
    assert_equal batch.sign(pod("a")), batch.sign(pod("b")), "names and uids are not part of the signature"
    refute_equal batch.sign(pod("a")), batch.sign(pod("big", "containers" => [{"name" => "c", "image" => "nginx",
                                                                               "resources" => {"requests" => {"cpu" => "2"}}}]))
  end

  def test_the_next_node_is_hinted_only_when_the_last_one_is_full
    now = 100.0
    batch = Scheduler::OpportunisticBatch.new(plugin_names: PLUGINS, system_default_constraints: false, clock: -> { now })
    signature = batch.sign(pod("a"))
    batch.store(signature, nil, "n1", %w[n2 n3], 1)

    assert_nil batch.node_hint(signature, 2, fits_last: ->(_name) { true }), "n1 still fits: rescoring is needed"
    batch.store(signature, nil, "n1", %w[n2 n3], 2)
    assert_equal "n2", batch.node_hint(signature, 3, fits_last: ->(_name) { false })
    batch.store(signature, "n2", "n2", nil, 3)
    assert_equal 1, batch.batched_pods
    assert_equal "n3", batch.node_hint(signature, 4, fits_last: ->(_name) { false })

    batch.store(signature, nil, "n1", %w[n2 n3], 10)
    assert_nil batch.node_hint(signature, 12, fits_last: ->(_name) { false }), "a skipped cycle voids the state"
    batch.store(signature, nil, "n1", %w[n2 n3], 20)
    assert_nil batch.node_hint(batch.sign(pod("x", "nodeSelector" => {"a" => "b"})), 21, fits_last: ->(_name) { false })
    batch.store(signature, nil, "n1", %w[n2 n3], 30)
    now += 0.6
    assert_nil batch.node_hint(signature, 31, fits_last: ->(_name) { false }), "state older than 500 ms is dropped"
  end

  # End to end through Framework#schedule: one Pod per node, the second
  # identical Pod goes to the hinted node without scoring every node.
  def test_consecutive_identical_pods_use_the_hint
    framework = Scheduler::Framework.new(bind: ->(_pod, _node) { true })
    framework.instance_variable_set(:@batch, Scheduler::OpportunisticBatch.new(
      plugin_names: framework.batch.instance_variable_get(:@plugin_names), system_default_constraints: false))
    nodes = %w[n1 n2 n3].map do |name|
      {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name},
       "status" => {"allocatable" => {"cpu" => "1", "memory" => "4Gi", "pods" => "10"},
                    "conditions" => [{"type" => "Ready", "status" => "True"}]}}
    end
    first = framework.schedule(pod("web-1"), nodes)
    placed = first.bound_pod.to_h
    second = framework.schedule(pod("web-2"), nodes, pods: [placed])

    assert_predicate second, :scheduled?
    refute_equal first.node_name, second.node_name
    assert_equal 1, framework.batch.batched_pods
    assert_equal 1, second.scores.length, "only the hinted node was scored"
  end
end
