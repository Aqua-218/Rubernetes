# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/scheduler"

class M3ContractRepairTest < Minitest::Test
  Controller = Rubernetes::Controller
  Scheduler = Rubernetes::Scheduler

  def test_controller_definition_validation_rejects_invalid_local_wiring
    kind = Controller::ResourceDescriptor.parse("ConfigMap")
    pod = Controller::ResourceDescriptor.parse("Pod")
    definition = Controller::ControllerDefinition.new(
      name: "invalid-controller",
      kind: kind,
      owns: [Controller::OwnershipEdge.new(owner: pod, dependent: kind)],
      watches: [Controller::WatchSpec.new(resource: pod, via: :unsupported)],
      reconcile_block: ->(_resource) {}
    )

    error = assert_raises(Controller::ValidationError) { definition.validate! }
    assert_match "ownership", error.message
  end

  def test_registry_validation_rejects_a_placeholder_implementation
    entry = Controller::BuiltinControllerCorpus.fetch("deployment-controller")
    kind = Controller::ResourceDescriptor.parse(entry.kind)
    definition = Controller::ControllerDefinition.new(
      name: entry.name,
      kind: kind,
      reconcile_block: ->(_resource) {},
      startup_conditions: entry.startup_conditions,
      feature_gates: entry.feature_gates,
      sync_targets: entry.sync_targets,
      status_fields: entry.status_fields,
      events: entry.events,
      implementation: Class.new
    )

    assert_predicate definition, :implemented?
    assert_raises(Controller::ValidationError) do
      definition.validate!(corpus_entry: entry)
    end
    assert_raises(Controller::ValidationError) do
      Controller::ControllerRegistry.new.register(definition)
    end
  end

  def test_default_controller_registry_exposes_only_concrete_implementations
    registry = Controller.default_registry
    expected = Controller::BUILTIN_IMPLEMENTATIONS.keys.sort

    assert_equal expected, registry.names
    assert_equal Controller::UNIMPLEMENTED_BUILTIN_CONTROLLERS.sort, registry.missing_names.sort
    assert_empty registry.unimplemented_names
    assert_equal 52, registry.registered_complete_count
    assert_empty registry.incomplete_controllers
    assert_same registry, registry.startup_validate!
  end

  def test_scheduler_registry_uses_pinned_names_order_phases_and_weights
    registry = Scheduler::Framework.default_registry
    actual = registry.all.map { |plugin| [plugin.name, plugin.phase, plugin.weight] }
    expected = [
      ["SchedulingGates", :pre_enqueue, 1], ["PrioritySort", :queue_sort, 1],
      ["NodeUnschedulable", :filter, 1], ["NodeName", :filter, 1],
      ["TaintToleration", :filter, 3], ["NodeAffinity", :filter, 2],
      ["NodePorts", :filter, 1], ["NodeResourcesFit", :filter, 1],
      ["VolumeRestrictions", :filter, 1], ["NodeVolumeLimits", :filter, 1],
      ["VolumeBinding", :filter, 1], ["VolumeZone", :filter, 1],
      ["PodTopologySpread", :filter, 2], ["InterPodAffinity", :filter, 2],
      ["DynamicResources", :filter, 2],
      ["DefaultPreemption", :post_filter, 1],
      ["NodeResourcesBalancedAllocation", :score, 1], ["ImageLocality", :score, 1],
      ["DefaultBinder", :bind, 1], ["NodeDeclaredFeatures", :filter, 1]
    ]

    assert_equal expected, actual
    assert_equal Scheduler::Framework::UNIMPLEMENTED_DEFAULT_PLUGIN_NAMES,
                 (Scheduler::Framework::DEFAULT_PLUGIN_NAMES - actual.map(&:first))
    assert_equal actual.map(&:first), registry.all.map(&:name)
  end

  def test_scheduler_default_plugins_execute_without_placeholder_behavior
    pending = pod("pending", requests: {"cpu" => "1"})
    unschedulable = node("blocked", unschedulable: true)
    available = node("available")

    result = Scheduler.new.schedule(pending, [unschedulable, available])

    assert_predicate result, :scheduled?
    assert_equal "available", result.node_name
    assert_equal "node is unschedulable", result.filtered.fetch("blocked").fetch("reason")
    assert(result.trace.events.any? { |event| event["plugin"] == "NodeUnschedulable" })
    assert(result.scores.all? { |score| score.plugins.all? { |plugin| plugin.fetch("weight").is_a?(Integer) } })
  end

  private

  def pod(name, requests: {})
    {
      "apiVersion" => "v1", "kind" => "Pod",
      "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"},
      "spec" => {"containers" => [{"name" => "container", "resources" => {"requests" => requests}}]}
    }
  end

  def node(name, unschedulable: false)
    {
      "apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name},
      "spec" => {"unschedulable" => unschedulable},
      "status" => {"allocatable" => {"cpu" => "2"},
                   "conditions" => [{"type" => "Ready", "status" => "True"}]}
    }
  end
end
