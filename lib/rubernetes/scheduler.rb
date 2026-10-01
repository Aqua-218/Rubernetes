# frozen_string_literal: true

# Public scheduler entry point.  The framework is intentionally independent of
# the API server: adapters can supply Hashes, generated schema ValueObjects, or
# callbacks for durable reservation and bind effects.
module Rubernetes
  module Scheduler
    class Error < StandardError
      attr_reader :plugin, :phase, :cause_error, :cleanup_error, :rollback_error, :restore_error

      def initialize(message = nil, plugin: nil, phase: nil, cause_error: nil)
        @plugin = plugin&.to_s&.freeze
        @phase = phase&.to_sym
        @cause_error = cause_error
        super(message)
      end
    end

    class ValidationError < Error; end

    class PluginError < Error; end

    class FilterError < PluginError; end

    class ScoreError < PluginError; end

    class ReservationError < Error; end

    class BindError < Error; end

    class PreemptionError < Error; end

    class Unschedulable < Error; end
  end
end

require_relative "scheduler/support"
require_relative "scheduler/types"
require_relative "scheduler/plugins"
require_relative "scheduler/filters"
require_relative "scheduler/scores"
require_relative "scheduler/queue"
require_relative "scheduler/preemption"
require_relative "scheduler/dynamic_resources"
require_relative "scheduler/volume_binding"
require_relative "scheduler/framework"

module Rubernetes
  module Scheduler
    class << self
      # Build a framework directly, or evaluate the compact scheduler DSL.
      def new(**options, &block)
        if block
          registry = options.delete(:plugins)
          registry = if registry.is_a?(PluginRegistry)
                       registry
                     elsif registry.respond_to?(:registry)
                       registry.registry
                     else
                       PluginRegistry.new
                     end
          DSL.new(registry).instance_eval(&block)
          options[:plugins] = registry
        end
        Framework.new(**options)
      end

      alias build new
      alias configure new

      def scheduler(**, &)
        new(**, &)
      end

      def default_registry
        Framework.default_registry
      end
    end

    STANDARD_FILTERS = {
      scheduling_gates: Filters::SchedulingGates,
      node_unschedulable: Filters::NodeUnschedulable,
      resources_fit: Filters::NodeResourcesFit,
      node_name: Filters::NodeName,
      node_ports: Filters::NodePorts,
      node_selector: Filters::NodeSelector,
      node_affinity: Filters::NodeAffinity,
      taint_toleration: Filters::TaintToleration,
      volume_restrictions: Filters::VolumeRestrictions,
      node_volume_limits: Filters::NodeVolumeLimits,
      volume_binding: Filters::VolumeBinding,
      volume_zone: Filters::VolumeZone,
      pod_topology_spread: Filters::PodTopologySpread,
      inter_pod_affinity: Filters::InterPodAffinity,
      node_declared_features: Filters::NodeDeclaredFeatures,
      pod_affinity: Filters::PodAffinity,
      pod_anti_affinity: Filters::PodAntiAffinity,
      ready: Filters::Ready
    }.freeze
    STANDARD_SCORES = {
      taint_toleration: Scores::TaintToleration,
      node_affinity: Scores::NodeAffinity,
      resources_fit: Scores::LeastAllocated,
      node_resources_balanced_allocation: Scores::NodeResourcesBalancedAllocation,
      least_allocated: Scores::LeastAllocated,
      topology_spread: Scores::TopologySpread,
      inter_pod_affinity: Scores::InterPodAffinity,
      image_locality: Scores::ImageLocality
    }.freeze

    # Flat aliases keep the public API pleasant for adapters that register one
    # standard plugin at a time while the grouped namespaces remain available
    # for discovery and documentation.
    NodeResourcesFit = Filters::NodeResourcesFit unless const_defined?(:NodeResourcesFit, false)
    SchedulingGates = Filters::SchedulingGates unless const_defined?(:SchedulingGates, false)
    NodePorts = Filters::NodePorts unless const_defined?(:NodePorts, false)
    NodeUnschedulable = Filters::NodeUnschedulable unless const_defined?(:NodeUnschedulable, false)
    NodeName = Filters::NodeName unless const_defined?(:NodeName, false)
    NodeSelector = Filters::NodeSelector unless const_defined?(:NodeSelector, false)
    NodeAffinity = Filters::NodeAffinity unless const_defined?(:NodeAffinity, false)
    TaintToleration = Filters::TaintToleration unless const_defined?(:TaintToleration, false)
    PodAffinity = Filters::PodAffinity unless const_defined?(:PodAffinity, false)
    PodAntiAffinity = Filters::PodAntiAffinity unless const_defined?(:PodAntiAffinity, false)
    InterPodAffinity = Filters::InterPodAffinity unless const_defined?(:InterPodAffinity, false)
    Ready = Filters::Ready unless const_defined?(:Ready, false)
    VolumeRestrictions = Filters::VolumeRestrictions unless const_defined?(:VolumeRestrictions, false)
    NodeVolumeLimits = Filters::NodeVolumeLimits unless const_defined?(:NodeVolumeLimits, false)
    VolumeBinding = Filters::VolumeBinding unless const_defined?(:VolumeBinding, false)
    VolumeZone = Filters::VolumeZone unless const_defined?(:VolumeZone, false)
    PodTopologySpreadFilter = Filters::PodTopologySpread unless const_defined?(:PodTopologySpreadFilter, false)
    DefaultPreemption = Preemption::Evaluator unless const_defined?(:DefaultPreemption, false)
    ImageLocality = Scores::ImageLocality unless const_defined?(:ImageLocality, false)
    DefaultBinder = Scheduler::DefaultBinder unless const_defined?(:DefaultBinder, false)
    NodeResourcesBalancedAllocation = Scores::NodeResourcesBalancedAllocation unless const_defined?(:NodeResourcesBalancedAllocation, false)
    LeastAllocated = Scores::LeastAllocated unless const_defined?(:LeastAllocated, false)
    TopologySpread = Scores::TopologySpread unless const_defined?(:TopologySpread, false)
    FilterPlugin = Plugin unless const_defined?(:FilterPlugin, false)
    ScorePlugin = Plugin unless const_defined?(:ScorePlugin, false)
    FilterRejection = Rejection unless const_defined?(:FilterRejection, false)
  end

  # A small top-level convenience mirrors the DSL example in the normative
  # document while preserving the namespaced API for embedders.
  def self.scheduler(**, &)
    Scheduler.new(**, &)
  end
end
