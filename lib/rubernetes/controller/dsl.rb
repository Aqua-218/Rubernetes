# frozen_string_literal: true

require_relative "errors"
require_relative "support"
require_relative "types"

module Rubernetes
  module Controller
    # Ruby declaration builder.  It emits immutable wiring metadata and never
    # executes a reconcile block during validation.
    class DSLBuilder
      attr_reader :definition

      def initialize(name, registry:, kind: nil)
        @registry = registry
        @name = normalize_controller_name(name)
        @kind = registry_descriptor(kind || infer_kind(name))
        @owns = []
        @watches = []
        @reconcile = nil
        @feature_gates = []
        @startup_conditions = []
        @sync_targets = []
        @status_fields = []
        @events = []
      end

      def owns(resource, controller: true, block_owner_deletion: true, scope: nil)
        dependent = registry_descriptor(resource, scope: scope)
        edge = OwnershipEdge.new(owner: @kind, dependent: dependent,
                                 controller: controller, block_owner_deletion: block_owner_deletion)
        raise OwnershipCycleError, "controller #{@name} cannot own itself (#{dependent.identifier})" if dependent == @kind

        @owns << edge
        self
      end

      def watches(resource, via: :owner_reference, predicate: nil, index: nil,
                  index_name: nil, queue_key: nil, scope: nil)
        descriptor = registry_descriptor(resource, scope: scope)
        relationship = via.to_sym
        unless %i[owner_reference label selector all].include?(relationship)
          raise InvalidWatchError, "unsupported watch relationship #{relationship.inspect}"
        end
        if index && !index.is_a?(String) && !index.is_a?(Symbol)
          raise InvalidWatchError, "watch index must be a static name"
        end

        # `index` is the public shorthand used by the DSL specification.  It
        # used to be accepted and then discarded, leaving generated wiring
        # without the requested static index lookup.
        index_name ||= index
        index_name ||= if relationship == :owner_reference
                         "owner/#{@kind.identifier}/#{descriptor.identifier}"
                       elsif relationship == :label
                         "labels/#{@kind.identifier}/#{descriptor.identifier}"
                       end
        predicate ||= default_predicate(relationship)
        queue_key ||= default_queue_key(relationship, descriptor)
        @watches << WatchSpec.new(resource: descriptor, via: relationship,
                                  predicate: predicate, index_name: index_name,
                                  queue_key: queue_key, scope: scope || descriptor.scope)
        self
      end

      def reconcile(&block)
        raise ArgumentError, "reconcile requires a block" unless block
        raise MissingReconcileError, "controller #{@name} has more than one reconcile block" if @reconcile

        @reconcile = block
        self
      end

      def feature_gates(*names)
        @feature_gates.concat(names.flatten.map(&:to_s))
        self
      end

      def startup_conditions(*conditions)
        @startup_conditions.concat(conditions.flatten.map(&:to_s))
        self
      end

      def sync_targets(*targets)
        @sync_targets.concat(targets.flatten.map(&:to_s))
        self
      end

      def status_fields(*fields)
        @status_fields.concat(fields.flatten.map(&:to_s))
        self
      end

      def emits(*events)
        @events.concat(events.flatten.map(&:to_s))
        self
      end

      def build(implementation: nil)
        raise MissingReconcileError, "controller #{@name} must declare reconcile" unless @reconcile
        definition = ControllerDefinition.new(
          name: @name,
          kind: @kind,
          owns: @owns,
          watches: @watches,
          reconcile_block: @reconcile,
          feature_gates: @feature_gates,
          startup_conditions: @startup_conditions,
          sync_targets: @sync_targets,
          status_fields: @status_fields,
          events: @events,
          implementation: implementation
        )
        @registry.register(definition)
        definition
      end

      private

      def registry_descriptor(value, scope: nil)
        descriptor = ResourceDescriptor.parse(value)
        if scope && scope.to_sym != descriptor.scope
          raise ScopeMismatchError, "scope #{scope.inspect} conflicts with #{descriptor.identifier} (#{descriptor.scope})"
        end
        @registry.validate_descriptor!(descriptor)
        descriptor
      end

      def infer_kind(name)
        text = name.respond_to?(:name) && !name.is_a?(String) ? name.name.to_s : name.to_s
        normalized = text.sub(/-controller\z/, "").sub(/Controller\z/, "")
        normalized = normalized.split(/[-_]/).map { |part| part[0].to_s.upcase + part[1..].to_s }.join
        aliases = {
          "ReplicaSet" => "ReplicaSet", "StatefulSet" => "StatefulSet",
          "DaemonSet" => "DaemonSet", "Deployment" => "Deployment",
          "CronJob" => "CronJob", "Node" => "Node", "Endpoint" => "Endpoints",
          "Endpoints" => "Endpoints", "GarbageCollector" => "GarbageCollector"
        }
        aliases.fetch(normalized, normalized)
      end

      def normalize_controller_name(value)
        text = value.respond_to?(:name) && !value.is_a?(String) ? value.name.to_s : value.to_s
        return text if text.end_with?("-controller")

        "#{text.downcase.gsub(/(?<!\A)([A-Z])/, '-\\1').tr("_", "-")}-controller"
      end

      def default_predicate(relationship)
        case relationship
        when :owner_reference
          ->(object) { !Support.owner_references(object).empty? }
        when :label
          ->(object) { !Support.labels(object).empty? }
        else
          ->(_object) { true }
        end
      end

      def default_queue_key(relationship, descriptor)
        lambda do |object|
          if relationship == :owner_reference
            reference = Support.owner_references(object).find do |ref|
              Support.ref_value(ref, "kind", "").to_s == @kind.kind
            end
            if reference
              namespace = Support.namespace(object)
              [namespace, Support.ref_value(reference, "name", "")].compact.join("/")
            end
          end || [descriptor.identifier, Support.namespace(object), Support.name(object)].compact.join("/")
        end
      end
    end

    module DSL
      module_function

      def controller(name, registry: Controller.default_registry, kind: nil, implementation: nil, &block)
        raise ArgumentError, "controller DSL block is required" unless block

        builder = DSLBuilder.new(name, registry: registry, kind: kind)
        builder.instance_eval(&block)
        builder.build(implementation: implementation)
      end

      alias define controller
      alias register controller
    end

    class << self
      def controller(name, registry: default_registry, kind: nil, implementation: nil, &block)
        DSL.controller(name, registry: registry, kind: kind, implementation: implementation, &block)
      end

      alias define controller

      def registry
        default_registry
      end
    end
  end
end
