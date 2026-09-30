# frozen_string_literal: true

module Rubernetes
  module Scheduler
    # A frozen resource map keeps quantity arithmetic exact.  Plugins may use
    # the map with ordinary Hash methods while the scheduler retains Rational
    # values internally and therefore never makes a fit decision from a
    # rounded float.
    class ResourceMap < Hash
      def initialize(values = {})
        super()
        Support.quantity_map(values).each { |resource, amount| self[resource] = amount }
        freeze
      end

      def +(other)
        self.class.new(Support.sum_maps(self, other))
      end

      def -(other)
        self.class.new(Support.subtract_maps(self, other))
      end

      def >=(other)
        other_map = Support.quantity_map(other)
        other_map.all? { |resource, amount| fetch(resource, Rational(0)) >= amount }
      end

      def <=(other)
        other_map = Support.quantity_map(other)
        each.all? { |resource, amount| amount <= other_map.fetch(resource, Rational(0)) }
      end

      def to_h
        each_with_object({}) { |(resource, amount), result| result[resource] = amount }
      end

      alias to_hash to_h
    end

    # Immutable, schema-shaped view passed to filter and score plugins.
    class Snapshot
      attr_reader :raw

      def initialize(value)
        @raw = Support.snapshot(value)
      end

      def [](key)
        Support.value(@raw, key)
      end

      def key?(key)
        @raw.key?(key.to_s) || @raw.key?(key.to_sym)
      end

      def dig(*path)
        current = @raw
        path.each do |key|
          return nil unless current.is_a?(Hash)

          current = if current.key?(key.to_s)
                      current[key.to_s]
                    elsif current.key?(key.to_sym)
                      current[key.to_sym]
                    end
        end
        current
      end

      def fetch(key, *arguments, &block)
        @raw.fetch(key.to_s, *arguments, &block)
      end

      def to_h
        @raw
      end

      alias to_hash to_h

      def as_json(*)
        @raw
      end

      def with(changes = {})
        updates = Support.object_hash(changes)
        merged = Support.deep_copy(@raw)
        updates.each { |key, value| merged[key.to_s] = Support.deep_copy(value) }
        self.class.new(merged)
      end

      # Explicit field access keeps the plugin ABI stable and avoids dynamic
      # method dispatch for untrusted plugin code.
      def field(key, default = nil)
        value = Support.value(@raw, key, default)
        value.nil? ? default : value
      end

      def ==(other)
        other.is_a?(self.class) && other.to_h == to_h
      end
      alias eql? ==

      def hash
        to_h.hash
      end

    end

    class Pod < Snapshot
      def initialize(value)
        super
        kind = self["kind"]
        raise ValidationError, "scheduler expected a Pod, got #{kind.inspect}" if kind && kind.to_s != "Pod"
        validate_shape!
        freeze
      end

      def metadata
        Support.snapshot(self["metadata"] || {})
      end

      def spec
        Support.snapshot(self["spec"] || {})
      end

      def status
        Support.snapshot(self["status"] || {})
      end

      def name
        Support.name(self)
      end

      def namespace
        Support.namespace(self)
      end

      def uid
        Support.uid(self)
      end

      def labels
        Support.labels(self)
      end

      def annotations
        Support.annotations(self)
      end

      def requests
        ResourceMap.new(Support.requests_for(self))
      end

      alias resource_requests requests

      # The requests LeastAllocated scores with (defaults for what is unset).
      def non_zero_requests
        ResourceMap.new(Support.non_zero_requests_for(self))
      end

      def node_name
        Support.value(spec, "nodeName", "")&.to_s.to_s
      end

      def priority
        Support.priority_for(self)
      end

      # status.nominatedNodeName: where preemption made room for this Pod,
      # or where its binding is expected to land.
      def nominated_node_name
        Support.value(status, "nominatedNodeName", "").to_s
      end

      def terminating?
        !Support.value(metadata, "deletionTimestamp", nil).nil?
      end

      # preemption.go podTerminatingByPreemption: being deleted, with the
      # DisruptionTarget condition the scheduler's preemption sets.
      def terminating_by_preemption?
        return false unless terminating?

        Array(Support.value(status, "conditions", [])).any? do |condition|
          Support.value(condition, "type", nil) == "DisruptionTarget" &&
            Support.value(condition, "status", nil) == "True" &&
            Support.value(condition, "reason", nil) == "PreemptionByScheduler"
        end
      end

      def priority_class_name
        Support.value(spec, "priorityClassName", "")&.to_s.to_s
      end

      def preemption_policy
        Support.value(spec, "preemptionPolicy", "PreemptLowerPriority").to_s
      end

      def scheduler_name
        Support.value(spec, "schedulerName", "default-scheduler").to_s
      end

      def scheduling_gates
        Support.snapshot(Array(Support.value(spec, "schedulingGates", [])))
      end

      # spec.schedulingGroup.podGroupName (GenericWorkload), or nil.
      def scheduling_group
        name = Support.value(Support.value(spec, "schedulingGroup", {}) || {}, "podGroupName", nil)
        name.to_s.empty? ? nil : name.to_s
      end

      def gated?
        !scheduling_gates.empty?
      end

      def containers
        Support.snapshot(Array(Support.value(spec, "containers", [])))
      end

      def init_containers
        Support.snapshot(Array(Support.value(spec, "initContainers", [])))
      end

      def volumes
        Support.snapshot(Array(Support.value(spec, "volumes", [])))
      end

      def tolerations
        Support.snapshot(Array(Support.value(spec, "tolerations", [])))
      end

      def affinity
        Support.snapshot(Support.value(spec, "affinity", {}))
      end

      def node_selector
        Support.snapshot(Support.value(spec, "nodeSelector", {}))
      end

      def topology_spread_constraints
        Support.snapshot(Array(Support.value(spec, "topologySpreadConstraints", [])))
      end

      def node_affinity
        Support.snapshot(Support.value(affinity, "nodeAffinity", {}))
      end

      def pod_affinity
        Support.snapshot(Support.value(affinity, "podAffinity", {}))
      end

      def pod_anti_affinity
        Support.snapshot(Support.value(affinity, "podAntiAffinity", {}))
      end

      private

      def validate_shape!
        %w[metadata spec status].each do |key|
          value = self[key]
          next if value.nil?
          raise ValidationError, "pod #{key} must be an object" unless value.respond_to?(:to_h)
        end
        labels = Support.value(metadata, "labels")
        raise ValidationError, "pod metadata.labels must be an object" if labels && !labels.respond_to?(:to_h)
        selectors = Support.value(spec, "nodeSelector")
        raise ValidationError, "pod spec.nodeSelector must be an object" if selectors && !selectors.respond_to?(:to_h)
      end
    end

    class Node < Snapshot
      attr_reader :pods

      def initialize(value, pods: nil)
        super(value)
        kind = self["kind"]
        raise ValidationError, "scheduler expected a Node, got #{kind.inspect}" if kind && kind.to_s != "Node"
        validate_shape!
        @pods_explicit = !pods.nil? || key?("pods")
        source_pods = pods.nil? ? self["pods"] : pods
        @pods = Array(source_pods).map { |pod| pod.is_a?(Pod) ? pod : Pod.new(pod) }.freeze
        freeze
      end

      def metadata
        Support.snapshot(self["metadata"] || {})
      end

      def spec
        Support.snapshot(self["spec"] || {})
      end

      def status
        Support.snapshot(self["status"] || {})
      end

      def name
        Support.node_name(self)
      end

      def labels
        Support.labels(self)
      end

      def taints
        Support.snapshot(Array(Support.value(spec, "taints", Support.value(self, "taints", []))))
      end

      def used_ports
        Support.snapshot(Support.value(self, "usedPorts", Support.value(status, "usedPorts", {})))
      end

      def volume_limits
        Support.snapshot(Support.value(self, "volumeLimits",
                                       Support.value(status, "volumeLimits", Support.value(self, "csiVolumeLimits", {}))))
      end

      def image_states
        Support.snapshot(Support.value(self, "imageStates", Support.value(status, "images", {})))
      end

      def unschedulable?
        Support.truthy?(Support.value(spec, "unschedulable", Support.value(self, "unschedulable", false)))
      end

      def allocatable
        ResourceMap.new(
          Support.value(status, "allocatable",
                        Support.value(self, "allocatable",
                                      Support.value(spec, "allocatable", Support.value(status, "capacity", {}))))
        )
      end

      def capacity
        ResourceMap.new(Support.value(status, "capacity", Support.value(self, "capacity", Support.value(spec, "capacity", allocatable))))
      end

      def requested
        return ResourceMap.new(Support.sum_maps(@pods.map(&:requests))) if @pods_explicit

        ResourceMap.new(
          Support.value(self, "requested", Support.value(status, "requested", Support.value(status, "used", Support.value(self, "used", {}))))
        )
      end

      alias used requested

      # NodeInfo.NonZeroRequested: the node's Pods sized with the scoring defaults.
      def non_zero_requested
        return ResourceMap.new(Support.sum_maps(@pods.map(&:non_zero_requests))) if @pods_explicit

        requested
      end

      def available
        ResourceMap.new(Support.subtract_maps(allocatable, requested))
      end

      def utilization_percent
        resources = allocatable.keys.select { |resource| allocatable.fetch(resource).positive? }
        return 0 if resources.empty?

        ratio = resources.sum do |resource|
          [(requested.fetch(resource, Rational(0)) * 100 / allocatable.fetch(resource)), Rational(100)] .min
        end
        (ratio / resources.length).floor
      end

      def ready?
        explicit, present = Support.present_value(self, "ready")
        return Support.truthy?(explicit) if present

        status_value, status_present = Support.present_value(self, "status")
        return false unless status_present

        conditions = Array(Support.value(status_value, "conditions", nil))
        return false if conditions.empty?

        condition = conditions.find { |entry| Support.value(entry, "type", "").to_s == "Ready" }
        condition && Support.value(condition, "status", "").to_s == "True"
      end

      def with_pods(pod_list, preserve_requested: false)
        return self if preserve_requested && Array(pod_list).empty? && !@pods_explicit

        self.class.new(to_h, pods: pod_list)
      end

      private

      def validate_shape!
        %w[metadata spec status].each do |key|
          value = self[key]
          next if value.nil?
          raise ValidationError, "node #{key} must be an object" unless value.respond_to?(:to_h)
        end
        labels = Support.value(metadata, "labels")
        raise ValidationError, "node metadata.labels must be an object" if labels && !labels.respond_to?(:to_h)
      end
    end

    PodSnapshot = Pod unless const_defined?(:PodSnapshot, false)
    NodeSnapshot = Node unless const_defined?(:NodeSnapshot, false)
  end
end
