# frozen_string_literal: true

require_relative "schema/quantity"

module Rubernetes
  # Port of k8s.io/component-helpers/nodedeclaredfeatures (v1.36.2): the
  # shared library the kubelet, kube-scheduler and kube-apiserver use to agree
  # on which node-level features a Node declares (Node.status.declaredFeatures)
  # and which of them a Pod -- at scheduling time, or for one update -- needs.
  #
  # Pods are the JSON form (string keys), as everywhere else in this code base.
  module NodeDeclaredFeatures
    class Error < StandardError; end

    # bitmap.go.  A fixed-size set indexed by the framework's sorted feature
    # list; sets of different sizes never compare.
    class FeatureSet
      attr_reader :size, :bits

      def initialize(size, bits = 0)
        raise ArgumentError, "bitmap size must be positive: #{size}" if size.negative?

        @size = size
        @bits = bits
        freeze
      end

      def set(index)
        check_index!(index)
        FeatureSet.new(@size, @bits | (1 << index))
      end

      def get(index)
        check_index!(index)
        @bits[index] == 1
      end

      def difference(other)
        check_size!(other)
        FeatureSet.new(@size, @bits & ~other.bits)
      end

      def subset?(other)
        check_size!(other)
        @bits.nobits?(~other.bits)
      end

      def ==(other)
        other.is_a?(FeatureSet) && other.size == @size && other.bits == @bits
      end
      alias eql? ==

      def hash = [@size, @bits].hash
      def empty? = @bits.zero?

      # "10100": one character per registered feature, index order.
      def to_s
        (0...@size).map { |index| @bits[index] == 1 ? "1" : "0" }.join
      end

      def inspect = "#<#{self.class.name} #{self}>"

      private

      def check_index!(index)
        raise IndexError, "bitmap index out of range: #{index}" if index.negative? || index >= @size
      end

      def check_size!(other)
        raise Error, "bitmap size mismatch: #{@size} != #{other.size}" unless other.size == @size
      end
    end

    # featureset.go: maps sorted feature names to FeatureSet indexes.
    class FeatureMapper
      attr_reader :registered_features

      def initialize(features)
        @registered_features = Array(features).map(&:to_s).sort.freeze
      end

      def new_feature_set = FeatureSet.new(@registered_features.length)

      # Input must be sorted; an unknown name is an error.
      def map_sorted(sorted_features) = map_features(sorted_features, ignore_unknown: false)

      # Like map_sorted, but names this framework does not know are dropped
      # (a newer node may declare features an older scheduler never heard of).
      def try_map(sorted_features) = map_features(sorted_features, ignore_unknown: true)

      def unmap(set)
        unless set.size == @registered_features.length
          raise Error, "feature size mismatch! s.size=#{set.size}; len(m.registeredFeatures)=#{@registered_features.length}"
        end

        @registered_features.each_index.select { |index| set.get(index) }.map { |index| @registered_features[index] }
      end

      private

      # The two-pointer merge of featureset.go#mapSorted, including its
      # behaviour on unsorted input: it relies on order, as upstream does.
      def map_features(sorted_features, ignore_unknown:)
        set = new_feature_set
        names = Array(sorted_features).map(&:to_s)
        i = 0
        j = 0
        while i < names.length && j < @registered_features.length
          if names[i] == @registered_features[j]
            set = set.set(j)
            i += 1
            j += 1
          elsif names[i] < @registered_features[j]
            raise Error, "unknown feature #{names[i]}" unless ignore_unknown

            i += 1
          else
            j += 1
          end
        end
        raise Error, "unknown feature #{names[i]}" if !ignore_unknown && i < names.length

        set
      end
    end

    # types.go NodeConfiguration.  feature_gates responds to #call(name) or
    # #[](name), or is a Hash of name => Boolean.
    NodeConfiguration = Data.define(:feature_gates, :version, :runtime_features) do
      def initialize(feature_gates: {}, version: nil, runtime_features: {})
        super(feature_gates: feature_gates, version: version, runtime_features: runtime_features || {})
      end

      def gate_enabled?(name)
        gates = feature_gates
        value = if gates.respond_to?(:enabled?) then gates.enabled?(name)
                elsif gates.respond_to?(:call) then gates.call(name)
                elsif gates.respond_to?(:[]) then gates[name.to_s]
                end
        value == true
      end

      def runtime_feature?(name)
        runtime_features[name.to_s] == true || runtime_features[name.to_sym] == true
      end
    end

    MatchResult = Data.define(:match, :unsatisfied_requirements) do
      def match? = match
    end

    FeatureRequirements = Data.define(:enabled_feature_gates, :required_runtime_features)

    module PodHelpers
      module_function

      def spec(pod_info)
        pod_info = pod_info.fetch("spec", pod_info) if pod_info.is_a?(Hash) && pod_info.key?("spec")
        pod_info.is_a?(Hash) ? pod_info : {}
      end

      def containers(spec, field)
        Array(spec[field]).grep(Hash)
      end

      def sidecar?(container) = container["restartPolicy"] == "Always"

      # Go reflect.DeepEqual on the decoded structs: an absent map and an
      # empty one decode to the same nil map, anything else compares as is.
      def decoded(value)
        case value
        when Hash
          value.each_with_object({}) do |(key, item), output|
            normalized = decoded(item)
            output[key.to_s] = normalized unless normalized.nil? || (normalized.respond_to?(:empty?) && normalized.empty?)
          end
        when Array then value.map { |item| decoded(item) }
        else value
        end
      end

      # apiequality.Semantic.DeepEqual: quantities compare by value
      # ("1" == "1000m"); a nil pointer differs from an allocated empty one.
      def semantic_resources_equal?(left, right)
        return left.nil? && right.nil? if left.nil? || right.nil?

        semantic(decoded(left)) == semantic(decoded(right))
      end

      def semantic(value)
        case value
        when Hash
          value.to_h do |key, item|
            [key, if %w[requests limits].include?(key) && item.is_a?(Hash)
                    item.transform_values do |quantity|
                      quantity_value(quantity)
                    end
                  else
                    semantic(item)
                  end]
          end
        when Array then value.map { |item| semantic(item) }
        else value
        end
      end

      def quantity_value(quantity)
        Schema::Quantity.parse(quantity.to_s)
      rescue StandardError
        quantity
      end
    end

    # Each feature mirrors one file under features/ in the upstream library.
    module Features
      # Base: gate-only discovery, no scheduling/update inference, no max version.
      class Base
        def name = self.class::NAME
        def discover(config) = config.gate_enabled?(self.class::GATE)
        def requirements = FeatureRequirements.new(enabled_feature_gates: [self.class::GATE], required_runtime_features: nil)
        def infer_for_scheduling(_pod_info) = false
        def infer_for_update(_old_pod_info, _new_pod_info) = false
        def max_version = nil
      end

      # restartallcontainers/restart_all_containers.go
      class RestartAllContainers < Base
        NAME = "RestartAllContainersOnContainerExits"
        GATE = "RestartAllContainersOnContainerExits"

        def infer_for_scheduling(pod_info)
          spec = PodHelpers.spec(pod_info)
          %w[containers initContainers].any? do |field|
            PodHelpers.containers(spec, field).any? do |container|
              Array(container["restartPolicyRules"]).any? { |rule| rule.is_a?(Hash) && rule["action"] == "RestartAllContainers" }
            end
          end
        end
      end

      # inplacepodresize/pod_level_resource_resize.go
      class PodLevelResourcesResize < Base
        NAME = "InPlacePodLevelResourcesVerticalScaling"
        GATE = "InPlacePodLevelResourcesVerticalScaling"

        def infer_for_update(old_pod_info, new_pod_info)
          old_resources = PodHelpers.spec(old_pod_info)["resources"]
          new_resources = PodHelpers.spec(new_pod_info)["resources"]
          return false if old_resources.nil? && new_resources.nil?

          !PodHelpers.semantic_resources_equal?(old_resources, new_resources)
        end
      end

      # extendwebsocketstokubelet/feature.go
      class ExtendWebSocketsToKubelet < Base
        NAME = "ExtendWebSocketsToKubelet"
        GATE = "ExtendWebSocketsToKubelet"
      end

      # inplacepodresize/nonsidecar_initcontainers_resize.go
      class NonSidecarInitContainerResize < Base
        NAME = "InPlacePodVerticalScalingInitContainers"
        GATE = "InPlacePodVerticalScalingInitContainers"

        def infer_for_update(old_pod_info, new_pod_info)
          new_init = PodHelpers.containers(PodHelpers.spec(new_pod_info), "initContainers")
          PodHelpers.containers(PodHelpers.spec(old_pod_info), "initContainers").each_with_index.any? do |container, index|
            next false if PodHelpers.sidecar?(container)

            PodHelpers.decoded(container["resources"]) != PodHelpers.decoded(new_init.fetch(index, {})["resources"])
          end
        end
      end

      # usernamespaceshostnetwork/user_namespaces_host_network.go
      class UserNamespacesHostNetwork < Base
        NAME = "UserNamespacesHostNetworkSupport"
        GATE = "UserNamespacesHostNetworkSupport"
        RUNTIME_FEATURE = "userNamespacesHostNetwork"

        def requirements
          FeatureRequirements.new(enabled_feature_gates: [GATE], required_runtime_features: {RUNTIME_FEATURE => true})
        end

        def discover(config)
          config.gate_enabled?(GATE) && config.runtime_feature?(RUNTIME_FEATURE)
        end

        def infer_for_scheduling(pod_info)
          spec = PodHelpers.spec(pod_info)
          spec["hostNetwork"] == true && spec["hostUsers"] == false
        end
      end

      # features/registry.go AllFeatures (the framework sorts them by name).
      ALL = [
        RestartAllContainers.new,
        PodLevelResourcesResize.new,
        ExtendWebSocketsToKubelet.new,
        NonSidecarInitContainerResize.new,
        UserNamespacesHostNetwork.new
      ].freeze
    end

    # framework.go
    class Framework
      attr_reader :registry, :mapper

      def initialize(registry = Features::ALL)
        @registry = Array(registry).sort_by(&:name).freeze
        @mapper = FeatureMapper.new(@registry.map(&:name))
      end

      def new_feature_set = @mapper.new_feature_set
      def map_sorted(names) = @mapper.map_sorted(names)
      def try_map(names) = @mapper.try_map(names)
      def unmap(set) = @mapper.unmap(set)

      # Sorted names of every registered feature this node configuration
      # enables (and whose max version the node does not exceed).
      def discover_node_features(config)
        @registry.select do |feature|
          next false unless feature.discover(config)

          !(config.version && feature.max_version && version_greater?(config.version, feature.max_version))
        end.map(&:name)
      end

      def infer_for_pod_scheduling(pod_info, target_version)
        infer(target_version) { |feature| feature.infer_for_scheduling(pod_info) }
      end

      def infer_for_pod_update(old_pod_info, new_pod_info, target_version)
        infer(target_version) { |feature| feature.infer_for_update(old_pod_info, new_pod_info) }
      end

      def match_node(required, node)
        raise Error, "node cannot be nil" if node.nil?

        declared = node.is_a?(Hash) ? Array(node.dig("status", "declaredFeatures")) : Array(node)
        match_node_feature_set(required, try_map(declared))
      end

      def match_node_feature_set(required, node_features)
        return MatchResult.new(match: true, unsatisfied_requirements: []) if required.empty?
        return MatchResult.new(match: true, unsatisfied_requirements: []) if required.subset?(node_features)

        MatchResult.new(match: false, unsatisfied_requirements: unmap(required.difference(node_features)))
      end

      def feature_requirements(name)
        feature = @registry.find { |candidate| candidate.name == name.to_s }
        raise Error, "feature '#{name}' not registered" if feature.nil?

        feature.requirements
      end

      private

      def infer(target_version)
        raise Error, "target version cannot be nil" if target_version.nil?

        @registry.each_with_index.reduce(new_feature_set) do |set, (feature, index)|
          next set if feature.max_version && version_greater?(target_version, feature.max_version)

          yield(feature) ? set.set(index) : set
        end
      end

      def version_greater?(left, right)
        Gem::Version.new(left.to_s.delete_prefix("v").split(/[-+]/).first) > Gem::Version.new(right.to_s.delete_prefix("v").split(/[-+]/).first)
      end
    end

    DEFAULT_FRAMEWORK = Framework.new

    # The Kubernetes version the components of this tree implement: the
    # version the framework compares against feature max versions.
    KUBERNETES_VERSION = "v1.36.2"

    GATE = "NodeDeclaredFeatures"
  end
end
