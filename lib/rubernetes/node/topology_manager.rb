# frozen_string_literal: true

require_relative "../resource_helpers"

module Rubernetes
  module Node
    # pkg/kubelet/cm/topologymanager (v1.36.2): the pod admit handler that
    # asks each hint provider (CPU, memory and device managers) which NUMA
    # nodes it could serve a container -- or the whole Pod -- from, merges
    # the hints under the configured policy (none, best-effort, restricted,
    # single-numa-node), rejects the Pod with TopologyAffinityError when the
    # policy demands alignment the providers cannot give, and otherwise
    # records the chosen affinity and has every provider allocate.
    module TopologyManager
      class Error < StandardError; end

      POLICY_NONE = "none"
      POLICY_BEST_EFFORT = "best-effort"
      POLICY_RESTRICTED = "restricted"
      POLICY_SINGLE_NUMA_NODE = "single-numa-node"
      SCOPE_CONTAINER = "container"
      SCOPE_POD = "pod"
      SCOPE_NONE = "none"
      DEFAULT_MAX_ALLOWABLE_NUMA_NODES = 8
      PREFER_CLOSEST_NUMA_NODES = "prefer-closest-numa-nodes"
      MAX_ALLOWABLE_NUMA_NODES = "max-allowable-numa-nodes"
      ERROR_TOPOLOGY_AFFINITY = "TopologyAffinityError"
      ERROR_UNEXPECTED = "UnexpectedAdmissionError"

      # bitmask.BitMask over NUMA node ids 0..63, as an immutable value.
      class BitMask
        include Comparable

        attr_reader :value

        def self.of(*bits)
          value = 0
          bits.flatten.each do |bit|
            raise Error, "bit number must be in range 0-63" if bit.negative? || bit >= 64

            value |= 1 << bit
          end
          new(value)
        end

        def self.empty = new(0)

        # IterateBitMasks: every non-empty subset, by size, then in order.
        def self.iterate(bits)
          iterate = lambda do |rest, accum, size, &block|
            if accum.length == size
              block.call(of(*accum))
              next
            end
            rest.each_index { |i| iterate.call(rest[(i + 1)..], accum + [rest[i]], size, &block) }
          end
          (1..bits.length).each { |size| iterate.call(bits, [], size) { |mask| yield mask } }
        end

        def initialize(value)
          @value = value & 0xffff_ffff_ffff_ffff
          freeze
        end

        def and(*masks) = BitMask.new(masks.reduce(@value) { |value, mask| value & mask.value })
        def or(*masks) = BitMask.new(masks.reduce(@value) { |value, mask| value | mask.value })
        def empty? = @value.zero?
        def set?(bit) = bit >= 0 && bit < 64 && @value[bit] == 1
        def any_set?(bits) = bits.any? { |bit| set?(bit) }
        def count = @value.to_s(2).count("1")
        def bits = (0...64).select { |bit| @value[bit] == 1 }
        def ==(other) = other.is_a?(BitMask) && other.value == @value
        alias eql? ==
        def hash = @value.hash
        def <=>(other) = @value <=> other.value
        def less_than?(other) = @value < other.value
        def greater_than?(other) = @value > other.value

        # IsNarrowerThan: fewer bits, or as many and numerically lower.
        def narrower_than?(other)
          count == other.count ? less_than?(other) : count < other.count
        end

        # String: binary, zero-padded to an even width.
        def to_s
          shift = 62
          while shift.positive?
            return @value.to_s(2).rjust(shift + 2, "0") if @value > (1 << shift)

            shift -= 2
          end
          @value.to_s(2).rjust(2, "0")
        end

        def inspect = "#<BitMask #{bits.join(",")}>"
      end

      # TopologyHint: a NUMA affinity (nil = any) and whether it is preferred.
      Hint = Struct.new(:affinity, :preferred) do
        def self.any(preferred: true) = new(nil, preferred)

        def equal_hint?(other)
          return false unless preferred == other.preferred
          return affinity.nil? && other.affinity.nil? if affinity.nil? || other.affinity.nil?

          affinity == other.affinity
        end

        def to_h = {"affinity" => affinity&.bits, "preferred" => preferred}
      end

      # admission.Error types.
      class AdmissionError < StandardError
        attr_reader :reason

        def initialize(message, reason:)
          super(message)
          @reason = reason
        end
      end

      class TopologyAffinityError < AdmissionError
        def initialize(message = "Resources cannot be allocated with Topology locality")
          super(message, reason: ERROR_TOPOLOGY_AFFINITY)
        end
      end

      # PodLevelTopologyAffinityError.
      class PodLevelTopologyAffinityError < TopologyAffinityError
        def initialize(message = nil)
          super(message.to_s.empty? ? "Pod Scope Resources cannot be allocated with Topology locality" : "Pod Scope #{message}")
        end
      end

      # PodAdmitResult.
      AdmitResult = Struct.new(:admit, :reason, :message) do
        def self.ok = new(true, nil, nil)

        # admission.GetPodAdmitResult: an error of a known type keeps its
        # reason; anything else is unexpected.
        def self.from_error(error)
          return ok if error.nil?

          if error.respond_to?(:reason) && error.reason
            new(false, error.reason, error.message)
          else
            new(false, ERROR_UNEXPECTED, "Allocate failed due to #{error.message}, which is unexpected")
          end
        end

        def admit? = admit
      end

      # NUMAInfo: the node ids and their distance rows.
      class NUMAInfo
        attr_reader :nodes, :distances

        def initialize(nodes, distances = {})
          @nodes = nodes
          @distances = distances
        end

        def self.from_machine(topology, prefer_closest: false)
          distances = {}
          nodes = Array(topology).map do |node|
            if prefer_closest
              raise Error, "error getting NUMA distances from cadvisor" if node[:distances].nil?

              distances[node[:id]] = node[:distances]
            end
            node[:id]
          end
          new(nodes, distances)
        end

        def default_affinity = BitMask.of(*@nodes)
        def narrowest(first, second) = first.narrower_than?(second) ? first : second

        def closest(first, second)
          return narrowest(first, second) unless first.count == second.count

          a = average_distance(first)
          b = average_distance(second)
          return (first.less_than?(second) ? first : second) if a == b

          a < b ? first : second
        end

        def average_distance(mask)
          return 0.0 if mask.count.zero?

          sum = 0.0
          count = 0
          mask.bits.each do |a|
            mask.bits.each do |b|
              sum += Array(@distances[a])[b].to_f
              count += 1
            end
          end
          sum / count
        end
      end

      # Policy options.
      Options = Struct.new(:prefer_closest_numa, :max_allowable_numa_nodes, keyword_init: true) do
        def self.parse(options)
          result = new(prefer_closest_numa: false, max_allowable_numa_nodes: DEFAULT_MAX_ALLOWABLE_NUMA_NODES)
          (options || {}).each do |name, value|
            name = name.to_s
            case name
            when PREFER_CLOSEST_NUMA_NODES
              result.prefer_closest_numa = parse_bool(name, value)
            when MAX_ALLOWABLE_NUMA_NODES
              number = begin
                Integer(value.to_s, 10)
              rescue ArgumentError
                raise Error, "unable to convert policy option to integer #{name.dump}: strconv.Atoi: parsing #{value.to_s.dump}: invalid syntax"
              end
              if number < DEFAULT_MAX_ALLOWABLE_NUMA_NODES
                raise Error, "the minimum value of #{name.dump} should not be less than #{DEFAULT_MAX_ALLOWABLE_NUMA_NODES}"
              end

              result.max_allowable_numa_nodes = number
            else
              raise Error, "unknown Topology Manager Policy option: #{name.dump}"
            end
          end
          result
        end

        def self.parse_bool(name, value)
          case value.to_s
          when "1", "t", "T", "true", "TRUE", "True" then true
          when "0", "f", "F", "false", "FALSE", "False" then false
          else raise Error, "bad value for option #{name.dump}: strconv.ParseBool: parsing #{value.to_s.dump}: invalid syntax"
          end
        end
      end

      module_function

      # filterProvidersHints: a provider with no opinion is "any, preferred";
      # a resource with no possible affinity is "any, not preferred".
      def filter_providers_hints(providers_hints)
        providers_hints.flat_map do |hints|
          next [[Hint.any]] if hints.nil? || hints.empty?

          hints.map do |_resource, list|
            if list.nil?
              [Hint.any]
            elsif list.empty?
              [Hint.any(preferred: false)]
            else
              list
            end
          end
        end
      end

      def merge_permutation(default_affinity, permutation)
        preferred = true
        affinities = []
        permutation.each do |hint|
          if hint.affinity
            affinities << hint.affinity
            preferred = false unless hint.affinity == affinities.first
          end
          preferred = false unless hint.preferred
        end
        Hint.new(default_affinity.and(*affinities), preferred)
      end

      def narrowest_hint(hints)
        best = nil
        hints.each do |hint|
          next if hint.affinity.nil?

          best ||= hint
          best = hint if hint.affinity.narrower_than?(best.affinity)
        end
        best
      end

      def max_of_min_affinity_counts(filtered)
        filtered.map { |hints| narrowest_hint(hints)&.affinity&.count || 0 }.max || 0
      end

      # HintMerger.
      class HintMerger
        def initialize(numa_info, hints, policy_name, options)
          @numa_info = numa_info
          @hints = hints
          @best_non_preferred = TopologyManager.max_of_min_affinity_counts(hints)
          @closest = policy_name != POLICY_SINGLE_NUMA_NODE && options.prefer_closest_numa
        end

        def compare_masks(current, candidate)
          return current if candidate.affinity == current.affinity

          best = @closest ? @numa_info.closest(current.affinity, candidate.affinity) : @numa_info.narrowest(current.affinity, candidate.affinity)
          best == current.affinity ? current : candidate
        end

        def compare(current, candidate)
          return current if candidate.affinity.count.zero?
          return candidate if current.nil?
          return candidate if !current.preferred && candidate.preferred
          return current if current.preferred && !candidate.preferred
          return compare_masks(current, candidate) if current.preferred && candidate.preferred

          best = @best_non_preferred
          current_count = current.affinity.count
          candidate_count = candidate.affinity.count
          return compare_masks(current, candidate) if current_count > best
          if current_count == best
            return current if candidate_count != best

            return compare_masks(current, candidate)
          end
          return current if candidate_count > best
          return candidate if candidate_count == best
          return candidate if candidate_count > current_count
          return current if candidate_count < current_count

          compare_masks(current, candidate)
        end

        def merge
          default_affinity = @numa_info.default_affinity
          best = nil
          iterate(0, []) do |permutation|
            best = compare(best, TopologyManager.merge_permutation(default_affinity, permutation))
          end
          best || Hint.new(default_affinity, false)
        end

        private

        def iterate(index, accum, &block)
          return block.call(accum) if index == @hints.length

          @hints[index].each { |hint| iterate(index + 1, accum + [hint], &block) }
        end
      end

      # Policies: name, merge(providers_hints) => [hint, admit].
      class NonePolicy
        def name = POLICY_NONE
        def merge(_providers_hints) = [Hint.new(nil, false), true]
      end

      class BestEffortPolicy
        def initialize(numa_info, options)
          @numa_info = numa_info
          @options = options
        end

        def name = POLICY_BEST_EFFORT

        def merge(providers_hints)
          best = HintMerger.new(@numa_info, TopologyManager.filter_providers_hints(providers_hints), name, @options).merge
          [best, admit?(best)]
        end

        def admit?(_hint) = true
      end

      class RestrictedPolicy < BestEffortPolicy
        def name = POLICY_RESTRICTED
        def admit?(hint) = hint.preferred
      end

      class SingleNumaNodePolicy < BestEffortPolicy
        def name = POLICY_SINGLE_NUMA_NODE

        def merge(providers_hints)
          filtered = TopologyManager.filter_providers_hints(providers_hints).map do |hints|
            hints.select { |hint| hint.preferred && (hint.affinity.nil? || hint.affinity.count == 1) }
          end
          best = HintMerger.new(@numa_info, filtered, name, @options).merge
          best = Hint.new(nil, best.preferred) if best.affinity == @numa_info.default_affinity
          [best, best.preferred]
        end
      end

      # A scope: where hints are asked for (per container, or once for the
      # Pod) and the affinity store the hint providers read back.
      class Scope
        attr_reader :name, :policy

        # +pod_level+: PodLevelResourceManagers (and PodLevelResources) on.
        attr_accessor :pod_level
        # The kubelet registry (admission errors, aligned-resource counts).
        attr_accessor :metrics

        def initialize(name, policy)
          @name = name
          @policy = policy
          @pod_level = false
          @mutex = Mutex.new
          @hints = {}
          @containers = {}
          @providers = []
        end

        def add_hint_provider(provider) = @providers << provider

        # GetAffinity: the zero hint when none was recorded.
        def affinity(pod_uid, container)
          @mutex.synchronize { @hints.dig(pod_uid.to_s, container.to_s) } || Hint.new(nil, false)
        end

        def add_container(pod, container, container_id)
          @mutex.synchronize { @containers[container_id.to_s] = [uid(pod), container["name"].to_s] }
        end

        def remove_container(container_id)
          @mutex.synchronize do
            reference = @containers.delete(container_id.to_s)
            return nil unless reference
            return nil if @containers.value?(reference)

            pod_uid, name = reference
            @hints[pod_uid]&.delete(name)
            @hints.delete(pod_uid) if @hints[pod_uid] && @hints[pod_uid].empty?
          end
          nil
        end

        def admit(pod) = raise NotImplementedError

        protected

        def containers(pod) = Array(pod.dig("spec", "initContainers")) + Array(pod.dig("spec", "containers"))
        def uid(pod) = pod.dig("metadata", "uid").to_s

        def set_hint(pod, container, hint)
          @mutex.synchronize { (@hints[uid(pod)] ||= {})[container["name"].to_s] = hint }
        end

        def allocate(pod, container)
          @providers.each { |provider| provider.allocate(pod, container) }
          nil
        end

        def pod_level?(pod) = @pod_level && ResourceHelpers.pod_level_resources_set?(pod)

        # IsAlignmentGuaranteed: the single-numa-node policy.
        def alignment_guaranteed? = @policy.respond_to?(:name) && @policy.name == POLICY_SINGLE_NUMA_NODE

        def count(name, scope = nil)
          return unless @metrics

          labels = scope ? {"scope" => scope, "boundary" => "numa_node"} : {}
          @metrics.increment(name, labels)
        rescue StandardError
          nil
        end

        def admission_error = count("kubelet_topology_manager_admission_errors_total")

        # allocateAlignedResources: an allocation that fails is an admission error.
        def allocate_counted(pod, container)
          allocate(pod, container)
        rescue StandardError
          admission_error
          raise
        end

        def admit_each_container
          yield
          AdmitResult.ok
        rescue AdmissionError, StandardError => error
          AdmitResult.from_error(error)
        end
      end

      class NoneScope < Scope
        def initialize = super(SCOPE_NONE, NonePolicy.new)

        def admit(pod)
          admit_each_container { containers(pod).each { |container| allocate(pod, container) } }
        end
      end

      class ContainerScope < Scope
        def initialize(policy) = super(SCOPE_CONTAINER, policy)

        def admit(pod)
          admit_each_container do
            containers(pod).each do |container|
              best, admit = @policy.merge(@providers.map { |provider| provider.topology_hints(pod, container) })
              unless admit
                count("kubelet_container_aligned_compute_resources_failure_count", "container") if alignment_guaranteed?
                admission_error
                raise PodLevelTopologyAffinityError, "pod with pod-level resources failed admission with a container-level topology manager" if pod_level?(pod)

                raise TopologyAffinityError
              end

              set_hint(pod, container, best)
              allocate_counted(pod, container)
              count("kubelet_container_aligned_compute_resources_count", "container") if alignment_guaranteed?
            end
          end
        end
      end

      class PodScope < Scope
        def initialize(policy) = super(SCOPE_POD, policy)

        def admit(pod)
          best, admit = @policy.merge(@providers.map { |provider| provider.pod_topology_hints(pod) })
          # checkAffinity.
          unless admit
            count("kubelet_container_aligned_compute_resources_failure_count", "pod") if alignment_guaranteed?
            admission_error
          end
          return admit_using_pod_resources(pod, best, admit) if pod_level?(pod)
          return AdmitResult.from_error(TopologyAffinityError.new) unless admit

          result = admit_each_container do
            containers(pod).each do |container|
              set_hint(pod, container, best)
              allocate_counted(pod, container)
            end
          end
          count("kubelet_container_aligned_compute_resources_count", "pod") if result.admit? && alignment_guaranteed?
          result
        end
      end

      class PodScope
        # admitUsingPodResources: the best hint for every container, then one
        # AllocatePod per hint provider.
        def admit_using_pod_resources(pod, best, admit)
          unless admit
            return AdmitResult.from_error(PodLevelTopologyAffinityError.new("pod with pod-level resources failed admission under pod-scope topology manager"))
          end

          result = admit_each_container do
            containers(pod).each { |container| set_hint(pod, container, best) }
            begin
              @providers.each { |provider| provider.allocate_pod(pod) if provider.respond_to?(:allocate_pod) }
            rescue StandardError
              admission_error
              raise
            end
          end
          count("kubelet_container_aligned_compute_resources_count", "pod") if result.admit? && alignment_guaranteed?
          result
        end
      end

      # topologymanager.NewManager.
      class Manager
        attr_reader :scope

        def initialize(policy: POLICY_NONE, scope: SCOPE_CONTAINER, options: {}, topology: [], pod_level: false)
          policy = policy.to_s
          if policy == POLICY_NONE
            @scope = NoneScope.new
            return
          end

          parsed = Options.parse(options)
          numa_info = NUMAInfo.from_machine(topology, prefer_closest: parsed.prefer_closest_numa)
          if numa_info.nodes.length > parsed.max_allowable_numa_nodes
            raise Error, "unsupported on machines with more than #{parsed.max_allowable_numa_nodes} NUMA Nodes"
          end

          merger = case policy
                   when POLICY_BEST_EFFORT then BestEffortPolicy.new(numa_info, parsed)
                   when POLICY_RESTRICTED then RestrictedPolicy.new(numa_info, parsed)
                   when POLICY_SINGLE_NUMA_NODE then SingleNumaNodePolicy.new(numa_info, parsed)
                   else raise Error, "unknown policy: \"#{policy}\""
                   end
          @scope = case scope.to_s
                   when SCOPE_CONTAINER then ContainerScope.new(merger)
                   when SCOPE_POD then PodScope.new(merger)
                   else raise Error, "unknown scope: \"#{scope}\""
                   end
          @scope.pod_level = pod_level
        end

        def policy = @scope.policy
        def name = @scope.name
        def affinity(pod_uid, container) = @scope.affinity(pod_uid, container)
        def add_hint_provider(provider) = @scope.add_hint_provider(provider)
        def add_container(pod, container, container_id) = @scope.add_container(pod, container, container_id)
        def remove_container(container_id) = @scope.remove_container(container_id)

        # The kubelet registry; a manager with a policy other than none also
        # makes its aligned-resource series exist (initializeMetrics).
        def metrics=(registry)
          @metrics = registry
          @scope.metrics = registry
          return if @scope.is_a?(NoneScope)

          %w[container pod].each do |scope|
            labels = {"scope" => scope, "boundary" => "numa_node"}
            registry.touch("kubelet_container_aligned_compute_resources_count", labels)
            registry.touch("kubelet_container_aligned_compute_resources_failure_count", labels)
          end
        end

        # The pod admit handler: kubelet_topology_manager_admission_requests_total
        # and _duration_ms (whole milliseconds).
        def admit(pod)
          @metrics&.increment("kubelet_topology_manager_admission_requests_total")
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          result = @scope.admit(pod)
          @metrics&.observe("kubelet_topology_manager_admission_duration_ms", ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).floor)
          result
        end
      end
    end
  end
end
