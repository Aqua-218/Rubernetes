# frozen_string_literal: true

require_relative "assignment"
require_relative "state"
require_relative "../topology_manager"
require_relative "../../resource_helpers"

module Rubernetes
  module Node
    module CPUManager
      POLICY_NONE = "none"
      POLICY_STATIC = "static"

      FULL_PCPUS_ONLY = "full-pcpus-only"
      DISTRIBUTE_CPUS_ACROSS_NUMA = "distribute-cpus-across-numa"
      ALIGN_BY_SOCKET = "align-by-socket"
      DISTRIBUTE_CPUS_ACROSS_CORES = "distribute-cpus-across-cores"
      STRICT_CPU_RESERVATION = "strict-cpu-reservation"
      PREFER_ALIGN_BY_UNCORE_CACHE = "prefer-align-cpus-by-uncorecache"
      ALPHA_OPTIONS = [ALIGN_BY_SOCKET, DISTRIBUTE_CPUS_ACROSS_CORES].freeze
      BETA_OPTIONS = [DISTRIBUTE_CPUS_ACROSS_NUMA].freeze
      STABLE_OPTIONS = [FULL_PCPUS_ONLY, STRICT_CPU_RESERVATION, PREFER_ALIGN_BY_UNCORE_CACHE].freeze
      ERROR_SMT_ALIGNMENT = "SMTAlignmentError"

      class Error < StandardError; end

      # SMTAlignmentError (an admission.Error: the Pod is rejected with this
      # reason).
      # admission.EmptyPodSharedPoolError.
      class EmptyPodSharedPoolError < TopologyManager::AdmissionError
        def initialize(message) = super(message, reason: "EmptyPodSharedPoolError")
      end

      class SMTAlignmentError < TopologyManager::AdmissionError
        def initialize(requested:, cpus_per_core:, available_physical: nil)
          message = if available_physical
                      "SMT Alignment Error: not enough free physical CPUs: available physical CPUs = #{available_physical}, " \
                        "requested CPUs = #{requested}, CPUs per core = #{cpus_per_core}"
                    else
                      "SMT Alignment Error: requested #{requested} cpus not multiple cpus per core = #{cpus_per_core}"
                    end
          super(message, reason: ERROR_SMT_ALIGNMENT)
        end
      end

      # StaticPolicyOptions.
      StaticOptions = Struct.new(:full_physical_cpus_only, :distribute_cpus_across_numa, :align_by_socket,
                                 :distribute_cpus_across_cores, :strict_cpu_reservation, :prefer_align_by_uncore_cache,
                                 keyword_init: true) do
        # NewStaticPolicyOptions; +gates+ are the CPUManagerPolicy{Alpha,Beta}Options gates.
        def self.parse(options, alpha: false, beta: true)
          result = new(**members.to_h { |member| [member, false] })
          (options || {}).each do |name, value|
            name = name.to_s
            unless ALPHA_OPTIONS.include?(name) || BETA_OPTIONS.include?(name) || STABLE_OPTIONS.include?(name)
              raise Error, "unknown CPU Manager Policy option: #{name.dump}"
            end
            if ALPHA_OPTIONS.include?(name) && !alpha
              raise Error, "CPU Manager Policy Alpha-level Options not enabled, but option #{name.dump} provided"
            end
            if BETA_OPTIONS.include?(name) && !beta
              raise Error, "CPU Manager Policy Beta-level Options not enabled, but option #{name.dump} provided"
            end

            flag = TopologyManager::Options.parse_bool(name, value)
            member = {FULL_PCPUS_ONLY => :full_physical_cpus_only, DISTRIBUTE_CPUS_ACROSS_NUMA => :distribute_cpus_across_numa,
                      ALIGN_BY_SOCKET => :align_by_socket, DISTRIBUTE_CPUS_ACROSS_CORES => :distribute_cpus_across_cores,
                      STRICT_CPU_RESERVATION => :strict_cpu_reservation,
                      PREFER_ALIGN_BY_UNCORE_CACHE => :prefer_align_by_uncore_cache}.fetch(name)
            result[member] = flag
          end
          [
            [:full_physical_cpus_only, :distribute_cpus_across_cores, FULL_PCPUS_ONLY, DISTRIBUTE_CPUS_ACROSS_CORES],
            [:distribute_cpus_across_numa, :distribute_cpus_across_cores, DISTRIBUTE_CPUS_ACROSS_NUMA, DISTRIBUTE_CPUS_ACROSS_CORES],
            [:prefer_align_by_uncore_cache, :distribute_cpus_across_cores, PREFER_ALIGN_BY_UNCORE_CACHE, DISTRIBUTE_CPUS_ACROSS_CORES],
            [:prefer_align_by_uncore_cache, :distribute_cpus_across_numa, PREFER_ALIGN_BY_UNCORE_CACHE, DISTRIBUTE_CPUS_ACROSS_NUMA]
          ].each do |first, second, first_name, second_name|
            if result[first] && result[second]
              raise Error, "static policy options #{first_name} and #{second_name} can not be used at the same time"
            end
          end
          result
        rescue TopologyManager::Error => error
          raise Error, error.message
        end
      end

      # Pod helpers shared by the policies.
      module PodResources
        module_function

        def containers(pod) = Array(pod.dig("spec", "initContainers")) + Array(pod.dig("spec", "containers"))
        def uid(pod) = pod.dig("metadata", "uid").to_s
        def restartable_init?(container) = container["restartPolicy"].to_s == "Always"

        # cmqos.IsContainerEquivalentQOSGuaranteed: the container's own CPU
        # and memory requests are set and equal to its limits.
        def container_equivalent_guaranteed?(container)
          %w[cpu memory].all? do |name|
            request = container.dig("resources", "requests", name)
            limit = container.dig("resources", "limits", name)
            next false if request.nil? || limit.nil?

            value = ResourceHelpers::Quantity.from_json(request.to_s).value
            value.positive? && value == ResourceHelpers::Quantity.from_json(limit.to_s).value
          end
        rescue StandardError
          false
        end

        def init_container?(pod, container) = Array(pod.dig("spec", "initContainers")).any? { |entry| entry["name"] == container["name"] }

        def cpu_request(container)
          value = container.dig("resources", "requests", "cpu")
          value.nil? ? nil : ResourceHelpers::Quantity.from_json(value)
        end

        # isIntegralCPUAmount: Value()*1000 == MilliValue().
        def integral_cpus(quantity)
          value = quantity.value
          whole = value.ceil
          whole * 1000 == (value * 1000).ceil ? whole : nil
        end

        def qos(pod) = ResourceHelpers.pod_qos(pod)
        def pod_level_resources?(pod) = ResourceHelpers.pod_level_resources_set?(pod)
      end

      # The none policy: every container runs on the shared pool.
      class NonePolicy
        def initialize(options = {})
          raise Error, "None policy: received unsupported options=#{options}" unless options.nil? || options.empty?
        end

        def name = POLICY_NONE
        def start(_state) = nil
        def allocate(_state, _pod, _container) = nil
        def remove_container(_state, _pod_uid, _container) = nil
        def topology_hints(_state, _pod, _container) = nil
        def pod_topology_hints(_state, _pod) = nil
        def allocatable_cpus(_state) = CPUSet.empty
      end

      # policy_static.go: Guaranteed containers with integral CPU requests get
      # exclusive CPUs, taken from the shared pool by topology; everything
      # else shares what is left.  The reserved CPUs stay in the shared pool
      # (or, with strict-cpu-reservation, out of every pool).
      class StaticPolicy
        attr_reader :topology, :reserved_cpus, :reserved_physical_cpus, :options, :cpu_group_size

        # +pod_level+: PodLevelResourceManagers (and PodLevelResources) on.
        def initialize(topology:, num_reserved:, reserved_cpus: CPUSet.empty, affinity: nil, options: {}, alpha_options: false,
                       beta_options: true, pod_level: false)
          @pod_level = pod_level
          @topology = topology
          @affinity = affinity
          @options = StaticOptions.parse(options, alpha: alpha_options, beta: beta_options)
          if @options.align_by_socket
            if affinity.respond_to?(:policy) && affinity.policy.name == TopologyManager::POLICY_SINGLE_NUMA_NODE
              raise Error, "Topolgy manager #{TopologyManager::POLICY_SINGLE_NUMA_NODE} policy is incompatible with " \
                           "CPUManager #{ALIGN_BY_SOCKET} policy option"
            end
            if topology.num_sockets > topology.num_numa_nodes
              raise Error, "Align by socket is not compatible with hardware where number of sockets are more than number of NUMA"
            end
          end
          @cpu_group_size = topology.cpus_per_core
          @cpus_to_reuse = {}
          all = topology.cpu_details.cpus
          reserved = if reserved_cpus.size.positive?
                       reserved_cpus
                     else
                       begin
                         take_by_topology(all, num_reserved)
                       rescue Assignment::Error
                         CPUSet.empty
                       end
                     end
          if reserved.size != num_reserved
            raise Error, "[cpumanager] unable to reserve the required amount of CPUs (size of #{reserved} did not equal #{num_reserved})"
          end

          physical = CPUSet.empty
          reserved.each do |cpu|
            info = topology.cpu_details[cpu]
            raise Error, "[cpumanager] unable to build the reserved physical CPUs from the reserved set: unknown CPU ID: #{cpu}" unless info

            physical = physical.union(topology.cpu_details.cpus_in_cores(info.core_id))
          end
          @reserved_cpus = reserved
          @reserved_physical_cpus = physical
        end

        def name = POLICY_STATIC

        # The kubelet registry the policy's metrics go to (increment / set).
        attr_writer :metrics

        def start(state)
          validate_state(state)
          initialize_metrics(state)
        end

        # validateState: a fresh state takes every CPU as the default set; a
        # restored one must still account for exactly the CPUs there are.
        def validate_state(state)
          assignments = state.assignments
          default = state.default_cpu_set
          all = @topology.cpu_details.cpus
          all = all.difference(@reserved_cpus) if @options.strict_cpu_reservation
          if default.empty?
            raise Error, "default cpuset cannot be empty" unless assignments.empty?

            state.default_cpu_set = all
            return
          end

          if @options.strict_cpu_reservation
            overlap = @reserved_cpus.intersection(default)
            unless overlap.empty?
              raise Error, "some of strictly reserved cpus: #{overlap.to_s.dump} are present in defaultCpuSet: #{default.to_s.dump}"
            end
          elsif @reserved_cpus.intersection(default) != @reserved_cpus
            raise Error, "not all reserved cpus: #{@reserved_cpus.to_s.dump} are present in defaultCpuSet: #{default.to_s.dump}"
          end
          assignments.each do |pod, containers|
            containers.each do |container, cpus|
              next if default.intersection(cpus).empty?

              raise Error,
                    "pod: #{pod}, container: #{container} cpuset: #{cpus.to_s.dump} overlaps with default cpuset #{default.to_s.dump}"
            end
          end
          known = default.union(*assignments.values.flat_map(&:values))
          known = known.union(*state.pod_cpu_sets.values) if @pod_level && state.respond_to?(:pod_cpu_sets)
          return if known == all

          raise Error, "current set of available CPUs #{all.to_s.dump} doesn't match with CPUs in state #{known.to_s.dump}"
        end

        def allocatable_cpus(_state = nil) = @topology.cpu_details.cpus.difference(@reserved_cpus)
        def available_cpus(state) = state.default_cpu_set.difference(@reserved_cpus)
        def available_physical_cpus(state) = state.default_cpu_set.difference(@reserved_physical_cpus)

        # Allocate.
        def allocate(state, pod, container)
          count = guaranteed_cpus(pod, container)
          return nil if count.zero?
          # PodLevelResourceManagers off: pod-level resources are not managed
          # at all.  On, a pod-scope admission already placed the container
          # (AllocatePod); a container-scope one allocates it here.
          return nil if PodResources.pod_level_resources?(pod) && !@pod_level

          metric(:increment, "kubelet_cpu_manager_pinning_requests_total")
          begin
            enforce_smt_alignment(state, count)
            pod_uid = PodResources.uid(pod)
            if (existing = state.cpu_set(pod_uid, container["name"]))
              update_cpus_to_reuse(pod, container, existing)
            else
              hint = @affinity ? @affinity.affinity(pod_uid, container["name"]) : TopologyManager::Hint.new(nil, false)
              cpus = allocate_cpus(state, count, hint.affinity, @cpus_to_reuse[pod_uid] || CPUSet.empty)
              state.set_cpu_set(pod_uid, container["name"], cpus)
              update_cpus_to_reuse(pod, container, cpus)
              update_metrics_on_allocate(state, cpus)
            end
          rescue StandardError
            metric(:increment, "kubelet_cpu_manager_pinning_errors_total")
            if @options.full_physical_cpus_only
              metric(:increment, "kubelet_container_aligned_compute_resources_failure_count",
                     ALIGNED_PHYSICAL_CPU)
            end
            raise
          end
          metric(:increment, "kubelet_container_aligned_compute_resources_count", ALIGNED_PHYSICAL_CPU) if @options.full_physical_cpus_only
          nil
        end

        # RemoveContainer: its CPUs go back to the shared pool, except those a
        # sibling still holds (an init container's, reused by an app one).
        def remove_container(state, pod_uid, container_name)
          released = state.cpu_set(pod_uid, container_name)
          return nil unless released

          state.delete(pod_uid, container_name)
          # A Pod's CPU bubble goes back as a whole, with its last container.
          if @pod_level && state.respond_to?(:pod_cpu_set) && (pod_cpus = state.pod_cpu_set(pod_uid))
            if (state.assignments[pod_uid.to_s] || {}).empty?
              state.default_cpu_set = state.default_cpu_set.union(pod_cpus)
              state.delete_pod(pod_uid)
              update_metrics_on_release(state, pod_cpus)
            end
            return nil
          end
          siblings = (state.assignments[pod_uid.to_s] || {}).values
          released = released.difference(CPUSet.empty.union(*siblings))
          state.default_cpu_set = state.default_cpu_set.union(released)
          update_metrics_on_release(state, released)
          nil
        end

        ALIGNED_PHYSICAL_CPU = {"scope" => "container", "boundary" => "physical_cpu"}.freeze
        ALIGNED_UNCORE_CACHE = {"scope" => "container", "boundary" => "uncore_cache"}.freeze

        # initializeMetrics.
        def initialize_metrics(state)
          return unless @metrics

          metric(:set, "kubelet_cpu_manager_shared_pool_size_millicores", available_cpus(state).size * 1000)
          metric(:touch, "kubelet_container_aligned_compute_resources_failure_count", ALIGNED_PHYSICAL_CPU)
          metric(:touch, "kubelet_container_aligned_compute_resources_count", ALIGNED_PHYSICAL_CPU)
          metric(:touch, "kubelet_container_aligned_compute_resources_count", ALIGNED_UNCORE_CACHE)
          assigned = assigned_exclusive_cpus(state)
          metric(:set, "kubelet_cpu_manager_exclusive_cpu_allocation_count", assigned.size)
          allocation_per_numa(assigned)
        end

        # updateMetricsOnAllocate.
        def update_metrics_on_allocate(state, cpus)
          return unless @metrics

          metric(:increment, "kubelet_cpu_manager_exclusive_cpu_allocation_count", {}, cpus.size)
          metric(:increment, "kubelet_cpu_manager_shared_pool_size_millicores", {}, -cpus.size * 1000)
          metric(:increment, "kubelet_container_aligned_compute_resources_count", ALIGNED_UNCORE_CACHE) if aligned_at_uncore_cache?(cpus)
          allocation_per_numa(assigned_exclusive_cpus(state))
        end

        # updateMetricsOnRelease.
        def update_metrics_on_release(state, cpus)
          return unless @metrics

          metric(:increment, "kubelet_cpu_manager_exclusive_cpu_allocation_count", {}, -cpus.size)
          metric(:increment, "kubelet_cpu_manager_shared_pool_size_millicores", {}, cpus.size * 1000)
          allocation_per_numa(assigned_exclusive_cpus(state).difference(cpus))
        end

        def assigned_exclusive_cpus(state)
          CPUSet.empty.union(*state.assignments.values.flat_map(&:values))
        end

        # updateAllocationPerNUMAMetric: only the NUMA nodes with a CPU are set.
        def allocation_per_numa(cpus)
          counts = Hash.new(0)
          cpus.each { |cpu| counts[@topology.cpu_details[cpu]&.numa_node_id.to_i] += 1 }
          counts.each { |numa, count| metric(:set, "kubelet_cpu_manager_allocation_per_numa", count, {"numa_node" => numa.to_s}) }
        end

        # isAlignedAtUncoreCache.
        def aligned_at_uncore_cache?(cpus)
          ids = cpus.to_a
          return true if ids.length <= 1

          reference = @topology.cpu_details[ids.first]
          return false unless reference

          ids.drop(1).all? { |cpu| @topology.cpu_details[cpu]&.uncore_cache_id == reference.uncore_cache_id }
        end

        # (:increment, name, labels, by) / (:set, name, value, labels) / (:touch, name, labels).
        def metric(kind, name, *arguments)
          return unless @metrics

          case kind
          when :increment
            labels, by = arguments
            @metrics.increment(name, labels || {}, by: by || 1)
          when :set then @metrics.set(name, arguments[0], arguments[1] || {})
          when :touch then @metrics.touch(name, arguments[0] || {})
          end
        rescue StandardError
          nil
        end

        # guaranteedCPUs.
        def guaranteed_cpus(pod, container)
          return 0 unless PodResources.qos(pod) == "Guaranteed"
          # A container of a pod-level Pod gets exclusive CPUs only when it is
          # Guaranteed on its own terms.
          return 0 if @pod_level && PodResources.pod_level_resources?(pod) && !PodResources.container_equivalent_guaranteed?(container)

          quantity = PodResources.cpu_request(container)
          return 0 if quantity.nil?

          PodResources.integral_cpus(quantity) || 0
        end

        # podGuaranteedCPUs.
        def pod_guaranteed_cpus(pod)
          # Pod-level resources: the Pod's own integral CPU request.
          if @pod_level && PodResources.pod_level_resources?(pod)
            return 0 unless PodResources.qos(pod) == "Guaranteed"

            request = pod.dig("spec", "resources", "requests", "cpu")
            return request.nil? ? 0 : (PodResources.integral_cpus(ResourceHelpers::Quantity.from_json(request.to_s)) || 0)
          end
          by_init = 0
          by_sidecars = 0
          Array(pod.dig("spec", "initContainers")).each do |container|
            next if container.dig("resources", "requests", "cpu").nil?

            requested = guaranteed_cpus(pod, container)
            if PodResources.restartable_init?(container)
              by_sidecars += requested
            elsif by_sidecars + requested > by_init
              by_init = by_sidecars + requested
            end
          end
          by_apps = Array(pod.dig("spec", "containers")).sum do |container|
            container.dig("resources", "requests", "cpu").nil? ? 0 : guaranteed_cpus(pod, container)
          end
          [by_init, by_apps + by_sidecars].max
        end

        def take_by_topology(available, count)
          strategy = @options.distribute_cpus_across_cores ? Assignment::SPREAD : Assignment::PACKED
          if @options.distribute_cpus_across_numa
            group = @options.full_physical_cpus_only ? @cpu_group_size : 1
            return Assignment.take_by_topology_numa_distributed(@topology, available, count, group, strategy: strategy)
          end

          Assignment.take_by_topology_numa_packed(@topology, available, count, strategy: strategy,
                                                                               prefer_align_by_uncore_cache: @options.prefer_align_by_uncore_cache)
        end

        # validatePodScopeResources: containers left for the Pod's shared
        # CPUs must have some.
        def validate_pod_scope_resources(pod)
          total = pod_guaranteed_cpus(pod)
          shared_long_running = false
          exclusive = 0
          Array(pod.dig("spec", "initContainers")).each do |container|
            cpus = guaranteed_cpus(pod, container)
            if !PodResources.restartable_init?(container)
              if cpus.zero? && exclusive >= total
                raise EmptyPodSharedPoolError, "pod rejected, pod has shared init containers but no cpus available for them"
              end
            elsif cpus.zero?
              shared_long_running = true
            else
              exclusive += cpus
            end
          end
          Array(pod.dig("spec", "containers")).each do |container|
            cpus = guaranteed_cpus(pod, container)
            cpus.zero? ? shared_long_running = true : exclusive += cpus
          end
          return unless shared_long_running && exclusive >= total

          raise EmptyPodSharedPoolError,
                "pod rejected, sum of exclusive container cpu requests equals pod budget, leaving no cpus for shared containers"
        end

        # AllocatePod: one CPU "bubble" for the Pod, partitioned among its
        # containers -- exclusive sets for the eligible ones (a sidecar's
        # stays taken, an init container's comes back), the rest of the
        # bubble shared by everyone else.
        def allocate_pod(state, pod)
          total = pod_guaranteed_cpus(pod)
          return nil if total.zero?

          begin
            validate_pod_scope_resources(pod)
            enforce_smt_alignment(state, total)
            pod_uid = PodResources.uid(pod)
            first = PodResources.containers(pod).first
            hint = @affinity ? @affinity.affinity(pod_uid, first && first["name"]) : TopologyManager::Hint.new(nil, false)
            bubble = allocate_cpus(state, total, hint.affinity, CPUSet.empty)
          rescue StandardError
            metric(:increment, "kubelet_cpu_manager_pinning_errors_total")
            raise
          end
          update_metrics_on_allocate(state, bubble)
          state.set_pod_cpu_set(pod_uid, bubble)
          exclusive = {}
          sidecars = CPUSet.empty
          Array(pod.dig("spec", "initContainers")).each do |container|
            count = guaranteed_cpus(pod, container)
            if count.positive?
              metric(:increment, "kubelet_cpu_manager_pinning_requests_total")
              cpus = take_by_topology(bubble.difference(sidecars), count)
              exclusive[container["name"]] = cpus
              sidecars = sidecars.union(cpus) if PodResources.restartable_init?(container)
            elsif !PodResources.restartable_init?(container)
              exclusive[container["name"]] = bubble.difference(sidecars)
            end
          end
          shared = bubble.difference(sidecars)
          Array(pod.dig("spec", "containers")).each do |container|
            count = guaranteed_cpus(pod, container)
            next unless count.positive?

            metric(:increment, "kubelet_cpu_manager_pinning_requests_total")
            cpus = take_by_topology(shared, count)
            exclusive[container["name"]] = cpus
            shared = shared.difference(cpus)
          end
          PodResources.containers(pod).each do |container|
            state.set_cpu_set(pod_uid, container["name"], exclusive.fetch(container["name"], shared))
          end
          nil
        end

        # GetTopologyHints.
        def topology_hints(state, pod, container)
          requested = guaranteed_cpus(pod, container)
          return nil if requested.zero?
          return nil if PodResources.pod_level_resources?(pod) && !@pod_level

          if (allocated = state.cpu_set(PodResources.uid(pod), container["name"]))
            return {"cpu" => []} if allocated.size != requested

            return {"cpu" => cpu_topology_hints(allocated, CPUSet.empty, requested)}
          end
          {"cpu" => cpu_topology_hints(available_cpus(state), @cpus_to_reuse[PodResources.uid(pod)] || CPUSet.empty, requested)}
        end

        # GetPodTopologyHints.
        def pod_topology_hints(state, pod)
          requested = pod_guaranteed_cpus(pod)
          return nil if requested.zero?
          return nil if PodResources.pod_level_resources?(pod) && !@pod_level

          if @pod_level && PodResources.pod_level_resources?(pod)
            begin
              validate_pod_scope_resources(pod)
            rescue EmptyPodSharedPoolError
              return {"cpu" => []}
            end
          end

          assigned = CPUSet.empty
          PodResources.containers(pod).each do |container|
            by_container = guaranteed_cpus(pod, container)
            allocated = state.cpu_set(PodResources.uid(pod), container["name"])
            next unless allocated
            return {"cpu" => []} if allocated.size != by_container

            assigned = assigned.union(allocated)
          end
          return {"cpu" => cpu_topology_hints(assigned, CPUSet.empty, requested)} if assigned.size == requested

          reusable = (@cpus_to_reuse[PodResources.uid(pod)] || CPUSet.empty).union(assigned)
          {"cpu" => cpu_topology_hints(available_cpus(state), reusable, requested)}
        end

        # generateCPUTopologyHints.
        def cpu_topology_hints(available, reusable, request)
          details = @topology.cpu_details
          min_affinity = details.numa_nodes.size
          hints = []
          TopologyManager::BitMask.iterate(details.numa_nodes.to_a) do |mask|
            in_mask = details.cpus_in_numa_nodes(*mask.bits).size
            min_affinity = mask.count if in_mask >= request && mask.count < min_affinity
            next unless reusable.all? { |cpu| mask.set?(details[cpu].numa_node_id) }

            matching = reusable.size + available.count { |cpu| mask.set?(details[cpu].numa_node_id) }
            next if matching < request

            hints << TopologyManager::Hint.new(mask, false)
          end
          hints.each do |hint|
            hint.preferred = true if @options.align_by_socket && hint_socket_aligned?(hint, min_affinity)
            hint.preferred = true if hint.affinity.count == min_affinity
          end
          hints
        end

        private

        def enforce_smt_alignment(state, count)
          return unless @options.full_physical_cpus_only
          raise SMTAlignmentError.new(requested: count, cpus_per_core: @cpu_group_size) unless (count % @cpu_group_size).zero?

          available = available_physical_cpus(state).size
          return if count <= available

          raise SMTAlignmentError.new(requested: count, cpus_per_core: @cpu_group_size, available_physical: available)
        end

        # updateCPUsToReuse: an init container's CPUs may be reused by the
        # containers after it; a sidecar's and an app container's may not.
        def update_cpus_to_reuse(pod, container, cpus)
          pod_uid = PodResources.uid(pod)
          @cpus_to_reuse.delete_if { |uid, _| uid != pod_uid }
          @cpus_to_reuse[pod_uid] ||= CPUSet.empty
          init = Array(pod.dig("spec", "initContainers")).find { |entry| entry["name"] == container["name"] }
          if init && !PodResources.restartable_init?(init)
            @cpus_to_reuse[pod_uid] = @cpus_to_reuse[pod_uid].union(cpus)
            return
          end
          @cpus_to_reuse[pod_uid] = @cpus_to_reuse[pod_uid].difference(cpus)
        end

        # allocateCPUs: the NUMA-aligned share first, the rest from anywhere.
        def allocate_cpus(state, count, numa_affinity, reusable)
          allocatable = available_cpus(state).union(reusable)
          result = CPUSet.empty
          if numa_affinity
            aligned = aligned_cpus(numa_affinity, allocatable)
            result = result.union(take_by_topology(aligned, [count, aligned.size].min))
          end
          result = result.union(take_by_topology(allocatable.difference(result), count - result.size))
          state.default_cpu_set = state.default_cpu_set.difference(result)
          result
        end

        def aligned_cpus(numa_affinity, allocatable)
          details = @topology.cpu_details
          if @options.align_by_socket
            sockets = details.sockets_in_numa_nodes(*numa_affinity.bits)
            return CPUSet.empty.union(*sockets.map { |socket| allocatable.intersection(details.cpus_in_sockets(socket)) })
          end

          CPUSet.empty.union(*numa_affinity.bits.map { |numa| allocatable.intersection(details.cpus_in_numa_nodes(numa)) })
        end

        def hint_socket_aligned?(hint, min_affinity)
          per_socket = @topology.num_numa_nodes / @topology.num_sockets
          return false if per_socket.zero?

          min_sockets = (min_affinity + per_socket - 1) / per_socket
          @topology.cpu_details.sockets_in_numa_nodes(*hint.affinity.bits).size == min_sockets
        end
      end
    end
  end
end
