# frozen_string_literal: true

require "thread"
require "time"

require_relative "../resource_helpers"
require_relative "../schema/quantity"

module Rubernetes
  module Node
    # pkg/kubelet/eviction (v1.36.2): the kubelet's eviction manager.
    #
    # Every housekeeping pass (synchronize) turns the Summary API into signal
    # observations (makeSignalObservations), finds the thresholds met -- hard
    # at once, soft once their grace period has run, a met threshold staying
    # met until its minimum reclaim is also satisfied -- reports the node
    # conditions they imply (MemoryPressure / DiskPressure / PIDPressure,
    # held for the pressure transition period), enforces local storage
    # limits (emptyDir sizeLimit, pod and container ephemeral-storage
    # limits), tries node-level reclaim, and otherwise evicts ONE Pod, the
    # first by the signal's ranking.  An evicted Pod goes Failed with reason
    # Evicted, the kubelet's message and a DisruptionTarget condition
    # (TerminationByKubelet).  While the node has a condition, Admit refuses
    # new Pods the way the eviction admit handler does.
    #
    # Thresholds are {signal:, quantity: or percentage:, grace_period:,
    # min_reclaim:}; ParseThresholdConfig (parse_threshold_config) builds
    # them from the kubelet's evictionHard / evictionSoft /
    # evictionSoftGracePeriod / evictionMinimumReclaim maps.
    class EvictionManager
      Quantity = Schema::Quantity

      REASON = "Evicted"
      NODE_LOW_MESSAGE_FMT = "The node was low on resource: %s. "
      NODE_CONDITION_MESSAGE_FMT = "The node had condition: %s. "
      CONTAINER_MESSAGE_FMT = "Container %s was using %s, request is %s, has larger consumption of %s. "
      POD_MESSAGE_FMT = "Pod %s was using %s, request is %s, has larger consumption of %s. "
      CONTAINER_EPHEMERAL_STORAGE_MESSAGE_FMT = "Container %s exceeded its local ephemeral storage limit %s. "
      POD_EPHEMERAL_STORAGE_MESSAGE_FMT = "Pod ephemeral local storage usage exceeds the total limit of containers %s. "
      EMPTY_DIR_MESSAGE_FMT = "Usage of EmptyDir volume %s exceeds the limit %s. "
      THRESHOLD_MET_MESSAGE_FMT = "Threshold quantity: %s, available: %s. "

      OFFENDING_CONTAINERS_KEY = "offending_containers"
      OFFENDING_CONTAINERS_USAGE_KEY = "offending_containers_usage"
      OFFENDING_POD_KEY = "offending_pod"
      OFFENDING_POD_USAGE_KEY = "offending_pod_usage"
      STARVED_RESOURCE_KEY = "starved_resource"

      IMMEDIATE_EVICTION_GRACE_PERIOD_SECONDS = 1
      # kubelet.go evictionMonitoringPeriod.
      MONITORING_PERIOD_SECONDS = 10.0
      # KubeletConfiguration defaults.
      DEFAULT_PRESSURE_TRANSITION_PERIOD = 300.0
      POD_CLEANUP_TIMEOUT = 30.0
      POD_CLEANUP_POLL = 1.0

      # eviction/defaults_linux.go DefaultEvictionHard.
      DEFAULT_EVICTION_HARD = {
        "memory.available" => "100Mi",
        "nodefs.available" => "10%",
        "nodefs.inodesFree" => "5%",
        "imagefs.available" => "15%",
        "imagefs.inodesFree" => "5%"
      }.freeze

      MEMORY_AVAILABLE = "memory.available"
      ALLOCATABLE_MEMORY_AVAILABLE = "allocatableMemory.available"
      NODEFS_AVAILABLE = "nodefs.available"
      NODEFS_INODES_FREE = "nodefs.inodesFree"
      IMAGEFS_AVAILABLE = "imagefs.available"
      IMAGEFS_INODES_FREE = "imagefs.inodesFree"
      CONTAINERFS_AVAILABLE = "containerfs.available"
      CONTAINERFS_INODES_FREE = "containerfs.inodesFree"
      PID_AVAILABLE = "pid.available"

      SIGNAL_TO_NODE_CONDITION = {
        MEMORY_AVAILABLE => "MemoryPressure", ALLOCATABLE_MEMORY_AVAILABLE => "MemoryPressure",
        IMAGEFS_AVAILABLE => "DiskPressure", CONTAINERFS_AVAILABLE => "DiskPressure", NODEFS_AVAILABLE => "DiskPressure",
        IMAGEFS_INODES_FREE => "DiskPressure", NODEFS_INODES_FREE => "DiskPressure", CONTAINERFS_INODES_FREE => "DiskPressure",
        PID_AVAILABLE => "PIDPressure"
      }.freeze
      SIGNAL_TO_RESOURCE = {
        MEMORY_AVAILABLE => "memory", ALLOCATABLE_MEMORY_AVAILABLE => "memory",
        IMAGEFS_AVAILABLE => "ephemeral-storage", IMAGEFS_INODES_FREE => "inodes",
        CONTAINERFS_AVAILABLE => "ephemeral-storage", CONTAINERFS_INODES_FREE => "inodes",
        NODEFS_AVAILABLE => "ephemeral-storage", NODEFS_INODES_FREE => "inodes",
        PID_AVAILABLE => "pids"
      }.freeze
      # Byte signals are BinarySI quantities, counts DecimalSI.
      DECIMAL_SIGNALS = [NODEFS_INODES_FREE, IMAGEFS_INODES_FREE, CONTAINERFS_INODES_FREE, PID_AVAILABLE].freeze

      # scheduling.SystemCriticalPriority.
      SYSTEM_CRITICAL_PRIORITY = 2 * 1_000_000_000

      class ConfigError < ArgumentError; end

      # +quantity+ is the threshold's Quantity or nil, +percentage+ a
      # fraction of capacity (0..1); +grace_period+ seconds (0 = hard).
      Threshold = Data.define(:signal, :quantity, :percentage, :grace_period, :min_reclaim) do
        def initialize(signal:, quantity: nil, percentage: 0.0, grace_period: 0.0, min_reclaim: nil)
          super(signal: signal.to_s, quantity: quantity, percentage: Float(percentage), grace_period: Float(grace_period),
                min_reclaim: min_reclaim)
        end

        def hard? = grace_period.zero?
      end

      # A minimum reclaim is a Quantity or a percentage.
      ThresholdValue = Data.define(:quantity, :percentage)

      Observation = Data.define(:available, :capacity, :time)

      # ParseThresholdConfig.
      def self.parse_threshold_config(hard: DEFAULT_EVICTION_HARD, soft: {}, soft_grace_period: {}, minimum_reclaim: {},
                                      allocatable_config: ["pods"])
        results = parse_statements(hard || {})
        soft_thresholds = parse_statements(soft || {})
        grace = (soft_grace_period || {}).to_h { |signal, value| [signal.to_s, parse_duration(value)] }
        reclaims = (minimum_reclaim || {}).to_h { |signal, value| [signal.to_s, parse_value(signal.to_s, value.to_s)] }
        soft_thresholds = soft_thresholds.map do |threshold|
          period = grace[threshold.signal]
          raise ConfigError, "grace period must be specified for the soft eviction threshold #{threshold.signal}" if period.nil?

          threshold.with(grace_period: period)
        end
        results = (results + soft_thresholds).map do |threshold|
          reclaims.key?(threshold.signal) ? threshold.with(min_reclaim: reclaims[threshold.signal]) : threshold
        end
        results = add_allocatable_thresholds(results) if Array(allocatable_config).map(&:to_s).include?("pods")
        results
      end

      def self.parse_statements(statements)
        statements.filter_map do |signal, value|
          signal = signal.to_s
          raise ConfigError, "unsupported eviction signal #{signal}" unless SIGNAL_TO_RESOURCE.key?(signal)

          value = value.to_s
          if value.end_with?("%")
            next nil if %w[0% 100%].include?(value)

            Threshold.new(signal: signal, percentage: percentage(signal, value))
          else
            quantity = Quantity.parse(value)
            raise ConfigError, "eviction threshold #{signal} must be positive: #{quantity}" unless quantity.value.positive?

            Threshold.new(signal: signal, quantity: quantity)
          end
        end
      end

      def self.parse_value(signal, value)
        return ThresholdValue.new(quantity: nil, percentage: percentage(signal, value)) if value.end_with?("%")

        quantity = Quantity.parse(value)
        raise ConfigError, "negative reclaim defined for #{signal}: #{quantity}" if quantity.negative?

        ThresholdValue.new(quantity: quantity, percentage: 0.0)
      end

      # parsePercentage: float32(ParseFloat(s, 32)) / 100 in float32 -- so
      # "10%" is 0.10000000149..., and a percentage of a capacity comes out
      # as upstream's (one float32 rounding of a quotient of float32s equals
      # the float32 division).
      def self.percentage(signal, value)
        fraction = float32(float32(Float(value.delete_suffix("%"))) / 100.0)
        raise ConfigError, "eviction percentage threshold #{signal} must be >= 0%: #{value}" if fraction.negative?
        raise ConfigError, "eviction percentage threshold #{signal} must be <= 100%: #{value}" if fraction > 1

        fraction
      end

      def self.float32(value) = [value].pack("f").unpack1("f")

      def self.parse_duration(value)
        return Float(value) if value.is_a?(Numeric)

        total = 0.0
        text = value.to_s
        matched = text.scan(/(\d+(?:\.\d+)?)(h|ms|m|s)/)
        raise ConfigError, "invalid duration #{text}" if matched.empty? || matched.map(&:join).join != text

        matched.each { |number, unit| total += Float(number) * {"h" => 3600, "m" => 60, "s" => 1, "ms" => 0.001}.fetch(unit) }
        raise ConfigError, "invalid eviction grace period #{text}" if total.negative?

        total
      end

      # addAllocatableThresholds.
      def self.add_allocatable_thresholds(thresholds)
        extra = thresholds.select { |threshold| threshold.signal == MEMORY_AVAILABLE && threshold.hard? }.map do |threshold|
          Threshold.new(signal: ALLOCATABLE_MEMORY_AVAILABLE, quantity: threshold.quantity, percentage: threshold.percentage,
                        min_reclaim: threshold.min_reclaim)
        end
        thresholds + extra
      end

      # UpdateContainerFsThresholds: containerfs follows nodefs, or imagefs
      # when only the images are on a separate filesystem.
      def self.update_container_fs_thresholds(thresholds, image_fs:, split_container_fs: false)
        source_available, source_inodes = if image_fs && !split_container_fs
                                            [IMAGEFS_AVAILABLE, IMAGEFS_INODES_FREE]
                                          elsif image_fs == split_container_fs
                                            [NODEFS_AVAILABLE, NODEFS_INODES_FREE]
                                          end
        return thresholds unless source_available

        kept = thresholds.reject { |threshold| [CONTAINERFS_AVAILABLE, CONTAINERFS_INODES_FREE].include?(threshold.signal) }
        derived = {CONTAINERFS_AVAILABLE => source_available, CONTAINERFS_INODES_FREE => source_inodes}.flat_map do |target, source|
          [true, false].map do |hard|
            origin = thresholds.find { |threshold| threshold.signal == source && threshold.hard? == hard }
            if origin
              Threshold.new(signal: target, quantity: origin.quantity, percentage: origin.percentage,
                            grace_period: hard ? 0 : origin.grace_period, min_reclaim: origin.min_reclaim)
            else
              # Upstream appends a zero-valued threshold, which can never be met.
              Threshold.new(signal: target)
            end
          end
        end
        kept + derived
      end

      # +summary_provider+: #summary -> stats/v1alpha1 Summary hash.
      # +active_pods+: -> [pod] (the kubelet's allocated, not yet terminated Pods).
      # +kill_pod+: (pod, grace_period_seconds:, message:, condition:) -> truthy.
      # +pod_cleaned_up+: (pod) -> true once its resources are released.
      # +node_reclaim+: {signal => [callable]} node-level reclaim (image and
      # container GC) tried before any Pod is evicted.
      def initialize(summary_provider:, active_pods:, kill_pod:, thresholds: nil, pressure_transition_period: DEFAULT_PRESSURE_TRANSITION_PERIOD,
                     max_pod_grace_period_seconds: 0, local_storage_capacity_isolation: true, dedicated_image_fs: nil,
                     split_container_fs: false, node_reclaim: {}, recorder: nil, node_ref: nil, pod_cleaned_up: nil,
                     clock: -> { Time.now.utc }, monotonic: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                     sleeper: ->(seconds) { sleep(seconds) }, error_handler: nil, on_conditions_changed: nil)
        @summary_provider = summary_provider
        @active_pods = active_pods
        @kill_pod = kill_pod
        @on_eviction = nil
        @configured_thresholds = thresholds || self.class.parse_threshold_config
        @thresholds = nil
        @pressure_transition_period = Float(pressure_transition_period)
        @max_pod_grace_period_seconds = Integer(max_pod_grace_period_seconds)
        @local_storage_capacity_isolation = local_storage_capacity_isolation
        @dedicated_image_fs = dedicated_image_fs
        @split_container_fs = split_container_fs
        @node_reclaim = (node_reclaim || {}).to_h { |signal, funcs| [signal.to_s, Array(funcs)] }
        @recorder = recorder
        @node_ref = node_ref
        @pod_cleaned_up = pod_cleaned_up
        @clock = clock
        @monotonic = monotonic
        @sleeper = sleeper
        @error_handler = error_handler
        @on_conditions_changed = on_conditions_changed
        @mutex = Mutex.new
        @node_conditions = []
        @thresholds_first_observed_at = {}
        @node_conditions_last_observed_at = {}
        @thresholds_met = []
        @last_observations = {}
        @thread = nil
        @stop = false
      end

      attr_reader :configured_thresholds
      # kubelet_evictions: called with the signal of each eviction.
      attr_writer :on_eviction
      # ->(signal, seconds): how old the stats behind a threshold used for an
      # eviction were (kubelet_eviction_stats_age_seconds).
      attr_writer :on_stats_age

      def thresholds
        @mutex.synchronize { (@thresholds || @configured_thresholds).dup }
      end

      def node_conditions
        @mutex.synchronize { @node_conditions.dup }
      end

      def under_memory_pressure? = node_conditions.include?("MemoryPressure")
      def under_disk_pressure? = node_conditions.include?("DiskPressure")
      def under_pid_pressure? = node_conditions.include?("PIDPressure")

      # The eviction admit handler: [reason, message] to refuse the Pod, nil
      # to admit it.
      def admit(pod)
        conditions = node_conditions
        return nil if conditions.empty? || critical_pod?(pod)

        if conditions == ["MemoryPressure"]
          return nil unless ResourceHelpers.qos_class(pod) == "BestEffort"
          return nil if tolerates_memory_pressure?(pod)
        end
        [REASON, format(NODE_CONDITION_MESSAGE_FMT, "[#{conditions.join(" ")}]")]
      end

      # One housekeeping pass: the Pods it evicted.
      def synchronize
        configured = @configured_thresholds
        return [] if configured.empty? && !@local_storage_capacity_isolation

        prepare_thresholds
        thresholds = @mutex.synchronize { @thresholds }
        active = Array(@active_pods.call)
        summary = @summary_provider.summary
        observations, stats = make_signal_observations(summary)

        met = thresholds_met(thresholds, observations, enforce_min_reclaim: false)
        previously_met = @mutex.synchronize { @thresholds_met }
        met = merge_thresholds(met, thresholds_met(previously_met, observations, enforce_min_reclaim: true)) unless previously_met.empty?

        now = @monotonic.call
        first_observed = @mutex.synchronize { @thresholds_first_observed_at }
        first_observed = met.to_h { |threshold| [threshold, first_observed.fetch(threshold, now)] }
        conditions = node_conditions_for(met)
        last_observed = @mutex.synchronize { @node_conditions_last_observed_at }
        last_observed = conditions.to_h { |condition| [condition, now] }.merge(last_observed.reject { |key, _| conditions.include?(key) })
        conditions = last_observed.select { |_condition, at| now - at < @pressure_transition_period }.keys
        met = first_observed.select { |threshold, at| now - at >= threshold.grace_period }.keys

        changed = false
        updated = @mutex.synchronize do
          changed = @node_conditions.sort != conditions.sort
          @node_conditions = sort_conditions(conditions)
          @thresholds_first_observed_at = first_observed
          @node_conditions_last_observed_at = last_observed
          @thresholds_met = met
          fresh = thresholds_updated_stats(met, observations, @last_observations)
          @last_observations = observations
          fresh
        end
        notify_conditions if changed

        if @local_storage_capacity_isolation
          evicted = local_storage_eviction(active, stats)
          return evicted unless evicted.empty?
        end
        return [] if updated.empty?

        updated = sort_by_eviction_priority(updated)
        threshold = updated.find { |candidate| SIGNAL_TO_RESOURCE.key?(candidate.signal) }
        return [] unless threshold

        resource = SIGNAL_TO_RESOURCE.fetch(threshold.signal)
        record_node_event("Warning", "EvictionThresholdMet", "Attempting to reclaim #{resource}")
        return [] if reclaim_node_level_resources(threshold.signal)
        return [] if active.empty?

        ranked = rank(threshold.signal, active, stats)
        record_stats_age(updated, observations)
        ranked.each do |pod|
          grace = IMMEDIATE_EVICTION_GRACE_PERIOD_SECONDS
          unless threshold.hard?
            grace = @max_pod_grace_period_seconds
            spec_grace = pod.dig("spec", "terminationGracePeriodSeconds")
            grace = [@max_pod_grace_period_seconds, Integer(spec_grace)].min unless spec_grace.nil?
          end
          message, annotations = eviction_message(resource, pod, stats, updated, observations)
          condition = {"type" => "DisruptionTarget", "status" => "True", "reason" => "TerminationByKubelet", "message" => message,
                       "observedGeneration" => pod.dig("metadata", "generation")}.compact
          return [pod] if evict_pod(pod, grace, message, annotations, condition, signal: threshold.signal)
        end
        []
      end

      # Start: a pass every +interval+ seconds; after an eviction, wait (up
      # to 30s) for the evicted Pods to be cleaned up before the next one.
      def start(interval: MONITORING_PERIOD_SECONDS)
        @mutex.synchronize do
          return self if @thread&.alive?

          @stop = false
          @thread = Thread.new do
            until @mutex.synchronize { @stop }
              evicted = begin
                synchronize
              rescue StandardError => error
                @error_handler&.call(error, :eviction)
                []
              end
              if evicted.empty?
                pause(interval)
              else
                wait_for_pods_cleanup(evicted)
              end
            end
          end
        end
        self
      end

      def stop
        thread = @mutex.synchronize do
          @stop = true
          @thread
        end
        thread&.wakeup rescue nil
        thread&.join(5) unless thread == Thread.current
        self
      end

      # makeSignalObservations: [{signal => Observation}, {uid => pod stats}].
      def record_stats_age(thresholds, observations)
        return unless @on_stats_age

        now = @clock.call
        thresholds.each do |candidate|
          observed = observations[candidate.signal]&.time
          next if observed.nil? || observed.to_s.empty?

          at = observed.is_a?(Time) ? observed : Time.parse(observed.to_s)
          @on_stats_age.call(candidate.signal.to_s, now - at)
        end
      rescue StandardError
        nil
      end

      def make_signal_observations(summary)
        summary ||= {}
        node = summary["node"] || {}
        stats = Array(summary["pods"]).to_h { |pod| [pod.dig("podRef", "uid").to_s, pod] }
        result = {}
        memory = node["memory"]
        if memory && memory["availableBytes"] && memory["workingSetBytes"]
          result[MEMORY_AVAILABLE] = Observation.new(available: memory["availableBytes"].to_i,
                                                     capacity: memory["availableBytes"].to_i + memory["workingSetBytes"].to_i,
                                                     time: memory["time"])
        end
        pods_container = Array(node["systemContainers"]).find { |container| container["name"] == "pods" }
        allocatable = pods_container && pods_container["memory"]
        if allocatable && allocatable["availableBytes"] && allocatable["workingSetBytes"]
          result[ALLOCATABLE_MEMORY_AVAILABLE] = Observation.new(available: allocatable["availableBytes"].to_i,
                                                                 capacity: allocatable["availableBytes"].to_i + allocatable["workingSetBytes"].to_i,
                                                                 time: allocatable["time"])
        end
        add_fs_observations(result, node["fs"], NODEFS_AVAILABLE, NODEFS_INODES_FREE)
        runtime = node["runtime"] || {}
        add_fs_observations(result, runtime["imageFs"], IMAGEFS_AVAILABLE, IMAGEFS_INODES_FREE)
        add_fs_observations(result, runtime["containerFs"], CONTAINERFS_AVAILABLE, CONTAINERFS_INODES_FREE)
        rlimit = node["rlimit"]
        if rlimit && rlimit["curproc"] && rlimit["maxpid"]
          result[PID_AVAILABLE] = Observation.new(available: rlimit["maxpid"].to_i - rlimit["curproc"].to_i,
                                                  capacity: rlimit["maxpid"].to_i, time: rlimit["time"])
        end
        [result, stats]
      end

      # thresholdsMet.
      def thresholds_met(thresholds, observations, enforce_min_reclaim:)
        thresholds.select do |threshold|
          observed = observations[threshold.signal]
          next false unless observed

          quantity = threshold_quantity(threshold.quantity, threshold.percentage, observed.capacity)
          if enforce_min_reclaim && threshold.min_reclaim
            quantity += threshold_quantity(threshold.min_reclaim.quantity, threshold.min_reclaim.percentage, observed.capacity)
          end
          quantity > observed.available
        end
      end

      # The rank function for +signal+ (buildSignalToRankFunc): +pods+ in
      # eviction order.
      def rank(signal, pods, stats)
        comparators = case signal
                      when MEMORY_AVAILABLE, ALLOCATABLE_MEMORY_AVAILABLE
                        [exceed_memory_requests(stats), method(:priority_cmp), memory_cmp(stats)]
                      when PID_AVAILABLE
                        [method(:priority_cmp), process_cmp(stats)]
                      else
                        fs_types, resource = disk_rank_config(signal)
                        return pods.dup unless fs_types

                        [exceed_disk_requests(stats, fs_types, resource), method(:priority_cmp), disk_cmp(stats, fs_types, resource)]
                      end
        # multiSorter; ties keep input order.
        pods.each_with_index.sort do |(left, left_index), (right, right_index)|
          result = 0
          comparators.each do |comparator|
            result = comparator.call(left, right)
            break unless result.zero?
          end
          result.zero? ? left_index <=> right_index : result
        end.map(&:first)
      end

      private

      def prepare_thresholds
        @mutex.synchronize do
          return if @thresholds

          image_fs = @dedicated_image_fs.respond_to?(:call) ? @dedicated_image_fs.call : @dedicated_image_fs
          @dedicated_image_fs = image_fs ? true : false
          @thresholds = self.class.update_container_fs_thresholds(@configured_thresholds, image_fs: @dedicated_image_fs,
                                                                                         split_container_fs: @split_container_fs)
        end
      end

      def add_fs_observations(result, fs, bytes_signal, inodes_signal)
        return unless fs.is_a?(Hash)

        if fs["availableBytes"] && fs["capacityBytes"]
          result[bytes_signal] = Observation.new(available: fs["availableBytes"].to_i, capacity: fs["capacityBytes"].to_i, time: fs["time"])
        end
        return unless fs["inodesFree"] && fs["inodes"]

        result[inodes_signal] = Observation.new(available: fs["inodesFree"].to_i, capacity: fs["inodes"].to_i, time: fs["time"])
      end

      # evictionapi.GetThresholdQuantity (an integer, truncated like int64()).
      def threshold_quantity(quantity, percentage, capacity)
        return quantity.value.ceil if quantity

        (capacity.to_f * percentage).to_i
      end

      def merge_thresholds(left, right)
        left + right.reject { |threshold| left.include?(threshold) }
      end

      def node_conditions_for(thresholds)
        thresholds.filter_map { |threshold| SIGNAL_TO_NODE_CONDITION[threshold.signal] }.uniq
      end

      def sort_conditions(conditions)
        order = %w[MemoryPressure DiskPressure PIDPressure]
        conditions.uniq.sort_by { |condition| order.index(condition) || order.length }
      end

      # thresholdsUpdatedStats: only thresholds whose observation is newer
      # than the last pass's act (no eviction on a stale sample).
      def thresholds_updated_stats(thresholds, observations, last_observations)
        thresholds.select do |threshold|
          observed = observations[threshold.signal]
          next false unless observed

          last = last_observations[threshold.signal]
          last.nil? || observed.time.nil? || last.time.nil? || parse_time(observed.time) > parse_time(last.time)
        end
      end

      # byEvictionPriority: memory first, thresholds with no resource last.
      def sort_by_eviction_priority(thresholds)
        memory, rest = thresholds.partition { |threshold| [MEMORY_AVAILABLE, ALLOCATABLE_MEMORY_AVAILABLE].include?(threshold.signal) }
        with_resource, without = rest.partition { |threshold| SIGNAL_TO_RESOURCE.key?(threshold.signal) }
        memory + with_resource + without
      end

      def reclaim_node_level_resources(signal)
        funcs = @node_reclaim.fetch(signal, [])
        return false if funcs.empty?

        funcs.each do |func|
          func.call
        rescue StandardError => error
          @error_handler&.call(error, :eviction_reclaim)
        end
        observations, = make_signal_observations(@summary_provider.summary)
        thresholds_met(@mutex.synchronize { @thresholds }, observations, enforce_min_reclaim: true).empty?
      rescue StandardError => error
        @error_handler&.call(error, :eviction_reclaim)
        false
      end

      # --------------------------------------------------- local storage

      def local_storage_eviction(pods, stats)
        pods.select do |pod|
          pod_stats = stats[pod.dig("metadata", "uid").to_s]
          next false unless pod_stats

          empty_dir_limit_eviction(pod_stats, pod) || pod_ephemeral_storage_limit_eviction(pod_stats, pod) ||
            container_ephemeral_storage_limit_eviction(pod_stats, pod)
        end
      end

      def empty_dir_limit_eviction(pod_stats, pod)
        used = Array(pod_stats["volume"]).to_h { |volume| [volume["name"].to_s, volume["usedBytes"].to_i] }
        Array(pod.dig("spec", "volumes")).each do |volume|
          empty_dir = volume["emptyDir"]
          next unless empty_dir.is_a?(Hash) && empty_dir["sizeLimit"]

          size = Quantity.from_json(empty_dir["sizeLimit"])
          usage = used[volume["name"].to_s]
          next unless usage && size.value.positive? && usage > size.value

          return evict_pod(pod, IMMEDIATE_EVICTION_GRACE_PERIOD_SECONDS,
                           format(EMPTY_DIR_MESSAGE_FMT, go_quote(volume["name"].to_s), go_quote(size.to_s)), nil, nil,
                           signal: "emptydirfs.limit")
        end
        false
      rescue Quantity::ParseError
        false
      end

      def pod_ephemeral_storage_limit_eviction(pod_stats, pod)
        limit = ResourceHelpers.pod_limits(pod)["ephemeral-storage"]
        return false unless limit

        usage = pod_stats.dig("ephemeral-storage", "usedBytes").to_i
        return false unless usage > limit.value

        evict_pod(pod, IMMEDIATE_EVICTION_GRACE_PERIOD_SECONDS, format(POD_EPHEMERAL_STORAGE_MESSAGE_FMT, limit.to_s), nil, nil,
                  signal: "ephemeralpodfs.limit")
      end

      def container_ephemeral_storage_limit_eviction(pod_stats, pod)
        limits = Array(pod.dig("spec", "containers")).each_with_object({}) do |container, result|
          value = container.dig("resources", "limits", "ephemeral-storage")
          next if value.nil?

          quantity = Quantity.from_json(value)
          result[container["name"].to_s] = quantity unless quantity.zero?
        rescue Quantity::ParseError
          nil
        end
        Array(pod_stats["containers"]).each do |container|
          used = container.dig("logs", "usedBytes").to_i
          used += container.dig("rootfs", "usedBytes").to_i unless @dedicated_image_fs
          limit = limits[container["name"].to_s]
          next unless limit && limit.value < used

          return evict_pod(pod, IMMEDIATE_EVICTION_GRACE_PERIOD_SECONDS,
                           format(CONTAINER_EPHEMERAL_STORAGE_MESSAGE_FMT, container["name"], go_quote(limit.to_s)), nil, nil,
                           signal: "ephemeralcontainerfs.limit")
        end
        false
      end

      # --------------------------------------------------------- ranking

      # cmpBool: true sorts first.
      def cmp_bool(left, right)
        return 0 if left == right

        left ? -1 : 1
      end

      # Both found, or the one without stats first.
      def with_stats(stats, left, right)
        left_stats = stats[left.dig("metadata", "uid").to_s]
        right_stats = stats[right.dig("metadata", "uid").to_s]
        return cmp_bool(left_stats.nil?, right_stats.nil?) if left_stats.nil? || right_stats.nil?

        yield left_stats, right_stats
      end

      def exceed_memory_requests(stats)
        lambda do |left, right|
          with_stats(stats, left, right) do |left_stats, right_stats|
            cmp_bool(memory_usage(left_stats) > request_quantity(left, "memory"),
                     memory_usage(right_stats) > request_quantity(right, "memory"))
          end
        end
      end

      def memory_cmp(stats)
        lambda do |left, right|
          with_stats(stats, left, right) do |left_stats, right_stats|
            (memory_usage(right_stats) - request_quantity(right, "memory")) <=> (memory_usage(left_stats) - request_quantity(left, "memory"))
          end
        end
      end

      def process_cmp(stats)
        lambda do |left, right|
          with_stats(stats, left, right) do |left_stats, right_stats|
            right_stats.dig("process_stats", "process_count").to_i <=> left_stats.dig("process_stats", "process_count").to_i
          end
        end
      end

      def exceed_disk_requests(stats, fs_types, resource)
        lambda do |left, right|
          with_stats(stats, left, right) do |left_stats, right_stats|
            cmp_bool(pod_disk_usage(left_stats, left, fs_types)[resource] > request_quantity(left, resource),
                     pod_disk_usage(right_stats, right, fs_types)[resource] > request_quantity(right, resource))
          end
        end
      end

      # Upstream subtracts the ephemeral-storage request for inodes too.
      def disk_cmp(stats, fs_types, resource)
        lambda do |left, right|
          with_stats(stats, left, right) do |left_stats, right_stats|
            (pod_disk_usage(right_stats, right, fs_types)[resource] - request_quantity(right, "ephemeral-storage")) <=>
              (pod_disk_usage(left_stats, left, fs_types)[resource] - request_quantity(left, "ephemeral-storage"))
          end
        end
      end

      # corev1helpers.PodPriority: lower priority sorts first.
      def priority_cmp(left, right)
        pod_priority(left) <=> pod_priority(right)
      end

      def pod_priority(pod)
        Integer(pod.dig("spec", "priority") || 0)
      rescue ArgumentError, TypeError
        0
      end

      def disk_rank_config(signal)
        all = %i[images root logs local_volume]
        types = if @dedicated_image_fs && !@split_container_fs
                  {NODEFS_AVAILABLE => %i[logs local_volume], NODEFS_INODES_FREE => %i[logs local_volume],
                   IMAGEFS_AVAILABLE => %i[root images], IMAGEFS_INODES_FREE => %i[root images],
                   CONTAINERFS_AVAILABLE => %i[root images], CONTAINERFS_INODES_FREE => %i[root images]}
                elsif @dedicated_image_fs
                  {NODEFS_AVAILABLE => %i[logs local_volume root], NODEFS_INODES_FREE => %i[logs local_volume root],
                   CONTAINERFS_AVAILABLE => %i[logs local_volume root], CONTAINERFS_INODES_FREE => %i[logs local_volume root],
                   IMAGEFS_AVAILABLE => %i[images], IMAGEFS_INODES_FREE => %i[images]}
                else
                  [NODEFS_AVAILABLE, NODEFS_INODES_FREE, IMAGEFS_AVAILABLE, IMAGEFS_INODES_FREE,
                   CONTAINERFS_AVAILABLE, CONTAINERFS_INODES_FREE].to_h { |candidate| [candidate, all] }
                end
        fs_types = types[signal]
        return nil unless fs_types

        [fs_types, SIGNAL_TO_RESOURCE.fetch(signal)]
      end

      def memory_usage(pod_stats)
        pod_stats.dig("memory", "workingSetBytes").to_i
      end

      # podDiskUsage: {"ephemeral-storage" => bytes, "inodes" => count}.
      def pod_disk_usage(pod_stats, pod, fs_types)
        disk = 0
        inodes = 0
        Array(pod_stats["containers"]).each do |container|
          parts = []
          parts << container["rootfs"] if fs_types.include?(:root)
          parts << container["logs"] if fs_types.include?(:logs)
          parts.compact.each do |fs|
            disk += fs["usedBytes"].to_i
            inodes += fs["inodesUsed"].to_i
          end
        end
        if fs_types.include?(:local_volume)
          names = local_volume_names(pod)
          Array(pod_stats["volume"]).each do |volume|
            next unless names.include?(volume["name"].to_s)

            disk += volume["usedBytes"].to_i
            inodes += volume["inodesUsed"].to_i
          end
        end
        {"ephemeral-storage" => disk, "inodes" => inodes}
      end

      # localVolumeNames: hostPath and local ephemeral volumes (emptyDir not
      # on memory, gitRepo, configMap, downwardAPI, secret).
      def local_volume_names(pod)
        Array(pod.dig("spec", "volumes")).filter_map do |volume|
          local = volume["hostPath"] ||
                  (volume["emptyDir"].is_a?(Hash) && volume["emptyDir"]["medium"].to_s != "Memory") ||
                  volume["gitRepo"] || volume["configMap"] || volume["downwardAPI"] || volume["secret"]
          volume["name"].to_s if local
        end
      end

      # v1resource.GetResourceRequestQuantity (integer value).
      def request_quantity(pod, resource)
        helpers = ResourceHelpers
        requests = helpers.pod_requests(pod, exclude_overhead: true, skip_container_level: helpers.pod_level_resources_set?(pod))
        value = requests[resource] ? requests[resource].value : Rational(0)
        overhead = helpers.resource_list(helpers.spec(pod)["overhead"])[resource]
        value += overhead.value if overhead && !value.zero?
        value.ceil
      end

      # ------------------------------------------------------ evicting

      # evictionMessage: [message, annotations].
      def eviction_message(resource, pod, stats, thresholds, observations)
        annotations = {}
        message = format(NODE_LOW_MESSAGE_FMT, resource)
        threshold = thresholds.find { |candidate| SIGNAL_TO_RESOURCE[candidate.signal] == resource && observations[candidate.signal] }
        if threshold
          observed = observations[threshold.signal]
          message += format(THRESHOLD_MET_MESSAGE_FMT, quantity_string(threshold, observed),
                            format_quantity(observed.available, threshold.signal))
        end
        pod_stats = stats[pod.dig("metadata", "uid").to_s]
        return [message, annotations] unless pod_stats

        if resource == "memory" && ResourceHelpers.pod_level_resources_set?(pod)
          request = pod.dig("spec", "resources", "requests", "memory")
          if request && pod_stats["memory"]
            usage = binary(memory_usage(pod_stats))
            message += format(POD_MESSAGE_FMT, pod.dig("metadata", "name"), usage, request_string(request), resource)
            annotations[OFFENDING_POD_KEY] = pod.dig("metadata", "name").to_s
            annotations[OFFENDING_POD_USAGE_KEY] = usage
          end
        end
        containers = Array(pod.dig("spec", "containers")) + Array(pod.dig("spec", "initContainers"))
        exceeded = []
        usages = []
        Array(pod_stats["containers"]).each do |container_stats|
          container = containers.find { |candidate| candidate["name"] == container_stats["name"] }
          next unless container

          request = container.dig("resources", "requests", resource)
          request_value = request.nil? ? 0 : (Quantity.from_json(request).value rescue 0)
          usage = case resource
                  when "ephemeral-storage"
                    rootfs = container_stats.dig("rootfs", "usedBytes")
                    logs = container_stats.dig("logs", "usedBytes")
                    rootfs && logs ? rootfs.to_i + logs.to_i : nil
                  when "memory"
                    container_stats.dig("memory", "workingSetBytes")&.to_i
                  end
          next unless usage && usage > request_value

          message += format(CONTAINER_MESSAGE_FMT, container["name"], binary(usage), request_string(request), resource)
          exceeded << container["name"].to_s
          usages << binary(usage)
        end
        annotations[OFFENDING_CONTAINERS_KEY] = exceeded.join(",")
        annotations[OFFENDING_CONTAINERS_USAGE_KEY] = usages.join(",")
        annotations[STARVED_RESOURCE_KEY] = resource
        [message, annotations]
      end

      # evictPod: refuses critical Pods; otherwise records the Evicted event
      # and has the Pod killed Failed/Evicted.  True once the kill was asked
      # for, whether or not it succeeded (as upstream).
      def evict_pod(pod, grace, message, annotations, condition, signal: nil)
        return false if critical_pod?(pod)

        record_pod_event(pod, message, annotations)
        begin
          @kill_pod.call(pod, grace_period_seconds: grace, message: message, condition: condition)
        rescue StandardError => error
          @error_handler&.call(error, :eviction_kill)
        end
        # metrics.Evictions by signal.
        begin
          @on_eviction&.call(signal.to_s) if signal
        rescue StandardError
          nil
        end
        true
      end

      # kubelettypes.IsCriticalPod: static, mirror, or system-critical priority.
      def critical_pod?(pod)
        annotations = pod.dig("metadata", "annotations") || {}
        source = annotations["kubernetes.io/config.source"]
        return true if source && source != "api"
        return true if annotations.key?("kubernetes.io/config.mirror")

        priority = pod.dig("spec", "priority")
        !priority.nil? && Integer(priority) >= SYSTEM_CRITICAL_PRIORITY
      rescue ArgumentError, TypeError
        false
      end

      def tolerates_memory_pressure?(pod)
        Array(pod.dig("spec", "tolerations")).any? do |toleration|
          effect = toleration["effect"].to_s
          next false unless effect.empty? || effect == "NoSchedule"

          key = toleration["key"].to_s
          operator = toleration["operator"].to_s
          operator = "Equal" if operator.empty?
          if key.empty?
            operator == "Exists"
          else
            key == "node.kubernetes.io/memory-pressure" && (operator == "Exists" || toleration["value"].to_s.empty?)
          end
        end
      end

      def wait_for_pods_cleanup(pods)
        return pause(MONITORING_PERIOD_SECONDS) unless @pod_cleaned_up

        deadline = @monotonic.call + POD_CLEANUP_TIMEOUT
        until @mutex.synchronize { @stop } || @monotonic.call >= deadline
          pause(POD_CLEANUP_POLL)
          return if pods.all? { |pod| @pod_cleaned_up.call(pod) }
        end
      end

      def pause(seconds)
        @sleeper.call(seconds) unless @mutex.synchronize { @stop }
      end

      def notify_conditions
        @on_conditions_changed&.call(node_conditions)
      rescue StandardError => error
        @error_handler&.call(error, :eviction_conditions)
      end

      def record_node_event(type, reason, message)
        return unless @recorder && @node_ref

        @recorder.record(involved_object: @node_ref, reason: reason, type: type, message: message)
      rescue StandardError => error
        @error_handler&.call(error, :eviction_event)
      end

      def record_pod_event(pod, message, annotations)
        return unless @recorder

        metadata = pod["metadata"] || {}
        event = {involved_object: {"apiVersion" => "v1", "kind" => "Pod", "namespace" => metadata["namespace"],
                                   "name" => metadata["name"], "uid" => metadata["uid"]},
                 reason: REASON, type: "Warning", namespace: metadata["namespace"], message: message}
        event[:annotations] = annotations if annotations && !annotations.empty?
        @recorder.record(**event)
      rescue ArgumentError
        event.delete(:annotations)
        @recorder.record(**event)
      rescue StandardError => error
        @error_handler&.call(error, :eviction_event)
      end

      def quantity_string(threshold, observed)
        return threshold.quantity.to_s if threshold.quantity

        format_quantity(threshold_quantity(nil, threshold.percentage, observed.capacity), threshold.signal)
      end

      # GetThresholdQuantity for a percentage is always BinarySI; the
      # observations are BinarySI for bytes and DecimalSI for counts.
      def format_quantity(value, signal)
        Quantity.new(Rational(value), DECIMAL_SIGNALS.include?(signal) ? :decimal_si : :binary_si).canonical
      end

      def binary(value) = Quantity.new(Rational(value), :binary_si).canonical

      def request_string(request)
        return "0" if request.nil?

        Quantity.from_json(request).to_s
      rescue Quantity::ParseError
        request.to_s
      end

      # Go's %q.
      def go_quote(text) = text.to_s.dump

      def parse_time(value)
        value.is_a?(Time) ? value : Time.parse(value.to_s)
      rescue ArgumentError
        Time.at(0)
      end
    end

    NodeEvictionManager = EvictionManager unless const_defined?(:NodeEvictionManager, false)
  end
end
