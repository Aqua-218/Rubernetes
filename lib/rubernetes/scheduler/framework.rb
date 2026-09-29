# frozen_string_literal: true

require "thread"
require "monitor"
require_relative "batch"
require_relative "metrics"

module Rubernetes
  module Scheduler
    # Immutable context shared by built-in filters and scores.  Custom DSL
    # blocks receive only Pod/Node snapshots; the context is intentionally not
    # exposed as mutable plugin state.
    class CycleContext
      attr_reader :nodes, :pods, :namespace_data, :volume_data, :workload_selectors, :cycle_state

      # +workload_selectors+: {"services" => [{namespace, selector}], "controllers" =>
      # {"<Kind>/<namespace>/<name>" => selector}} -- what PodTopologySpread's
      # system default constraints select by (helper.DefaultSelector); nil
      # when the caller has no Service/controller informers.
      # +cycle_state+: the framework's CycleState -- plugin state for this
      # scheduling cycle only (DynamicResources keeps its PreFilter result
      # there); shared by the contexts #with derives, as upstream's Clone of
      # stateData shares the same data.
      def initialize(nodes:, pods:, namespace_data: {}, volume_data: {}, workload_selectors: nil, cycle_state: nil)
        @cycle_state = cycle_state || {}
        @nodes = Array(nodes).freeze
        @pods = Array(pods).freeze
        @namespace_data = Support.snapshot(namespace_data || {})
        @volume_data = Support.snapshot(volume_data || {})
        @workload_selectors = workload_selectors.nil? ? nil : Support.snapshot(workload_selectors)
        freeze
      end

      def namespace_labels(namespace)
        Support.snapshot(@namespace_data[namespace.to_s] || {})
      end

      def node_for_pod(pod)
        @nodes.find { |node| node.name == pod.node_name }
      end

      def with(nodes: @nodes, pods: @pods, volume_data: @volume_data)
        self.class.new(nodes: nodes, pods: pods, namespace_data: @namespace_data, volume_data: volume_data,
                       workload_selectors: @workload_selectors, cycle_state: @cycle_state)
      end
    end

    class ScoreBreakdown
      attr_reader :node, :total, :plugins

      def initialize(node:, total:, plugins:)
        @node = node
        @total = total
        @plugins = Support.snapshot(plugins)
        freeze
      end

      def to_h
        {"node" => node.name, "total" => total, "plugins" => plugins}
      end
    end

    class ScheduleResult
      attr_reader :status, :pod, :node, :filtered, :scores, :victims, :trace, :error, :reason, :reservation,
                  :nominated_node

      # +nominated_node+ (NominatingInfo): nil leaves the Pod's
      # status.nominatedNodeName alone, "" clears it, a name sets it.
      def initialize(status:, pod:, node: nil, filtered: {}, scores: [], victims: [], trace:, error: nil,
                     reason: nil, reservation: nil, gated: false, nominated_node: nil)
        @status = status.to_sym
        @nominated_node = nominated_node&.to_s&.freeze
        @gated = gated ? true : false
        @pod = pod
        @node = node
        @filtered = Support.snapshot(filtered)
        @scores = Array(scores).freeze
        @victims = Array(victims).freeze
        @trace = trace
        @error = error
        @reason = reason&.to_s&.freeze
        @reservation = reservation
        freeze
      end

      def scheduled?
        status == :scheduled
      end

      def requeued?
        status == :requeued
      end

      def unschedulable?
        status == :unschedulable
      end

      # Rejected by a PreEnqueue plugin: the Pod never entered a scheduling
      # cycle, so kube-scheduler records neither a condition nor an event.
      def gated?
        @gated
      end

      def failed?
        status == :failed
      end

      # The Pod no longer exists: it was not requeued and never will be.
      def dropped?
        status == :dropped
      end

      def node_name
        node&.name
      end

      def trace_digest
        trace.digest
      end

      alias trace_sha256 trace_digest

      def bound_pod
        pod
      end

      def to_h
        result = {
          "status" => status.to_s,
          "pod" => pod.to_h,
          "node" => node&.name,
          "filtered" => filtered,
          "scores" => scores.map(&:to_h),
          "victims" => victims.map { |victim| victim.respond_to?(:to_h) ? victim.to_h : victim },
          "trace" => trace.to_h,
          "trace_sha256" => trace.digest
        }
        result["reason"] = reason if reason
        if error
          error_details = {"class" => error.class.name, "message" => error.message}
          %i[cleanup_error rollback_error restore_error].each do |attribute|
            nested = error.public_send(attribute) if error.respond_to?(attribute)
            next unless nested

            error_details[attribute.to_s] = {"class" => nested.class.name, "message" => nested.message}
          end
          result["error"] = error_details
        end
        result
      end
    end

    class ReservationToken
      attr_reader :key, :pod, :node, :external

      def initialize(key:, pod:, node:, external: nil)
        @key = key.freeze
        @pod = pod
        @node = node
        @external = external
        freeze
      end

      def to_h
        {"key" => key, "pod" => pod.to_h, "node" => node.name}
      end
    end

    # The scheduling framework implements the normative pipeline:
    # Queue -> Filter -> Score -> Reserve -> Bind.  Every externally visible
    # choice is derived from immutable snapshots and deterministic sorting.
    class Framework
      # Ordered MultiPoint inventory copied from Kubernetes v1.36.2's
      # getDefaultPlugins.  Only entries with a complete implementation in
      # this pipeline are materialized in #default_registry below; the
      # remainder stays visible as an explicit unsupported boundary.
      KUBERNETES_V1_36_2_DEFAULT_PLUGINS = [
        {name: "SchedulingGates", phase: :multi_point, weight: 1},
        {name: "PrioritySort", phase: :multi_point, weight: 1},
        {name: "NodeUnschedulable", phase: :multi_point, weight: 1},
        {name: "NodeName", phase: :multi_point, weight: 1},
        {name: "TaintToleration", phase: :multi_point, weight: 3},
        {name: "NodeAffinity", phase: :multi_point, weight: 2},
        {name: "NodePorts", phase: :multi_point, weight: 1},
        {name: "NodeResourcesFit", phase: :multi_point, weight: 1},
        {name: "VolumeRestrictions", phase: :multi_point, weight: 1},
        {name: "NodeVolumeLimits", phase: :multi_point, weight: 1},
        {name: "VolumeBinding", phase: :multi_point, weight: 1},
        {name: "VolumeZone", phase: :multi_point, weight: 1},
        {name: "PodTopologySpread", phase: :multi_point, weight: 2},
        {name: "InterPodAffinity", phase: :multi_point, weight: 2},
        # applyDynamicResources: before DefaultPreemption, weight 2.
        {name: "DynamicResources", phase: :multi_point, weight: 2},
        {name: "DefaultPreemption", phase: :multi_point, weight: 1},
        {name: "NodeResourcesBalancedAllocation", phase: :multi_point, weight: 1},
        {name: "ImageLocality", phase: :multi_point, weight: 1},
        {name: "DefaultBinder", phase: :multi_point, weight: 1},
        # applyFeatureGates: NodeDeclaredFeatures (Beta, default on in 1.36).
        {name: "NodeDeclaredFeatures", phase: :multi_point, weight: 1}
      ].map(&:freeze).freeze

      # A single registry entry represents each pinned MultiPoint plugin.  The
      # supported phase list is expanded by PluginRegistry, so a plugin which
      # implements both Filter and Score still keeps one inventory position.
      DEFAULT_PLUGIN_SPECS = [
        {name: "SchedulingGates", phase: :pre_enqueue, phases: %i[pre_enqueue], weight: 1,
         implementation: Filters::SchedulingGates.new},
        {name: "PrioritySort", phase: :queue_sort, phases: %i[queue_sort], weight: 1,
         implementation: PrioritySort.new},
        {name: "NodeUnschedulable", phase: :filter, phases: %i[filter], weight: 1,
         implementation: Filters::NodeUnschedulable.new},
        {name: "NodeName", phase: :filter, phases: %i[filter], weight: 1,
         implementation: Filters::NodeName.new},
        {name: "TaintToleration", phase: :filter, phases: %i[filter score], weight: 3,
         implementation: Filters::TaintToleration.new, score_implementation: Scores::TaintToleration.new},
        {name: "NodeAffinity", phase: :filter, phases: %i[filter score], weight: 2,
         implementation: Filters::NodeAffinity.new, score_implementation: Scores::NodeAffinity.new},
        {name: "NodePorts", phase: :filter, phases: %i[filter], weight: 1,
         implementation: Filters::NodePorts.new},
        {name: "NodeResourcesFit", phase: :filter, phases: %i[filter score], weight: 1,
         implementation: Filters::NodeResourcesFit.new, score_implementation: Scores::LeastAllocated.new},
        {name: "VolumeRestrictions", phase: :filter, phases: %i[filter], weight: 1,
         implementation: Filters::VolumeRestrictions.new},
        {name: "NodeVolumeLimits", phase: :filter, phases: %i[filter], weight: 1,
         implementation: Filters::NodeVolumeLimits.new},
        # Stateful (assumed bindings, the API): one per Framework.
        {name: "VolumeBinding", phase: :filter, phases: %i[filter reserve unreserve pre_bind], weight: 1,
         factory: -> { VolumeBinding.new }},
        {name: "VolumeZone", phase: :filter, phases: %i[filter], weight: 1,
         implementation: Filters::VolumeZone.new},
        {name: "PodTopologySpread", phase: :filter, phases: %i[filter score], weight: 2,
         implementation: Filters::PodTopologySpread.new, score_implementation: Scores::TopologySpread.new},
        {name: "InterPodAffinity", phase: :filter, phases: %i[filter score], weight: 2,
         implementation: Filters::InterPodAffinity.new, score_implementation: Scores::InterPodAffinity.new},
        # Stateful (in-flight allocations, the API): one per Framework.
        {name: "DynamicResources", phase: :filter, phases: %i[pre_enqueue filter score post_filter reserve unreserve pre_bind],
         weight: 2, factory: -> { DynamicResources.new }},
        {name: "DefaultPreemption", phase: :post_filter, phases: %i[post_filter], weight: 1,
         implementation: Preemption::Evaluator.new},
        {name: "NodeResourcesBalancedAllocation", phase: :score, phases: %i[score], weight: 1,
         implementation: Scores::NodeResourcesBalancedAllocation.new},
        {name: "ImageLocality", phase: :score, phases: %i[score], weight: 1,
         implementation: Scores::ImageLocality.new},
        {name: "DefaultBinder", phase: :bind, phases: %i[bind], weight: 1,
         implementation: DefaultBinder.new},
        {name: "NodeDeclaredFeatures", phase: :filter, phases: %i[filter], weight: 1,
         implementation: Filters::NodeDeclaredFeatures.new}
      ].map(&:freeze).freeze

      DEFAULT_PLUGIN_NAMES = KUBERNETES_V1_36_2_DEFAULT_PLUGINS.map { |plugin| plugin.fetch(:name) }.freeze
      IMPLEMENTED_DEFAULT_PLUGIN_NAMES = DEFAULT_PLUGIN_SPECS.map { |plugin| plugin.fetch(:name) }.freeze
      UNIMPLEMENTED_DEFAULT_PLUGIN_NAMES = (DEFAULT_PLUGIN_NAMES - IMPLEMENTED_DEFAULT_PLUGIN_NAMES).freeze

      STANDARD_FILTERS = [
        ["SchedulingGates", Filters::SchedulingGates.new, 1],
        ["NodeUnschedulable", Filters::NodeUnschedulable.new, 1],
        ["NodeName", Filters::NodeName.new, 1],
        ["TaintToleration", Filters::TaintToleration.new, 3],
        ["NodeAffinity", Filters::NodeAffinity.new, 2],
        ["NodePorts", Filters::NodePorts.new, 1],
        ["NodeResourcesFit", Filters::NodeResourcesFit.new, 1],
        ["VolumeRestrictions", Filters::VolumeRestrictions.new, 1],
        ["NodeVolumeLimits", Filters::NodeVolumeLimits.new, 1],
        ["VolumeBinding", Filters::VolumeBinding.new, 1],
        ["VolumeZone", Filters::VolumeZone.new, 1],
        ["PodTopologySpread", Filters::PodTopologySpread.new, 2],
        ["InterPodAffinity", Filters::InterPodAffinity.new, 2],
        ["NodeDeclaredFeatures", Filters::NodeDeclaredFeatures.new, 1]
      ].freeze
      STANDARD_SCORES = [
        ["TaintToleration", 3, Scores::TaintToleration.new],
        ["NodeAffinity", 2, Scores::NodeAffinity.new],
        ["NodeResourcesFit", 1, Scores::LeastAllocated.new],
        ["PodTopologySpread", 2, Scores::TopologySpread.new],
        ["InterPodAffinity", 2, Scores::InterPodAffinity.new],
        ["NodeResourcesBalancedAllocation", 1, Scores::NodeResourcesBalancedAllocation.new],
        ["ImageLocality", 1, Scores::ImageLocality.new]
      ].freeze

      attr_reader :plugins, :queue, :preemption, :dynamic_resources, :volume_binding

      # +overrides+: plugin name => implementation, for the stateful plugins
      # built per Framework (DynamicResources).
      def self.default_registry(overrides = {})
        registry = PluginRegistry.new
        DEFAULT_PLUGIN_SPECS.each do |spec|
          implementation = overrides[spec.fetch(:name)] || spec[:implementation] || spec[:factory]&.call
          score_implementation = spec[:score_implementation]
          block = lambda do |pod, node|
            phase = Thread.current[:rubernetes_scheduler_plugin_phase]
            active = phase == :score ? (score_implementation || implementation) : implementation
            if phase == :pre_enqueue && active.respond_to?(:pre_enqueue)
              active.pre_enqueue(pod, node, Thread.current[:rubernetes_scheduler_plugin_context])
            elsif phase == :post_filter && active.respond_to?(:post_filter)
              active.post_filter(pod, Thread.current[:rubernetes_scheduler_plugin_context])
            elsif phase == :queue_sort
              unless active.respond_to?(:compare)
                raise PluginError, "default queue sort #{spec.fetch(:name)} has no comparator"
              end

              active.compare(pod, node)
            elsif phase == :post_filter
              evaluator = Thread.current[:rubernetes_scheduler_preemption] || active
              context = Thread.current[:rubernetes_scheduler_plugin_context]
              unless evaluator && context
                raise PreemptionError, "default preemption requires a scheduling context"
              end

              filter = Thread.current[:rubernetes_scheduler_filter]
              if evaluator.respond_to?(:call)
                evaluator.call(pod, nil, context)
              elsif evaluator.respond_to?(:find)
                evaluator.find(pod, nodes: context.nodes, pods: context.pods,
                               filter: filter || ->(_candidate_node, _remaining_pods) { true })
              else
                raise PreemptionError, "default preemption evaluator has no #call or #find"
              end
            elsif phase == :bind
              active.call(pod, node, Thread.current[:rubernetes_scheduler_plugin_context])
            elsif phase == :reserve && active.respond_to?(:reserve)
              active.reserve(pod, node, Thread.current[:rubernetes_scheduler_plugin_context])
            elsif phase == :unreserve && active.respond_to?(:unreserve)
              active.unreserve(pod, node, Thread.current[:rubernetes_scheduler_plugin_context])
            elsif phase == :pre_bind && active.respond_to?(:pre_bind)
              active.pre_bind(pod, node, Thread.current[:rubernetes_scheduler_plugin_context])
            elsif active.respond_to?(:call)
              active.call(pod, node, Thread.current[:rubernetes_scheduler_plugin_context])
            else
              raise PluginError, "default plugin #{spec.fetch(:name)} has no implementation for #{phase}"
            end
          end
          scorer = spec[:score_implementation] || (spec.fetch(:phases).include?(:score) ? implementation : nil)
          registry.register(Plugin.new(name: spec.fetch(:name), phase: spec.fetch(:phase),
                                       supported_phases: spec.fetch(:phases), weight: spec.fetch(:weight), block: block,
                                       score_extension: scorer.respond_to?(:score_nodes) ? scorer : nil))
        end
        registry
      end

      def initialize(plugins: nil, standard_plugins: true, filters: nil, scores: nil, queue: nil,
                     reserve: nil, unreserve: nil, bind: nil, rollback: nil, delete_pod: nil,
                     restore_pod: nil, preemption: nil, namespace_labels: {}, random: nil, dynamic_resources: nil,
                     volume_binding: nil, nominate: nil, clear_nomination: nil, async_preemption: true,
                     preemption_observer: nil, opportunistic_batching: true, metrics: nil, **_options)
        custom = normalize_plugins(plugins, filters: filters, scores: scores)
        @metrics = metrics || NullMetrics.new
        @dynamic_resources = dynamic_resources || DynamicResources.new
        @volume_binding = volume_binding || VolumeBinding.new
        @plugins = if standard_plugins
                     self.class.default_registry("DynamicResources" => @dynamic_resources,
                                                 "VolumeBinding" => @volume_binding).merge(custom)
                   else
                     custom
                   end.freeze
        @queue = queue || SchedulingQueue.new
        @reserve_handler = reserve
        @unreserve_handler = unreserve
        @bind_handler = bind
        @rollback_handler = rollback
        @delete_pod_handler = delete_pod
        # Accepted for compatibility only: upstream never restores an evicted
        # preemption victim, and neither does this framework any more.
        @restore_pod_handler = restore_pod
        @preemption = preemption == false ? nil : (preemption || Preemption::Evaluator.new)
        @namespace_labels = Support.snapshot(namespace_labels || {})
        @random = random || Random.new
        @reservations = {}
        @pod_locks = {}
        @mutex = Mutex.new
        # The nominator: nominations this scheduler made (or cleared) that
        # the informer's copy of the Pod may not show yet; nil = cleared.
        @nominations = {}
        @nominate_handler = nominate
        @clear_nomination_handler = clear_nomination
        # SchedulerAsyncPreemption (Beta, on).
        @async_preemption = async_preemption ? true : false
        @preempting = {}
        @preemption_threads = []
        @preemption_observer = preemption_observer
        @cycle = 0
        @batch = if opportunistic_batching
                   OpportunisticBatch.new(plugin_names: (filter_plugins + score_plugins).map(&:name))
                 end
        @batch.metrics = @metrics if @batch.respond_to?(:metrics=)
        @queue.metrics = @metrics if @queue.respond_to?(:metrics=)
        @metrics.queue = @queue if @metrics.respond_to?(:queue=)
        @volume_binding.metrics = @metrics if @volume_binding.respond_to?(:metrics=)
        @dynamic_resources.metrics = @metrics if @dynamic_resources.respond_to?(:metrics=)
        configure_queue_sort!
      end

      attr_reader :batch, :metrics

      # The node this Pod is nominated to, as far as this scheduler knows.
      def nominated_node_for(pod)
        key = pod_lock_key(pod)
        @mutex.synchronize do
          return @nominations[key].to_s if @nominations.key?(key)
        end
        pod.nominated_node_name
      end

      # The Pod was bound or deleted: its nomination means nothing any more.
      def forget_nomination(pod)
        key = pod_lock_key(pod)
        @mutex.synchronize { @nominations.delete(key) }
      end

      # IsPodRunningPreemption: an asynchronous preemption for this Pod is
      # still deleting its victims.
      def preempting?(pod)
        key = pod_lock_key(pod)
        @mutex.synchronize { @preempting.key?(key) }
      end

      # Waits for the asynchronous preemptions started so far (tests, stop).
      def wait_for_preemptions(timeout = 10)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        threads = @mutex.synchronize { @preemption_threads.dup }
        threads.each { |thread| thread.join([deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC), 0].max) }
        threads.none?(&:alive?)
      end

      def filter_plugins
        plugins.filters
      end

      def score_plugins
        plugins.scores
      end

      def pre_enqueue_plugins
        plugins.phase_plugins(:pre_enqueue)
      end

      def queue_sort_plugins
        plugins.phase_plugins(:queue_sort)
      end

      def post_filter_plugins
        plugins.phase_plugins(:post_filter)
      end

      def bind_plugins
        plugins.phase_plugins(:bind)
      end

      def enqueue(pod, reason: nil)
        queue.enqueue(pod, reason: reason)
      end

      alias enqueue_pod enqueue

      def unschedulable_queue
        queue.unschedulable_q
      end

      # Schedule one pod.  Positional and keyword node forms are both
      # accepted because API adapters commonly call this method differently.
      def schedule(pod, nodes = nil, pods: nil, namespace_labels: nil, volume_data: nil, enqueue: false,
                   trace: nil, workload_selectors: nil, **keywords)
        nodes ||= keywords.delete(:nodes)
        raise ArgumentError, "nodes are required" if nodes.nil?
        raise ArgumentError, "unknown scheduler options: #{keywords.keys.inspect}" unless keywords.empty?

        typed_pod = pod.is_a?(Pod) ? pod : Pod.new(pod)
        lock_key = pod_lock_key(typed_pod)
        pod_lock = acquire_pod_lock(lock_key)
        begin
          node_objects = normalize_nodes(nodes)
          existing_pods = normalize_pods(pods, node_objects)
          context = build_context(node_objects, existing_pods, namespace_labels, volume_data, workload_selectors)
          queue.enqueue(typed_pod) if enqueue && !queue.include?(typed_pod)
          trace ||= Trace.new

          if preempting?(typed_pod)
            # DefaultPreemption's PreEnqueue: the Pod waits until its victims'
            # eviction calls are done; the preemption then activates it.
            reason = "waiting for the preemption for this pod to be finished"
            queue.enqueue_unschedulable(typed_pod, reason: reason)
            return ScheduleResult.new(status: :unschedulable, pod: typed_pod, filtered: {},
                                       scores: [], victims: [], trace: trace, reason: reason, gated: true)
          end

          Thread.current[:rubernetes_scheduler_sample_plugins] = @metrics.sample_plugins?
          gate_started = monotonic
          gate_result = run_pre_enqueue(typed_pod, context, trace)
          @metrics.extension_point(:pre_enqueue, gate_result == true ? Metrics::STATUS_SUCCESS : Metrics::STATUS_UNSCHEDULABLE,
                                   monotonic - gate_started)
          unless gate_result == true
            reason = gate_result.fetch("reason", "pod is not ready for scheduling")
            queue.enqueue_unschedulable(typed_pod, reason: reason, gated: true, plugins: [gate_result["plugin"]].compact)
            return ScheduleResult.new(status: :unschedulable, pod: typed_pod, filtered: {},
                                       scores: [], victims: [], trace: trace, reason: reason, gated: true)
          end

          algorithm_started = monotonic
          cycle = (@cycle += 1)
          signature = @batch&.sign(typed_pod)
          nominated = nominated_pods_index(context)
          hint = if @batch && signature
                   @batch.node_hint(signature, cycle, fits_last: lambda { |name|
                     last = context.nodes.find { |item| item.name == name }
                     last && run_filters_with_nominated(typed_pod, last, context, nominated, trace: nil) == true
                   })
                 end

          # findNodesThatFitPod: the nominated node (preemption made room
          # there) and the batch hint are tried alone first.
          candidates = nil
          filtered = {}
          nominated_status = nil
          nominated_name = nominated_node_for(typed_pod)
          [nominated_name, hint].compact.reject(&:empty?).uniq.each do |name|
            preferred = context.nodes.find { |item| item.name == name }
            next unless preferred

            result = run_filters_with_nominated(typed_pod, preferred, context, nominated, trace: trace)
            if result == true
              candidates = [preferred]
              filtered = {name => {"accepted" => true}}
              break
            end
            nominated_status = result if name == nominated_name
          end
          filter_started = monotonic
          candidates, filtered = filter_nodes(typed_pod, context.nodes, context, trace: trace, nominated: nominated) if candidates.nil?
          @metrics.extension_point(:filter, candidates.empty? ? Metrics::STATUS_UNSCHEDULABLE : Metrics::STATUS_SUCCESS,
                                   monotonic - filter_started)

          if candidates.empty? && @preemption
            eligible = eligible_to_preempt?(typed_pod, context, nominated_name, nominated_status)
            preemption = nil
            if eligible
              post_filter_started = monotonic
              begin
                preemption = run_post_filters(typed_pod, context, filtered, trace, nominated: nominated)
                @metrics.extension_point(:post_filter, preemption ? Metrics::STATUS_SUCCESS : Metrics::STATUS_UNSCHEDULABLE,
                                         monotonic - post_filter_started)
              rescue PreemptionError, PluginError => error
                @metrics.extension_point(:post_filter, Metrics::STATUS_ERROR, monotonic - post_filter_started)
                @batch&.failed(cycle)
                status = requeue_after_failure(typed_pod, error)
                return ScheduleResult.new(status: status, pod: typed_pod, filtered: filtered,
                                           scores: [], victims: [], trace: trace, error: error,
                                           reason: "preemption evaluation failed")
              end
            end
            if preemption
              begin
                start_preemption!(preemption, typed_pod, context, nominated)
              rescue PreemptionError => error
                @batch&.failed(cycle)
                status = requeue_after_failure(typed_pod, error)
                return ScheduleResult.new(status: status, pod: typed_pod, filtered: filtered,
                                           scores: [], victims: preemption.victims, trace: trace,
                                           error: error, reason: "preemption failed")
              end
              # The Pod waits for its victims to go: it is nominated to the
              # node and retried when they are deleted.
              node_name = preemption.node.name
              nominate!(typed_pod, node_name)
              reason = filtered.values.map { |value| value["reason"] }.compact.first || "no feasible nodes"
              queue.enqueue_unschedulable(typed_pod, reason: reason, plugins: rejecting_plugins(filtered))
              @batch&.failed(cycle)
              return ScheduleResult.new(status: :unschedulable, pod: typed_pod, filtered: filtered,
                                         scores: [], victims: preemption.victims, trace: trace, reason: reason,
                                         nominated_node: node_name)
            end
            # Preemption found no candidate: an old nomination is void.
            if eligible && !nominated_name.empty?
              clear_nomination!(typed_pod)
              cleared = true
            end
          end

          if candidates.empty?
            reason = filtered.values.map { |value| value["reason"] }.compact.first || "no feasible nodes"
            queue.enqueue_unschedulable(typed_pod, reason: reason, plugins: rejecting_plugins(filtered))
            @batch&.failed(cycle)
            @metrics.algorithm(monotonic - algorithm_started)
            return ScheduleResult.new(status: :unschedulable, pod: typed_pod, filtered: filtered,
                                       scores: [], victims: [], trace: trace, reason: reason,
                                       nominated_node: cleared ? "" : nil)
          end

          victims = []
          score_started = monotonic
          begin
            breakdowns = score_nodes(typed_pod, candidates, context, trace)
          rescue StandardError
            @metrics.extension_point(:score, Metrics::STATUS_ERROR, monotonic - score_started)
            @batch&.failed(cycle)
            raise
          end
          @metrics.extension_point(:score, Metrics::STATUS_SUCCESS, monotonic - score_started)
          selected = select_host(breakdowns)
          @metrics.algorithm(monotonic - algorithm_started)
          if @batch
            ranked = breakdowns.reject { |breakdown| breakdown.equal?(selected) }
                               .sort_by { |breakdown| [-breakdown.total, breakdown.node.name] }
                               .map { |breakdown| breakdown.node.name }
            @batch.store(signature, hint, selected.node.name, ranked, cycle)
          end

          reservation = nil
          begin
            reserve_started = monotonic
            begin
              reservation = reserve!(typed_pod, selected.node, context: context, trace: trace)
            rescue StandardError
              @metrics.extension_point(:reserve, Metrics::STATUS_ERROR, monotonic - reserve_started)
              raise
            end
            @metrics.extension_point(:reserve, Metrics::STATUS_SUCCESS, monotonic - reserve_started)
            bound_pod = bind!(pod, typed_pod, selected.node, context: context, trace: trace)
            commit_reservation!(reservation)
            forget_nomination(typed_pod)
            record_pod_scheduled(typed_pod)
            queue.delete(typed_pod)
            queue.forget(typed_pod) if queue.respond_to?(:forget)
            ScheduleResult.new(status: :scheduled, pod: bound_pod, node: selected.node,
                               filtered: filtered, scores: breakdowns, victims: victims, trace: trace,
                               reservation: reservation)
          rescue StandardError => error
            @batch&.failed(cycle)
            unreserve_started = monotonic
            rollback!(reservation, typed_pod, selected.node, error, context: context, trace: trace)
            @metrics.extension_point(:unreserve, Metrics::STATUS_SUCCESS, monotonic - unreserve_started)
            status = requeue_after_failure(typed_pod, error)
            ScheduleResult.new(status: status, pod: typed_pod, node: selected.node,
                               filtered: filtered, scores: breakdowns, victims: victims, trace: trace,
                               error: error, reason: "bind or reserve failed")
          end
        ensure
          release_pod_lock(lock_key, pod_lock)
        end
      end

      alias schedule_pod schedule
      alias run schedule

      def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      private :monotonic

      # The plugins that rejected the Pod on some node (scheduler_unschedulable_pods).
      def rejecting_plugins(filtered)
        filtered.values.filter_map { |entry| entry.is_a?(Hash) ? entry["plugin"] : nil }.uniq
      end
      private :rejecting_plugins

      # scheduler_pod_scheduling_attempts / _sli_duration_seconds for a Pod
      # that just bound, from the queue's pop bookkeeping.
      def record_pod_scheduled(pod)
        attempts = queue.respond_to?(:pop_attempts) ? queue.pop_attempts(pod) : 0
        # A Pod scheduled straight from schedule() was never popped: one attempt.
        attempts = 1 if attempts.zero?
        since = queue.respond_to?(:seconds_since_first_attempt) ? queue.seconds_since_first_attempt(pod) : nil
        @metrics.pod_scheduled(attempts, since)
      rescue StandardError
        nil
      end
      private :record_pod_scheduled

      def schedule_next(nodes:, pods: nil, namespace_labels: nil, volume_data: nil, workload_selectors: nil)
        trace = Trace.new
        item = queue.pop(trace: trace)
        return nil unless item

        schedule(item.pod, nodes, pods: pods, namespace_labels: namespace_labels, volume_data: volume_data,
                                  workload_selectors: workload_selectors, trace: trace)
      rescue StandardError => error
        requeue_after_failure(item.pod, error) if item
        raise
      end

      def schedule!(pod, nodes = nil, **options)
        result = schedule(pod, nodes, **options)
        raise result.error if result.failed? || result.requeued? && result.error
        result
      end

      private

      def configure_queue_sort!
        registered = queue_sort_plugins
        return if registered.empty?
        if registered.length != 1
          raise ValidationError, "scheduler must register exactly one queue sort plugin"
        end
        unless @queue.respond_to?(:configure_sort)
          raise ValidationError, "scheduler queue does not support registry-backed queue sorting"
        end

        plugin = registered.first
        comparator = lambda do |left, right|
          typed_left = left.is_a?(Pod) ? left : Pod.new(left)
          typed_right = right.is_a?(Pod) ? right : Pod.new(right)
          invoke_plugin(plugin, typed_left, typed_right, nil, phase: :queue_sort)
        end
        @queue.configure_sort(comparator, name: plugin.name, weight: plugin.weight)
      end

      def normalize_plugins(plugins, filters:, scores:)
        registry = if plugins.nil?
                     PluginRegistry.new
                   elsif plugins.is_a?(PluginRegistry)
                     plugins.dup
                   elsif plugins.respond_to?(:registry)
                     plugins.registry.dup
                   else
                     raise ValidationError, "plugins must be a PluginRegistry or DSL"
                   end
        Array(filters).each do |item|
          if item.is_a?(Plugin)
            registry.register(item)
          elsif item.respond_to?(:call)
            name = item.respond_to?(:name) && item.name ? item.name : "custom_filter_#{registry.filters.length}"
            registry.filter(name, &item)
          else
            raise ValidationError, "invalid filter plugin #{item.inspect}"
          end
        end
        Array(scores).each do |item|
          if item.is_a?(Plugin)
            registry.register(item)
          elsif item.respond_to?(:call)
            name = item.respond_to?(:name) && item.name ? item.name : "custom_score_#{registry.scores.length}"
            registry.score(name, &item)
          else
            raise ValidationError, "invalid score plugin #{item.inspect}"
          end
        end
        registry
      end

      def normalize_nodes(nodes)
        list = nodes.is_a?(Hash) ? nodes.values : Array(nodes)
        normalized = list.map { |node| node.is_a?(Node) ? node : Node.new(node) }
        names = normalized.map(&:name)
        raise ValidationError, "scheduler nodes must have unique non-empty names" if names.any?(&:empty?) || names.uniq.length != names.length

        normalized.sort_by(&:name)
      end

      def normalize_pods(pods, nodes)
        values = Array(pods).map { |pod| pod.is_a?(Pod) ? pod : Pod.new(pod) }
        nodes.each { |node| values.concat(node.pods) }
        deduplicate_pods(values)
      end

      def build_context(nodes, pods, namespace_labels, volume_data = nil, workload_selectors = nil)
        node_objects = nodes.map do |node|
          assigned = pods.select { |pod| pod.node_name == node.name }
          node.with_pods(assigned, preserve_requested: assigned.empty?)
        end
        CycleContext.new(nodes: node_objects, pods: pods, namespace_data: namespace_labels || @namespace_labels,
                         volume_data: volume_data || {}, workload_selectors: workload_selectors)
      end

      def run_pre_enqueue(pod, context, trace)
        pre_enqueue_plugins.each do |plugin|
          output = invoke_plugin(plugin, pod, nil, context, phase: :pre_enqueue)
          result = normalize_filter_result(output, plugin)
          trace.record(plugin: plugin.name, phase: :pre_enqueue, weight: plugin.weight,
                       input: {"pod" => pod.to_h}, output: result.to_h)
          return result.to_h.merge("plugin" => plugin.name) unless result.accepted?
        end
        true
      end

      def plugin_weight(name)
        plugin = plugins.find(name)
        plugin ? plugin.weight : 1
      end

      def filter_nodes(pod, nodes, context, trace:, nominated: nil)
        accepted = []
        filtered = {}
        nodes.sort_by(&:name).each do |node|
          result = run_filters_with_nominated(pod, node, context, nominated, trace: trace)
          if result == true
            accepted << node
            filtered[node.name] = {"accepted" => true}
          else
            filtered[node.name] = result
          end
        end
        [accepted, filtered]
      end

      # Pending Pods nominated to each node (the nominator's view): the
      # informer's status.nominatedNodeName, overridden by what this
      # scheduler nominated or cleared since.
      def nominated_pods_index(context)
        own = @mutex.synchronize { @nominations.empty? ? nil : @nominations.dup }
        index = nil
        context.pods.each do |candidate|
          next unless candidate.node_name.empty?

          key = pod_lock_key(candidate)
          name = own&.key?(key) ? own[key].to_s : candidate.nominated_node_name
          next if name.empty? || candidate.terminating?

          ((index ||= {})[name] ||= []) << candidate
        end
        prune_nominations(context) if own && own.length > NOMINATION_PRUNE_THRESHOLD
        index
      end

      NOMINATION_PRUNE_THRESHOLD = 1024

      def prune_nominations(context)
        live = context.pods.to_h { |candidate| [pod_lock_key(candidate), true] }
        @mutex.synchronize { @nominations.select! { |key, _name| live.key?(key) } }
      end

      # RunFilterPluginsWithNominatedPods: Pods of equal or higher priority
      # nominated to this node count as already running there.  A node the
      # Pod fits only thanks to them (affinity to a nominated Pod) must fit
      # it without them too, so both runs have to pass.
      def run_filters_with_nominated(pod, node, context, nominated, trace:)
        added = nominated && nominated[node.name]
        added = added&.select { |candidate| !same_pod?(candidate, pod) && candidate.priority >= pod.priority }
        return run_filters(pod, node, context, trace: trace) if added.nil? || added.empty?

        placed = added.map { |candidate| candidate.with("spec" => candidate.spec.merge("nodeName" => node.name)) }
        trial_node = node.with_pods(node.pods + placed)
        trial_nodes = context.nodes.map { |item| item.name == node.name ? trial_node : item }
        remaining = context.pods.reject { |candidate| added.any? { |entry| same_pod?(entry, candidate) } }
        result = run_filters(pod, trial_node, context.with(nodes: trial_nodes, pods: remaining + placed), trace: trace)
        return result unless result == true

        run_filters(pod, node, context, trace: nil)
      end

      # DefaultPreemption#PodEligibleToPreemptOthers.
      def eligible_to_preempt?(pod, context, nominated_name, nominated_status)
        return false if pod.preemption_policy == "Never"
        return true if nominated_name.empty?
        return true if nominated_status.is_a?(Hash) && nominated_status["code"] == "UnschedulableAndUnresolvable"

        # Victims of an earlier preemption are still terminating on the
        # nominated node: wait for them instead of evicting more.
        context.pods.none? do |candidate|
          candidate.node_name == nominated_name && candidate.priority < pod.priority &&
            candidate.terminating_by_preemption?
        end
      end

      def nominate!(pod, node_name)
        key = pod_lock_key(pod)
        @mutex.synchronize { @nominations[key] = node_name }
      end

      def clear_nomination!(pod)
        key = pod_lock_key(pod)
        @mutex.synchronize { @nominations[key] = nil }
      end

      # prepareCandidate(Async): evict the victims -- from a thread of its own
      # with SchedulerAsyncPreemption, the Pod gated meanwhile -- and clear
      # the nominations of lower-priority Pods nominated to the same node.
      def start_preemption!(result, pod, context, nominated)
        raise PreemptionError, "preemption requires a delete handler" unless @delete_pod_handler

        # A victim already being deleted needs no second call; with none left
        # there is nothing to wait for (prepareCandidateAsync returns here).
        victims = result.victims.reject(&:terminating?)
        return true if victims.empty?

        node_name = result.node.name
        lower = Array(nominated && nominated[node_name]).select do |candidate|
          !same_pod?(candidate, pod) && candidate.priority < pod.priority
        end
        unless @async_preemption
          evict_victims!(victims)
          clear_lower_nominations(lower)
          return true
        end

        key = pod_lock_key(pod)
        @mutex.synchronize { @preempting[key] = true }
        thread = Thread.new do
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          outcome = "success"
          begin
            clear_lower_nominations(lower)
            evict_victims!(victims)
          rescue StandardError
            outcome = "error"
          ensure
            @mutex.synchronize do
              @preempting.delete(key)
              @preemption_threads.delete(Thread.current)
            end
            # Upstream activates only after an error and otherwise waits for
            # the victims' delete events; activating always costs one extra
            # cycle that waits on the terminating victims, and can never
            # strand the Pod.
            queue.activate(pod) if queue.respond_to?(:activate)
            observe_preemption(outcome, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
          end
        end
        thread.name = "scheduler-preemption" if thread.respond_to?(:name=)
        @mutex.synchronize { @preemption_threads << thread if thread.alive? }
        true
      end

      # All victims but the last in parallel, then the last one (executor.go:
      # Parallelizer().Until over len-1, then the last victim).
      def evict_victims!(victims)
        *others, last = victims
        errors = others.map do |victim|
          Thread.new do
            evict_victim!(victim)
            nil
          rescue StandardError => error
            error
          end
        end.map(&:value).compact
        raise errors.first if errors.first.is_a?(PreemptionError)
        raise PreemptionError.new("preemption failed: #{errors.first.message}", cause_error: errors.first) if errors.first

        evict_victim!(last) if last
      end

      def evict_victim!(victim)
        response = invoke_handler(@delete_pod_handler, :delete, victim)
        raise PreemptionError, "victim deletion rejected #{victim.name}" if response == false
      rescue PreemptionError
        raise
      rescue StandardError => error
        raise PreemptionError.new("preemption failed: #{error.message}", cause_error: error), cause: error
      end

      def clear_lower_nominations(pods)
        pods.each { |candidate| clear_nomination!(candidate) }
        return unless @clear_nomination_handler

        pods.each do |candidate|
          invoke_handler(@clear_nomination_handler, :clear, candidate)
        rescue StandardError
          nil
        end
      end

      def observe_preemption(outcome, seconds)
        @preemption_observer&.call(outcome, seconds)
      rescue StandardError
        nil
      end

      # NominatedNodeNameForExpectation (Beta, on): RunPreBindPreFlights --
      # when a PreBind plugin has work to do (volumes to bind, claims to
      # allocate) the Pod is nominated to its node first, so other components
      # see where it is about to land.
      def pre_bind_work?(pod, node, context)
        plugins.phase_plugins(:pre_bind).any? do |plugin|
          implementation = case plugin.name
                           when "VolumeBinding" then @volume_binding
                           when "DynamicResources" then @dynamic_resources
                           end
          implementation.respond_to?(:pre_bind_preflight?) && implementation.pre_bind_preflight?(pod, node, context)
        end
      end

      def run_filters(pod, node, context, trace:)
        plugins.filters.each do |plugin|
          input = {"pod" => pod.to_h, "node" => node.to_h}
          @metrics.plugin_evaluated(:filter, plugin.name)
          output = invoke_plugin(plugin, pod, node, context, phase: :filter)
          result = normalize_filter_result(output, plugin)
          trace.record(plugin: plugin.name, phase: :filter, weight: plugin.weight,
                       input: input, output: result.to_h) if trace
          unless result.accepted?
            return result.to_h.merge("plugin" => plugin.name)
          end
        end
        true
      end

      def run_post_filters(pod, context, filtered, trace, nominated: nil)
        return nil if post_filter_plugins.empty?

        filter = lambda do |candidate_node, remaining_pods|
          trial_nodes = context.nodes.map { |item| item.name == candidate_node.name ? candidate_node : item }
          trial_context = context.with(nodes: trial_nodes, pods: remaining_pods)
          filter_nodes(pod, [candidate_node], trial_context, trace: nil, nominated: nominated).first.any?
        end

        post_filter_plugins.each do |plugin|
          previous_filter = Thread.current[:rubernetes_scheduler_filter]
          previous_preemption = Thread.current[:rubernetes_scheduler_preemption]
          Thread.current[:rubernetes_scheduler_filter] = filter
          Thread.current[:rubernetes_scheduler_preemption] = @preemption
          begin
            output = invoke_plugin(plugin, pod, nil, context, phase: :post_filter)
            result = normalize_post_filter_result(output, plugin, context, pod)
            trace.record(plugin: plugin.name, phase: :post_filter, weight: plugin.weight,
                         input: {"pod" => pod.to_h, "filtered" => filtered},
                         output: result ? result.to_h : {"node" => nil, "victims" => []})
            return result if result
          ensure
            Thread.current[:rubernetes_scheduler_filter] = previous_filter
            Thread.current[:rubernetes_scheduler_preemption] = previous_preemption
          end
        end
        nil
      end

      # kube-scheduler picks ONE of the highest-scoring nodes at random --
      # reservoir sampling in schedule_one.go selectHost, "picks one in a
      # reservoir sampling manner from the nodes that had the highest score".
      # Taking the first one by name instead looks harmless while every node
      # scores differently, and is catastrophic the moment they tie: a
      # BestEffort Pod requests nothing, so LeastAllocated scores every node
      # 100 and every Pod in the cluster lands on the alphabetically first
      # node.  A conformance run put 23 of 27 Pods on worker-0 while worker-1
      # ran one, and the Pods queued behind each other there timed out waiting
      # to start.
      def select_host(breakdowns)
        selected = nil
        tied = 0
        breakdowns.each do |breakdown|
          if selected.nil? || breakdown.total > selected.total
            selected = breakdown
            tied = 1
          elsif breakdown.total == selected.total
            tied += 1
            selected = breakdown if @random.rand(tied).zero?
          end
        end
        selected
      end

      # Plugin-major, as the framework runs RunScorePlugins: a plugin with a
      # score extension scores every feasible node at once (PreScore, Score,
      # NormalizeScore) and may Skip -- a skipped plugin is left out of the
      # breakdown and the total, exactly as upstream leaves it out.
      def score_nodes(pod, nodes, context, trace)
        ordered = nodes.sort_by(&:name)
        extension_scores = {}
        plugins.scores.each do |plugin|
          @metrics.plugin_evaluated(:score, plugin.name)
          extension = plugin.score_extension
          next unless extension

          extension_scores[plugin.name] = with_plugin_context(context, :score) { extension.score_nodes(pod, ordered, context) }
        end
        ordered.map do |node|
          total = 0
          details = []
          plugins.scores.each do |plugin|
            next if extension_scores[plugin.name].equal?(Scores::SKIP)

            input = {"pod" => pod.to_h, "node" => node.to_h}
            output = if extension_scores.key?(plugin.name)
                       extension_scores[plugin.name].fetch(node.name, 0)
                     else
                       invoke_plugin(plugin, pod, node, context, phase: :score)
                     end
            score = normalize_score(output, plugin)
            trace.record(plugin: plugin.name, phase: :score, weight: plugin.weight,
                         input: input, output: score) if trace
            weighted = score * plugin.weight
            total += weighted
            details << {"plugin" => plugin.name, "score" => score, "weight" => plugin.weight, "weighted" => weighted}
          end
          ScoreBreakdown.new(node: node, total: total, plugins: details)
        end
      end

      # Pod and Node snapshots are deep-frozen (Support.snapshot), so a plugin
      # that tries to mutate its input raises FrozenError, which the rescue
      # below turns into a PluginError.  This used to prove the same thing by
      # canonicalising and SHA-256 digesting the Pod and the Node -- with
      # every Pod assigned to it -- before and after every plugin call: per
      # Pod, per node, per filter and score plugin, several hundred digests a
      # scheduling cycle, and most of the scheduler's CPU under a burst.
      def with_plugin_context(context, phase)
        previous_context = Thread.current[:rubernetes_scheduler_plugin_context]
        previous_phase = Thread.current[:rubernetes_scheduler_plugin_phase]
        Thread.current[:rubernetes_scheduler_plugin_context] = context
        Thread.current[:rubernetes_scheduler_plugin_phase] = phase
        yield
      rescue FrozenError, PluginError, PreemptionError
        raise
      rescue StandardError => error
        raise PluginError.new("score plugin failed: #{error.message}", phase: phase, cause_error: error), cause: error
      ensure
        Thread.current[:rubernetes_scheduler_plugin_context] = previous_context
        Thread.current[:rubernetes_scheduler_plugin_phase] = previous_phase
      end

      def invoke_plugin(plugin, pod, node, context, phase:)
        previous_context = Thread.current[:rubernetes_scheduler_plugin_context]
        previous_phase = Thread.current[:rubernetes_scheduler_plugin_phase]
        Thread.current[:rubernetes_scheduler_plugin_context] = context
        Thread.current[:rubernetes_scheduler_plugin_phase] = phase.to_sym
        sampled = Thread.current[:rubernetes_scheduler_sample_plugins]
        started = sampled ? monotonic : nil
        status = Metrics::STATUS_ERROR
        begin
          output = plugin.block.call(pod, node)
          status = plugin_status(output)
          output
        rescue FrozenError => error
          raise PluginError.new("#{phase} plugin #{plugin.name} mutated its input snapshot: #{error.message}",
                                plugin: plugin.name, phase: phase, cause_error: error), cause: error
        rescue PluginError
          raise
        rescue PreemptionError
          raise
        rescue StandardError => error
          raise PluginError.new("#{phase} plugin #{plugin.name} failed: #{error.message}",
                                plugin: plugin.name, phase: phase, cause_error: error), cause: error
        ensure
          @metrics.plugin_execution(phase, plugin.name, status, monotonic - started) if started
          Thread.current[:rubernetes_scheduler_plugin_context] = previous_context
          Thread.current[:rubernetes_scheduler_plugin_phase] = previous_phase
        end
      end

      # framework.Status code of a plugin's answer.
      def plugin_status(output)
        case output
        when true, nil then Metrics::STATUS_SUCCESS
        when false then Metrics::STATUS_UNSCHEDULABLE
        when Rejection, FilterResult
          code = output.respond_to?(:code) ? output.code.to_s : ""
          code.empty? ? Metrics::STATUS_UNSCHEDULABLE : code
        when Hash
          output["accepted"] == false ? (output["code"] || Metrics::STATUS_UNSCHEDULABLE).to_s : Metrics::STATUS_SUCCESS
        else
          output.equal?(Scores::SKIP) ? Metrics::STATUS_SKIP : Metrics::STATUS_SUCCESS
        end
      end

      def normalize_filter_result(output, plugin)
        case output
        when true
          FilterResult.new(accepted: true)
        when false
          FilterResult.new(accepted: false, reason: "rejected by #{plugin.name}")
        when Rejection
          FilterResult.new(accepted: false, reason: output.reason, code: output.code, details: output.details)
        when FilterResult
          output
        when String
          FilterResult.new(accepted: false, reason: output)
        when Hash
          hash = Support.object_hash(output)
          accepted = hash["accepted"]
          if accepted == true
            FilterResult.new(accepted: true)
          elsif accepted == false || hash.key?("reason")
            FilterResult.new(accepted: false, reason: hash["reason"] || "rejected by #{plugin.name}",
                             code: hash["code"], details: hash["details"])
          else
            raise PluginError.new("filter plugin #{plugin.name} returned an invalid result",
                                  plugin: plugin.name, phase: :filter)
          end
        else
          raise PluginError.new("filter plugin #{plugin.name} must return true or a rejection",
                                plugin: plugin.name, phase: :filter)
        end
      end

      def normalize_post_filter_result(output, plugin, context, pending)
        return nil if output.nil?
        unless output.is_a?(Preemption::Result)
          raise PluginError.new("post-filter plugin #{plugin.name} must return a preemption result or nil",
                                plugin: plugin.name, phase: :post_filter)
        end

        node = output.node && context.nodes.find { |candidate| candidate.name == output.node.name }
        unless node
          raise PluginError.new("post-filter plugin #{plugin.name} returned an unknown node",
                                plugin: plugin.name, phase: :post_filter)
        end
        unless output.victims.any? && output.victims.all? { |victim| victim.is_a?(Pod) }
          raise PluginError.new("post-filter plugin #{plugin.name} returned an invalid victim set",
                                plugin: plugin.name, phase: :post_filter)
        end
        identities = context.pods.each_with_object({}) { |candidate, result| result[pod_identity(candidate)] = candidate }
        victims = output.victims.map do |victim|
          canonical = identities[pod_identity(victim)]
          unless canonical && canonical.priority < pending.priority && canonical.node_name == node.name
            raise PluginError.new("post-filter plugin #{plugin.name} returned an invalid victim",
                                  plugin: plugin.name, phase: :post_filter)
          end
          canonical
        end
        if victims.map { |victim| pod_identity(victim) }.uniq.length != victims.length
          raise PluginError.new("post-filter plugin #{plugin.name} returned duplicate victims",
                                plugin: plugin.name, phase: :post_filter)
        end

        Preemption::Result.new(node: node, victims: victims, reason: output.reason)
      end

      def normalize_score(output, plugin)
        unless output.is_a?(Integer) && !output.is_a?(TrueClass) && output.between?(0, 100)
          raise PluginError.new("score plugin #{plugin.name} must return an integer from 0 to 100",
                                plugin: plugin.name, phase: :score)
        end
        output
      end

      def reserve!(pod, node, context: nil, trace: nil)
        key = [pod.namespace, pod.name, pod.uid, node.name].join("/")
        plugins.phase_plugins(:reserve).each do |plugin|
          output = invoke_plugin(plugin, pod, node, context || CycleContext.new(nodes: [node], pods: []), phase: :reserve)
          trace&.record(plugin: plugin.name, phase: :reserve, weight: plugin.weight,
                        input: {"pod" => pod.to_h, "node" => node.to_h}, output: output == true ? true : output)
          raise ReservationError, "reserve plugin #{plugin.name} rejected #{pod.name}" if output == false || output.is_a?(Rejection)
        end
        external = if @reserve_handler
                     result = invoke_handler(@reserve_handler, :reserve, pod, node)
                     raise ReservationError, "reserve handler rejected #{pod.name}" if result == false

                     result
                   end
        token = ReservationToken.new(key: key, pod: pod, node: node, external: external)
        @mutex.synchronize { @reservations[key] = token }
        token
      rescue StandardError => error
        raise error if error.is_a?(ReservationError)

        raise ReservationError.new("reserve failed: #{error.message}", cause_error: error), cause: error
      end

      def bind!(original, pod, node, context: nil, trace: nil)
        initial_name = pod.node_name
        current_name = Support.value(Support.object_hash(Support.value(original, "spec", {})), "nodeName", "").to_s if original
        if current_name && !current_name.empty? && current_name != initial_name
          raise BindError, "pod changed while scheduling"
        end

        bind_context = context || CycleContext.new(nodes: [node], pods: [])
        if @nominate_handler && pre_bind_work?(pod, node, bind_context)
          begin
            invoke_handler(@nominate_handler, :nominate, pod, node.name)
          rescue StandardError
            # Not critical enough to stop the binding (upstream logs it).
            nil
          end
        end
        pre_bind_started = monotonic
        begin
          plugins.phase_plugins(:pre_bind).each do |plugin|
            output = invoke_plugin(plugin, pod, node, bind_context, phase: :pre_bind)
            trace&.record(plugin: plugin.name, phase: :pre_bind, weight: plugin.weight,
                          input: {"pod" => pod.to_h, "node" => node.to_h}, output: output == true ? true : output)
            raise BindError, "pre-bind plugin #{plugin.name} rejected #{pod.name}" if output == false || output.is_a?(Rejection)
          end
        rescue StandardError
          @metrics.extension_point(:pre_bind, Metrics::STATUS_ERROR, monotonic - pre_bind_started)
          raise
        end
        @metrics.extension_point(:pre_bind, Metrics::STATUS_SUCCESS, monotonic - pre_bind_started)
        bind_started = monotonic
        begin
          bound = bind_through!(original, pod, node, bind_context, trace)
        rescue StandardError
          @metrics.extension_point(:bind, Metrics::STATUS_ERROR, monotonic - bind_started)
          raise
        end
        @metrics.extension_point(:bind, Metrics::STATUS_SUCCESS, monotonic - bind_started)
        bound
      rescue BindError
        raise
      rescue StandardError => error
        raise BindError.new("bind failed: #{error.message}", cause_error: error), cause: error
      end

        if @bind_handler
          result = invoke_handler(@bind_handler, :bind, pod, node)
          raise BindError, "bind handler rejected #{pod.name}" if result == false
          observed_name = Support.value(Support.object_hash(Support.value(original, "spec", {})), "nodeName", "").to_s if original
          if observed_name && !observed_name.empty? && observed_name != node.name
            raise BindError, "pod nodeName changed during bind"
          end
          bound = if result.is_a?(Pod)
                    result
                  elsif result.is_a?(Hash) || (result.respond_to?(:to_h) && !result.is_a?(TrueClass))
                    Pod.new(result)
                  else
                    pod
                  end
          unless same_pod?(bound, pod)
            raise BindError, "bind handler returned a different pod"
          end
          if !bound.node_name.empty? && bound.node_name != node.name
            raise BindError, "bind handler returned a pod bound to #{bound.node_name.inspect}"
          end
          return bound.with("spec" => bound.spec.merge("nodeName" => node.name)) if bound.node_name.empty?

          return bound
        end

        binder_plugins = bind_plugins
        bound = if binder_plugins.empty?
                  Support.deep_copy(pod.to_h)
                else
                  plugin = binder_plugins.first
                  output = invoke_plugin(plugin, pod, node, bind_context, phase: :bind)
                  trace&.record(plugin: plugin.name, phase: :bind, weight: plugin.weight,
                                input: {"pod" => pod.to_h, "node" => node.to_h},
                                output: output.respond_to?(:to_h) ? output.to_h : output)
                  if output == true || output.nil?
                    Support.deep_copy(pod.to_h)
                  elsif output.is_a?(Pod)
                    output.to_h
                  elsif output.respond_to?(:to_h)
                    output.to_h
                  else
                    raise BindError, "bind plugin #{plugin.name} returned an invalid result"
                  end
                end
        bound = Support.deep_copy(bound)
        bound["spec"] = Support.object_hash(bound["spec"] || {})
        bound["spec"]["nodeName"] = node.name
        if original.is_a?(Hash) && !original.frozen?
          original_spec = original["spec"] || original[:spec] || {}
          if original_spec.is_a?(Hash) && !original_spec.frozen?
            original_spec["nodeName"] = node.name
          end
        end
        Pod.new(bound)
      rescue BindError
        raise
      rescue StandardError => error
        raise BindError.new("bind failed: #{error.message}", cause_error: error), cause: error
      end

      # Decide what happens to a Pod whose scheduling cycle failed.
      #
      # A Pod that the API server reports as gone must NOT be requeued.  The
      # delete event that removed it from the queue has already been delivered
      # and will never arrive again, so re-admitting it resurrects an item
      # nothing can ever remove; because PrioritySort orders by creation time,
      # that zombie then sorts ahead of every Pod created after it and is
      # popped on every tick, starving the queue permanently.
      #
      # Every other failure is transient from the queue's point of view and
      # goes back through the backoff queue, never straight into the active
      # queue: a repeatedly failing item must not be able to monopolise the
      # scheduling loop.
      def requeue_after_failure(pod, error)
        typed = pod.is_a?(Pod) ? pod : Pod.new(pod)
        reason = "#{error.class}: #{error.message}"
        if pod_gone?(typed, error)
          if queue.respond_to?(:drop)
            queue.drop(typed, reason: reason)
          else
            queue.delete(typed)
          end
          return :dropped
        end

        if queue.respond_to?(:enqueue_backoff)
          queue.enqueue_backoff(typed, reason: reason)
        else
          queue.enqueue(typed, reason: reason)
        end
        :requeued
      end

      # True when the failure says this Pod no longer exists.  Deliberately
      # narrow: a 404 for some other object (a PVC, a Node) must not evict a
      # live Pod from the queue, so the Pod's own name has to appear in the
      # failing request.
      def pod_gone?(pod, error)
        name = pod.name.to_s
        return false if name.empty?

        current = error
        8.times do
          break unless current

          status = current.respond_to?(:status) ? current.status : nil
          if status.to_i == 404
            message = current.message.to_s
            return true if message.include?("/pods/#{name}") ||
                           message.include?("pods \"#{name}\"") ||
                           message.include?("/pods/#{name}/binding")
          end
          nxt = current.respond_to?(:cause_error) ? current.cause_error : nil
          nxt ||= current.respond_to?(:cause) ? current.cause : nil
          break if nxt.equal?(current)

          current = nxt
        end
        false
      end

      def rollback!(reservation, pod, node, error, context: nil, trace: nil)
        if reservation
          begin
            invoke_unreserve(@unreserve_handler, pod, node, reservation) if @unreserve_handler
          rescue StandardError => cleanup_error
            error.instance_variable_set(:@cleanup_error, cleanup_error)
          ensure
            @mutex.synchronize { @reservations.delete(reservation.key) }
          end
        end
        plugins.phase_plugins(:unreserve).each do |plugin|
          begin
            output = invoke_plugin(plugin, pod, node, context || CycleContext.new(nodes: [node], pods: []), phase: :unreserve)
            trace&.record(plugin: plugin.name, phase: :unreserve, weight: plugin.weight,
                          input: {"pod" => pod.to_h, "node" => node.to_h}, output: output == true ? true : output)
          rescue StandardError => cleanup_error
            error.instance_variable_set(:@cleanup_error, cleanup_error)
          end
        end
        begin
          invoke_handler(@rollback_handler, :rollback, pod, node, error) if @rollback_handler
        rescue StandardError => cleanup_error
          error.instance_variable_set(:@rollback_error, cleanup_error)
        end
      end

      def commit_reservation!(reservation)
        return unless reservation

        @mutex.synchronize do
          @reservations.delete(reservation.key) if @reservations[reservation.key].equal?(reservation)
        end
      end

      def invoke_handler(handler, method_name, *arguments)
        return nil unless handler
        callable = if handler.respond_to?(:call)
                     handler
                   elsif handler.respond_to?(method_name)
                     handler.method(method_name)
                   else
                     raise ArgumentError, "handler does not implement #{method_name}"
                   end
        arity = callable.arity
        return callable.call(*arguments) if arity.negative?

        case arity
        when 0 then callable.call
        when 1 then callable.call(arguments.first)
        when 2 then callable.call(*arguments.take(2))
        else callable.call(*arguments.take(arity))
        end
      end

      def invoke_unreserve(handler, pod, node, reservation)
        callable = if handler.respond_to?(:call)
                     handler
                   elsif handler.respond_to?(:unreserve)
                     handler.method(:unreserve)
                   else
                     raise ArgumentError, "handler does not implement unreserve"
                   end
        return callable.call(reservation) if callable.arity == 1
        return callable.call(pod, node) if callable.arity == 2
        return callable.call(reservation, pod, node) if callable.arity == 3 || callable.arity.negative?

        callable.call
      end

      def same_pod?(left, right)
        if !left.uid.empty? || !right.uid.empty?
          left.uid == right.uid && left.namespace == right.namespace && left.name == right.name
        else
          left.namespace == right.namespace && left.name == right.name
        end
      end

      def pod_identity(pod)
        pod.uid.empty? ? [pod.namespace, pod.name] : ["uid", pod.uid, pod.namespace, pod.name]
      end

      def deduplicate_pods(values)
        seen = {}
        values.each_with_object([]) do |pod, result|
          key = pod.uid.empty? ? [pod.namespace, pod.name] : ["uid", pod.uid]
          existing = seen[key]
          if existing
            next if existing.to_h == pod.to_h

            raise ValidationError, "scheduler received conflicting pods for #{key.inspect}"
          end
          seen[key] = pod
          result << pod
        end
      end

      def pod_lock_key(pod)
        pod.uid.empty? ? [pod.namespace, pod.name] : ["uid", pod.uid]
      end

      # Lock order is map mutex -> per-Pod monitor for acquisition and
      # per-Pod monitor -> map mutex for release; the map mutex is never held
      # while waiting for a monitor, which prevents lock-order deadlocks.
      def acquire_pod_lock(key)
        entry = @mutex.synchronize do
          value = (@pod_locks[key] ||= {monitor: Monitor.new, users: 0})
          value[:users] += 1
          value
        end
        entry[:monitor].enter
        entry
      end

      def release_pod_lock(key, entry)
        entry[:monitor].exit
        @mutex.synchronize do
          entry[:users] -= 1
          @pod_locks.delete(key) if entry[:users].zero? && @pod_locks[key].equal?(entry)
        end
      end

    end

    SchedulerFramework = Framework unless const_defined?(:SchedulerFramework, false)
  end
end
