# frozen_string_literal: true

require_relative "../observability/metrics"
require_relative "resource_metrics"

module Rubernetes
  module Scheduler
    # pkg/scheduler/metrics: what kube-scheduler records around a scheduling
    # cycle, with upstream's names, labels and bucket bounds (declared by
    # the v1.36.2 inventory the registry is built from).  The framework, the
    # queue and the service call these; NullMetrics is what they get when no
    # registry is wired (library use, tests).
    class Metrics
      PROFILE = "default-scheduler"
      # Extension point names as pkg/scheduler/metrics spells them.
      EXTENSION_POINTS = {
        pre_enqueue: "PreEnqueue", queue_sort: "Sort", pre_filter: "PreFilter", filter: "Filter",
        post_filter: "PostFilter", pre_score: "PreScore", score: "Score", reserve: "Reserve",
        unreserve: "Unreserve", permit: "Permit", pre_bind: "PreBind", bind: "Bind", post_bind: "PostBind"
      }.freeze
      # framework.Code strings.
      STATUS_SUCCESS = "Success"
      STATUS_ERROR = "Error"
      STATUS_UNSCHEDULABLE = "Unschedulable"
      STATUS_SKIP = "Skip"
      # Every tenth cycle records per-plugin durations
      # (pluginMetricsSamplePercent = 10).
      PLUGIN_METRICS_SAMPLE_PERCENT = 10
      # getAttemptsLabel caps the attempts label.
      ATTEMPTS_LABEL_MAX = 15
      # metrics.Binding / metrics.PreemptionEvaluation, the goroutine
      # operations this scheduler runs concurrently.
      GOROUTINE_BINDING = "binding"
      GOROUTINE_PREEMPTION = "preemption_evaluation"

      attr_reader :registry

      def initialize(registry: nil, profile: PROFILE, random: Random.new)
        @registry = registry || Observability::Metrics.new(apiserver: false, component: "kube-scheduler")
        @profile = profile
        @random = random
        @mutex = Mutex.new
        @pending_async = Hash.new(0)
        @goroutines = Hash.new(0)
        @cache_sizes = {}
        @unschedulable = {}
        @registry.add_collector { |registry| collect(registry) }
      end

      # -- scheduling cycle --------------------------------------------------

      # scheduler_framework_extension_point_duration_seconds.
      def extension_point(point, status, seconds)
        observe("scheduler_framework_extension_point_duration_seconds", seconds,
                {"extension_point" => EXTENSION_POINTS.fetch(point.to_sym, point.to_s), "profile" => @profile, "status" => status.to_s})
      end

      # Whether this cycle samples per-plugin durations.
      def sample_plugins?
        @random.rand(100) < PLUGIN_METRICS_SAMPLE_PERCENT
      end

      # scheduler_plugin_execution_duration_seconds (sampled cycles only).
      def plugin_execution(point, plugin, status, seconds)
        observe("scheduler_plugin_execution_duration_seconds", seconds,
                {"extension_point" => EXTENSION_POINTS.fetch(point.to_sym, point.to_s), "plugin" => plugin.to_s, "status" => status.to_s})
      end

      # scheduler_plugin_evaluation_total: once per Filter plugin per node,
      # once per Score plugin per cycle.
      def plugin_evaluated(point, plugin)
        increment("scheduler_plugin_evaluation_total",
                  {"extension_point" => EXTENSION_POINTS.fetch(point.to_sym, point.to_s), "plugin" => plugin.to_s, "profile" => @profile})
      end

      # scheduler_scheduling_algorithm_duration_seconds: schedulePod (filter
      # and score, without binding).
      def algorithm(seconds)
        observe("scheduler_scheduling_algorithm_duration_seconds", seconds)
      end

      # scheduler_schedule_attempts_total and
      # scheduler_scheduling_attempt_duration_seconds, result "scheduled",
      # "unschedulable" or "error".
      def attempt(result, seconds)
        labels = {"result" => result.to_s, "profile" => @profile}
        increment("scheduler_schedule_attempts_total", labels)
        observe("scheduler_scheduling_attempt_duration_seconds", seconds, labels)
      end

      # A Pod bound: scheduler_pod_scheduling_attempts (how many pops it
      # took) and scheduler_pod_scheduling_sli_duration_seconds (since its
      # first attempt, gated time excluded).
      def pod_scheduled(attempts, seconds_since_first_attempt)
        observe("scheduler_pod_scheduling_attempts", attempts.to_f)
        return if seconds_since_first_attempt.nil?

        label = attempts > ATTEMPTS_LABEL_MAX ? "#{ATTEMPTS_LABEL_MAX}+" : attempts.to_s
        observe("scheduler_pod_scheduling_sli_duration_seconds", seconds_since_first_attempt, {"attempts" => label})
      end

      # scheduler_preemption_attempts_total / scheduler_preemption_victims.
      def preemption(victims)
        increment("scheduler_preemption_attempts_total")
        observe("scheduler_preemption_victims", victims.to_f)
      end

      # SchedulerAsyncPreemption's goroutine series.
      def preemption_goroutine(result, seconds)
        labels = {"result" => result.to_s}
        observe("scheduler_preemption_goroutines_duration_seconds", seconds, labels)
        increment("scheduler_preemption_goroutines_execution_total", labels)
      end

      # scheduler_permit_wait_duration_seconds{result}: a Pod's stay in the
      # Permit waiting list (Success when allowed, Unschedulable otherwise).
      def permit_wait(result, seconds)
        observe("scheduler_permit_wait_duration_seconds", seconds, {"result" => result.to_s})
      end

      # -- queue -------------------------------------------------------------

      # scheduler_queue_incoming_pods_total{event, queue}.
      def queue_incoming(event, queue)
        increment("scheduler_queue_incoming_pods_total", {"event" => event.to_s, "queue" => queue.to_s})
      end

      # scheduler_event_handling_duration_seconds: one informer handler run.
      # scheduler_podgroup_schedule_attempts_total / _scheduling_attempt_duration_seconds
      # {profile,result} and the algorithm latency (GenericWorkload).
      def pod_group_attempt(profile, result, seconds)
        labels = {"profile" => profile.to_s, "result" => result.to_s}
        increment("scheduler_podgroup_schedule_attempts_total", labels)
        observe("scheduler_podgroup_scheduling_attempt_duration_seconds", seconds, labels)
      end

      def pod_group_algorithm(seconds)
        observe("scheduler_podgroup_scheduling_algorithm_duration_seconds", seconds)
      end

      # scheduler_queueing_hint_execution_duration_seconds{event,hint,plugin}.
      def queueing_hint(plugin, event, hint, seconds)
        observe("scheduler_queueing_hint_execution_duration_seconds", seconds, {"event" => event.to_s, "hint" => hint.to_s, "plugin" => plugin.to_s})
      end

      # scheduler_inflight_events{event}: the events the queue still holds
      # for the Pods being scheduled.
      def inflight_events(counts)
        @inflight_labels ||= []
        (@inflight_labels - counts.keys).each { |event| @registry.set("scheduler_inflight_events", 0, {"event" => event}) }
        counts.each { |event, count| @registry.set("scheduler_inflight_events", count, {"event" => event.to_s}) }
        @inflight_labels = counts.keys
      rescue StandardError
        nil
      end

      def event_handled(event, seconds)
        observe("scheduler_event_handling_duration_seconds", seconds, {"event" => event.to_s})
      end

      # The queue's view for scheduler_pending_pods and
      # scheduler_unschedulable_pods; asked at scrape time.
      attr_accessor :queue

      # -- async API calls (SchedulerAsyncAPICalls) --------------------------

      CALL_POD_BINDING = "pod_binding"
      CALL_POD_STATUS_PATCH = "pod_status_patch"

      def async_call_queued(call_type)
        @mutex.synchronize { @pending_async[call_type.to_s] += 1 }
      end

      def async_call(call_type, result, seconds)
        @mutex.synchronize { @pending_async[call_type.to_s] = [@pending_async[call_type.to_s] - 1, 0].max }
        labels = {"call_type" => call_type.to_s, "result" => result.to_s}
        increment("scheduler_async_api_call_execution_total", labels)
        observe("scheduler_async_api_call_execution_duration_seconds", seconds, labels)
      end

      # -- goroutines / cache --------------------------------------------------

      def goroutine_started(operation)
        @mutex.synchronize { @goroutines[operation.to_s] += 1 }
      end

      def goroutine_finished(operation)
        @mutex.synchronize { @goroutines[operation.to_s] = [@goroutines[operation.to_s] - 1, 0].max }
      end

      # scheduler_cache_size{type}: nodes, pods, assumed_pods.
      def cache_size(type, count)
        @mutex.synchronize { @cache_sizes[type.to_s] = count.to_i }
      end

      # -- opportunistic batching ---------------------------------------------

      def batch_attempt(result)
        increment("scheduler_batch_attempts_total", {"profile" => @profile, "result" => result.to_s})
      end

      def batch_flushed(reason)
        increment("scheduler_batch_cache_flushed_total", {"profile" => @profile, "reason" => reason.to_s})
      end

      def scheduled_after_flush
        increment("scheduler_pod_scheduled_after_flush_total")
      end

      def node_hint(hinted, seconds)
        observe("scheduler_get_node_hint_duration_seconds", seconds, {"hinted" => hinted ? "true" : "false", "profile" => @profile})
      end

      def store_schedule_results(seconds)
        observe("scheduler_store_schedule_results_duration_seconds", seconds, {"profile" => @profile})
      end

      # -- plugins with their own series ------------------------------------------

      # volumebinding: scheduler_volume_binder_cache_requests_total{operation}
      # ("assume", "bind") and scheduler_volume_scheduling_stage_error_total
      # {operation} ("predicate", "assume", "bind").
      def volume_binder_cache_request(operation)
        increment("scheduler_volume_binder_cache_requests_total", {"operation" => operation.to_s})
      end

      def volume_scheduling_stage_error(operation)
        increment("scheduler_volume_scheduling_stage_error_total", {"operation" => operation.to_s})
      end

      # dynamicresources: scheduler_resourceclaim_creates_total{status}
      # ("success", "failure").
      def resourceclaim_create(status)
        increment("scheduler_resourceclaim_creates_total", {"status" => status.to_s})
      end

      # -- rendering ----------------------------------------------------------------

      def render(now: nil) = @registry.render(now: now)

      private

      def collect(registry)
        queue = @queue
        if queue
          registry.set("scheduler_pending_pods", queue.size, {"queue" => "active"}) if queue.respond_to?(:size)
          registry.set("scheduler_pending_pods", queue.backoff_size, {"queue" => "backoff"}) if queue.respond_to?(:backoff_size)
          if queue.respond_to?(:unschedulable_size)
            gated = queue.respond_to?(:gated_size) ? queue.gated_size : 0
            registry.set("scheduler_pending_pods", queue.unschedulable_size - gated, {"queue" => "unschedulable"})
            registry.set("scheduler_pending_pods", gated, {"queue" => "gated"})
          end
          if queue.respond_to?(:unschedulable_plugins)
            registry.reset("scheduler_unschedulable_pods")
            queue.unschedulable_plugins.each do |plugin, count|
              registry.set("scheduler_unschedulable_pods", count, {"plugin" => plugin.to_s, "profile" => @profile})
            end
          end
        end
        snapshot = @mutex.synchronize { [@pending_async.dup, @goroutines.dup, @cache_sizes.dup] }
        pending, goroutines, sizes = snapshot
        pending.each { |type, count| registry.set("scheduler_pending_async_api_calls", count, {"call_type" => type}) }
        goroutines.each { |operation, count| registry.set("scheduler_goroutines", count, {"operation" => operation}) }
        sizes.each { |type, count| registry.set("scheduler_cache_size", count, {"type" => type}) }
      end

      def observe(name, value, labels = {})
        @registry.observe(name, value, labels)
      rescue StandardError
        nil
      end

      def increment(name, labels = {})
        @registry.increment(name, labels)
      rescue StandardError
        nil
      end
    end

    # What the framework and queue use when nothing is measuring.
    class NullMetrics
      attr_accessor :queue

      def sample_plugins? = false
      def render(**) = ""
      def registry = nil

      def method_missing(name, *_arguments, **_keywords, &_block)
        return nil if Metrics.method_defined?(name)

        super
      end

      def respond_to_missing?(name, include_private = false)
        Metrics.method_defined?(name) || super
      end
    end
  end
end
