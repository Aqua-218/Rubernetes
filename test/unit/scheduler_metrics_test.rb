# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"
require "rubernetes/storage/memory_store"
require "rubernetes/controller/lease"
require "rubernetes/watch/delta_fifo"

# pkg/scheduler/metrics: the series kube-scheduler serves, recorded by the
# framework, the queue and the plugins with upstream's names and labels.
class SchedulerMetricsTest < Minitest::Test
  Scheduler = Rubernetes::Scheduler
  Controller = Rubernetes::Controller

  def pod(name, cpu: "1", spec: {})
    Scheduler::Pod.new({"apiVersion" => "v1", "kind" => "Pod",
                        "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"},
                        "spec" => {"containers" => [{"name" => "c", "image" => "nginx",
                                                     "resources" => {"requests" => {"cpu" => cpu}}}]}.merge(spec)})
  end

  def node(name, cpu: "2")
    Scheduler::Node.new({"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "labels" => {}},
                         "spec" => {"taints" => []},
                         "status" => {"allocatable" => {"cpu" => cpu, "memory" => "2Gi"}, "conditions" => [{"type" => "Ready", "status" => "True"}]}})
  end

  def framework(metrics)
    Scheduler::Framework.new(bind: ->(_pod, _node) { true }, metrics: metrics, opportunistic_batching: false)
  end

  def line(text, name, **labels)
    text.lines.map(&:chomp).find do |entry|
      entry.start_with?(name) && labels.all? { |key, value| entry.include?("#{key}=\"#{value}\"") }
    end
  end

  def value(text, name, **labels)
    found = line(text, name, **labels)
    found && Float(found.split.last)
  end

  def test_registry_declares_the_inventory_and_leaves_unimplemented_series_out
    metrics = Scheduler::Metrics.new
    names = metrics.registry.registered_names
    %w[scheduler_schedule_attempts_total scheduler_scheduling_attempt_duration_seconds scheduler_pending_pods
       scheduler_framework_extension_point_duration_seconds scheduler_plugin_execution_duration_seconds
       scheduler_queue_incoming_pods_total scheduler_unschedulable_pods scheduler_cache_size scheduler_goroutines
       scheduler_async_api_call_execution_total scheduler_pod_scheduling_attempts scheduler_pod_scheduling_sli_duration_seconds
       scheduler_volume_binder_cache_requests_total scheduler_resourceclaim_creates_total scheduler_batch_attempts_total
       scheduler_get_node_hint_duration_seconds kubernetes_build_info disabled_metrics_total].each do |name|
      assert_includes names, name
    end
    %w[scheduler_inflight_events scheduler_queueing_hint_execution_duration_seconds
       scheduler_podgroup_schedule_attempts_total rest_client_exec_plugin_call_total rest_client_rate_limiter_duration_seconds].each do |name|
      refute_includes names, name, "#{name} measures machinery that does not exist here"
    end
    # client-go registers these plain families unconditionally: present and
    # empty (the TTL gauge at +Inf) as on every upstream component.
    assert_includes names, "rest_client_exec_plugin_certificate_rotation_age"
    assert_includes metrics.render, "rest_client_exec_plugin_ttl_seconds +Inf"
    text = metrics.render
    assert_equal 0.0, value(text, "disabled_metrics_total")
    # Upstream bucket bounds come from the inventory: attempt duration is
    # ExponentialBuckets(0.001, 2, 15), victims ExponentialBuckets(1, 2, 7).
    entry = Rubernetes::Observability::Metrics.upstream.fetch("scheduler_scheduling_attempt_duration_seconds")
    assert_equal 15, entry["buckets"].length
    assert_in_delta 0.001, entry["buckets"].first
  end

  def test_a_scheduled_pod_records_extension_points_plugins_queue_events_and_attempts
    metrics = Scheduler::Metrics.new
    fw = framework(metrics)
    result = fw.schedule(pod("web"), [node("a"), node("b")], enqueue: true)
    assert result.scheduled?
    text = metrics.render
    assert_equal 1.0, value(text, "scheduler_framework_extension_point_duration_seconds_count", extension_point: "PreEnqueue", status: "Success")
    assert_equal 1.0, value(text, "scheduler_framework_extension_point_duration_seconds_count", extension_point: "Filter", status: "Success")
    assert_equal 1.0, value(text, "scheduler_framework_extension_point_duration_seconds_count", extension_point: "Score", status: "Success")
    assert_equal 1.0, value(text, "scheduler_framework_extension_point_duration_seconds_count", extension_point: "Reserve", status: "Success")
    assert_equal 1.0, value(text, "scheduler_framework_extension_point_duration_seconds_count", extension_point: "PreBind", status: "Success")
    assert_equal 1.0, value(text, "scheduler_framework_extension_point_duration_seconds_count", extension_point: "Bind", status: "Success")
    assert_equal 1.0, value(text, "scheduler_scheduling_algorithm_duration_seconds_count")
    # Filter plugins are counted once per node, Score plugins once per cycle.
    assert_equal 2.0, value(text, "scheduler_plugin_evaluation_total", extension_point: "Filter", plugin: "NodeName", profile: "default-scheduler")
    assert_equal 1.0, value(text, "scheduler_plugin_evaluation_total", extension_point: "Score", plugin: "NodeResourcesFit")
    assert_equal 1.0, value(text, "scheduler_queue_incoming_pods_total", event: "PodAdd", queue: "active")
    assert_equal 1.0, value(text, "scheduler_pod_scheduling_attempts_count")
    assert_equal 0.0, value(text, "scheduler_pending_pods", queue: "active")
    assert_equal 0.0, value(text, "scheduler_pending_pods", queue: "gated")
  end

  def test_an_unschedulable_pod_is_counted_against_the_rejecting_plugin
    metrics = Scheduler::Metrics.new
    fw = framework(metrics)
    result = fw.schedule(pod("big", cpu: "8"), [node("a"), node("b")], enqueue: true)
    assert result.unschedulable?
    text = metrics.render
    assert_equal 1.0, value(text, "scheduler_framework_extension_point_duration_seconds_count", extension_point: "Filter", status: "Unschedulable")
    assert_equal 1.0, value(text, "scheduler_unschedulable_pods", plugin: "NodeResourcesFit", profile: "default-scheduler")
    assert_equal 1.0, value(text, "scheduler_queue_incoming_pods_total", event: "ScheduleAttemptFailure", queue: "unschedulable")
    assert_equal 1.0, value(text, "scheduler_pending_pods", queue: "unschedulable")
    # A retry moves it back to the active queue under the triggering event.
    fw.queue.promote_unschedulable(event: "NodeAdd")
    text = metrics.render
    assert_equal 1.0, value(text, "scheduler_queue_incoming_pods_total", event: "NodeAdd", queue: "active")
    assert_equal 0.0, value(text, "scheduler_unschedulable_pods", plugin: "NodeResourcesFit") || 0.0
  end

  def test_a_gated_pod_is_pending_as_gated_and_never_attempted
    metrics = Scheduler::Metrics.new
    fw = framework(metrics)
    result = fw.schedule(pod("gated", spec: {"schedulingGates" => [{"name" => "example.com/wait"}]}), [node("a")], enqueue: true)
    assert result.gated?
    text = metrics.render
    assert_equal 1.0, value(text, "scheduler_framework_extension_point_duration_seconds_count", extension_point: "PreEnqueue", status: "Unschedulable")
    assert_equal 1.0, value(text, "scheduler_pending_pods", queue: "gated")
    assert_equal 0.0, value(text, "scheduler_pending_pods", queue: "unschedulable")
    # Never observed: the label-less histogram shows count 0, like client_golang.
    assert_equal 0.0, value(text, "scheduler_scheduling_algorithm_duration_seconds_count")
  end

  def test_pop_attempts_feed_the_scheduling_attempts_histogram
    metrics = Scheduler::Metrics.new
    fw = framework(metrics)
    queue = fw.queue
    queue.enqueue(pod("late"))
    popped = queue.pop
    queue.enqueue_backoff(popped.pod, reason: "bind failed")
    queue.flush_backoff(Process.clock_gettime(Process::CLOCK_MONOTONIC) + 60)
    popped = queue.pop
    assert_equal 2, queue.pop_attempts(popped.pod)
    result = fw.schedule(popped.pod, [node("a")])
    assert result.scheduled?
    text = metrics.render
    assert_equal 1.0, value(text, "scheduler_queue_incoming_pods_total", event: "BackoffComplete", queue: "active")
    assert_equal 1.0, value(text, "scheduler_queue_incoming_pods_total", event: "ScheduleAttemptFailure", queue: "backoff")
    assert_equal 1.0, value(text, "scheduler_pod_scheduling_sli_duration_seconds_count", attempts: "2")
    assert_equal 2.0, value(text, "scheduler_pod_scheduling_attempts_sum")
  end

  def test_plugin_execution_durations_are_sampled_per_cycle
    metrics = Scheduler::Metrics.new(random: Random.new(1))
    metrics.define_singleton_method(:sample_plugins?) { true }
    fw = framework(metrics)
    fw.schedule(pod("web"), [node("a")])
    text = metrics.render
    assert_operator value(text, "scheduler_plugin_execution_duration_seconds_count", extension_point: "Filter", plugin: "NodeName", status: "Success"), :>=, 1.0
  end

  def test_async_calls_goroutines_and_cache_sizes
    metrics = Scheduler::Metrics.new
    metrics.async_call_queued("pod_binding")
    metrics.goroutine_started("binding")
    metrics.cache_size("nodes", 3)
    text = metrics.render
    assert_equal 1.0, value(text, "scheduler_pending_async_api_calls", call_type: "pod_binding")
    assert_equal 1.0, value(text, "scheduler_goroutines", operation: "binding")
    assert_equal 3.0, value(text, "scheduler_cache_size", type: "nodes")
    metrics.async_call("pod_binding", "success", 0.01)
    metrics.goroutine_finished("binding")
    text = metrics.render
    assert_equal 0.0, value(text, "scheduler_pending_async_api_calls", call_type: "pod_binding")
    assert_equal 1.0, value(text, "scheduler_async_api_call_execution_total", call_type: "pod_binding", result: "success")
    assert_equal 0.0, value(text, "scheduler_goroutines", operation: "binding")
  end

  def test_resource_metrics_render_requests_and_limits_per_pod
    pods = [
      {"metadata" => {"name" => "web", "namespace" => "default"},
       "spec" => {"nodeName" => "a", "priority" => 10,
                  "initContainers" => [{"name" => "init", "resources" => {"requests" => {"cpu" => "1500m", "memory" => "64Mi"}}}],
                  "containers" => [{"name" => "c1", "resources" => {"requests" => {"cpu" => "500m", "memory" => "128Mi"}, "limits" => {"memory" => "256Mi"}}},
                                   {"name" => "c2", "resources" => {"requests" => {"cpu" => "250m"}}}]}},
      {"metadata" => {"name" => "done", "namespace" => "default"}, "status" => {"phase" => "Succeeded"},
       "spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => {"cpu" => "1"}}}]}},
      {"metadata" => {"name" => "pending", "namespace" => "default"},
       "spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => {"nvidia.com/gpu" => "1"}}}]}}
    ]
    text = Scheduler::ResourceMetrics.render(pods)
    # init container 1.5 cores > 0.5 + 0.25 of the app containers.
    assert_equal 1.5, value(text, "kube_pod_resource_request", pod: "web", resource: "cpu", unit: "cores", node: "a", priority: "10", scheduler: "default-scheduler")
    assert_equal 128 * 1024 * 1024.0, value(text, "kube_pod_resource_request", pod: "web", resource: "memory", unit: "bytes")
    assert_equal 256 * 1024 * 1024.0, value(text, "kube_pod_resource_limit", pod: "web", resource: "memory")
    assert_nil line(text, "kube_pod_resource_request", pod: "done")
    assert_equal 1.0, value(text, "kube_pod_resource_request", pod: "pending", resource: "nvidia.com/gpu", unit: "integer", node: "")
    assert_includes text, "# TYPE kube_pod_resource_request gauge"
  end

  def test_leader_renews_on_the_fast_path_and_counts_the_slow_path
    now = Time.utc(2026, 9, 29, 12, 0, 0)
    store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    elector = Controller::LeaseElector.new(store: store, identity: "one", clock: -> { now }, name: "kube-scheduler")
    assert_equal :acquired, elector.step
    reads = 0
    adapter = elector.instance_variable_get(:@adapter)
    original_get = adapter.method(:get)
    adapter.define_singleton_method(:get) { |*args, **options| reads += 1; original_get.call(*args, **options) }
    now += 3
    assert_equal :renewed, elector.step(force: true)
    assert_equal 0, reads, "a leader renews from its cached record without reading the Lease"
    # Somebody else rewrote the Lease: the cached update conflicts, the slow
    # path re-reads and (the holder still being us) renews again.
    other = Controller::LeaseElector.new(store: store, identity: "two", clock: -> { now }, name: "kube-scheduler")
    other.step
    live = adapter.get(elector.lease_descriptor, namespace: "kube-system", name: "kube-scheduler")
    candidate = Rubernetes::Controller::Support.deep_copy(live)
    candidate["metadata"]["annotations"] = {"touched" => "yes"}
    adapter.update(candidate, descriptor: elector.lease_descriptor, existing: live)
    registry = Rubernetes::Observability::Metrics.global
    before = value(registry.render_own, "leader_election_slowpath_total", name: "kube-scheduler") || 0.0
    now += 3
    assert_equal :renewed, elector.step(force: true)
    assert_equal before + 1, value(registry.render_own, "leader_election_slowpath_total", name: "kube-scheduler")
  end

  def test_delta_fifo_reports_how_long_a_key_waited
    clock_now = 1.0
    fifo = Rubernetes::Watch::DeltaFIFO.new(clock: -> { clock_now })
    fifo.add({"metadata" => {"name" => "a", "namespace" => "ns"}})
    clock_now = 3.0
    key, = fifo.pop(timeout: 0)
    clock_now = 4.0
    assert_in_delta 3.0, fifo.queued_seconds(key)
    fifo.done(key)
    assert_nil fifo.queued_seconds(key)
  end
end
