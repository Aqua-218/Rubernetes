# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "tmpdir"
require "rubernetes/node"
require_relative "../support/node_lifecycle_fakes"

# kubelet's pod startup SLI (pkg/kubelet/util/pod_startup_latency_tracker.go)
# and the pod worker / status manager / housekeeping metrics beside it
# (pkg/kubelet/metrics, v1.36.2).
class KubeletPodStartupMetricsTest < Minitest::Test
  T0 = Time.utc(2026, 9, 25, 12, 0, 0)

  def setup
    @now = T0
    @metrics = Rubernetes::Node::KubeletMetrics.new(node_name: "node-1", wall_clock: -> { @now })
    @tracker = @metrics.startup
  end

  def pod(uid: "u1", volumes: nil, host_network: false, running: false, start_time: nil, conditions: nil)
    status = {}
    status["startTime"] = start_time if start_time
    status["conditions"] = conditions if conditions
    status["containerStatuses"] = [{"name" => "c", "state" => running ? {"running" => {"startedAt" => "x"}} : {"waiting" => {}}}]
    spec = {"containers" => [{"name" => "c"}]}
    spec["volumes"] = volumes if volumes
    spec["hostNetwork"] = true if host_network
    {"metadata" => {"uid" => uid, "creationTimestamp" => T0.iso8601}, "spec" => spec, "status" => status}
  end

  def sample(name, suffix = "_count", labels = "")
    line = @metrics.registry.render.lines.find { |text| text.start_with?("#{name}#{suffix}#{labels} ") }
    line&.split&.last&.to_f
  end

  def test_the_sli_leaves_out_image_pulls_counted_once_and_init_containers
    @tracker.observed_pod_on_watch(pod, T0 + 1)
    @tracker.image_started_pulling("u1", T0 + 1)
    @tracker.image_started_pulling("u1", T0 + 3)
    @tracker.image_finished_pulling("u1", T0 + 5)
    @tracker.image_finished_pulling("u1", T0 + 7)
    @tracker.init_container_started("u1", T0 + 8)
    @tracker.init_container_finished("u1", T0 + 10)
    @now = T0 + 18
    @tracker.status_updated(pod(running: true))
    @tracker.observed_pod_on_watch(pod(running: true, start_time: "t"), T0 + 20)
    @tracker.observed_pod_on_watch(pod(running: true, start_time: "t"), T0 + 30)

    assert_equal 1, sample("kubelet_pod_start_total_duration_seconds")
    assert_equal 20, sample("kubelet_pod_start_total_duration_seconds", "_sum")
    assert_equal 12, sample("kubelet_pod_start_sli_duration_seconds", "_sum")
    assert_equal 12, sample("kubelet_first_network_pod_start_sli_duration_seconds", "")
  end

  def test_stateful_unschedulable_and_already_started_pods
    stateful = pod(uid: "s", volumes: [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "d"}}])
    @tracker.observed_pod_on_watch(stateful, T0)
    @tracker.status_updated(stateful.merge("status" => pod(running: true)["status"]))
    @tracker.observed_pod_on_watch(stateful.merge("status" => pod(running: true)["status"]), T0 + 4)

    assert_equal 1, sample("kubelet_pod_start_total_duration_seconds")
    assert_equal 0, sample("kubelet_pod_start_sli_duration_seconds").to_f

    pending = pod(uid: "p", conditions: [{"type" => "PodScheduled", "status" => "False"}])
    @tracker.observed_pod_on_watch(pending, T0)

    refute @tracker.tracked?("p")
    @tracker.observed_pod_on_watch(pod(uid: "late", start_time: "t"), T0)

    refute @tracker.tracked?("late")
  end

  def test_overlapping_pull_sessions
    time = Rubernetes::Node::PodStartupLatencyTracker.method(:image_pulling_time)

    assert_in_delta(0.0, time.call([]))
    assert_in_delta(6.0, time.call([[T0, T0 + 4], [T0 + 2, T0 + 6]]))
    assert_in_delta(5.0, time.call([[T0, T0 + 4], [T0 + 1, T0 + 2], [T0 + 10, T0 + 11]]))
  end

  def test_working_pods_admission_rejections_sandbox_gc_and_status_sync
    records = [{uid: "a", state: "Running", pod: {"spec" => {"ephemeralContainers" => [{"name" => "d"}]}}},
               {uid: "b", state: "Stopping", pod: {"metadata" => {"annotations" => {"kubernetes.io/config.source" => "file"}}}},
               {uid: "c", state: "Stopped", pod: {}}]
    %w[OutOfcpu OutOfexample.com/gpu Weird].each do |reason|
      @metrics.observe({uid: "r", admission_reason: reason}, {"type" => "pod.admission_failed", "reason" => "PodAdmissionFailed"})
    end
    @metrics.runtime_operation("run_podsandbox", 0.2, failed: true, runtime_handler: "kata")
    @metrics.image_garbage_collected("age")
    @metrics.pod_status_synced({}, nil, 0.0304)
    text = @metrics.render(records)

    assert_includes text, %(kubelet_working_pods{config="desired",lifecycle="sync",static="false"} 1)
    assert_includes text, %(kubelet_working_pods{config="desired",lifecycle="terminating",static="true"} 1)
    assert_includes text, %(kubelet_working_pods{config="desired",lifecycle="terminated",static="false"} 1)
    assert_includes text, %(kubelet_working_pods{config="runtime_only",lifecycle="sync",static="unknown"} 0)
    assert_equal(15, text.lines.count { |line| line.start_with?("kubelet_working_pods{") })
    assert_includes text, "kubelet_managed_ephemeral_containers 1"
    %w[OutOfcpu OutOfExtendedResources Other].each do |reason|
      assert_includes text, %(kubelet_admission_rejections_total{reason="#{reason}"} 1)
    end
    assert_includes text, %(kubelet_run_podsandbox_duration_seconds_count{runtime_handler="kata"} 1)
    assert_includes text, %(kubelet_run_podsandbox_errors_total{runtime_handler="kata"} 1)
    assert_includes text, %(kubelet_image_garbage_collected_total{reason="age"} 1)
    assert_includes text, "kubelet_pod_status_sync_duration_seconds_sum 0.03"
  end

  def test_the_worker_start_and_containers_per_pod
    clock = 100.0
    metrics = Rubernetes::Node::KubeletMetrics.new(node_name: "n", clock: -> { clock })
    pod = {"metadata" => {"uid" => "w"}, "spec" => {"containers" => [{"name" => "a"}, {"name" => "b"}]}}
    metrics.pod_seen(pod)
    clock = 100.5
    record = {uid: "w", pod: pod, containers: []}
    metrics.observe(record, {"type" => "state", "to" => "New"})
    metrics.observe(record, {"type" => "state", "to" => "New"})
    text = metrics.registry.render

    assert_includes text, "kubelet_pod_worker_start_duration_seconds_count 1"
    assert_includes text, "kubelet_pod_worker_start_duration_seconds_sum 0.5"
    assert_includes text, %(kubelet_containers_per_pod_count_bucket{le="2"} 1)
  end

  def test_node_startup_phases
    metrics = Rubernetes::Node::KubeletMetrics.new(node_name: "n", wall_clock: -> { @now })
    metrics.node_ready # before registration: nothing
    @now = T0 + 2
    metrics.node_registration_attempted
    @now = T0 + 5
    metrics.node_registered
    @now = T0 + 9
    metrics.node_ready
    @now = T0 + 20
    metrics.node_ready
    text = metrics.registry.render

    assert_includes text, "kubelet_node_startup_pre_registration_duration_seconds 2"
    assert_includes text, "kubelet_node_startup_registration_duration_seconds 3"
    assert_includes text, "kubelet_node_startup_post_registration_duration_seconds 4"
    boot = Rubernetes::Node::KubeletMetrics.boot_time
    assert_includes text, "kubelet_node_startup_duration_seconds #{Rubernetes::Observability::Metrics.go_float(T0.to_f + 9 - boot)}" if boot
  end

  def test_pod_worker_durations_user_namespaces_and_image_volumes
    pod = {"metadata" => {"uid" => "w"},
           "spec" => {"hostUsers" => false, "volumes" => [{"name" => "img", "image" => {"reference" => "x"}}, {"name" => "e", "emptyDir" => {}}],
                      "containers" => [{"name" => "a"}]}}
    @metrics.pod_worker_synced(pod, "ADDED", 0.1)
    @metrics.pod_worker_synced(pod, "MODIFIED", 0.1)
    @metrics.pod_worker_synced(pod, "SYNC", 0.1)
    @metrics.pod_worker_synced(pod, "DELETED", 0.1)
    record = {uid: "w", pod: pod,
              containers: [{name: "a", category: "app", spec: {"volumeMounts" => [{"name" => "img"}, {"name" => "e"}]}}]}
    @metrics.observe(record, {"type" => "sandbox.create"})
    @metrics.observe(record, {"type" => "container.create", "name" => "a"})
    @metrics.observe(record, {"type" => "pod.failed"})
    @metrics.observe(record, {"type" => "pod.failed"})
    text = @metrics.registry.render

    %w[create update sync kill].each do |type|
      assert_includes text, %(kubelet_pod_worker_duration_seconds_count{operation_type="#{type}"} 1)
    end
    assert_includes text, "kubelet_started_user_namespaced_pods_total 1"
    assert_includes text, "kubelet_started_user_namespaced_pods_errors_total 1"
    assert_includes text, "kubelet_image_volume_requested_total 1"
    assert_includes text, "kubelet_image_volume_mounted_succeed_total 1"
  end

  def test_shutdown_eviction_and_cgroup_metrics
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, "graceful_node_shutdown_state"),
                 JSON.generate("startTime" => "2026-09-25T10:00:00.5Z", "endTime" => "0001-01-01T00:00:00Z"))
      manager = Rubernetes::Node::ShutdownManager.new(periods: [], active_pods: -> { [] }, kill_pod: ->(*) {}, pod_terminated: lambda { |_|
        true
      },
                                                      state_directory: dir, inhibiter: -> {})
      gauges = {}
      manager.gauge_sink = ->(name, value) { gauges[name] = value }
      manager.load_metrics

      assert_equal({"kubelet_graceful_shutdown_start_time_seconds" => Time.utc(2026, 9, 25, 10).to_i}, gauges)
    end
    @metrics.eviction_stats_age("memory.available", 1.5)
    @metrics.cgroup_operation("update", 0.002)
    @metrics.runtime_operation("update_podsandbox_resources", 0.01)
    text = @metrics.registry.render

    assert_includes text, %(kubelet_eviction_stats_age_seconds_count{eviction_signal="memory.available"} 1)
    assert_includes text, %(kubelet_cgroup_manager_duration_seconds_count{operation_type="update"} 2)
  end

  def test_resize_metrics
    old = {"spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => {"cpu" => "100m", "memory" => "64Mi"},
                                                                       "limits" => {"memory" => "128Mi"}}}]}}
    new = {"spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => {"cpu" => "200m"},
                                                                       "limits" => {"memory" => "64Mi", "cpu" => "1"}}}]}}
    @metrics.resize_requested(old, new)
    @metrics.pod_resize_duration(0.0421, true)
    @metrics.pod_infeasible_resize("guaranteed_pod_cpu_manager_static_policy")
    @metrics.deferred_resize_accepted("pod_updated")
    records = [{uid: "a", state: "Running", pod: {}, resize_pending: {"reason" => "Deferred"}},
               {uid: "b", state: "Running", pod: {}, resize_pending: {"reason" => "Infeasible"}, resize_in_progress: {}}]
    text = @metrics.render(records)

    {%w[cpu requests] => "increase", %w[memory requests] => "remove", %w[memory limits] => "decrease",
     %w[cpu limits] => "add"}.each do |(resource, kind), operation|
      assert_includes text,
                      %(kubelet_container_requested_resizes_total{operation="#{operation}",requirement="#{kind}",resource="#{resource}"} 1)
    end
    assert_includes text, %(kubelet_pod_resize_duration_milliseconds_sum{success="true"} 42)
    assert_includes text, %(kubelet_pod_infeasible_resizes_total{reason_detail="guaranteed_pod_cpu_manager_static_policy"} 1)
    assert_includes text, %(kubelet_pod_deferred_accepted_resizes_total{retry_trigger="pod_updated"} 1)
    assert_includes text, %(kubelet_pod_pending_resizes{reason="deferred"} 1)
    assert_includes text, %(kubelet_pod_pending_resizes{reason="infeasible"} 1)
    assert_includes text, "kubelet_pod_in_progress_resizes 1"
    text = @metrics.render([])

    refute_includes text, "kubelet_pod_pending_resizes{"
  end

  def test_a_static_cpu_manager_makes_a_guaranteed_cpu_resize_infeasible
    pod = lambda do |cpu|
      {"spec" => {"containers" => [{"name" => "c", "resources" => {"requests" => {"cpu" => cpu, "memory" => "1Gi"},
                                                                   "limits" => {"cpu" => cpu, "memory" => "1Gi"}}}]}}
    end
    infeasible = Rubernetes::Node::PodResize.method(:infeasible)

    assert_equal ["guaranteed_pod_cpu_manager_static_policy", %(Resize is infeasible for Guaranteed Pods alongside CPU Manager policy "static")],
                 infeasible.call(pod.call("1"), pod.call("2"), cpu_policy: "static", memory_policy: "None")
    assert_nil infeasible.call(pod.call("1"), pod.call("2"), cpu_policy: "none", memory_policy: "None")
    assert_nil infeasible.call(pod.call("1"), pod.call("1000m"), cpu_policy: "static", memory_policy: "None")
  end
end
