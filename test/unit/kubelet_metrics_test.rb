# frozen_string_literal: true

# kubelet /metrics (pkg/kubelet/metrics): counters from the lifecycle's trace
# (started Pods and containers by type, start errors, terminations, Pod start
# latency, evictions) and gauges from the records (node name, running Pods
# and containers by state, desired / active / mirror Pods).

require_relative "../test_helper"
require "rubernetes/node"

class KubeletMetricsTest < Minitest::Test
  def record(uid, state: "Running", static: false)
    annotations = static ? {"kubernetes.io/config.source" => "file", "kubernetes.io/config.mirror" => "x"} : {}
    {uid: uid, state: state, sandbox_id: "s-#{uid}",
     pod: {"metadata" => {"name" => uid, "namespace" => "ns", "uid" => uid, "annotations" => annotations}},
     containers: [{id: "#{uid}-init", name: "init", category: "init", started: true, exited: true},
                  {id: "#{uid}-app", name: "app", category: "app", started: true},
                  {id: "#{uid}-new", name: "late", category: "app"}]}
  end

  def test_trace_entries_and_records_become_upstream_metrics
    now = 0.0
    metrics = Rubernetes::Node::KubeletMetrics.new(node_name: "worker-0", clock: -> { now })
    a = record("a")
    metrics.observe(a, {"type" => "sandbox.create"})
    metrics.observe(a, {"type" => "container.started", "name" => "init"})
    metrics.observe(a, {"type" => "container.exited", "name" => "init", "exit_code" => 0, "reason" => "Completed"})
    metrics.observe(a, {"type" => "container.started", "name" => "app"})
    metrics.observe(a, {"type" => "container.restart_failed", "name" => "late"})
    now = 2.5
    metrics.observe(a, {"type" => "state", "from" => "Pending", "to" => "Running"})
    metrics.observe(a, {"type" => "state", "from" => "Running", "to" => "Running"})
    metrics.eviction("memory.available")
    text = metrics.render([a, record("b", static: true), record("gone", state: "Removed")])

    assert_includes text, "kubelet_node_name{node=\"worker-0\"} 1"
    assert_includes text, "kubelet_started_pods_total 1"
    assert_includes text, "kubelet_started_containers_total{container_type=\"init_container\"} 1"
    assert_includes text, "kubelet_started_containers_total{container_type=\"container\"} 1"
    assert_includes text, "kubelet_started_containers_errors_total{code=\"Unknown\",container_type=\"container\"} 1"
    assert_includes text, "kubelet_terminated_containers_total{container_type=\"init_container\",exit_code=\"0\",reason=\"Completed\"} 1"
    assert_includes text, "kubelet_pod_start_duration_seconds_count 1"
    assert_includes text, "kubelet_pod_start_duration_seconds_bucket{le=\"3\"} 1"
    assert_includes text, "kubelet_pod_start_duration_seconds_bucket{le=\"2\"} 0"
    assert_includes text, "kubelet_evictions{eviction_signal=\"memory.available\"} 1"
    assert_includes text, "kubelet_running_pods 2"
    assert_includes text, "kubelet_running_containers{container_state=\"running\"} 3"
    assert_includes text, "kubelet_running_containers{container_state=\"exited\"} 3"
    assert_includes text, "kubelet_running_containers{container_state=\"created\"} 3"
    assert_includes text, "kubelet_desired_pods{static=\"true\"} 1"
    assert_includes text, "kubelet_active_pods{static=\"false\"} 1"
    assert_includes text, "kubelet_mirror_pods 1"
  end

  def test_the_streaming_server_serves_them_with_volume_stats
    metrics = Rubernetes::Node::KubeletMetrics.new(node_name: "worker-0")
    lifecycle = Struct.new(:records).new({})
    server = Rubernetes::Node::StreamingServer.new(log_service: Object.new, lifecycle: lifecycle, kubelet_metrics: metrics)
    request = Struct.new(:path, :method) do
      def headers = {}
      def header(_) = nil
    end.new("/metrics", "GET")
    status, _headers, body = server.call(request)

    assert_equal 200, status
    assert_includes body.join, "kubelet_node_name{node=\"worker-0\"} 1"
    assert_equal 1, body.join.scan(/^# TYPE process_start_time_seconds /).length
  end

  def test_runtime_operations_are_counted_by_cri_name
    metrics = Rubernetes::Node::KubeletMetrics.new(node_name: "worker-0")
    metrics.runtime_operation("run_podsandbox", 0.01)
    metrics.runtime_operation("run_podsandbox", 0.02, failed: true)
    text = metrics.render([])

    assert_includes text, 'kubelet_runtime_operations_total{operation_type="run_podsandbox"} 2'
    assert_includes text, 'kubelet_runtime_operations_errors_total{operation_type="run_podsandbox"} 1'
    assert_includes text, 'kubelet_runtime_operations_duration_seconds_bucket{operation_type="run_podsandbox",le="0.0125"} 1'
    assert_equal 14, Rubernetes::Node::KubeletMetrics::RUNTIME_BUCKETS.length
    assert_in_delta 745.058, Rubernetes::Node::KubeletMetrics::RUNTIME_BUCKETS.last, 0.01
  end

  def test_pleg_relists_record_duration_interval_and_last_seen
    metrics = Rubernetes::Node::KubeletMetrics.new(node_name: "worker-0")
    metrics.pleg_relist(10.0, 0.02)
    metrics.pleg_relist(11.0, 0.03)
    text = metrics.render([])

    assert_includes text, "kubelet_pleg_relist_duration_seconds_count 2"
    assert_includes text, "kubelet_pleg_relist_interval_seconds_count 1"
    assert_includes text, "kubelet_pleg_relist_interval_seconds_sum 1"
    assert_match(/^kubelet_pleg_last_seen_seconds \d+/, text)
  end

  # server.go ServeHTTP.
  def test_the_server_counts_its_requests
    metrics = Rubernetes::Node::KubeletMetrics.new(node_name: "worker-0")
    server = Rubernetes::Node::StreamingServer.new(log_service: Object.new, lifecycle: Struct.new(:records).new({}),
                                                   kubelet_metrics: metrics)
    request = Struct.new(:path, :method) do
      def headers = {}
      def header(_) = nil
    end
    server.call(request.new("/healthz", "GET"))
    server.call(request.new("/metrics/probes", "GET"))
    server.call(request.new("/nowhere/at/all", "BREW"))
    text = metrics.registry.render

    assert_includes text, %(kubelet_http_requests_total{long_running="false",method="GET",path="healthz",server_type="readonly"} 1)
    assert_includes text, %(kubelet_http_requests_total{long_running="false",method="GET",path="metrics/probes",server_type="readonly"} 1)
    assert_includes text, %(kubelet_http_requests_total{long_running="false",method="other",path="other",server_type="readonly"} 1)
    assert_includes text, %(kubelet_http_inflight_requests{long_running="false",method="GET",path="healthz",server_type="readonly"} 0)
    assert_includes text,
                    %(kubelet_http_requests_duration_seconds_count{long_running="false",method="GET",path="healthz",server_type="readonly"} 1)
    assert_equal "exec", Rubernetes::Node::StreamingServer.metric_path("/exec/ns/pod/c")
    assert_equal "metrics", Rubernetes::Node::StreamingServer.metric_path("/metrics")
  end

  # The client certificate metrics exist only with rotation; the serving
  # ones never (serving certificates are not rotated here).
  def test_certificate_metrics_follow_the_managers
    now = Time.utc(2026, 9, 25)
    metrics = Rubernetes::Node::KubeletMetrics.new(node_name: "worker-0", wall_clock: -> { now })

    refute_includes metrics.render([]), "kubelet_certificate_manager"
    certificate = Struct.new(:not_after).new(now + 3600.7)
    metrics.client_certificate_source = -> { certificate }
    metrics.client_certificate_renew_failed
    text = metrics.render([])

    assert_includes text, "kubelet_certificate_manager_client_ttl_seconds 3600\n"
    assert_includes text, "kubelet_certificate_manager_client_expiration_renew_errors 1\n"
    refute_includes text, "kubelet_certificate_manager_server_ttl_seconds"
    certificate = nil

    assert_includes metrics.render([]), "kubelet_certificate_manager_client_ttl_seconds +Inf\n"
  end
end
