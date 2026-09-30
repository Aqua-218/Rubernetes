# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

# pkg/proxy/metrics: kube-proxy's series as the proxy engine records them.
class ProxyMetricsTest < Minitest::Test
  Proxy = Rubernetes::Proxy

  def service(traffic: {})
    {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "svc", "namespace" => "ns"},
     "spec" => {"clusterIP" => "10.96.0.10", "clusterIPs" => ["10.96.0.10"], "ipFamilies" => ["IPv4"], "type" => "ClusterIP",
                "ports" => [{"name" => "http", "port" => 80, "protocol" => "TCP", "targetPort" => 80}]}.merge(traffic)}
  end

  def slice(node: "worker-1", trigger: nil)
    metadata = {"name" => "svc-abc", "namespace" => "ns", "labels" => {"kubernetes.io/service-name" => "svc"}}
    metadata["annotations"] = {"endpoints.kubernetes.io/last-change-trigger-time" => trigger} if trigger
    {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice", "metadata" => metadata,
     "addressType" => "IPv4", "ports" => [{"name" => "http", "port" => 8080, "protocol" => "TCP"}],
     "endpoints" => [{"addresses" => ["10.244.0.5"], "nodeName" => node, "conditions" => {"ready" => true}}]}
  end

  def value(text, name, **labels)
    found = text.lines.map(&:chomp).find do |entry|
      entry.start_with?(name) && labels.all? { |key, item| entry.include?("#{key}=\"#{item}\"") }
    end
    found && Float(found.split.last)
  end

  def proxy_with_metrics(clock: -> { Time.now.to_f })
    metrics = Proxy::Metrics.new(clock: clock)
    proxy = Proxy::Proxy.new(local_node: "worker-0", backend: Proxy::MemoryBackend.new)
    proxy.metrics = metrics
    [proxy, metrics]
  end

  def test_registry_declares_the_inventory_without_iptables_families
    metrics = Proxy::Metrics.new
    names = metrics.registry.registered_names
    %w[kubeproxy_sync_proxy_rules_duration_seconds kubeproxy_sync_full_proxy_rules_duration_seconds
       kubeproxy_sync_partial_proxy_rules_duration_seconds kubeproxy_network_programming_duration_seconds
       kubeproxy_sync_proxy_rules_endpoint_changes_total kubeproxy_sync_proxy_rules_service_changes_pending
       kubeproxy_sync_proxy_rules_last_timestamp_seconds kubeproxy_sync_proxy_rules_nftables_sync_failures_total
       kubeproxy_sync_proxy_rules_no_local_endpoints_total kubeproxy_proxy_healthz_total kubernetes_build_info].each do |name|
      assert_includes names, name
    end
    %w[kubeproxy_sync_proxy_rules_iptables_total kubeproxy_iptables_ct_state_invalid_dropped_packets_total
       kubeproxy_conntrack_reconciler_deleted_entries_total].each do |name|
      refute_includes names, name
    end
    entry = Rubernetes::Observability::Metrics.upstream.fetch("kubeproxy_network_programming_duration_seconds")
    assert_equal 80, entry["buckets"].length
  end

  def test_changes_syncs_and_network_programming_latency
    now = 1_000.0
    proxy, metrics = proxy_with_metrics(clock: -> { now })
    proxy.apply_service(service)
    proxy.apply_endpoint_slice(slice(trigger: Time.at(now - 0.25).utc.iso8601(3)))
    text = metrics.render
    assert_equal 1.0, value(text, "kubeproxy_sync_proxy_rules_service_changes_total")
    assert_equal 1.0, value(text, "kubeproxy_sync_proxy_rules_endpoint_changes_total")
    # Without coalescing every change publishes at once: nothing stays pending.
    assert_equal 0.0, value(text, "kubeproxy_sync_proxy_rules_service_changes_pending")
    assert_equal 0.0, value(text, "kubeproxy_sync_proxy_rules_endpoint_changes_pending")
    assert_operator value(text, "kubeproxy_sync_proxy_rules_duration_seconds_count", ip_family: "IPv4"), :>=, 2.0
    assert_equal 1.0, value(text, "kubeproxy_sync_full_proxy_rules_duration_seconds_count", ip_family: "IPv4"), "the first publish is a full sync"
    assert_operator value(text, "kubeproxy_sync_partial_proxy_rules_duration_seconds_count", ip_family: "IPv4"), :>=, 1.0
    assert_equal 1.0, value(text, "kubeproxy_network_programming_duration_seconds_count", ip_family: "IPv4")
    assert_in_delta 0.25, value(text, "kubeproxy_network_programming_duration_seconds_sum", ip_family: "IPv4"), 0.01
    assert_equal now, value(text, "kubeproxy_sync_proxy_rules_last_timestamp_seconds", ip_family: "IPv4")
    assert_equal now, value(text, "kubeproxy_sync_proxy_rules_last_queued_timestamp_seconds", ip_family: "IPv4")
    assert metrics.healthy?(now)
  end

  def test_pending_changes_wait_for_a_coalesced_publish
    proxy, metrics = proxy_with_metrics
    proxy.publish_coalescing_seconds = 5
    proxy.apply_service(service)
    proxy.apply_endpoint_slice(slice)
    text = metrics.render
    assert_equal 1.0, value(text, "kubeproxy_sync_proxy_rules_service_changes_pending")
    assert_equal 1.0, value(text, "kubeproxy_sync_proxy_rules_endpoint_changes_pending")
    proxy.flush_publish!
    text = metrics.render
    assert_equal 0.0, value(text, "kubeproxy_sync_proxy_rules_service_changes_pending")
    assert_equal 0.0, value(text, "kubeproxy_sync_proxy_rules_endpoint_changes_pending")
  end

  def test_local_policies_without_local_endpoints_are_counted
    proxy, metrics = proxy_with_metrics
    proxy.apply_service(service(traffic: {"internalTrafficPolicy" => "Local"}))
    proxy.apply_endpoint_slice(slice(node: "worker-1"))
    text = metrics.render
    assert_equal 1.0, value(text, "kubeproxy_sync_proxy_rules_no_local_endpoints_total", ip_family: "IPv4", traffic_policy: "internal")
    assert_equal 0.0, value(text, "kubeproxy_sync_proxy_rules_no_local_endpoints_total", ip_family: "IPv4", traffic_policy: "external")
    proxy.apply_endpoint_slice(slice(node: "worker-0"))
    text = metrics.render
    assert_equal 0.0, value(text, "kubeproxy_sync_proxy_rules_no_local_endpoints_total", ip_family: "IPv4", traffic_policy: "internal")
  end

  def test_health_counts_and_stale_syncs
    now = 5_000.0
    metrics = Proxy::Metrics.new(clock: -> { now })
    assert metrics.healthy?, "nothing queued yet"
    metrics.sync_queued
    now += 10
    assert metrics.healthy?, "within the timeout of the queued sync"
    now += 60
    refute metrics.healthy?, "queued 70s ago and never synced"
    metrics.synced(0.01)
    assert metrics.healthy?
    metrics.healthz(200)
    metrics.healthz(503)
    metrics.livez(200)
    text = metrics.render
    assert_equal 1.0, value(text, "kubeproxy_proxy_healthz_total", code: "200")
    assert_equal 1.0, value(text, "kubeproxy_proxy_healthz_total", code: "503")
    assert_equal 1.0, value(text, "kubeproxy_proxy_livez_total", code: "200")
  end

  def test_a_failing_backend_counts_a_sync_failure
    metrics = Proxy::Metrics.new
    backend = Proxy::MemoryBackend.new
    backend.define_singleton_method(:apply) { |_diff| raise "nft: transaction rejected" }
    proxy = Proxy::Proxy.new(local_node: "worker-0", backend: backend)
    proxy.metrics = metrics
    assert_raises(RuntimeError) { proxy.apply_service(service) }
    text = metrics.render
    assert_equal 1.0, value(text, "kubeproxy_sync_proxy_rules_nftables_sync_failures_total", ip_family: "IPv4")
  end
end
