# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/node_stats_summary_harness"
require "rubernetes/node"
require "fileutils"
require "json"
require "tmpdir"

# The Summary API (/stats/summary) computed the way the kubelet's
# cadvisor-backed provider computes it on cgroup v2, and /metrics/resource
# (collectors/resource_metrics.go) rendered from it.  Both used to be stubs:
# /stats/summary had no Pods and /metrics/resource no samples, so
# metrics-server, `kubectl top` and HPA had nothing to read, and the eviction
# manager had no signals.
class NodeStatsSummaryTest < Minitest::Test
  include NodeStatsSummaryHarness

  def test_summary_follows_the_cadvisor_semantics
    runtime = Runtime.new(usage(cpu_usec: 1_000_000))
    subject = provider(runtime)
    subject.summary
    runtime.usage = usage(cpu_usec: 1_500_000)
    @mono += 2.0
    summary = subject.summary

    node = summary.fetch("node")

    assert_equal "node-a", node["nodeName"]
    assert_equal "2026-01-01T00:00:00Z", node["startTime"]
    assert_equal 2_000_000_000, node.dig("cpu", "usageCoreNanoSeconds")
    assert_equal 500 * MI, node.dig("memory", "usageBytes"), "anon + file of the root memory.stat"
    assert_equal 400 * MI, node.dig("memory", "workingSetBytes"), "usage - inactive_file"
    assert_equal (2048 * MI) - (400 * MI), node.dig("memory", "availableBytes"), "capacity - workingSet"
    assert_equal({"time" => "2026-01-01T00:01:00Z", "maxpid" => 32_768, "curproc" => 2}, node["rlimit"])
    pods_container = node.fetch("systemContainers").find { |entry| entry["name"] == "pods" }

    assert_equal 40 * MI, pods_container.dig("memory", "workingSetBytes")
    assert_equal (1024 * MI) - (40 * MI), pods_container.dig("memory", "availableBytes")

    pods = summary.fetch("pods")

    assert_equal 1, pods.length, "only running Pods are reported"
    pod = pods.first

    assert_equal({"name" => "web", "namespace" => "ns", "uid" => "u1"}, pod["podRef"])
    assert_equal 250_000_000, pod.dig("cpu", "usageNanoCores"), "rate over the 2s between samples"
    assert_equal 50 * MI, pod.dig("memory", "usageBytes")
    assert_equal 40 * MI, pod.dig("memory", "workingSetBytes")
    assert_equal({"process_count" => 3}, pod["process_stats"])
    container = pod.fetch("containers").first

    assert_equal "app", container["name"]
    assert_equal "2026-01-01T00:00:01Z", container["startTime"]
    assert_equal 35 * MI, container.dig("memory", "workingSetBytes")
    assert_operator container.dig("rootfs", "usedBytes"), :>=, 8192
    assert_operator container.dig("logs", "usedBytes"), :>=, 4096
    volumes = pod.fetch("volume").to_h { |volume| [volume["name"], volume] }

    assert_equal({"name" => "claim", "namespace" => "ns"}, volumes.fetch("data")["pvcRef"])
    refute volumes.fetch("scratch").key?("pvcRef")
    ephemeral = pod.fetch("ephemeral-storage")

    assert_equal container.dig("rootfs", "usedBytes") + container.dig("logs", "usedBytes") + volumes.fetch("scratch")["usedBytes"],
                 ephemeral["usedBytes"], "rootfs + logs + ephemeral volumes, not the PVC"
  end

  def test_resource_metrics_render_the_summary
    runtime = Runtime.new(usage(cpu_usec: 1_000_000))
    body = Rubernetes::Node::ResourceMetrics.render(provider(runtime).summary)

    assert_includes body, "# HELP node_cpu_usage_seconds_total [STABLE] Cumulative cpu time consumed by the node in core-seconds\n" \
                          "# TYPE node_cpu_usage_seconds_total counter\nnode_cpu_usage_seconds_total 2 1767225660000\n"
    assert_includes body, "node_memory_working_set_bytes #{go_float(400 * MI)} 1767225660000\n"
    assert_includes body, "container_cpu_usage_seconds_total{container=\"app\",namespace=\"ns\",pod=\"web\"} 1 1767225660000\n"
    assert_includes body,
                    "container_memory_working_set_bytes{container=\"app\",namespace=\"ns\",pod=\"web\"} #{go_float(35 * MI)} 1767225660000\n"
    assert_includes body, "container_start_time_seconds{container=\"app\",namespace=\"ns\",pod=\"web\"} 1.767225601e+09 1767225601000\n"
    assert_includes body, "pod_memory_working_set_bytes{namespace=\"ns\",pod=\"web\"} #{go_float(40 * MI)} 1767225660000\n"
    assert_includes body, "resource_scrape_error 0\n"
    assert_includes Rubernetes::Node::ResourceMetrics.render({"node" => {}, "pods" => []}, scrape_error: true), "resource_scrape_error 1\n"
  end

  def test_streaming_server_serves_summary_and_resource_metrics
    stats = provider(Runtime.new(usage(cpu_usec: 1_000_000)))
    server = Rubernetes::Node::StreamingServer.new(log_service: Object.new, lifecycle: Lifecycle.new(records), stats_provider: stats)
    status, headers, body = server.call(Request.new("/stats/summary", "GET", {}))

    assert_equal 200, status
    assert_equal "application/json", headers["content-type"]
    full = JSON.parse(body.join)

    assert full.dig("node", "fs")
    status, _headers, body = server.call(Request.new("/stats/summary", "GET", {"only_cpu_and_memory" => "true"}))

    assert_equal 200, status
    trimmed = JSON.parse(body.join)

    assert_equal %w[cpu memory nodeName startTime], trimmed["node"].keys.sort
    assert_equal %w[containers cpu memory podRef startTime], trimmed["pods"].first.keys.sort
    assert_equal %w[cpu memory name startTime], trimmed["pods"].first["containers"].first.keys.sort

    status, _headers, body = server.call(Request.new("/metrics/resource", "GET", {}))

    assert_equal 200, status
    assert_includes body.join, "pod_cpu_usage_seconds_total{namespace=\"ns\",pod=\"web\"} 1 "

    bare = Rubernetes::Node::StreamingServer.new(log_service: Object.new, lifecycle: Lifecycle.new({}))

    assert_equal 404, bare.call(Request.new("/stats/summary", "GET", {})).first
  end
end
