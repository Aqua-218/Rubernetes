# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# kubelet serves Prometheus metrics at /metrics; the e2e MetricsGrabber reads
# them through nodes/<name>:<port>/proxy/metrics after every failure and
# retries a 404 for two minutes, so the endpoint has to exist and parse.
class NodeStreamingMetricsTest < Minitest::Test
  Lifecycle = Struct.new(:records)
  Request = Struct.new(:path, :method)

  def server
    server = Rubernetes::Node::StreamingServer.allocate
    server.instance_variable_set(:@lifecycle, Lifecycle.new({
                                                              "u1" => {pod: {"metadata" => {"name" => "p"}},
                                                                       containers: [{name: "a"}, {name: "b"}]},
                                                              "u2" => {pod: {"metadata" => {"name" => "q"}}},
                                                              "u3" => {}
                                                            }))
    server
  end

  def test_metrics_is_prometheus_text_with_kubelet_gauges
    status, headers, body = server.call(Request.new("/metrics", "GET"))

    assert_equal 200, status
    assert_equal "text/plain; version=0.0.4; charset=utf-8", headers["content-type"]
    text = body.join

    assert_includes text, "# TYPE kubelet_running_pods gauge"
    assert_includes text, "kubelet_running_pods 2"
    assert_includes text, "kubelet_running_containers{container_state=\"running\"} 2"
    text.each_line { |line| assert_match(/\A(#|[a-z_]+(\{[^}]*\})? \S+)/, line) }
  end

  def test_the_kubelet_metric_variants_answer_too
    %w[/metrics/cadvisor /metrics/resource /metrics/probes].each do |path|
      status, = server.call(Request.new(path, "GET"))

      assert_equal 200, status, path
    end
  end

  def test_metrics_without_a_lifecycle_is_still_valid
    bare = Rubernetes::Node::StreamingServer.allocate
    status, _headers, body = bare.call(Request.new("/metrics", "GET"))

    assert_equal 200, status
    assert_includes body.join, "kubelet_running_pods 0"
  end
end
