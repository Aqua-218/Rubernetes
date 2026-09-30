# frozen_string_literal: true

# The process-wide families every component serves (component-base
# legacyregistry): client-go's rest_client_* and the workqueues'
# workqueue_*, merged into each registry's /metrics once.

require_relative "../test_helper"
require "rubernetes/client"
require "rubernetes/watch/work_queue"
require "rubernetes/observability/metrics"

class ComponentClientMetricsTest < Minitest::Test
  def test_workqueue_metrics_follow_client_go
    queue = Rubernetes::Watch::WorkQueue.new(name: "test-queue-#{object_id}")
    name = queue.name
    queue.add("a")
    queue.add("a")
    queue.add("b")
    key, = queue.get(timeout: 0)
    registry = Rubernetes::Observability::Metrics.new(apiserver: false)
    text = registry.render

    assert_includes text, "workqueue_adds_total{name=\"#{name}\"} 2", "a duplicate add is not counted"
    assert_includes text, "workqueue_depth{name=\"#{name}\"} 1"
    assert_includes text, "workqueue_queue_duration_seconds_count{name=\"#{name}\"} 1"
    assert_match(/workqueue_longest_running_processor_seconds\{name="#{name}"\} [0-9.e-]+/, text)
    queue.done(key)
    queue.add_rate_limited("c")
    text = registry.render

    assert_includes text, "workqueue_work_duration_seconds_count{name=\"#{name}\"} 1"
    assert_includes text, "workqueue_retries_total{name=\"#{name}\"} 1"
    assert_equal 1, text.scan(/^# TYPE workqueue_depth /).length
    assert_equal 1, text.scan(/^# TYPE process_start_time_seconds /).length
  end

  def test_rest_client_requests_are_recorded
    uri = URI("https://10.0.0.1:6443/api/v1/pods")
    Rubernetes::Client::RestClientMetrics.record("GET", uri, 200, 0.02, 0, 512)
    Rubernetes::Client::RestClientMetrics.record("POST", uri, "<error>", 0.5, 100, nil)
    text = Rubernetes::Observability::Metrics.new(apiserver: false).render

    assert_match(/rest_client_requests_total\{code="200",host="10.0.0.1:6443",method="GET"\} \d+/, text)
    assert_match(/rest_client_requests_total\{code="<error>",host="10.0.0.1:6443",method="POST"\} \d+/, text)
    assert_match(/rest_client_request_duration_seconds_count\{host="10.0.0.1:6443",verb="GET"\} \d+/, text)
    assert_match(/rest_client_response_size_bytes_bucket\{host="10.0.0.1:6443",verb="GET",le="1024"\} \d+/, text)
  end

  def test_dns_resolution_is_timed_per_host
    uri = URI("https://api.example.test:6443/api")
    Rubernetes::Client::RestClientMetrics.dns_resolution(uri, 0.003)
    text = Rubernetes::Observability::Metrics.new(apiserver: false).render

    assert_match(/rest_client_dns_resolution_duration_seconds_count\{host="api.example.test:6443"\} \d+/, text)
    assert_match(/rest_client_dns_resolution_duration_seconds_bucket\{host="api.example.test:6443",le="0.005"\} \d+/, text)
  end
end
