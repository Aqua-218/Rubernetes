# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/transport/http_server"

# kube-apiserver's endpoints/metrics label sets and the metrics beside
# apiserver_request_total: upper-case verbs (LIST, WATCH, ...) with
# CleanScope, response sizes of reads only, the SLO/SLI latency of
# everything but a watch, a watch counted in apiserver_longrunning_requests
# while it streams and recorded when it ends, its events in
# apiserver_watch_events_total/_sizes, and the stored object counts.
class APIServerRequestMetricsTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @metrics = Rubernetes::Observability::Metrics.new
    @server = API::Server.new(registry: API::Registry.new, store: API::MemoryStore.new, metrics: @metrics)
    call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "dev"}})
  end

  def call(method, path, body = nil, headers: {})
    @server.call(API::Request.new(method: method, path: path, body: body, headers: headers))
  end

  def samples(name)
    @metrics.render.lines.grep(/\A#{Regexp.escape(name)}[{ ]/).map(&:strip)
  end

  def sample(name, **labels)
    samples(name).find { |line| labels.all? { |key, value| line.include?(%(#{key}="#{value}")) } }
  end

  def value(name, **labels) = sample(name, **labels)&.split&.last&.to_f

  def test_verbs_and_scopes_are_upstreams
    call("POST", "/api/v1/namespaces/dev/configmaps", {"metadata" => {"name" => "a"}})
    listed = call("GET", "/api/v1/namespaces/dev/configmaps")
    # The transport encodes the decoded body and reports its size.
    encoded = Rubernetes::Transport::HTTPServer.allocate.send(:normalize_response, listed)
    call("GET", "/api/v1/configmaps")
    call("GET", "/api/v1/namespaces/dev/configmaps/a")
    assert value("apiserver_request_total", verb: "POST", resource: "configmaps", scope: "resource", code: "201")
    assert value("apiserver_request_total", verb: "LIST", resource: "configmaps", scope: "namespace", code: "200")
    assert value("apiserver_request_total", verb: "LIST", resource: "configmaps", scope: "cluster", code: "200")
    assert value("apiserver_request_total", verb: "GET", resource: "configmaps", scope: "resource", code: "200")
    assert_equal encoded.body.bytesize.to_f, value("apiserver_response_sizes_sum", verb: "LIST", resource: "configmaps", scope: "namespace")
    refute sample("apiserver_response_sizes_count", verb: "POST"), "only reads report their response size"
    assert sample("apiserver_request_sli_duration_seconds_count", verb: "POST", resource: "configmaps")
    # ALPHA, deprecated in 1.27: hidden in 1.36 (component-base shouldHide).
    refute sample("apiserver_request_slo_duration_seconds_count"), "apiserver_request_slo_duration_seconds is hidden"
    assert sample("apiserver_request_sli_duration_seconds_count", verb: "GET", resource: "configmaps")
  end

  def test_a_watch_is_long_running_until_it_ends
    response = call("GET", "/api/v1/namespaces/dev/configmaps?watch=true&timeoutSeconds=2")
    assert_kind_of API::LongRunningBody, response.body
    events = Queue.new
    reader = Thread.new do
      response.body.each do |event|
        events << event
        response.body.piece_written(1500)
        break
      end
    end
    call("POST", "/api/v1/namespaces/dev/configmaps", {"metadata" => {"name" => "w"}})
    assert_equal "ADDED", events.pop["type"]
    reader.join(5)
    assert_equal 0.0, value("apiserver_longrunning_requests", verb: "WATCH", resource: "configmaps")
    assert_equal 1.0, value("apiserver_watch_events_total", resource: "configmaps", version: "v1")
    assert_equal 1.0, value("apiserver_watch_events_sizes_bucket", resource: "configmaps", le: "2048")
    assert value("apiserver_request_total", verb: "WATCH", resource: "configmaps", code: "200"), "recorded when the stream ended"
    refute sample("apiserver_request_slo_duration_seconds_count", verb: "WATCH"), "a watch has no SLO latency"
  end

  def test_the_gauge_counts_a_watch_while_it_streams
    response = call("GET", "/api/v1/namespaces/dev/configmaps?watch=true&timeoutSeconds=5")
    started = Queue.new
    finish = Queue.new
    reader = Thread.new do
      response.body.each do
        started << true
        finish.pop
        break
      end
    end
    call("POST", "/api/v1/namespaces/dev/configmaps", {"metadata" => {"name" => "g"}})
    started.pop
    assert_equal 1.0, value("apiserver_longrunning_requests", verb: "WATCH", resource: "configmaps", scope: "namespace")
    refute value("apiserver_request_total", verb: "WATCH"), "not recorded before it ends"
    finish << true
    reader.join(5)
    assert_equal 0.0, value("apiserver_longrunning_requests", verb: "WATCH", resource: "configmaps")
  end

  def test_stored_objects_are_counted_per_resource
    call("POST", "/api/v1/namespaces/dev/configmaps", {"metadata" => {"name" => "a"}})
    call("POST", "/api/v1/namespaces/dev/configmaps", {"metadata" => {"name" => "b"}})
    assert_equal 2.0, value("apiserver_storage_objects", resource: "configmaps")
    assert_equal 2.0, value("apiserver_resource_objects", group: "", resource: "configmaps")
    assert_equal 1.0, value("apiserver_resource_objects", group: "", resource: "namespaces")
    assert_equal 0.0, value("apiserver_resource_objects", group: "", resource: "pods")
  end
end
