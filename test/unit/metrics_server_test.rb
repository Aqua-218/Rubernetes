# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/metrics_server"
require "rubernetes/node/resource_metrics"

# The metrics-server component end to end without sockets: two scrapes of a
# node's /metrics/resource (rendered by the agent's own ResourceMetrics),
# then metrics.k8s.io/v1beta1 reads through delegated authentication
# (TokenReview) and authorization (SubjectAccessReview).
class MetricsServerTest < Minitest::Test
  MS = Rubernetes::MetricsServer

  class FakeClient
    attr_reader :reviews
    attr_accessor :allowed

    Response = Struct.new(:status, :body)

    def initialize
      @reviews = []
      @allowed = true
    end

    def get(path, query: nil)
      case path
      when "/api/v1/nodes" then {"items" => [node]}
      when "/api/v1/nodes/node-a" then node
      when "/api/v1/namespaces/ns/pods", "/api/v1/pods" then {"items" => [pod]}
      when "/api/v1/namespaces/ns/pods/web" then pod
      when MS::Server::AUTH_CONFIGMAP then {"data" => {}}
      else raise "unexpected GET #{path} #{query.inspect}"
      end
    end

    def raw(method, path, body: nil, headers: {}, raise_for_status: true)
      review = JSON.parse(body)
      @reviews << [path, review]
      status = if path.end_with?("tokenreviews")
                 {"authenticated" => review.dig("spec", "token") == "good", "user" => {"username" => "alice", "groups" => ["dev"]}}
               else
                 {"allowed" => @allowed}
               end
      Response.new(201, JSON.generate(review.merge("status" => status)))
    end

    def node
      {"metadata" => {"name" => "node-a", "labels" => {"zone" => "a"},
                      "annotations" => {"node.rubernetes.io/streaming-address" => "127.0.0.1"}},
       "status" => {"daemonEndpoints" => {"kubeletEndpoint" => {"Port" => 10_250}}}}
    end

    def pod = {"metadata" => {"name" => "web", "namespace" => "ns", "labels" => {"app" => "web"}}}
  end

  Request = Struct.new(:method, :path, :query, :headers, keyword_init: true) do
    def header(name) = headers.find { |key, _| key.casecmp?(name) }&.last
    def client_certificate = nil
    def client_chain = []
    def remote_address = "127.0.0.1"
  end

  def summary(seconds, cpu, memory)
    time = (Time.utc(2026, 9, 24) + seconds).iso8601(3)
    {"node" => {"cpu" => {"time" => time, "usageCoreNanoSeconds" => cpu * 4}, "memory" => {"time" => time, "workingSetBytes" => memory * 4}},
     "pods" => [{"podRef" => {"namespace" => "ns", "name" => "web"},
                 "containers" => [{"name" => "app", "startTime" => "2026-09-23T00:00:00Z",
                                   "cpu" => {"time" => time, "usageCoreNanoSeconds" => cpu},
                                   "memory" => {"time" => time, "workingSetBytes" => memory}}]}]}
  end

  def setup
    @client = FakeClient.new
    @bodies = [Rubernetes::Node::ResourceMetrics.render(summary(0, 1_000_000_000, 64 * 1024 * 1024)),
               Rubernetes::Node::ResourceMetrics.render(summary(15, 4_000_000_000, 80 * 1024 * 1024))]
    @urls = []
    http_get = lambda do |url, _timeout|
      @urls << url
      @bodies.shift
    end
    @server = MS::Server.new(client: @client, config: {"jitter" => false}, http_get: http_get)
    @server.send(:refresh_authentication)
    2.times { @server.scrape_once }
  end

  def get(path, token: "good", accept: "application/json", query: {})
    headers = {"Accept" => accept}
    headers["Authorization"] = "Bearer #{token}" if token
    code, _headers, body = @server.call(Request.new(method: "GET", path: path, query: query, headers: headers))
    [code, JSON.parse(body.join)]
  end

  def test_scrapes_the_advertised_streaming_endpoint
    assert_equal ["http://127.0.0.1:10250/metrics/resource"] * 2, @urls
  end

  def test_node_metrics_are_rates_over_the_window
    code, body = get("/apis/metrics.k8s.io/v1beta1/nodes/node-a")
    assert_equal 200, code
    assert_equal %w[NodeMetrics metrics.k8s.io/v1beta1], body.values_at("kind", "apiVersion")
    assert_equal "15s", body["window"]
    assert_equal "2026-09-24T00:00:15Z", body["timestamp"]
    assert_equal({"cpu" => "800m", "memory" => "320Mi"}, body["usage"])
    assert_equal({"zone" => "a"}, body.dig("metadata", "labels"))
  end

  def test_pod_metrics_list_and_get
    code, list = get("/apis/metrics.k8s.io/v1beta1/namespaces/ns/pods")
    assert_equal 200, code
    assert_equal "PodMetricsList", list["kind"]
    pod = list["items"].first
    assert_equal [{"name" => "app", "usage" => {"cpu" => "200m", "memory" => "80Mi"}}], pod["containers"]
    code, single = get("/apis/metrics.k8s.io/v1beta1/namespaces/ns/pods/web")
    assert_equal [200, "web"], [code, single.dig("metadata", "name")]
  end

  def test_field_selectors_and_unknown_fields
    _code, list = get("/apis/metrics.k8s.io/v1beta1/nodes", query: {"fieldSelector" => ["metadata.name=other"]})
    assert_empty list["items"]
    code, status = get("/apis/metrics.k8s.io/v1beta1/nodes", query: {"fieldSelector" => ["spec.unschedulable=true"]})
    assert_equal 400, code
    assert_includes status["message"], "field label not supported"
  end

  def test_discovery_and_table
    _code, resources = get("/apis/metrics.k8s.io/v1beta1")
    assert_equal %w[nodes pods], resources["resources"].map { |resource| resource["name"] }
    _code, table = get("/apis/metrics.k8s.io/v1beta1/nodes", accept: "application/json;as=Table;v=v1beta1;g=meta.k8s.io")
    assert_equal %w[Name cpu memory Window], table["columnDefinitions"].map { |column| column["name"] }
    assert_equal ["node-a", "800m", "320Mi", "15s"], table["rows"].first["cells"]
  end

  def test_delegated_authentication_and_authorization
    code, _body = get("/apis/metrics.k8s.io/v1beta1/nodes", token: "bad")
    assert_equal 401, code
    @client.allowed = false
    code, status = get("/apis/metrics.k8s.io/v1beta1/namespaces/ns/pods")
    assert_equal 403, code
    assert_includes status["message"], %(User "alice" cannot list resource "pods")
    _path, review = @client.reviews.reverse.find { |path, _| path.end_with?("subjectaccessreviews") }
    assert_equal({"group" => "metrics.k8s.io", "version" => "v1beta1", "resource" => "pods", "namespace" => "ns", "verb" => "list"},
                 review.dig("spec", "resourceAttributes").slice("group", "version", "resource", "namespace", "verb"))
  end

  def test_health_paths_need_no_credentials
    code, _headers, body = @server.call(Request.new(method: "GET", path: "/readyz", query: {}, headers: {}))
    assert_equal [200, "ok"], [code, body.join]
  end

  def test_the_https_listener_serves_behind_tls
    require "net/http"
    server = MS::Server.new(client: FakeClient.new, config: {"port" => 0, "bind_address" => "127.0.0.1", "jitter" => false,
                                                              "metric_resolution_seconds" => 3600},
                            http_get: ->(_url, _timeout) { nil }, logger: (ENV["MS_DEBUG"] ? Class.new { def method_missing(level, event, **fields) = warn("#{level} #{event} #{fields}"); def respond_to_missing?(*) = true }.new : nil))
    server.start
    http = Net::HTTP.new("127.0.0.1", server.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    response = http.get("/healthz")
    assert_equal ["200", "ok"], [response.code, response.body]
    denied = http.get("/apis/metrics.k8s.io/v1beta1/nodes", {"authorization" => "Bearer bad"})
    assert_equal "401", denied.code
  ensure
    server&.stop
  end
end
