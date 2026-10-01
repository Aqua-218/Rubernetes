# frozen_string_literal: true

# Shared harness extracted from unit/api_crd_aggregation_test.rb; included by that
# test and by the tests that used to subclass it (a test file must not require
# another test file: its tests would run under both classes).
require "json"
require "rubernetes/api"
require "rubernetes/security/cel"

module CRDAggregationHarness
  API = Rubernetes::API

  def setup
    @store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    @registry = build_registry
    @openapi = API::OpenAPIRepository.new
    @crd_manager = API::CRD::Manager.new(registry: @registry, store: @store, openapi: @openapi, cel: Rubernetes::Security::CEL::Evaluator.new)
    @aggregator = API::Aggregator.new(http_factory: ->(uri, backend) { FakeHTTP.new(uri, backend) })
    @server = API::Server.new(registry: @registry, store: @store, crd_manager: @crd_manager, aggregator: @aggregator,
                              openapi_repository: @openapi)
  end

  # Only the two configuration resources are needed from the corpus.
  def build_registry
    registry = API::Registry.new(resources: [], defaults: false)
    registry.register(API::Resource.new(group: "apiextensions.k8s.io", version: "v1", resource: "customresourcedefinitions", kind: "CustomResourceDefinition",
                                        scope: :cluster, subresources: [{resource: "status", verbs: %w[get patch update]}]))
    registry.register(API::Resource.new(group: "apiregistration.k8s.io", version: "v1", resource: "apiservices", kind: "APIService", scope: :cluster,
                                        subresources: [{resource: "status", verbs: %w[get patch update]}]))
    registry.register(API::Resource.new(group: "", version: "v1", resource: "namespaces", kind: "Namespace", scope: :cluster))
    registry.register(API::Resource.new(group: "", version: "v1", resource: "services", kind: "Service", scope: :namespaced))
    registry.register(API::Resource.new(group: "discovery.k8s.io", version: "v1", resource: "endpointslices", kind: "EndpointSlice",
                                        scope: :namespaced))
    registry
  end

  def wait_until(seconds: 10)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    loop do
      return true if yield
      return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.05
    end
  end

  def wait_for_crd_removal(name)
    assert wait_until { call("GET", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/#{name}").status == 404 },
           "the CRD finalizer must remove #{name}"
  end

  def call(method, path, body: nil, headers: {})
    headers = {"content-type" => "application/json"}.merge(headers) if body
    @server.call(API::Request.new(method: method, path: path, headers: headers, body: body && JSON.generate(body),
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def crd(name: "widgets.example.com", extra_versions: [])
    schema = {"type" => "object", "properties" => {
      "spec" => {"type" => "object", "required" => ["size"],
                 "properties" => {"size" => {"type" => "integer", "minimum" => 1, "maximum" => 10}, "color" => {"type" => "string", "default" => "blue"},
                                  "tags" => {"type" => "array", "items" => {"type" => "string"}, "x-kubernetes-list-type" => "set"}},
                 "x-kubernetes-validations" => [{"rule" => "self.size <= 5 || self.color == 'red'", "message" => "large widgets must be red"}]},
      "status" => {"type" => "object", "properties" => {"ready" => {"type" => "boolean"}}}
    }}
    {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition", "metadata" => {"name" => name},
     "spec" => {"group" => "example.com", "scope" => "Namespaced",
                "names" => {"plural" => "widgets", "singular" => "widget", "kind" => "Widget", "shortNames" => ["wd"]},
                "versions" => [{"name" => "v1", "served" => true, "storage" => true, "schema" => {"openAPIV3Schema" => schema}, "subresources" => {"status" => {}}}] + extra_versions}}
  end

  class FakeHTTP
    attr_reader :requests

    def initialize(uri, backend)
      @uri = uri
      @backend = backend
    end

    def use_ssl=(_value); end
    def use_ssl? = true
    def open_timeout=(_value); end
    def read_timeout=(_value); end
    def verify_mode=(_value); end
    def cert_store=(_value); end
    def cert=(_value); end
    def key=(_value); end

    Response = Struct.new(:code, :body, :headers) do
      def [](name) = headers[name.downcase]
    end

    def get(path, _headers = {})
      request(Struct.new(:method, :path, :body).new("GET", path, nil))
    end

    def request(outbound)
      path = outbound.path
      if path == "/apis/metrics.example/v1beta1"
        Response.new("200", JSON.generate({"kind" => "APIResourceList", "apiVersion" => "v1", "groupVersion" => "metrics.example/v1beta1",
                                           "resources" => [{"name" => "nodes", "singularName" => "", "namespaced" => false, "kind" => "NodeMetrics", "verbs" => %w[get list]}]}), {"content-type" => "application/json"})
      elsif path.start_with?("/apis/metrics.example/v1beta1/nodes")
        user = outbound.respond_to?(:[]) ? outbound["X-Remote-User"] : nil
        Response.new("200", JSON.generate({"kind" => "NodeMetricsList", "apiVersion" => "metrics.example/v1beta1", "items" => [], "seenUser" => user,
                                           "authorization" => (outbound.respond_to?(:[]) ? outbound["authorization"] : nil)}),
                     {"content-type" => "application/json"})
      else
        Response.new("404", "nope", {"content-type" => "text/plain"})
      end
    end
  end

  def condition_reason(name)
    body = call("GET", "/apis/apiregistration.k8s.io/v1/apiservices/#{name}").body
    Array(body.dig("status", "conditions")).find { |condition| condition["type"] == "Available" }&.fetch("reason", nil)
  end
end
