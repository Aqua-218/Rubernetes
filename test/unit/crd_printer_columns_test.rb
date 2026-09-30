# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# additionalPrinterColumns were stored on the registry entry and never used:
# `kubectl get widgets` printed NAME and AGE whatever the CRD declared.
# apiextensions serves each version's columns through its table convertor
# (JSONPath over the object), and Age when a version declares none.
class CRDPrinterColumnsTest < Minitest::Test
  API = Rubernetes::API
  TABLE = "application/json;as=Table;v=v1;g=meta.k8s.io"

  def setup
    @store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    @registry = API::Registry.new(resources: [], defaults: false)
    @registry.register(API::Resource.new(group: "apiextensions.k8s.io", version: "v1", resource: "customresourcedefinitions",
                                         kind: "CustomResourceDefinition", scope: :cluster,
                                         subresources: [{resource: "status", verbs: %w[get patch update]}]))
    @registry.register(API::Resource.new(group: "", version: "v1", resource: "namespaces", kind: "Namespace", scope: :cluster))
    @openapi = API::OpenAPIRepository.new
    @crd_manager = API::CRD::Manager.new(registry: @registry, store: @store, openapi: @openapi)
    @server = API::Server.new(registry: @registry, store: @store, crd_manager: @crd_manager, openapi_repository: @openapi)
    call("POST", "/api/v1/namespaces", body: {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "team"}})
  end

  def call(method, path, body: nil, headers: {})
    headers = {"content-type" => "application/json"}.merge(headers) if body
    @server.call(API::Request.new(method: method, path: path, headers: headers, body: body && JSON.generate(body),
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def crd
    schema = {"openAPIV3Schema" => {"type" => "object", "x-kubernetes-preserve-unknown-fields" => true}}
    columns = [{"name" => "Replicas", "type" => "integer", "jsonPath" => ".spec.replicas"},
               {"name" => "Phase", "type" => "string", "jsonPath" => ".status.phase", "priority" => 1},
               {"name" => "First", "type" => "string", "jsonPath" => ".spec.items[0].name", "description" => "first item"}]
    {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition", "metadata" => {"name" => "widgets.example.com"},
     "spec" => {"group" => "example.com", "scope" => "Namespaced",
                "names" => {"plural" => "widgets", "singular" => "widget", "kind" => "Widget", "listKind" => "WidgetList"},
                "versions" => [{"name" => "v1", "served" => true, "storage" => true, "schema" => schema, "additionalPrinterColumns" => columns},
                               {"name" => "v2", "served" => true, "storage" => false, "schema" => schema}]}}
  end

  def wait_until(seconds: 10)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    loop do
      return true if yield
      return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.05
    end
  end

  def test_versions_print_their_own_columns
    assert_includes [201, 409], call("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", body: crd).status
    assert(wait_until { call("GET", "/apis/example.com/v1/namespaces/team/widgets").status == 200 })
    created = call("POST", "/apis/example.com/v1/namespaces/team/widgets",
                   body: {"apiVersion" => "example.com/v1", "kind" => "Widget", "metadata" => {"name" => "w"},
                          "spec" => {"replicas" => 3, "items" => [{"name" => "alpha"}]}, "status" => {"phase" => "Ready"}})

    assert_equal 201, created.status, created.body.inspect

    v1 = call("GET", "/apis/example.com/v1/namespaces/team/widgets", headers: {"accept" => TABLE}).body

    assert_equal(%w[Name Replicas Phase First], v1["columnDefinitions"].map { |column| column["name"] })
    assert_equal([0, 0, 1, 0], v1["columnDefinitions"].map { |column| column["priority"] })
    assert_equal "first item", v1["columnDefinitions"].last["description"]
    assert_equal ["w", 3, "Ready", "alpha"], v1["rows"].first["cells"]

    v2 = call("GET", "/apis/example.com/v2/namespaces/team/widgets/w", headers: {"accept" => TABLE}).body

    assert_equal(%w[Name Age], v2["columnDefinitions"].map { |column| column["name"] })
    assert_equal "date", v2["columnDefinitions"].last["type"]
  end
end
