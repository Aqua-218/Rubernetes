# frozen_string_literal: true

require "yaml"

require_relative "../test_helper"
require "rubernetes/api"

class OpenAPIV2ProtobufTest < Minitest::Test
  API = Rubernetes::API
  WIRE = Rubernetes::Schema::Codec::Protobuf
  PODS = "/api/v1/namespaces/{namespace}/pods"
  WIDGETS = "/apis/example.com/v1/namespaces/{namespace}/widgets"

  def setup
    @repository = API::OpenAPIRepository.new
    @registry = API::Registry.new
    @store = Rubernetes::Storage::MemoryStore.new
    @server = API::Server.new(registry: @registry, store: @store, openapi_repository: @repository)
  end

  def test_paths_and_referenced_parameters_are_served_in_protobuf
    publish_widgets
    json = get.body
    response = get("accept" => API::OpenAPIV2Protobuf::CONTENT_TYPE)

    assert_equal 200, response.status
    paths = named_entries(field(response.body, 8), 2)

    assert_equal json.fetch("paths").keys.sort, paths.keys.sort
    namespace_ref = field(paths.fetch(PODS), 9, 2, 1)

    assert_equal json.dig("paths", PODS, "parameters", 0, "$ref"), namespace_ref
    parameters = named_entries(field(response.body, 10), 1)

    assert_equal json.fetch("parameters").keys.sort, parameters.keys.sort
    shared_namespace = field(parameters.fetch(namespace_ref.delete_prefix("#/parameters/")), 2, 4)

    assert_equal "namespace", field(shared_namespace, 4)
    assert_equal 1, field(shared_namespace, 1)

    widgets = paths.fetch(WIDGETS)

    assert_equal namespace_ref, field(widgets, 9, 2, 1)
    request_body = field(widgets, 4, 8, 1, 1)

    assert_equal "#/definitions/com.example.v1.Widget", field(request_body, 5, 1)
    assert_equal "#/definitions/com.example.v1.WidgetList", get_response_reference(widgets)
    assert_equal "#/definitions/io.k8s.api.autoscaling.v1.Scale", get_response_reference(paths.fetch("#{WIDGETS}/{name}/scale"))
  end

  def test_free_form_values_preserve_types_and_unicode
    extension = {"text" => ["1e6", "no", "\u0085\u2028\u2029😀\u007f\u0080\ufffe\uffff"], "number" => 100, "empty" => nil}
    protobuf = API::OpenAPIV2Protobuf.encode({"swagger" => "2.0", "info" => {"title" => "API", "version" => "1"}, "paths" => {}, "x-test" => extension})
    any = named_entries(protobuf, 16).fetch("x-test")

    assert_equal extension, YAML.safe_load(field(any, 2))
  end

  private

  def get(headers = {})
    @server.call(API::Request.new(method: "GET", path: "/openapi/v2", headers: headers,
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def publish_widgets
    manager = API::CRD::Manager.new(registry: @registry, store: @store, openapi: @repository)
    crd = {
      "apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition",
      "metadata" => {"name" => "widgets.example.com"},
      "spec" => {
        "group" => "example.com", "scope" => "Namespaced",
        "names" => {"plural" => "widgets", "singular" => "widget", "kind" => "Widget", "listKind" => "WidgetList"},
        "versions" => [{"name" => "v1", "served" => true, "storage" => true,
                        "subresources" => {"scale" => {"specReplicasPath" => ".spec.replicas", "statusReplicasPath" => ".status.replicas"}},
                        "schema" => {"openAPIV3Schema" => {"type" => "object", "properties" => {
                          "spec" => {"type" => "object", "properties" => {"replicas" => {"type" => "integer"}}},
                          "status" => {"type" => "object", "properties" => {"replicas" => {"type" => "integer"}}}
                        }}}}]
      }
    }
    manager.sync(crd)
  end

  def get_response_reference(path)
    responses = named_entries(field(path, 2, 9), 1)
    field(responses.fetch("200"), 1, 2, 1, 1)
  end

  def field(message, *numbers)
    numbers.reduce(message) do |bytes, number|
      selected = WIRE.parse_fields(bytes).find { |entry| entry.fetch(:number) == number }
      raise KeyError, "protobuf field #{number} is absent" unless selected

      selected.fetch(:value)
    end
  end

  def named_entries(message, number)
    WIRE.parse_fields(message).select { |entry| entry.fetch(:number) == number }.to_h do |entry|
      pair = entry.fetch(:value)
      [field(pair, 1), field(pair, 2)]
    end
  end
end
