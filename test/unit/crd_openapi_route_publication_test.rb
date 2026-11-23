# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

class CRDOpenAPIRoutePublicationTest < Minitest::Test
  API = Rubernetes::API
  GROUP = "test.example"
  PATH = "/apis/test.example/v1/namespaces/{namespace}/widgets"

  def setup
    @repository = API::OpenAPIRepository.new
    @manager = API::CRD::Manager.new(registry: API::Registry.new(resources: [], defaults: false),
                                     store: Rubernetes::Storage::MemoryStore.new, openapi: @repository)
  end

  def publish(kind, plural)
    schema = {"type" => "object", "properties" => {"color" => {"type" => "string"}}}
    version = {"name" => "v1", "selectableFields" => [{"jsonPath" => ".color"}]}
    crd = {"spec" => {"group" => GROUP, "scope" => "Namespaced", "versions" => [version],
                      "names" => {"kind" => kind, "listKind" => "#{kind}Bag", "plural" => plural}}}
    document = @manager.send(:openapi_document, crd, version, API::CRD::StructuralSchema.new(schema))
    @repository.publish(group: GROUP, version: "v1", owner: plural, document: document)
  end

  def test_both_openapi_versions_use_the_declared_list_kind_and_selectable_fields
    publish("Widget", "widgets")
    v2 = @repository.document_for("/openapi/v2")
    v3 = @repository.document_for("/openapi/v3/apis/test.example/v1")
    name = "example.test.v1.Widget"
    [v2.fetch("definitions"), v3.dig("components", "schemas")].each do |schemas|
      [name, "#{name}Bag"].each do |definition|
        assert_equal [{"fieldPath" => "color"}], schemas.fetch(definition).fetch("x-kubernetes-selectable-fields")
      end

      assert_equal "WidgetBag is a list of Widget", schemas.fetch("#{name}Bag").fetch("description")
    end

    assert_equal "#/definitions/#{name}Bag", v2.dig("paths", PATH, "get", "responses", "200", "schema", "$ref")
    assert_equal "#/components/schemas/#{name}Bag", v3.dig("paths", PATH, "get", "responses", "200", "content", "application/json", "schema", "$ref")
    assert_equal "#/definitions/#{name}", v2.dig("paths", PATH, "post", "parameters").find { |field| field["in"] == "body" }.dig("schema", "$ref")
  end

  def test_v2_paths_follow_publication_and_withdrawal_by_owner
    publish("Widget", "widgets")
    publish("Gadget", "gadgets")
    @repository.withdraw(group: GROUP, version: "v1", owner: "widgets")
    paths = @repository.document_for("/openapi/v2").fetch("paths")

    refute paths.key?(PATH)
    assert paths.key?(PATH.sub("widgets", "gadgets"))
    assert paths.key?("/api/v1/namespaces/{namespace}/pods")

    @repository.withdraw(group: GROUP, version: "v1", owner: "gadgets")

    refute @repository.document_for("/openapi/v2").fetch("paths").key?(PATH.sub("widgets", "gadgets"))
  end
end
