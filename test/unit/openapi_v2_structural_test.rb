# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# apiextensions-apiserver/pkg/controller/openapi/v2 ToStructuralOpenAPIV2:
# swagger 2.0 cannot express everything a CRD's structural schema can, and
# kubectl validates client-side against exactly that document.  Publishing the
# v3 schema verbatim left `properties` next to
# x-kubernetes-preserve-unknown-fields, so kubectl rejected every field the CRD
# deliberately allows: "unknown field \"b\" in ....spec".  Reproduced live on
# 2026-09-15 against the conformance spec "CustomResourcePublishOpenAPI works
# for CRD preserving unknown fields in a nested object".
class OpenAPIV2StructuralTest < Minitest::Test
  def setup
    @repository = Rubernetes::API::OpenAPIRepository.new
  end

  def publish(schema)
    @repository.publish(group: "nested.example.com", version: "v1", owner: "waldos.nested.example.com",
                        document: {"components" => {"schemas" => {"com.example.nested.v1.Waldo" => schema}}})
    @repository.document_for("/openapi/v2").fetch("definitions").fetch("com.example.nested.v1.Waldo")
  end

  # One group/version can be served by several CustomResourceDefinitions; each
  # publishes its own document and all of them have to be served.
  def test_several_definitions_share_one_group_version
    @repository.publish(group: "shared.example.com", version: "v1", owner: "foos.shared.example.com",
                        document: {"paths" => {"/apis/shared.example.com/v1/foos" => {}},
                                   "components" => {"schemas" => {"com.example.shared.v1.Foo" => {"type" => "object"}}}})
    @repository.publish(group: "shared.example.com", version: "v1", owner: "bars.shared.example.com",
                        document: {"paths" => {"/apis/shared.example.com/v1/bars" => {}},
                                   "components" => {"schemas" => {"com.example.shared.v1.Bar" => {"type" => "object"}}}})

    definitions = @repository.document_for("/openapi/v2").fetch("definitions")
    assert(definitions.key?("com.example.shared.v1.Foo"))
    assert(definitions.key?("com.example.shared.v1.Bar"))

    v3 = @repository.document_for("/openapi/v3/apis/shared.example.com/v1")
    assert_equal(%w[/apis/shared.example.com/v1/bars /apis/shared.example.com/v1/foos], v3.fetch("paths").keys.sort)
  end

  def test_withdrawing_one_definition_keeps_the_others
    @repository.publish(group: "shared.example.com", version: "v1", owner: "foos.shared.example.com",
                        document: {"components" => {"schemas" => {"com.example.shared.v1.Foo" => {"type" => "object"}}}})
    @repository.publish(group: "shared.example.com", version: "v1", owner: "bars.shared.example.com",
                        document: {"components" => {"schemas" => {"com.example.shared.v1.Bar" => {"type" => "object"}}}})
    @repository.withdraw(group: "shared.example.com", version: "v1", owner: "bars.shared.example.com")

    definitions = @repository.document_for("/openapi/v2").fetch("definitions")
    assert(definitions.key?("com.example.shared.v1.Foo"))
    refute(definitions.key?("com.example.shared.v1.Bar"))
  end

  def test_withdrawing_the_last_definition_removes_the_group_version
    @repository.publish(group: "gone.example.com", version: "v1", owner: "foos.gone.example.com",
                        document: {"components" => {"schemas" => {"com.example.gone.v1.Foo" => {"type" => "object"}}}})
    @repository.withdraw(group: "gone.example.com", version: "v1", owner: "foos.gone.example.com")

    refute(@repository.document_for("/openapi/v2").fetch("definitions").key?("com.example.gone.v1.Foo"))
    assert_nil(@repository.document_for("/openapi/v3/apis/gone.example.com/v1"))
  end

  def test_preserve_unknown_fields_drops_properties_and_type
    published = publish(
      "type" => "object",
      "properties" => {
        "spec" => {"type" => "object", "x-kubernetes-preserve-unknown-fields" => true,
                   "properties" => {"dummy" => {"type" => "object"}}}
      }
    )
    spec = published.dig("properties", "spec")

    refute(spec.key?("properties"), "properties make kubectl reject unknown fields")
    refute(spec.key?("type"), "an object type makes kubectl walk the missing properties")
    assert(spec.fetch("x-kubernetes-preserve-unknown-fields"))
  end

  def test_a_nullable_schema_loses_its_type_items_and_properties
    published = publish(
      "type" => "object",
      "properties" => {
        "spec" => {"type" => "object", "nullable" => true,
                   "properties" => {"dummy" => {"type" => "string"}}}
      }
    )
    spec = published.dig("properties", "spec")

    refute(spec.key?("type"))
    refute(spec.key?("nullable"))
    refute(spec.key?("properties"))
  end

  def test_a_nullable_property_is_dropped_from_required
    published = publish(
      "type" => "object",
      "required" => %w[spec status],
      "properties" => {
        "spec" => {"type" => "object", "nullable" => true},
        "status" => {"type" => "object"}
      }
    )

    assert_equal(["status"], published.fetch("required"))
  end

  def test_an_array_without_items_loses_its_type
    published = publish(
      "type" => "object",
      "properties" => {
        "bars" => {"type" => "array", "x-kubernetes-preserve-unknown-fields" => true,
                   "items" => {"type" => "object"}}
      }
    )
    bars = published.dig("properties", "bars")

    refute(bars.key?("items"))
    refute(bars.key?("type"))
  end

  def test_junctors_swagger_cannot_express_are_removed
    published = publish(
      "type" => "object",
      "properties" => {
        "spec" => {"type" => "object",
                   "allOf" => [{"required" => ["a"]}],
                   "oneOf" => [{"required" => ["b"]}],
                   "anyOf" => [{"required" => ["c"]}],
                   "not" => {"required" => ["d"]}}
      }
    )
    spec = published.dig("properties", "spec")

    %w[allOf oneOf anyOf not].each { |key| refute(spec.key?(key), "#{key} is not expressible in swagger 2.0") }
    assert_equal("object", spec.fetch("type"))
  end

  # buildKubeNative: a root schema that preserves unknown fields is published as
  # a bare object, because kubectl rejects every field a swagger definition
  # does not declare -- including the ones the CRD deliberately allows.
  def test_a_root_preserving_schema_is_published_as_a_bare_object
    published = publish(
      "description" => "preserve-unknown-properties at root for Testing",
      "type" => "object",
      "x-kubernetes-preserve-unknown-fields" => true,
      "properties" => {"apiVersion" => {"type" => "string"}, "kind" => {"type" => "string"}},
      "x-kubernetes-group-version-kind" => [{"group" => "nested.example.com", "kind" => "Waldo", "version" => "v1"}]
    )

    assert_equal({"type" => "object",
                  "x-kubernetes-group-version-kind" => [{"group" => "nested.example.com", "kind" => "Waldo",
                                                         "version" => "v1"}]},
                 published)
  end

  # An ordinary schema is published unchanged apart from the $ref dialect.
  def test_an_ordinary_schema_survives_intact
    published = publish(
      "type" => "object",
      "properties" => {"spec" => {"type" => "object", "properties" => {"dummy" => {"type" => "string"}}}}
    )

    assert_equal({"type" => "string"}, published.dig("properties", "spec", "properties", "dummy"))
  end
end
