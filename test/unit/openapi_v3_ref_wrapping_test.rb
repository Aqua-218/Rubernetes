# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# kube-openapi builder3/util WrapRefs: in the served OpenAPI v3 document a
# `$ref` with sibling keys becomes `allOf: [{$ref}]` + siblings.  kubectl
# resolves a bare `$ref` in place and loses the siblings, so
# `kubectl explain <crd>.metadata` showed ObjectMeta's description instead of
# the property's "Standard object's metadata ..." that
# "[sig-api-machinery] CustomResourcePublishOpenAPI works for CRD with
# validation schema" matches on.  swagger 2.0 keeps the sibling form.
class OpenAPIV3RefWrappingTest < Minitest::Test
  META_REF = "#/components/schemas/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"

  def setup
    @openapi = Rubernetes::API::OpenAPIRepository.new
    @openapi.publish(group: "example.com", version: "v1", document: {
      "openapi" => "3.0.0",
      "paths" => {"/apis/example.com/v1/foos" => {"get" => {"parameters" => [{"$ref" => "#/components/parameters/pretty"}]}}},
      "components" => {"schemas" => {
        "com.example.v1.Foo" => {
          "type" => "object",
          "properties" => {
            "metadata" => {"$ref" => META_REF, "description" => "Standard object's metadata. More info: x"},
            "spec" => {"type" => "object", "properties" => {
              "bars" => {"type" => "array", "items" => {"$ref" => "#/components/schemas/com.example.v1.Bar"}}
            }}
          }
        },
        "com.example.v1.Bar" => {"type" => "object"}
      }}
    })
  end

  def v3_schema
    @openapi.document_for("/openapi/v3/apis/example.com/v1").dig("components", "schemas", "com.example.v1.Foo")
  end

  def test_a_ref_with_siblings_is_wrapped_in_allof_in_v3
    metadata = v3_schema.dig("properties", "metadata")

    assert_equal([{"$ref" => META_REF}], metadata["allOf"])
    assert_equal("Standard object's metadata. More info: x", metadata["description"])
    refute(metadata.key?("$ref"))
  end

  def test_a_bare_ref_stays_a_bare_ref
    assert_equal({"$ref" => "#/components/schemas/com.example.v1.Bar"},
                 v3_schema.dig("properties", "spec", "properties", "bars", "items"))
    document = @openapi.document_for("/openapi/v3/apis/example.com/v1")
    assert_equal([{"$ref" => "#/components/parameters/pretty"}],
                 document.dig("paths", "/apis/example.com/v1/foos", "get", "parameters"))
  end

  def test_the_referenced_objectmeta_still_travels_with_the_document
    assert(@openapi.document_for("/openapi/v3/apis/example.com/v1").dig("components", "schemas").key?(META_REF.split("/").last))
  end

  def test_swagger_v2_keeps_the_sibling_form
    definition = @openapi.document_for("/openapi/v2").dig("definitions", "com.example.v1.Foo")
    metadata = definition.dig("properties", "metadata")

    assert_equal("#/definitions/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta", metadata["$ref"])
    assert_equal("Standard object's metadata. More info: x", metadata["description"])
    refute(metadata.key?("allOf"))
  end
end
