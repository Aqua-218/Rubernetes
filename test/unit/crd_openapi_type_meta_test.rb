# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# apiextensions-apiserver copies the TypeMeta and ObjectMeta property
# definitions -- descriptions and all -- into every published CRD schema
# (controller/openapi/builder/builder.go addTypeMetaProperties).  Publishing a
# bare "type: string" instead left `kubectl explain` printing
# "<no description>" for apiVersion, kind and metadata, which is exactly what
# "[sig-api-machinery] CustomResourcePublishOpenAPI works for CRD with
# validation schema" matches on:
#   DESCRIPTION:.*FIELDS:.*apiVersion.*<string>.*APIVersion defines.*
class CRDOpenAPITypeMetaTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    @registry = API::Registry.new(resources: [], defaults: false)
    @registry.register(API::Resource.new(group: "apiextensions.k8s.io", version: "v1",
                                         resource: "customresourcedefinitions",
                                         kind: "CustomResourceDefinition", scope: :cluster,
                                         subresources: [{resource: "status", verbs: %w[get patch update]}]))
    @openapi = API::OpenAPIRepository.new
    @manager = API::CRD::Manager.new(registry: @registry, store: @store, openapi: @openapi)
  end

  CRD = {
    "apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition",
    "metadata" => {"name" => "foos.example.com"},
    "spec" => {"group" => "example.com", "scope" => "Namespaced",
               "names" => {"plural" => "foos", "singular" => "foo", "kind" => "Foo", "listKind" => "FooList"},
               "versions" => [{"name" => "v1", "served" => true, "storage" => true,
                               "schema" => {"openAPIV3Schema" => {
                                 "type" => "object", "description" => "Foo CRD for Testing",
                                 "properties" => {"spec" => {"type" => "object",
                                                             "description" => "Specification of Foo"}}
                               }}}]}
  }.freeze

  def document
    version = CRD.dig("spec", "versions", 0)
    schema = API::CRD::StructuralSchema.new(version.dig("schema", "openAPIV3Schema"))
    @manager.send(:openapi_document, CRD, version, schema)
  end

  def object_properties
    schemas = document.fetch("components").fetch("schemas")
    name = schemas.keys.find { |key| key.end_with?(".Foo") }

    refute_nil(name, schemas.keys.inspect)
    schemas.fetch(name).fetch("properties")
  end

  def test_apiversion_carries_its_canonical_description
    assert_match(/\AAPIVersion defines the versioned schema/,
                 object_properties.fetch("apiVersion").fetch("description"))
  end

  def test_kind_carries_its_canonical_description
    assert_match(/\AKind is a string value representing the REST resource/,
                 object_properties.fetch("kind").fetch("description"))
  end

  def test_metadata_carries_its_canonical_description
    assert_match(/\AStandard object's metadata/,
                 object_properties.fetch("metadata").fetch("description"))
  end

  # The CRD's own descriptions are what the rest of the output is matched on,
  # so they have to survive alongside the injected ones.
  def test_the_crds_own_descriptions_survive
    schemas = document.fetch("components").fetch("schemas")
    name = schemas.keys.find { |key| key.end_with?(".Foo") }

    assert_equal("Foo CRD for Testing", schemas.fetch(name).fetch("description"))
    assert_equal("Specification of Foo", object_properties.fetch("spec").fetch("description"))
  end

  # A CRD that declares apiVersion itself keeps its own definition.
  def test_a_declared_property_is_not_overwritten
    crd = JSON.parse(JSON.generate(CRD))
    crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["apiVersion"] =
      {"type" => "string", "description" => "mine"}
    version = crd.dig("spec", "versions", 0)
    schema = API::CRD::StructuralSchema.new(version.dig("schema", "openAPIV3Schema"))
    schemas = @manager.send(:openapi_document, crd, version, schema).fetch("components").fetch("schemas")
    name = schemas.keys.find { |key| key.end_with?(".Foo") }

    assert_equal("mine", schemas.fetch(name).fetch("properties").fetch("apiVersion").fetch("description"))
  end

  # The published group/version document must resolve its own references:
  # `kubectl explain <crd>.metadata` lists ObjectMeta's FIELDS from it.
  def test_the_dynamic_document_carries_the_meta_components_it_references
    repository = Rubernetes::API::OpenAPIRepository.new
    repository.publish(group: "example.com", version: "v1", document: {
      "components" => {"schemas" => {"com.example.v1.Gadget" => {
        "properties" => {"metadata" => {"$ref" => "#/components/schemas/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"}}
      }}}
    })
    schemas = repository.document_for("/openapi/v3/apis/example.com/v1").dig("components", "schemas")
    assert schemas.key?("io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta")
    assert schemas.key?("io.k8s.apimachinery.pkg.apis.meta.v1.ManagedFieldsEntry"), "references are followed transitively"
    assert schemas.dig("io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta", "properties", "creationTimestamp")
  end
end
