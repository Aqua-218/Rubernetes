# frozen_string_literal: true

# A CRD whose later version has a non-structural schema is not established,
# and none of its versions is served -- not even the structural ones
# registered before the failing one; once the schema is fixed, every served
# version is.

require_relative "../test_helper"
require "rubernetes/api"

class CRDNonStructuralVersionTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @registry = API::Registry.new(resources: [], defaults: false)
    @openapi = API::OpenAPIRepository.new
    @manager = API::CRD::Manager.new(registry: @registry, store: Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil),
                                     openapi: @openapi)
  end

  STRUCTURAL = {"openAPIV3Schema" => {"type" => "object", "properties" => {"spec" => {"type" => "object", "x-kubernetes-preserve-unknown-fields" => true}}}}.freeze
  NON_STRUCTURAL = {"openAPIV3Schema" => {"type" => "object", "properties" => {"spec" => {"description" => "no type"}}}}.freeze

  def crd(v2_schema)
    {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition", "metadata" => {"name" => "gizmos.example.com"},
     "spec" => {"group" => "example.com", "scope" => "Namespaced",
                "names" => {"plural" => "gizmos", "singular" => "gizmo", "kind" => "Gizmo", "listKind" => "GizmoList"},
                "versions" => [{"name" => "v1", "served" => true, "storage" => true, "schema" => STRUCTURAL},
                               {"name" => "v2", "served" => true, "storage" => false, "schema" => v2_schema}]}}
  end

  def served?(version) = !@registry.find_gvr(group: "example.com", version: version, resource: "gizmos").nil?

  def test_nothing_is_served_until_every_version_is_structural
    conditions = @manager.sync(crd(NON_STRUCTURAL))
    established = conditions.find { |condition| condition["type"] == "Established" }
    assert_equal "False", established["status"]
    assert_equal "True", conditions.find { |condition| condition["type"] == "NonStructuralSchema" }&.fetch("status")
    refute served?("v1"), "the structural v1 registered before v2 failed must not stay served"
    refute served?("v2")
    refute @openapi.group_version_published?(group: "example.com", version: "v1")
    refute @manager.serving?("example.com", "v1", "gizmos")

    conditions = @manager.sync(crd(STRUCTURAL))
    assert_equal "True", conditions.find { |condition| condition["type"] == "Established" }["status"]
    assert served?("v1")
    assert served?("v2")
    assert @openapi.group_version_published?(group: "example.com", version: "v2")
  end

  def test_a_served_crd_that_turns_non_structural_is_withdrawn
    @manager.sync(crd(STRUCTURAL))
    assert served?("v1")
    @manager.sync(crd(NON_STRUCTURAL))
    refute served?("v1")
    refute served?("v2")
    refute @openapi.group_version_published?(group: "example.com", version: "v1")
  end
end
