# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# apiextensions' IntOrString exception: under x-kubernetes-int-or-string the
# `anyOf: [{type: integer}, {type: string}]` branches may set a type.  Argo
# CD's Application CRD uses it (kustomize replica counts) and was refused as
# non-structural, so applications.argoproj.io was never served.
class CRDIntOrStringAnyOfTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @registry = API::Registry.new(resources: [], defaults: false)
    @manager = API::CRD::Manager.new(registry: @registry, store: Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil),
                                     openapi: API::OpenAPIRepository.new)
  end

  def crd(count_schema)
    {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition", "metadata" => {"name" => "applications.example.io"},
     "spec" => {"group" => "example.io", "scope" => "Namespaced",
                "names" => {"plural" => "applications", "singular" => "application", "kind" => "Application", "listKind" => "ApplicationList"},
                "versions" => [{"name" => "v1alpha1", "served" => true, "storage" => true,
                                "schema" => {"openAPIV3Schema" => {"type" => "object", "properties" => {
                                  "spec" => {"type" => "object", "properties" => {"replicas" => {"type" => "array", "items" => {
                                    "type" => "object", "properties" => {"name" => {"type" => "string"}, "count" => count_schema}
                                  }}}}
                                }}}}]}}
  end

  def condition(conditions, type) = conditions.find { |entry| entry["type"] == type }&.fetch("status")

  def test_int_or_string_any_of_is_structural
    conditions = @manager.sync(crd({"x-kubernetes-int-or-string" => true, "anyOf" => [{"type" => "integer"}, {"type" => "string"}]}))

    assert_equal "True", condition(conditions, "Established"), conditions.inspect
    assert_nil condition(conditions, "NonStructuralSchema")
  end

  def test_any_of_with_types_is_still_refused_without_the_extension
    conditions = @manager.sync(crd({"type" => "string", "anyOf" => [{"type" => "integer"}, {"type" => "string"}]}))

    assert_equal "False", condition(conditions, "Established")
    assert_equal "True", condition(conditions, "NonStructuralSchema")
  end

  def test_int_or_string_with_a_third_branch_is_refused
    conditions = @manager.sync(crd({"x-kubernetes-int-or-string" => true,
                                    "anyOf" => [{"type" => "integer"}, {"type" => "string"}, {"type" => "boolean"}]}))

    assert_equal "True", condition(conditions, "NonStructuralSchema")
  end
end
