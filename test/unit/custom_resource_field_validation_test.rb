# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# apiextensions-apiserver prunes a custom resource against its structural
# schema, and server-side field validation reports what it would have removed
# rather than removing it silently.  Ours pruned in silence, so a Strict
# request could carry any field at all into a CR --
# "[sig-api-machinery] FieldValidation should create/apply an invalid CR with
# extra properties for CRD with validation schema" reported
# "error missing unknown field".
class CustomResourceFieldValidationTest < Minitest::Test
  Structural = Rubernetes::API::CRD::StructuralSchema

  SCHEMA = {
    "type" => "object",
    "properties" => {
      "spec" => {
        "type" => "object",
        "properties" => {
          "foo" => {"type" => "string"},
          "ports" => {
            "type" => "array",
            "items" => {"type" => "object",
                        "properties" => {"name" => {"type" => "string"},
                                         "containerPort" => {"type" => "integer"}}}
          }
        }
      }
    }
  }.freeze

  def schema(value = SCHEMA)
    Structural.new(value)
  end

  def test_a_field_the_schema_does_not_declare_is_reported
    paths = schema.unknown_field_paths(
      "apiVersion" => "fv.example.com/v1", "kind" => "Noxu",
      "metadata" => {"name" => "mytest"},
      "unknownField" => "unknown",
      "spec" => {"foo" => "foo1"}
    )

    assert_equal([["unknownField"]], paths)
  end

  def test_a_nested_and_list_item_field_is_reported_with_its_path
    paths = schema.unknown_field_paths(
      "metadata" => {"name" => "mytest"},
      "spec" => {"foo" => "a", "bar" => "b",
                 "ports" => [{"name" => "x"}, {"name" => "y", "extra" => 1}]}
    )

    assert_includes(paths, %w[spec bar])
    assert_includes(paths, ["spec", "ports", 1, "extra"])
    assert_equal(2, paths.length)
  end

  def test_a_declared_field_is_never_reported
    assert_empty(schema.unknown_field_paths("spec" => {"foo" => "a", "ports" => [{"containerPort" => 80}]}))
  end

  # x-kubernetes-preserve-unknown-fields is exactly the opt-out.
  def test_a_preserving_object_accepts_anything
    preserving = schema("type" => "object",
                        "properties" => {"spec" => {"type" => "object",
                                                    "x-kubernetes-preserve-unknown-fields" => true}})

    assert_empty(preserving.unknown_field_paths("spec" => {"whatever" => {"nested" => true}}))
  end

  def test_unknown_metadata_is_reported_at_the_root_and_in_an_embedded_resource
    embedded = schema(
      "type" => "object",
      "properties" => {
        "spec" => {
          "type" => "object",
          "properties" => {
            "template" => {"type" => "object", "x-kubernetes-embedded-resource" => true,
                           "x-kubernetes-preserve-unknown-fields" => true}
          }
        }
      }
    )

    paths = embedded.unknown_field_paths(
      "metadata" => {"name" => "mytest", "unknownMeta" => "x"},
      "spec" => {"template" => {"apiVersion" => "v1", "kind" => "Pod",
                                "metadata" => {"name" => "t", "unknownEmbedded" => "y"}}}
    )

    assert_includes(paths, %w[metadata unknownMeta])
    assert_includes(paths, %w[spec template metadata unknownEmbedded])
  end

  # sigs.k8s.io/json reports strict errors in the order the decoder met them,
  # and a body declares its unknown field before it repeats a known one.
  def test_unknown_fields_are_reported_before_duplicates
    resource = Rubernetes::API::Resource.new(group: "apps", version: "v1", resource: "deployments",
                                             kind: "Deployment", scope: :namespaced)
    server = Rubernetes::API::Server.allocate
    violations = server.send(:strict_field_violations, resource, {}, duplicates: ["spec.replicas"])

    assert_equal(['duplicate field "spec.replicas"'], violations)
  end

  def test_the_apply_message_uses_the_type_converter_wording
    resource = Rubernetes::API::Resource.new(group: "fv.example.com", version: "v1", resource: "noxus",
                                             kind: "Noxu", scope: :cluster)
    server = Rubernetes::API::Server.allocate
    message = server.send(:apply_validation_message, resource, ['unknown field "unknownField"'])

    assert_includes(message, ".unknownField: field not declared in schema")
    assert_includes(message, "Kind=Noxu")
  end
end
