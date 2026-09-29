# frozen_string_literal: true

require "json"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/manifest/builder"

class ManifestBuilderTest < Minitest::Test
  def test_generated_resource_and_field_methods_build_standard_json
    builder = Rubernetes::Manifest::Builder.new(registry: registry, definitions: definitions)

    builder.config_map("settings", namespace: "demo", labels: {"app" => "web"}) do
      data FEATURE: "enabled"
      immutable true
    end

    object = builder.result.fetch(0)
    assert_equal("v1", object.fetch("apiVersion"))
    assert_equal("ConfigMap", object.fetch("kind"))
    assert_equal("settings", object.dig("metadata", "name"))
    assert_equal("demo", object.dig("metadata", "namespace"))
    assert_equal({"FEATURE" => "enabled"}, object.fetch("data"))
    assert_equal(true, object.fetch("immutable"))
    assert_predicate(object, :frozen?)
  end

  def test_unknown_fields_cannot_fall_through_method_missing
    builder = Rubernetes::Manifest::Builder.new(registry: registry, definitions: definitions)

    assert_raises(NoMethodError) do
      builder.config_map("settings") { invented_field "value" }
    end
  end

  private

  def registry
    {
      "types" => [{
        "schema" => "io.k8s.api.core.v1.ConfigMap",
        "gvks" => [{"group" => "", "version" => "v1", "kind" => "ConfigMap"}]
      }],
      "resources" => [{"group" => "", "version" => "v1", "resource" => "configmaps", "kind" => "ConfigMap"}]
    }
  end

  def definitions
    {
      "io.k8s.api.core.v1.ConfigMap" => {
        "type" => "object",
        "properties" => {
          "apiVersion" => {"type" => "string"},
          "kind" => {"type" => "string"},
          "metadata" => {"type" => "object"},
          "data" => {"type" => "object", "additionalProperties" => {"type" => "string"}},
          "immutable" => {"type" => "boolean"}
        }
      }
    }
  end
end
