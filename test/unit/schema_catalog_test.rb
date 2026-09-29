# frozen_string_literal: true

require "json"
require "fileutils"
require "tmpdir"

require_relative "../test_helper"

class SchemaCatalogTest < Minitest::Test
  Catalog = Rubernetes::Schema::Catalog

  def test_loads_separate_type_and_resource_indexes_and_preserves_metadata
    with_catalog do |catalog|
      assert_equal 4, catalog.type_count
      assert_equal 2, catalog.resource_count
      assert_equal 5, catalog.gvk_count
      assert_equal 7, catalog.gvr_count

      orphan = catalog.find_gvk("apps/v1/Orphan")
      assert_equal "io.example.v1.Orphan", orphan.schema_name
      protocol_gvk = catalog.find_gvk("core/v1/PodExecOptions")
      assert_instance_of Catalog::GVKEntry, protocol_gvk
      assert protocol_gvk.protocol_only?
      assert_nil protocol_gvk.schema_name
      assert_nil protocol_gvk.openapi_schema
      assert_nil catalog.find_gvr(group: "apps", version: "v1", resource: "orphans")

      deployment = catalog.find_gvk(group: "apps", version: "v1beta1", kind: "Deployment")
      resource = catalog.find_gvr(group: "apps", version: "v1", resource: "deployments")
      assert_same resource, catalog.find_gvr("apps/v1/deployments")
      assert_same deployment.type, catalog.type(gvr: resource.gvr)
      assert_same deployment.type, catalog.type("apps/v1beta1/Deployment")
      assert_same deployment.type, resource.type
      assert_equal "io.example.v1.Deployment", catalog.schema_name(resource)
      assert_equal "io.example.v1.Deployment", catalog.schema_name("apps/v1/deployments")
      assert_equal "io.example.v1.Deployment", catalog.schema_name(
        group: "apps", version: "v1", resource: "deployments"
      )
      assert_equal({"type" => "object", "properties" => {"spec" => {"type" => "object"}}},
                   catalog.openapi_schema(resource))
      assert_equal %w[metadata spec], resource.field_set
      assert_equal ["spec"], resource.patch_set
      assert_equal :namespaced, resource.scope
      assert_equal({"spec.containers" => "name"}, resource.merge_keys)
      assert_equal ["get", "list"], resource.verbs

      deployment_status = catalog.find_gvr(group: "apps", version: "v1", resource: "deployments/status")
      assert_instance_of Catalog::GVR, deployment_status
      refute deployment_status.primary?
      assert deployment_status.subresource?
      assert_equal "Deployment", deployment_status.kind
      assert_same resource.type, deployment_status.type
      assert_equal ["get", "patch"], deployment_status.verbs

      autoscaling_scales = %w[deployments replicasets statefulsets].map do |parent|
        catalog.find_gvr(group: "autoscaling", version: "v1", resource: "#{parent}/scale")
      end
      assert_equal 3, autoscaling_scales.compact.length
      assert_equal 3, autoscaling_scales.map(&:gvr).uniq.length
      assert autoscaling_scales.all? { |entry| entry.primary_resource.nil? }
      refute_equal autoscaling_scales.first.gvr, catalog.find_gvr(
        group: "apps", version: "v1", resource: "deployments/scale"
      ).gvr

      assert_predicate(catalog.types, :frozen?)
      assert_predicate(catalog.gvks, :frozen?)
      assert_predicate(deployment, :frozen?)
      assert_predicate(deployment.openapi_schema, :frozen?)
      assert_raises(FrozenError) { deployment.openapi_schema.fetch("properties")["spec"] = {} }
      assert_raises(FrozenError) { resource.merge_keys["new"] = "name" }
    end
  end

  def test_rejects_path_traversal_invalid_json_duplicates_and_missing_schema
    Dir.mktmpdir("rubernetes-catalog-") do |root|
      write_catalog(root)
      assert_raises(Catalog::PathError) do
        Catalog.new(root: root, registry_path: "../registry.json", openapi_path: "openapi/v2.json")
      end

      File.write(File.join(root, "schema", "registry.json"), "not-json")
      assert_raises(Catalog::InvalidJSONError) { Catalog.new(root: root) }
    end

    Dir.mktmpdir("rubernetes-catalog-duplicate-gvk-") do |root|
      openapi = openapi_payload
      openapi.fetch("definitions")["io.example.v1.Duplicate"] = {"type" => "object"}
      write_catalog(root, registry: duplicate_gvk_registry, openapi: openapi)
      assert_raises(Catalog::DuplicateGVKError) { Catalog.new(root: root) }
    end

    Dir.mktmpdir("rubernetes-catalog-errors-") do |root|
      registry = duplicate_gvr_registry
      write_catalog(root, registry: registry)
      assert_raises(Catalog::DuplicateGVRError) { Catalog.new(root: root) }

      missing_openapi = openapi_payload
      missing_openapi.fetch("definitions").delete("io.example.v1.ConfigMap")
      write_catalog(root, openapi: missing_openapi)
      assert_raises(Catalog::MissingSchemaError) { Catalog.new(root: root) }

      duplicate_served_gvr = registry_payload
      duplicate_served_gvr.fetch("gvrs") << duplicate_served_gvr.fetch("gvrs").first.dup
      write_catalog(root, registry: duplicate_served_gvr)
      assert_raises(Catalog::DuplicateGVRError) { Catalog.new(root: root) }

      missing_served_gvr = registry_payload
      missing_served_gvr.fetch("gvrs").shift
      write_catalog(root, registry: missing_served_gvr)
      assert_raises(Catalog::MissingGVRError) { Catalog.new(root: root) }

      duplicate_covered_gvk = registry_payload
      duplicate_covered_gvk.fetch("gvks") << duplicate_covered_gvk.fetch("gvks").first.dup
      write_catalog(root, registry: duplicate_covered_gvk)
      assert_raises(Catalog::DuplicateGVKError) { Catalog.new(root: root) }

      missing_covered_gvk = registry_payload
      missing_covered_gvk.fetch("gvks").shift
      write_catalog(root, registry: missing_covered_gvk)
      assert_raises(Catalog::MissingGVKError) { Catalog.new(root: root) }

      missing_resource_schema = registry_payload
      missing_resource_schema.fetch("resources").first.delete("schema")
      write_catalog(root, registry: missing_resource_schema)
      assert_raises(Catalog::MissingSchemaError) { Catalog.new(root: root) }
    end
  end

  def test_canonical_generated_catalog_is_exactly_once_when_present
    generated = File.expand_path("../../generated", __dir__)
    registry_path = File.join(generated, "schema", "registry.json")
    openapi_path = File.join(generated, "openapi", "v2.json")
    skip "canonical generated schema is not present" unless File.file?(registry_path) && File.file?(openapi_path)

    registry = JSON.parse(File.read(registry_path))
    catalog = Catalog.new(root: generated)

    assert_equal registry.fetch("types").length, catalog.type_count
    assert_equal registry.fetch("gvks").length, catalog.gvk_count
    assert_equal registry.fetch("resources").length, catalog.resource_count
    assert_equal registry.fetch("gvrs").length, catalog.gvr_count
    assert_equal 150, catalog.route_gvr_count
    assert_equal catalog.types.map(&:schema_name).uniq.length, catalog.type_count
    assert_equal catalog.resources.map { |entry| entry.gvr.to_s }.uniq.length, catalog.resource_count
    assert_equal registry.fetch("types").sum { |entry| entry.fetch("gvks").length }, catalog.type_index.length
    assert_equal catalog.gvk_count, catalog.known_gvks.uniq.length
    assert_equal catalog.gvk_count, catalog.gvks.map(&:gvk).uniq.length
    assert_equal catalog.gvr_count, catalog.known_gvrs.uniq.length
    assert_equal catalog.gvr_count, catalog.gvrs.map(&:gvr).uniq.length
    assert_predicate(catalog.gvr_index, :frozen?)
    assert_predicate(catalog.gvk_index, :frozen?)
    assert catalog.find_gvk(group: "", version: "v1", kind: "Pod")
    protocol_gvk = catalog.find_gvk(group: "", version: "v1", kind: "NodeProxyOptions")
    assert_instance_of Catalog::GVKEntry, protocol_gvk
    assert protocol_gvk.protocol_only?
    assert catalog.find_gvr(group: "", version: "v1", resource: "pods")
  end

  private

  def with_catalog(registry: registry_payload, openapi: openapi_payload)
    Dir.mktmpdir("rubernetes-catalog-") do |root|
      write_catalog(root, registry: registry, openapi: openapi)
      @fixture_catalog = Catalog.new(root: root)
      yield @fixture_catalog
    end
  end

  def write_catalog(root, registry: registry_payload, openapi: openapi_payload)
    FileUtils.mkdir_p(File.join(root, "schema"))
    FileUtils.mkdir_p(File.join(root, "openapi"))
    File.write(File.join(root, "schema", "registry.json"), JSON.generate(registry))
    File.write(File.join(root, "openapi", "v2.json"), JSON.generate(openapi))
  end

  def registry_payload
    {
      "types" => [
        {
          "schema" => "io.example.v1.ConfigMap",
          "ruby_constant" => "ConfigMap",
          "fields" => %w[metadata data],
          "required" => ["metadata"],
          "patch_fields" => ["data"],
          "gvks" => [{"group" => "", "version" => "v1", "kind" => "ConfigMap"}]
        },
        {
          "schema" => "io.example.v1.Deployment",
          "ruby_constant" => "Deployment",
          "fields" => %w[metadata spec],
          "required" => ["metadata"],
          "patch_fields" => ["spec"],
          "gvks" => [
            {"group" => "apps", "version" => "v1", "kind" => "Deployment"},
            {"group" => "apps", "version" => "v1beta1", "kind" => "Deployment"}
          ]
        },
        {
          "schema" => "io.example.v1.Orphan",
          "ruby_constant" => "Orphan",
          "fields" => ["metadata"],
          "required" => [],
          "patch_fields" => [],
          "gvks" => [{"group" => "apps", "version" => "v1", "kind" => "Orphan"}]
        },
        {
          "schema" => "io.example.v1.NoIdentity",
          "ruby_constant" => "NoIdentity",
          "fields" => ["metadata"],
          "required" => [],
          "patch_fields" => [],
          "gvks" => []
        }
      ],
      "gvks" => [
        {"group" => "", "version" => "v1", "kind" => "ConfigMap", "identifier" => "core/v1/ConfigMap",
         "schema" => "io.example.v1.ConfigMap"},
        {"group" => "apps", "version" => "v1", "kind" => "Deployment",
         "identifier" => "apps/v1/Deployment", "schema" => "io.example.v1.Deployment"},
        {"group" => "apps", "version" => "v1beta1", "kind" => "Deployment",
         "identifier" => "apps/v1beta1/Deployment", "schema" => "io.example.v1.Deployment"},
        {"group" => "apps", "version" => "v1", "kind" => "Orphan", "identifier" => "apps/v1/Orphan",
         "schema" => "io.example.v1.Orphan"},
        {"group" => "", "version" => "v1", "kind" => "PodExecOptions",
         "identifier" => "core/v1/PodExecOptions", "schema" => nil}
      ],
      "resources" => [
        {
          "group" => "",
          "version" => "v1",
          "resource" => "configmaps",
          "kind" => "ConfigMap",
          "scope" => "Namespaced",
          "verbs" => %w[get list],
          "schema" => "io.example.v1.ConfigMap",
          "merge_keys" => {"data" => "name"}
        },
        {
          "group" => "apps",
          "version" => "v1",
          "resource" => "deployments",
          "kind" => "Deployment",
          "scope" => "Namespaced",
          "verbs" => %w[get list],
          "schema" => "io.example.v1.Deployment",
          "merge_keys" => {"spec.containers" => "name"},
          "subresources" => [
            {"resource" => "status", "kind" => "Deployment", "verbs" => %w[get patch]},
            {"resource" => "scale", "kind" => "Scale", "verbs" => %w[get patch update]}
          ]
        }
      ],
      "gvrs" => [
        {"group" => "", "version" => "v1", "resource" => "configmaps", "identifier" => "core/v1/configmaps"},
        {"group" => "apps", "version" => "v1", "resource" => "deployments", "identifier" => "apps/v1/deployments"},
        {"group" => "apps", "version" => "v1", "resource" => "deployments/status",
         "identifier" => "apps/v1/deployments/status"},
        {"group" => "apps", "version" => "v1", "resource" => "deployments/scale",
         "identifier" => "apps/v1/deployments/scale"},
        {"group" => "autoscaling", "version" => "v1", "resource" => "deployments/scale",
         "identifier" => "autoscaling/v1/deployments/scale"},
        {"group" => "autoscaling", "version" => "v1", "resource" => "replicasets/scale",
         "identifier" => "autoscaling/v1/replicasets/scale"},
        {"group" => "autoscaling", "version" => "v1", "resource" => "statefulsets/scale",
         "identifier" => "autoscaling/v1/statefulsets/scale"}
      ]
    }
  end

  def openapi_payload
    {
      "swagger" => "2.0",
      "definitions" => {
        "io.example.v1.ConfigMap" => {"type" => "object", "properties" => {"metadata" => {"type" => "object"}}},
        "io.example.v1.Deployment" => {"type" => "object", "properties" => {"spec" => {"type" => "object"}}},
        "io.example.v1.Orphan" => {"type" => "object", "properties" => {"metadata" => {"type" => "object"}}},
        "io.example.v1.NoIdentity" => {"type" => "object", "properties" => {"metadata" => {"type" => "object"}}}
      }
    }
  end

  def duplicate_gvk_registry
    value = Marshal.load(Marshal.dump(registry_payload))
    value.fetch("types") << {
      "schema" => "io.example.v1.Duplicate",
      "ruby_constant" => "Duplicate",
      "fields" => [],
      "required" => [],
      "patch_fields" => [],
      "gvks" => [{"group" => "", "version" => "v1", "kind" => "ConfigMap"}]
    }
    value
  end

  def duplicate_gvr_registry
    value = Marshal.load(Marshal.dump(registry_payload))
    value.fetch("resources") << Marshal.load(Marshal.dump(value.fetch("resources").first))
    value
  end
end
