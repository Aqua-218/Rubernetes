# frozen_string_literal: true

require "json"
require "open3"
require "rbconfig"
require "tmpdir"
require_relative "../test_helper"
require "fileutils"
require "securerandom"

class SchemaGeneratorTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  # Scratch output lives under build/ (excluded from the M0 source inventory);
  # a temp dir at the tree root changes the inventory while gate tests run.
  # Generated trees require_relative ../../lib, so scratch output must be a direct
  # child of ROOT.  The name follows the a11-generated.XXXXXX convention that the
  # M0 source inventory excludes; a plain mktmpdir at the tree root changed the
  # inventory while gate tests ran in parallel (source inventory mismatch).
  def scratch_dir
    dir = File.join(ROOT, "a11-generated.#{SecureRandom.alphanumeric(8)}")
    Dir.mkdir(dir, 0o700)
    yield dir
  ensure
    FileUtils.rm_rf(dir) if dir
  end
  CANONICAL_CORPUS = File.join(ROOT, "schema/kubernetes/v1.36.2")

  def test_generation_is_deterministic_and_field_sets_match
    Dir.mktmpdir("rubernetes-corpus-") do |corpus|
      scratch_dir do |first|
        scratch_dir do |second|
          write_corpus(corpus)
          run_generator(corpus, first)
          run_generator(corpus, second)

          assert_equal(tree(first), tree(second))
          field_sets = JSON.parse(File.read(File.join(first, "fixtures/field-sets.json")))
          sets = field_sets.fetch("io.k8s.api.core.v1.ConfigMap")

          assert_equal(sets.fetch("ruby"), sets.fetch("rbs"))
          assert_equal(sets.fetch("ruby"), sets.fetch("openapi"))
          assert_equal(sets.fetch("ruby"), sets.fetch("codec"))
          assert_equal(sets.fetch("ruby"), sets.fetch("patch"))
          registry = JSON.parse(File.read(File.join(first, "schema/registry.json")))

          assert_equal(2, registry.fetch("gvks").length)
          protocol_only = registry.fetch("gvks").find { |entry| entry.fetch("kind") == "PodExecOptions" }

          assert_nil(protocol_only.fetch("schema"))

          config_map = registry.fetch("types").find { |entry| entry.fetch("schema") == "io.k8s.api.core.v1.ConfigMap" }
          definitions = config_map.fetch("field_definitions")

          assert_equal("string", definitions.dig("data", "additional_properties", "type"))
          assert_equal("reference", definitions.dig("metadata", "type"))
          assert_equal("io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta", definitions.dig("metadata", "reference"))
          assert_equal("int32", definitions.dig("count", "format"))
          assert_equal(true, definitions.dig("count", "nullable"))
          assert_equal(2, definitions.dig("count", "default"))
          assert_equal("string", definitions.dig("names", "items", "type"))
          assert_equal("set", definitions.dig("names", "x_kubernetes_list_type"))
          assert_equal(true, definitions.dig("raw", "preserve_unknown_fields"))

          runtime = inspect_generated(first)

          assert_equal(2, runtime.fetch("definition_count"))
          assert_equal(true, runtime.fetch("definitions_frozen"))
          assert_equal(
            [%w[data key], %w[metadata name]],
            runtime.fetch("invalid_paths")
          )
          assert_equal(true, runtime.fetch("recursive_reference_valid"))
          assert_equal(2, runtime.fetch("default_count"))
          assert_equal({"count" => ["range"], "mode" => %w[enum pattern], "names" => ["type"]},
                       runtime.fetch("constraint_codes"))
          assert_equal(true, runtime.fetch("nullable_and_preserved_valid"))
        end
      end
    end
  end

  def test_canonical_generation_loads_all_typed_definitions_and_validates_representative_resources
    scratch_dir do |first|
      scratch_dir do |second|
        run_generator(CANONICAL_CORPUS, first)
        run_generator(CANONICAL_CORPUS, second)

        assert_equal(tree(first), tree(second))
        _stdout, stderr, status = Open3.capture3(RbConfig.ruby, "-c", File.join(first, "ruby/kubernetes_types.rb"), chdir: ROOT)

        assert_predicate(status, :success?, stderr)

        runtime = inspect_canonical_generated(first)

        assert_equal(771, runtime.fetch("definition_count"))
        assert_equal(true, runtime.fetch("definitions_frozen"))
        assert_equal("Rubernetes::Schema::Reference", runtime.fetch("pod_spec_type"))
        assert_equal("Rubernetes::Schema::Reference", runtime.fetch("pod_container_item_type"))
        assert_equal("string", runtime.fetch("config_map_value_type"))
        assert_equal("map", runtime.fetch("pod_container_list_type"))
        assert_equal("name", runtime.fetch("pod_container_patch_merge_key"))
        assert_equal(
          {
            "int_or_string" => {"format" => "int-or-string", "type" => "string"},
            "quantity" => {"format" => nil, "type" => "string"},
            "time" => {"format" => "date-time", "type" => "string"}
          },
          runtime.fetch("scalar_references")
        )
        assert_equal(true, runtime.fetch("scalar_reference_values_valid"))
        assert_equal(
          {
            "config_map" => [%w[data key]],
            "crd" => [%w[spec group]],
            "pod" => [%w[spec containers 0 name]]
          },
          runtime.fetch("invalid_paths")
        )
      end
    end
  end

  def test_duplicate_gvr_is_rejected
    Dir.mktmpdir("rubernetes-corpus-") do |corpus|
      Dir.mktmpdir("rubernetes-generated-") do |output|
        write_corpus(corpus, duplicate_resource: true)
        _stdout, stderr, status = invoke_generator(corpus, output)

        refute_predicate(status, :success?)
        assert_match(/duplicate GVR registrations/, stderr)
      end
    end
  end

  private

  def write_corpus(directory, duplicate_resource: false)
    FileUtils.mkdir_p(File.join(directory, "openapi"))
    FileUtils.mkdir_p(File.join(directory, "discovery"))
    swagger = {
      "swagger" => "2.0",
      "paths" => {},
      "definitions" => {
        "io.k8s.api.core.v1.ConfigMap" => {
          "type" => "object",
          "required" => ["metadata"],
          "properties" => {
            "apiVersion" => {"type" => "string"},
            "count" => {"type" => "integer", "format" => "int32", "nullable" => true, "default" => 2, "minimum" => 1, "maximum" => 5},
            "data" => {"type" => "object", "additionalProperties" => {"type" => "string"}, "x-kubernetes-map-type" => "atomic"},
            "kind" => {"type" => "string"},
            "metadata" => {"$ref" => "#/definitions/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"},
            "mode" => {"type" => "string", "enum" => %w[safe fast], "pattern" => "^(safe|fast)$"},
            "names" => {"type" => "array", "items" => {"type" => "string"}, "x-kubernetes-list-type" => "set",
                        "x-kubernetes-patch-strategy" => "merge"},
            "raw" => {"type" => "object", "x-kubernetes-preserve-unknown-fields" => true}
          },
          "x-kubernetes-group-version-kind" => [{"group" => "", "version" => "v1", "kind" => "ConfigMap"}]
        },
        "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta" => {
          "type" => "object",
          "required" => ["name"],
          "properties" => {
            "name" => {"type" => "string", "pattern" => "^[a-z]+$"},
            "owner" => {"$ref" => "#/definitions/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"}
          }
        }
      }
    }
    resource = {
      "resource" => "configmaps", "singularResource" => "configmap", "scope" => "Namespaced",
      "verbs" => %w[create delete get list patch update watch],
      "responseKind" => {"group" => "", "version" => "", "kind" => "ConfigMap"}
    }
    discovery = {
      "apiVersion" => "apidiscovery.k8s.io/v2", "kind" => "APIGroupDiscoveryList",
      "items" => [{"metadata" => {"name" => "core"},
                   "versions" => [{"version" => "v1", "resources" => duplicate_resource ? [resource, resource] : [resource]}]}]
    }
    File.write(File.join(directory, "openapi/v2.json"), JSON.generate(swagger))
    File.write(File.join(directory, "discovery/aggregated_v2.json"), JSON.generate(discovery))
    File.write(File.join(directory, "discovery/api__v1.json"),
               JSON.generate("groupVersion" => "v1", "kind" => "APIResourceList", "resources" => []))
    File.write(
      File.join(directory, "sources.json"),
      JSON.generate(
        "commit" => "test",
        "coverage" => {
          "covered_gvks" => ["core/v1/ConfigMap", "core/v1/PodExecOptions"],
          "covered_gvrs" => ["core/v1/configmaps"]
        }
      )
    )
  end

  def run_generator(corpus, output)
    stdout, stderr, status = invoke_generator(corpus, output)

    assert_predicate(status, :success?, "#{stdout}\n#{stderr}")
  end

  def invoke_generator(corpus, output)
    Open3.capture3(
      RbConfig.ruby,
      File.join(ROOT, "tools/schema/generate.rb"),
      "--corpus", corpus,
      "--output", output,
      chdir: ROOT
    )
  end

  def inspect_generated(output)
    script = <<~RUBY
      require "json"
      require File.expand_path(ARGV.fetch(0))
      constants = Rubernetes::Generated::SCHEMA_CONSTANTS.values
      definitions = constants.map { |name| Rubernetes::Generated.const_get(name, false)::DEFINITION }
      config_map = Rubernetes::Generated::IoK8sApiCoreV1ConfigMap
      invalid = config_map.definition.validator.errors(
        "data" => {"key" => 1},
        "metadata" => {"name" => 1}
      )
      recursive = config_map.definition.validator.valid?(
        {"metadata" => {"name" => "root", "owner" => {"name" => "child"}}},
        unknown_fields: :reject
      )
      constraints = config_map.definition.validator.errors(
        "metadata" => {"name" => "root"},
        "count" => 8,
        "mode" => "other",
        "names" => [1]
      ).group_by { |issue| issue.path.first }.transform_values { |issues| issues.map { |issue| issue.code.to_s }.uniq.sort }
      defaulted = config_map.definition.defaulting.apply_hash("metadata" => {"name" => "root"})
      nullable_and_preserved = config_map.definition.validator.valid?(
        {"metadata" => {"name" => "root"}, "count" => nil, "raw" => {"future" => {"value" => 1}}},
        unknown_fields: :reject
      )
      puts JSON.generate(
        "definition_count" => definitions.length,
        "definitions_frozen" => definitions.all?(&:frozen?),
        "invalid_paths" => invalid.map(&:path).sort,
        "recursive_reference_valid" => recursive,
        "default_count" => defaulted.fetch("count"),
        "constraint_codes" => constraints,
        "nullable_and_preserved_valid" => nullable_and_preserved
      )
    RUBY
    run_generated_inspector(output, script)
  end

  def inspect_canonical_generated(output)
    script = <<~RUBY
      require "json"
      require File.expand_path(ARGV.fetch(0))
      constants = Rubernetes::Generated::SCHEMA_CONSTANTS.values
      definitions = constants.map { |name| Rubernetes::Generated.const_get(name, false)::DEFINITION }
      pod = Rubernetes::Generated::IoK8sApiCoreV1Pod
      config_map = Rubernetes::Generated::IoK8sApiCoreV1ConfigMap
      crd = Rubernetes::Generated::IoK8sApiextensionsApiserverPkgApisApiextensionsV1CustomResourceDefinition
      containers = pod.definition.field("spec").type.resolve.field("containers")
      managed_fields = Rubernetes::Generated.definition_for("io.k8s.apimachinery.pkg.apis.meta.v1.ManagedFieldsEntry")
      resources = Rubernetes::Generated.definition_for("io.k8s.api.core.v1.ResourceRequirements")
      http_get = Rubernetes::Generated.definition_for("io.k8s.api.core.v1.HTTPGetAction")
      time = managed_fields.field("time")
      quantity = resources.field("limits").additional_properties
      int_or_string = http_get.field("port")
      invalid_paths = {
        "pod" => pod.definition.validator.errors({"spec" => {"containers" => [{"name" => 1}]}}).map(&:path),
        "config_map" => config_map.definition.validator.errors({"data" => {"key" => 1}}).map(&:path),
        "crd" => crd.definition.validator.errors(
          {"spec" => {"group" => 1, "names" => {"kind" => "Example", "plural" => "examples"}, "scope" => "Namespaced", "versions" => []}}
        ).map(&:path)
      }
      puts JSON.generate(
        "definition_count" => definitions.length,
        "definitions_frozen" => definitions.all? { |definition| definition.frozen? && definition.fields.frozen? },
        "pod_spec_type" => pod.definition.field("spec").type.class.name,
        "pod_container_item_type" => containers.items.type.class.name,
        "config_map_value_type" => config_map.definition.field("data").additional_properties.type.to_s,
        "pod_container_list_type" => containers.metadata.fetch(:x_kubernetes_list_type),
        "pod_container_patch_merge_key" => containers.metadata.fetch(:x_kubernetes_patch_merge_key),
        "scalar_references" => {
          "time" => {"type" => time.type.to_s, "format" => time.metadata.fetch(:format)},
          "quantity" => {"type" => quantity.type.to_s, "format" => quantity.metadata[:format]},
          "int_or_string" => {"type" => int_or_string.type.to_s, "format" => int_or_string.metadata.fetch(:format)}
        },
        "scalar_reference_values_valid" => (
          managed_fields.validator.valid?({"time" => "2026-08-22T00:00:00Z"}) &&
          resources.validator.valid?({"limits" => {"cpu" => "100m"}}) &&
          http_get.validator.valid?({"port" => 8080}) &&
          http_get.validator.valid?({"port" => "http"})
        ),
        "invalid_paths" => invalid_paths.transform_values(&:sort)
      )
    RUBY
    run_generated_inspector(output, script)
  end

  def run_generated_inspector(output, script)
    source = File.join(output, "ruby/kubernetes_types.rb")
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, "-I#{File.join(ROOT, "lib")}", "-e", script, source, chdir: ROOT)

    assert_predicate(status, :success?, stderr)
    JSON.parse(stdout)
  end

  def tree(directory)
    Dir.glob(File.join(directory, "**/*")).select { |path| File.file?(path) }.sort.to_h do |path|
      [path.delete_prefix("#{directory}/"), File.binread(path)]
    end
  end
end
