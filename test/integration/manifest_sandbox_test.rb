# frozen_string_literal: true

require "json"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/manifest"

class ManifestSandboxTest < Minitest::Test
  def test_manifest_runs_without_parent_environment_or_network_namespace
    Dir.mktmpdir("rubernetes-manifest-") do |directory|
      registry_path, openapi_path = write_schema(directory)
      manifest_path = File.join(directory, "app.rb")
      File.write(manifest_path, <<~RUBY)
        config_map "settings", namespace: "demo" do
          data "VISIBLE" => ENV.fetch("VISIBLE")
        end
      RUBY
      sandbox = Rubernetes::Manifest::Sandbox.new(
        registry_path: registry_path,
        openapi_path: openapi_path
      )

      declarations = nil
      resources = sandbox.compile(
        manifest_path,
        allow_code: true,
        environment: ["VISIBLE"],
        env: {"VISIBLE" => "allowed", "SECRET" => "hidden"}
      ) { |lines| declarations = lines }

      assert_equal("allowed", resources.fetch(0).dig("data", "VISIBLE"))
      assert_equal([1], declarations)
    end
  end

  def test_compiler_errors_name_the_original_manifest_and_line
    Dir.mktmpdir do |directory|
      registry_path, openapi_path = write_schema(directory)
      path = File.join(directory, "service_ports.rb")
      sandbox = Rubernetes::Manifest::Sandbox.new(registry_path: registry_path, openapi_path: openapi_path)
      ["config_map \"ok\"\nno_such_resource \"x\"\n", "config_map \"ok\"\n)\n"].each do |bad_source|
        File.write(path, bad_source)
        error = assert_raises(Rubernetes::Manifest::Error) { sandbox.compile(path, allow_code: true) }
        assert_includes error.message, "service_ports.rb:2:"
      end
    end
  end

  def test_slow_manifest_returns_a_single_timeout_error
    Dir.mktmpdir do |directory|
      registry_path, openapi_path = write_schema(directory)
      path = File.join(directory, "slow.rb")
      File.write(path, "sleep 2")
      sandbox = Rubernetes::Manifest::Sandbox.new(registry_path: registry_path, openapi_path: openapi_path, timeout: 0.25)

      _, stderr = capture_subprocess_io do
        error = assert_raises(Rubernetes::Manifest::Error) { sandbox.compile(path, allow_code: true) }
        assert_equal "manifest sandbox exceeded 0.25 seconds", error.message
      end

      assert_empty stderr
    end
  end

  def test_manifest_requires_explicit_code_permission
    Dir.mktmpdir("rubernetes-manifest-") do |directory|
      registry_path, openapi_path = write_schema(directory)
      manifest_path = File.join(directory, "app.rb")
      File.write(manifest_path, "config_map \"settings\"\n")
      sandbox = Rubernetes::Manifest::Sandbox.new(registry_path: registry_path, openapi_path: openapi_path)

      error = assert_raises(Rubernetes::Manifest::Error) do
        sandbox.compile(manifest_path, allow_code: false)
      end
      assert_match(/--allow-code/, error.message)
    end
  end

  private

  def write_schema(directory)
    registry_path = File.join(directory, "registry.json")
    openapi_path = File.join(directory, "openapi.json")
    registry = {
      "types" => [{
        "schema" => "io.k8s.api.core.v1.ConfigMap",
        "gvks" => [{"group" => "", "version" => "v1", "kind" => "ConfigMap"}]
      }],
      "resources" => [{"group" => "", "version" => "v1", "resource" => "configmaps", "kind" => "ConfigMap"}]
    }
    definitions = {
      "io.k8s.api.core.v1.ConfigMap" => {
        "type" => "object",
        "properties" => {
          "apiVersion" => {"type" => "string"}, "kind" => {"type" => "string"},
          "metadata" => {"type" => "object"},
          "data" => {"type" => "object", "additionalProperties" => {"type" => "string"}}
        }
      }
    }
    File.write(registry_path, JSON.generate(registry))
    File.write(openapi_path, JSON.generate("definitions" => definitions))
    [registry_path, openapi_path]
  end
end
