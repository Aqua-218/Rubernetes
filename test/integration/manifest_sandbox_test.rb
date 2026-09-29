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

      resources = sandbox.compile(
        manifest_path,
        allow_code: true,
        environment: ["VISIBLE"],
        env: {"VISIBLE" => "allowed", "SECRET" => "hidden"}
      )

      assert_equal("allowed", resources.fetch(0).dig("data", "VISIBLE"))
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
