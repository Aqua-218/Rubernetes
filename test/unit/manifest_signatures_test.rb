# frozen_string_literal: true

require_relative "../test_helper"
require "rbs"
require "rubernetes/manifest"

class ManifestSignaturesTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)

  def setup
    path = File.join(ROOT, "sig/rubernetes/manifest_resources.rbs")
    buffer = RBS::Buffer.new(name: path, content: File.read(path))
    manifest = RBS::Parser.parse_signature(buffer).last.first.members.first
    @declarations = manifest.members.to_h { |entry| [entry.name.to_s, entry] }
    @resources = @declarations.fetch("Builder").members.to_h { |method| [method.name, method] }
  end

  def test_every_short_and_qualified_constructor_is_discoverable
    live = Rubernetes::Manifest::Builder.load(registry_path: File.join(ROOT, "generated/schema/registry.json"),
                                              openapi_path: File.join(ROOT, "generated/openapi/v2.json"))

    assert_equal live.singleton_methods.sort, @resources.keys.sort
    assert_equal receiver(:deployment), receiver(:apps_v1_deployment)
    assert_includes receiver(:deployment), "_PodTemplateDSL"
    refute_includes receiver(:service), "_PodTemplateDSL"
    assert_includes receiver(:stateful_set), "_ClaimTemplateDSL"
    refute_includes receiver(:deployment), "_ClaimTemplateDSL"
    assert_includes receiver(:pod), "_RawImagePullSecretsDSL"
    refute_includes receiver(:deployment), "_RawImagePullSecretsDSL"
  end

  def test_deployment_shortcuts_and_nested_spec_use_the_same_field_type
    fields = @declarations.fetch("_DeploymentFields").members.grep(RBS::AST::Members::MethodDefinition)
    spec = fields.find { |method| method.name == :spec }
    nested = spec.overloads.filter_map { |overload| overload.method_type.block&.self_type }
    spec_fields = @declarations.fetch("_DeploymentSpecFields").members.grep(RBS::AST::Members::MethodDefinition)

    assert_equal ["ObjectBuilder & _DeploymentSpecFields"], nested.map(&:to_s)
    [fields, spec_fields].each do |methods|
      replicas = methods.find { |method| method.name == :replicas }
      argument = replicas.overloads.first.method_type.type.required_positionals.first

      assert_equal "Integer?", argument.type.to_s
    end
  end

  private

  def receiver(name)
    @resources.fetch(name).overloads.first.method_type.block.self_type.types.map(&:to_s)
  end
end
