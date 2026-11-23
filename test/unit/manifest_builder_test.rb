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

  def test_deferred_checks_can_inspect_later_resources_and_keep_rendered_output_clean
    builder = Rubernetes::Manifest::Builder.new(registry: registry, definitions: definitions)
    result = builder.evaluate(<<~RUBY, "config.rb")
      check "both environments are configured" do |resources|
        resources.frozen? && resources.map { |item| item.dig("metadata", "name") }.sort == %w[dev prod]
      end
      %w[prod dev].each { |name| config_map(name) {} }
    RUBY

    assert_equal(%w[prod dev], result.map { |object| object.dig("metadata", "name") })
    assert_equal [4, 4], builder.declaration_lines
  end

  def test_failed_checks_name_the_ruby_line_and_do_not_leak_values_or_run_in_the_next_file
    builder = Rubernetes::Manifest::Builder.new(registry: registry, definitions: definitions)
    failed = assert_raises(Rubernetes::Manifest::Error) { builder.evaluate("\ncheck('replica minimum') { false }", "rules.rb") }

    assert_equal "rules.rb:2: check failed: replica minimum", failed.message
    raised = assert_raises(Rubernetes::Manifest::Error) { builder.evaluate("check('config keys') { raise 'private-value' }", "keys.rb") }

    assert_equal 'keys.rb:1: check "config keys" raised RuntimeError', raised.message
    assert_empty builder.evaluate("", "next.rb")
  end

  def test_reusing_a_builder_after_a_failed_check_keeps_only_accepted_resources
    builder = Rubernetes::Manifest::Builder.new(registry: registry, definitions: definitions)
    accepted = builder.evaluate("config_map('accepted') {}", "good.rb")

    assert_raises(Rubernetes::Manifest::Error) do
      builder.evaluate("config_map('rejected') {}\ncheck('limit') { false }", "bad.rb")
    end

    assert_equal(["accepted"], accepted.map { |object| object.dig("metadata", "name") })
    assert_equal [1], builder.declaration_lines
    assert_equal(%w[accepted next], builder.evaluate("config_map('next') {}", "next.rb").map { |object| object.dig("metadata", "name") })
  end

  def test_unknown_fields_cannot_fall_through_method_missing
    builder = Rubernetes::Manifest::Builder.new(registry: registry, definitions: definitions)

    assert_raises(NoMethodError) do
      builder.config_map("settings") { invented_field "value" }
    end
  end

  def test_declaration_lines_follow_objects_created_from_helpers
    builder = Rubernetes::Manifest::Builder.new(registry: registry, definitions: definitions)
    objects = builder.evaluate(<<~RUBY, "fixture.rb")
      def app_settings(name)
        config_map(name) { data KEY: "value" }
      end
      app_settings("from-helper")
      resource(api_version: "v1", kind: "ConfigMap", name: "direct")
      result.reverse!
    RUBY

    assert_equal(%w[direct from-helper], objects.map { |object| object.dig("metadata", "name") })
    assert_equal [5, 2], builder.declaration_lines
  end

  def test_namespace_block_restores_the_previous_namespace_after_errors_and_nonlocal_exit
    builder = Rubernetes::Manifest::Builder.new(registry: registry, definitions: definitions)
    objects = builder.evaluate(<<~RUBY, "fixture.rb")
      in_namespace "preview" do
        begin
          in_namespace "staging" do
            config_map("before-error")
            config_map("broken") { unknown_field "value" }
          end
        rescue NoMethodError
          config_map("after-error")
        end
        catch(:leave) { in_namespace("staging") { throw :leave } }
        config_map("after-throw")
      end
      config_map("outside")
    RUBY

    assert_equal(["staging", "preview", "preview", nil], objects.map { |object| object.dig("metadata", "namespace") })
  end

  def test_namespace_block_rejects_invalid_dns_labels_at_the_source_line
    builder = Rubernetes::Manifest::Builder.new(registry: registry, definitions: definitions)
    error = assert_raises(Rubernetes::Manifest::Error) do
      builder.evaluate("\nin_namespace('bad.name') {}", "fixture.rb")
    end

    assert_includes error.message, 'fixture.rb:2: invalid namespace "bad.name": a lowercase RFC 1123 label'
    too_long = assert_raises(Rubernetes::Manifest::Error) do
      builder.in_namespace("x" * 64) { flunk "an invalid namespace must not yield" }
    end

    assert_includes too_long.message, "must be no more than 63 characters"
  end

  private

  def registry
    {
      "types" => [{
        "schema" => "io.k8s.api.core.v1.ConfigMap",
        "gvks" => [{"group" => "", "version" => "v1", "kind" => "ConfigMap"}]
      }],
      "resources" => [{"group" => "", "version" => "v1", "resource" => "configmaps", "kind" => "ConfigMap", "scope" => "Namespaced"}]
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
