# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/extension"

# An extension is a Ruby file.  Loading it must tell its author exactly what
# it declared or exactly where it went wrong, and must leave nothing of it in
# the process that loaded it except what it declared.
class ExtensionDefinitionTest < Minitest::Test
  E = Rubernetes::Extension
  Node = Struct.new(:labels)

  def compile(source, name: "demo")
    E::Definition.compile(name, source)
  end

  def error_of(source)
    assert_raises(E::CompileError) { compile(source) }
  end

  def test_each_declaration_is_listed_in_the_order_of_its_kind
    compiled = compile(<<~RUBY)
      controller("mirror", watch: "configmaps") { |_object, _api| nil }
      validate("pods") { |_request| nil }
      mutate("pods", "deployments.apps", on: :create) { |_request| nil }
      score("PreferSsd", weight: 3) { |_pod, _node| 100 }
      filter("NoGpu") { |_pod, _node| true }
    RUBY

    assert_equal %w[score:PreferSsd filter:NoGpu validate:pods mutate:pods-deployments-apps controller:mirror], compiled.provides
    assert_equal 3, compiled.scheduler_plugins.first.weight
    assert_equal %i[create], compiled.admission_hooks.last.operations
    assert_equal %i[create update], compiled.admission_hooks.first.operations
  end

  def test_a_helper_method_is_visible_in_every_block_of_its_extension_only
    compiled = compile(<<~RUBY)
      FAST = "ssd"
      def fast?(node) = node.labels["disk"] == FAST
      score("PreferSsd") { |_pod, node| fast?(node) ? 100 : 0 }
    RUBY

    assert_equal 100, compiled.scheduler_plugins.first.block.call(nil, Node.new({"disk" => "ssd"}))
    refute Object.private_method_defined?(:fast?), "the helper leaked into every object"
    refute Object.const_defined?(:FAST), "the constant leaked into the process"
    refute_respond_to E::Definition.new("other"), :fast?
  end

  def test_a_syntax_error_names_its_line_and_what_the_parser_expected
    error = error_of("x = 1\nfilter \"A\" do\n")

    assert_equal 2, error.line
    assert_match(/\Aline 2: syntax error: /, error.message)
  end

  def test_an_exception_while_loading_names_the_line_of_the_source
    error = error_of("x = 1\n\nundefined_thing!\n")

    assert_equal 3, error.line
    assert_match(/NoMethodError: undefined method 'undefined_thing!'/, error.message)
  end

  def test_declarations_are_checked_when_the_file_is_loaded
    assert_match(/invalid name "bad name"/, error_of('filter("bad name") { true }').message)
    assert_match(/score weight must be a positive Integer/, error_of('score("A", weight: 0) { 1 }').message)
    assert_match(/unknown admission operation :explode/, error_of('validate("pods", on: :explode) { }').message)
    assert_match(/validate needs at least one resource/, error_of("validate { }").message)
    assert_match(/filter needs a block/, error_of('filter("A")').message)
  end

  def test_a_source_that_never_finishes_loading_is_given_up_on
    error = assert_raises(E::CompileError) { E::Definition.compile("demo", "loop { }", timeout: 0.2) }

    assert_match(/loading took longer than/, error.message)
  end

  def test_the_manifest_is_the_object_kubectl_applies
    manifest = E.manifest("team-rules", "filter(\"A\") { true }")

    assert_equal "rubernetes.io/v1alpha1", manifest.fetch("apiVersion")
    assert_equal "Extension", manifest.fetch("kind")
    assert_equal "extensions.rubernetes.io", E::CRD.dig("metadata", "name")
    assert_equal "Cluster", E::CRD.dig("spec", "scope")
  end
end
