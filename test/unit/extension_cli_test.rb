# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/rubectl"
require "rubernetes/extension/cli"
require "stringio"
require "tmpdir"

# `rubectl extension`: a Ruby file goes in, and what each component made of
# it comes back.
class ExtensionCLITest < Minitest::Test
  E = Rubernetes::Extension
  Response = Struct.new(:body)

  class FakeClient
    attr_reader :applied, :deleted
    attr_accessor :components

    def initialize
      @applied = []
      @deleted = []
      @components = {}
    end

    def apply(manifest, path:, field_manager:, force:)
      @applied << [manifest, path, field_manager, force]
      manifest.merge("metadata" => manifest.fetch("metadata").merge("generation" => 4))
    end

    def raw(method, path, **)
      @deleted << path if method == "DELETE"
      item = {"metadata" => {"name" => "team-rules"}, "status" => {"components" => @components}}
      Response.new(JSON.generate(path == E::PATH ? {"items" => [item]} : item))
    end
  end

  def setup
    @client = FakeClient.new
    @stdout = StringIO.new
    @stderr = StringIO.new
    @directory = Dir.mktmpdir
  end

  def teardown
    FileUtils.remove_entry(@directory)
  end

  def write(name, source)
    File.join(@directory, name).tap { |path| File.write(path, source) }
  end

  def rubectl(*arguments)
    cli = Rubernetes::Rubectl::CLI.new(stdout: @stdout, stderr: @stderr, client: @client)
    E::CLI.stub(:new, ->(**options) { E::CLI.allocate.tap { |object| object.send(:initialize, **options, sleeper: ->(_seconds) {}) } }) do
      cli.run(["extension", *arguments])
    end
  end

  def loaded(generation = 4) = {"loaded" => true, "observedGeneration" => generation, "provides" => %w[filter:A], "failures" => 0}

  def test_check_lists_what_a_file_declares_without_a_cluster
    path = write("team_rules.rb", 'filter("A") { true }')
    status = Rubernetes::Rubectl::CLI.new(stdout: @stdout, stderr: @stderr, client_factory: ->(_options) { flunk("no cluster is needed") })
      .run(["extension", "check", path])

    assert_equal 0, status
    assert_equal "team-rules: filter:A\n", @stdout.string
  end

  def test_apply_stores_the_file_under_its_name_and_reports_each_component
    @client.components = {"scheduler" => loaded, "admission" => {"loaded" => false, "observedGeneration" => 4, "message" => "line 3: boom"},
                          "controller" => loaded(3)}
    path = write("team_rules.rb", 'filter("A") { true }')

    assert_equal 0, rubectl("apply", path)
    manifest, api_path, = @client.applied.fetch(0)

    assert_equal "/apis/rubernetes.io/v1alpha1/extensions/team-rules", api_path
    assert_equal 'filter("A") { true }', manifest.dig("spec", "source")
    assert_match(/scheduler +loaded$/, @stdout.string)
    assert_match(/admission +FAILED: line 3: boom$/, @stdout.string)
    assert_match(/controller +no report/, @stdout.string, "a report for an older generation is not this version's")
  end

  # A typo must not replace the version that is running.
  def test_a_file_that_does_not_load_is_never_sent
    path = write("team_rules.rb", "filter(\"A\") do\n")

    assert_equal 64, rubectl("apply", path)
    assert_empty @client.applied
    assert_match(/team-rules: line 1: syntax error/, @stderr.string)
  end

  def test_list_shows_each_component_and_the_failures
    @client.components = {"scheduler" => loaded.merge("failures" => 2), "controller" => {"loaded" => false}}

    assert_equal 0, rubectl("list")
    assert_match(/^team-rules +loaded +- +failed +2 +filter:A$/, @stdout.string)
  end

  def test_delete_removes_the_named_extensions
    assert_equal 0, rubectl("delete", "team-rules", "other")
    assert_equal %w[/apis/rubernetes.io/v1alpha1/extensions/team-rules /apis/rubernetes.io/v1alpha1/extensions/other], @client.deleted
  end

  def test_an_unknown_subcommand_prints_the_usage
    assert_equal 64, rubectl("explode")
    assert_includes @stderr.string, "Usage: rubectl extension COMMAND"
    assert_equal 64, rubectl("apply")
  end
end
