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

  def test_preview_uses_real_filter_and_score_hooks_offline
    source = File.expand_path("../../examples/extensions/team_rules.rb", __dir__)
    batch = {"kind" => "Pod", "metadata" => {"name" => "crunch", "namespace" => "dev", "labels" => {"tier" => "batch"}},
             "spec" => {"nodeName" => "quiet"}}
    nodes = %w[quiet busy interactive].map do |name|
      {"kind" => "Node", "metadata" => {"name" => name, "labels" => {"workload" => name}}}
    end
    resident = {"kind" => "Pod", "metadata" => {"name" => "resident", "uid" => "resident"}, "spec" => {"nodeName" => "busy"}}
    file = write("cluster.json", JSON.generate({"kind" => "List", "items" => [batch, resident, *nodes]}))

    assert_equal 0, rubectl("preview", source, "dev/crunch", file), @stderr.string
    assert_includes @stdout.string, "2/3 nodes pass"
    assert_includes @stdout.string, "quiet  pass  +200"
    assert_includes @stdout.string, "busy  pass  +180"
    assert_includes @stdout.string, "interactive  rejected  team-rules.KeepBatchOffInteractive: node is reserved"
    assert_empty @client.applied

    previous = write("previous.rb", 'score("PreferQuietNodes", weight: 2) { 100 }')
    @stdout.truncate(0)
    @stdout.rewind

    assert_equal 0, rubectl("diff", previous, source, "dev/crunch", file), @stderr.string
    assert_includes @stdout.string, "2/3 nodes changed"
    assert_includes @stdout.string, "busy  pass +200 → pass +180"
    assert_includes @stdout.string, "interactive  pass +200 → rejected by team-rules.KeepBatchOffInteractive"
    refute_match(/^  quiet/, @stdout.string)
  end

  def test_diff_explains_scoring_changes_that_cancel_out
    old = write("earlier.rb", %(score("Capacity") { 70 }\nscore("Cost") { 30 }))
    edited = write("policy.rb", %(score("Capacity") { 60 }\nscore("Cost") { 40 }))
    items = [{"kind" => "Pod", "metadata" => {"name" => "app"}}, {"kind" => "Node", "metadata" => {"name" => "blue"}}]
    snapshot = write("snapshot.json", JSON.generate({"kind" => "List", "items" => items}))

    assert_equal 0, rubectl("diff", old, edited, "default/app", snapshot), @stderr.string
    assert_includes @stdout.string, "blue  pass +100 → pass +100"
    assert_includes @stdout.string, "policy.Capacity  70 × 1 → 60 × 1  (#{edited}:1)"
    assert_includes @stdout.string, "policy.Cost  30 × 1 → 40 × 1  (#{edited}:2)"
    assert_empty @client.applied
  end

  def test_diff_reports_the_broken_local_file_before_reading_the_cluster
    old = write("previous.rb", "score(\"bad\") {")
    current = write("current.rb", 'score("valid") { 100 }')

    assert_equal 64, rubectl("diff", old, current, "default/test")
    assert_includes @stderr.string, old
    assert_includes @stderr.string, "line 1"
  end

  def test_preview_reads_paginated_live_state_and_reports_plugin_errors
    path = write("broken.rb", 'filter("Broken") { raise "bad rule" }')
    calls = []
    @client.define_singleton_method(:get) do |resource, query:|
      calls << [resource, query]
      if resource.end_with?("/nodes")
        {"items" => [{"metadata" => {"name" => "worker"}}]}
      elsif query["continue"]
        {"items" => [{"metadata" => {"name" => "target"}}]}
      else
        {"items" => [], "metadata" => {"continue" => "next"}}
      end
    end

    assert_equal 64, rubectl("preview", path, "default/target")
    assert_match(/broken.Broken.*bad rule/, @stderr.string)
    assert_equal ["/api/v1/pods", "/api/v1/pods", "/api/v1/nodes"], calls.map(&:first)
    assert_equal "next", calls[1].last.fetch("continue")
    assert_empty @client.applied
  end
end
