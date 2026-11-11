# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/extension/loader"

# What a component runs is what the API stores: a new version replaces the
# old one, a version that does not load takes the old one out, and each
# outcome is written back for whoever applied it.
class ExtensionLoaderTest < Minitest::Test
  E = Rubernetes::Extension

  def setup
    @published = []
    @statuses = []
    @now = Time.utc(2026, 11, 11, 15, 0, 0)
    @loader = E::Loader.new(component: "scheduler", on_change: ->(loaded) { @published << loaded.map(&:name) },
                            status_writer: ->(name, status) { @statuses << [name, status] }, clock: -> { @now })
  end

  def object(name, source, generation: 1, uid: "#{name}-uid")
    {"metadata" => {"name" => name, "uid" => uid, "generation" => generation}, "spec" => {"source" => source}}
  end

  FILTER = 'filter("A") { true }'

  def test_a_stored_extension_is_loaded_and_reported
    @loader.sync([object("one", FILTER)])

    assert_equal [%w[one]], @published
    name, status = @statuses.last

    assert_equal "one", name
    assert status.fetch("loaded")
    assert_equal 1, status.fetch("observedGeneration")
    assert_equal %w[filter:A], status.fetch("provides")
  end

  # Status writes come back as MODIFIED events with the same generation.
  def test_the_same_generation_is_not_loaded_twice
    @loader.sync([object("one", FILTER)])
    @loader.upsert(object("one", FILTER))
    @loader.sync([object("one", FILTER)])

    assert_equal 1, @published.length
    assert_equal 1, @statuses.length
  end

  def test_a_version_that_does_not_load_takes_the_working_one_out
    @loader.upsert(object("one", FILTER))
    @loader.upsert(object("one", "filter(\"A\") do\n", generation: 2))

    assert_equal [%w[one], []], @published
    assert_empty @loader.loaded
    status = @statuses.last.last

    refute status.fetch("loaded")
    assert_equal 2, status.fetch("observedGeneration")
    assert_match(/line 1: syntax error/, status.fetch("message"))
  end

  def test_an_object_recreated_under_the_same_name_is_a_new_extension
    @loader.upsert(object("one", FILTER))
    @loader.upsert(object("one", 'score("B") { 1 }', uid: "another"))

    assert_equal %w[score:B], @loader.loaded.first.provides
  end

  def test_what_is_no_longer_stored_is_no_longer_loaded
    @loader.sync([object("one", FILTER), object("two", FILTER)])
    @loader.sync([object("two", FILTER)])
    @loader.remove("two")
    @loader.remove("never-there")

    assert_equal [%w[one two], %w[two], []], @published
  end

  # A filter that raises does so for every Pod on every node.
  def test_failures_are_all_counted_but_reported_at_intervals
    @loader.upsert(object("one", FILTER))
    @statuses.clear
    3.times { @loader.failed("one", "filter:A", RuntimeError.new("boom")) }

    assert_equal 1, @statuses.length
    assert_equal 1, @statuses.last.last.fetch("failures")

    @now += E::Loader::FAILURE_REPORT_SECONDS
    @loader.failed("one", "filter:A", RuntimeError.new("boom again"))

    assert_equal 4, @statuses.last.last.fetch("failures")
    assert_equal "filter:A: RuntimeError: boom again", @statuses.last.last.fetch("lastFailure")
  end

  def test_a_status_that_cannot_be_written_does_not_unload_anything
    loader = E::Loader.new(component: "scheduler", on_change: ->(loaded) { @published << loaded.map(&:name) },
                           status_writer: ->(_name, _status) { raise IOError, "api server is away" })
    loader.upsert(object("one", FILTER))

    assert_equal [%w[one]], @published
  end

  class FakeClient
    attr_reader :requests

    def initialize
      @requests = []
    end

    def raw(method, path, body: nil, headers: {})
      @requests << [method, path, body && JSON.parse(body), headers]
    end
  end

  def test_the_default_status_writer_patches_only_its_own_component
    client = FakeClient.new
    E::Loader.new(component: "controller", on_change: ->(_loaded) {}, client: client).upsert(object("one", FILTER))
    method, path, body, headers = client.requests.fetch(0)

    assert_equal ["PATCH", "/apis/rubernetes.io/v1alpha1/extensions/one/status"], [method, path]
    assert_equal %w[controller], body.dig("status", "components").keys
    assert_equal "application/merge-patch+json", headers.fetch("Content-Type")
  end
end
