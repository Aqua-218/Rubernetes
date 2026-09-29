# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# The resourceVersion semantics table: for a WATCH, an unset or zero
# resourceVersion is "Get State and Start at Any" -- the server replays the
# current state as synthetic ADDED events and only then streams changes.  Ours
# started at the current revision and sent nothing, so a client that opened a
# watch right after creating an object waited out its whole timeout.  That is
# exactly how the conformance lifecycle specs are written, and
# "[sig-auth] ServiceAccounts should run through the lifecycle of a
# ServiceAccount" failed with "failed to find ADDED event".
class APIWatchInitialStateTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @server = API::Server.new(registry: API::Registry.new,
                              store: API::MemoryStore.new,
                              namespace_lifecycle: true)
    call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "dev"}})
  end

  def call(method, path, body = nil)
    @server.call(API::Request.new(method: method, path: path, body: body))
  end

  def create_configmap(name, labels = {})
    call("POST", "/api/v1/namespaces/dev/configmaps",
         {"metadata" => {"name" => name, "labels" => labels}, "data" => {"k" => "v"}})
  end

  def watch_events(query)
    response = call("GET", "/api/v1/namespaces/dev/configmaps?#{query}")
    body = response.body
    stream = body.respond_to?(:to_a) ? body.to_a : Array(body)
    stream.map { |event| [event["type"] || event[:type], (event["object"] || event[:object]).dig("metadata", "name")] }
  end

  def test_a_watch_without_a_resource_version_replays_the_current_state
    create_configmap("already-here")

    events = watch_events("watch=true&timeoutSeconds=0")

    assert_includes(events, ["ADDED", "already-here"])
  end

  def test_a_watch_at_resource_version_zero_replays_the_current_state
    create_configmap("already-here")

    events = watch_events("watch=true&resourceVersion=0&timeoutSeconds=0")

    assert_includes(events, ["ADDED", "already-here"])
  end

  def test_the_replayed_state_honours_the_label_selector
    create_configmap("selected", "team" => "blue")
    create_configmap("ignored", "team" => "green")

    events = watch_events("watch=true&labelSelector=team%3Dblue&timeoutSeconds=0")

    assert_equal([["ADDED", "selected"]], events)
  end

  def test_a_watch_at_an_explicit_resource_version_replays_nothing
    created = create_configmap("already-here")
    version = created.body.dig("metadata", "resourceVersion")

    events = watch_events("watch=true&resourceVersion=#{version}&timeoutSeconds=0")

    assert_empty(events)
  end
end
