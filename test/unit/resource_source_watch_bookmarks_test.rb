# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"
require "rubernetes/api"
require "rubernetes/storage/memory_store"

# A watch that never sees an event resumes with a version the store has
# compacted and is answered 410.  Asking for bookmarks keeps the version fresh.
class ResourceSourceWatchBookmarksTest < Minitest::Test
  class RecordingClient
    attr_reader :queries

    def initialize = @queries = []

    def watch_each(_resource, namespace: nil, api_version: nil, query: {})
      @queries << query
      [].each
    end
  end

  def test_the_source_asks_for_watch_bookmarks
    client = RecordingClient.new
    source = Rubernetes::Bootstrap::KubernetesResourceSource.new(client: client, resource: "Pod")

    source.watch(resource_version: "12", timeout_seconds: 300)

    assert_equal "true", client.queries.fetch(0)["allowWatchBookmarks"]
    assert_equal "12", client.queries.fetch(0)["resourceVersion"]
  end

  def test_the_api_server_streams_a_periodic_bookmark_to_a_watch_that_asks
    now = Time.at(1_000_000).utc
    clock = -> { now }
    store = Rubernetes::Storage::MemoryStore.new(clock: clock, bookmark_interval: 0.05)
    server = Rubernetes::API::Server.new(store: store)
    server.call(method: "POST", path: "/api/v1/namespaces/dev/configmaps", body: {"metadata" => {"name" => "a"}})
    version = server.call(method: "GET", path: "/api/v1/namespaces/dev/configmaps").body.dig("metadata", "resourceVersion")
    watch = server.call(method: "GET", path: "/api/v1/namespaces/dev/configmaps",
                        query: {"watch" => "true", "resourceVersion" => version, "allowWatchBookmarks" => "true",
                                "timeoutSeconds" => "1"}).body

    now += 1
    events = watch.first(1)

    assert_equal "BOOKMARK", events.fetch(0).type.to_s
    assert_equal version, events.fetch(0).object.dig("metadata", "resourceVersion")
  ensure
    watch&.close
  end
end
