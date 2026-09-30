# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/client"
require "rubernetes/storage/memory_store"

class M1APIClientRegressionTest < Minitest::Test
  Response = Rubernetes::Client::HTTPClient::Response

  def test_apply_rejects_body_gvk_mismatch_with_structured_causes
    server = Rubernetes::API::Server.new
    response = server.call(
      method: "PATCH",
      path: "/api/v1/namespaces/dev/configmaps/settings",
      body: {"apiVersion" => "apps/v1", "kind" => "Deployment",
             "metadata" => {"name" => "settings"}},
      query: {"fieldManager" => "regression"},
      headers: {"Content-Type" => "application/apply-patch+yaml"}
    )

    assert_equal 422, response.status
    assert_equal "Invalid", response.body["reason"]
    assert_equal(%w[apiVersion kind], response.body.dig("details", "causes").map { |cause| cause["field"] })
  end

  def test_generate_name_retries_a_collision
    suffixes = %w[aaaaa bbbbb].each
    server = Rubernetes::API::Server.new(name_generator: ->(_prefix) { suffixes.next })
    server.call(method: "POST", path: "/api/v1/namespaces/dev/configmaps",
                body: {"metadata" => {"name" => "job-aaaaa"}})

    response = server.call(method: "POST", path: "/api/v1/namespaces/dev/configmaps",
                           body: {"metadata" => {"generateName" => "job-"}})

    assert_equal 201, response.status
    assert_equal "job-bbbbb", response.body.dig("metadata", "name")
  end

  def test_list_limit_zero_is_unbounded_and_remaining_item_count_is_preserved
    store = Rubernetes::Storage::MemoryStore.new
    server = Rubernetes::API::Server.new(store: store)
    3.times do |index|
      server.call(method: "POST", path: "/api/v1/namespaces/dev/configmaps",
                  body: {"metadata" => {"name" => index.to_s}})
    end

    page = server.call(method: "GET", path: "/api/v1/namespaces/dev/configmaps",
                       query: {"limit" => "1"})
    unbounded = server.call(method: "GET", path: "/api/v1/namespaces/dev/configmaps",
                            query: {"limit" => "0", "resourceVersion" => "0",
                                    "resourceVersionMatch" => "NotOlderThan"})

    assert_equal 2, page.body.dig("metadata", "remainingItemCount")
    assert_equal 3, unbounded.body["items"].length
    refute unbounded.body["metadata"].key?("remainingItemCount")
  end

  def test_production_storage_rejects_malformed_selectors_as_bad_request
    server = Rubernetes::API::Server.new(store: Rubernetes::Storage::MemoryStore.new)

    response = server.call(method: "GET", path: "/api/v1/namespaces/dev/configmaps",
                           query: {"labelSelector" => "="})

    assert_equal 400, response.status
    assert_equal "BadRequest", response.body["reason"]
    assert_equal "labelSelector", response.body.dig("details", "causes", 0, "field")
  end

  # sendInitialEvents replays the state once and closes it with a bookmark; a
  # watch opened at the CURRENT revision has nothing to replay and must honour
  # its timeout rather than block.  (A watch with no resourceVersion at all
  # replays the current state -- see APIWatchInitialStateTest.)
  def test_watch_list_replays_state_once_and_a_current_watch_honors_its_timeout
    store = Rubernetes::API::MemoryStore.new
    server = Rubernetes::API::Server.new(store: store)
    server.call(method: "POST", path: "/api/v1/namespaces/dev/configmaps",
                body: {"metadata" => {"name" => "initial"}})
    response = server.call(
      method: "GET",
      path: "/api/v1/namespaces/dev/configmaps",
      query: {"watch" => "true", "sendInitialEvents" => "true",
              "resourceVersionMatch" => "NotOlderThan", "allowWatchBookmarks" => "true",
              "timeoutSeconds" => "1"}
    )

    assert_equal %w[ADDED BOOKMARK], response.body.to_a.map(&:type)
    watcher = store.watch("registry/v1/configmaps/dev", resource_version: store.resource_version,
                                                        timeout_seconds: 0.01)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    assert_nil watcher.next
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :>=, 0.005
  ensure
    watcher&.close
    response&.body&.close
  end

  def test_watch_list_not_older_than_restarts_after_compaction
    store = Rubernetes::Storage::MemoryStore.new(history_revisions: 1, history_seconds: nil)
    server = Rubernetes::API::Server.new(store: store)
    2.times do |index|
      server.call(method: "POST", path: "/api/v1/namespaces/dev/configmaps",
                  body: {"metadata" => {"name" => index.to_s}})
    end

    assert_operator store.compacted_revision, :>, 0

    response = server.call(
      method: "GET",
      path: "/api/v1/namespaces/dev/configmaps",
      query: {"watch" => "true", "sendInitialEvents" => "true",
              "resourceVersion" => "0", "resourceVersionMatch" => "NotOlderThan",
              "allowWatchBookmarks" => "true"}
    )

    assert_equal 200, response.status
    assert_equal %w[ADDED ADDED BOOKMARK], response.body.to_a.map(&:type)
  ensure
    response&.body&.close
  end

  def test_discovery_resolves_irregular_plural_cluster_scope_and_subresource_verbs
    rest = DiscoveryRest.new
    client = Rubernetes::Client::KubernetesClient.new(rest_client: rest, context: {namespace: "dev"})

    client.get("Person", "alice", api_version: "example.test/v1")
    client.patch("people", {"metadata" => {"labels" => {"x" => "y"}}},
                 api_version: "example.test/v1", name: "alice", subresource: "status")

    assert_equal "/apis/example.test/v1/people/alice", rest.calls[4][:path]
    assert_equal "/apis/example.test/v1/people/alice/status", rest.calls[5][:path]
    assert_raises(Rubernetes::Client::UsageError) do
      client.create({"apiVersion" => "example.test/v1", "kind" => "Person",
                     "metadata" => {"name" => "blocked"}})
    end
  end

  def test_scale_discovery_keeps_cross_group_identity_and_client_routes_alias
    resource = Rubernetes::API::Resource.new(
      group: "apps", version: "v1", resource: "deployments", kind: "Deployment",
      scope: :namespaced, subresources: [{resource: "scale", kind: "Scale", verbs: %w[get patch update]}]
    )
    server = Rubernetes::API::Server.new(
      registry: Rubernetes::API::Registry.new(resources: [resource], defaults: false)
    )
    discovery = server.call(method: "GET", path: "/apis/apps/v1")
    scale = discovery.body.fetch("resources").find { |entry| entry.fetch("name") == "deployments/scale" }

    assert_equal "autoscaling", scale.fetch("group")
    assert_equal "v1", scale.fetch("version")
    assert_equal "Scale", scale.fetch("kind")

    route = server.router.route("/apis/autoscaling/v1/namespaces/dev/deployments/demo/scale")

    assert_equal :resource, route.kind
    assert_equal resource, route.resource
    assert_equal "scale", route.subresource

    rest = ScaleAliasDiscoveryRest.new
    client = Rubernetes::Client::KubernetesClient.new(rest_client: rest, context: {namespace: "dev"})
    client.patch("deployments/scale", {"spec" => {"replicas" => 2}},
                 api_version: "autoscaling/v1", name: "demo")

    assert_equal "/apis/autoscaling/v1/namespaces/dev/deployments/demo/scale", rest.calls.last[:path]
  end

  def test_watch_reconnects_from_last_bookmark_after_disconnect
    rest = ReconnectingRest.new
    client = Rubernetes::Client::KubernetesClient.new(rest_client: rest, context: {namespace: "dev"})

    events = client.watch_each("pods", max_reconnects: 1).to_a

    assert_equal(%w[ADDED BOOKMARK], events.map { |event| event["type"] })
    assert_equal "1", rest.queries[1]["resourceVersion"]
  end

  def test_storage_watch_overflow_becomes_expired_status
    store = Rubernetes::Storage::MemoryStore.new(watcher_buffer_size: 1)
    server = Rubernetes::API::Server.new(store: store)
    watch = server.call(method: "GET", path: "/api/v1/namespaces/dev/configmaps",
                        query: {"watch" => "true", "resourceVersion" => "0"}).body
    2.times do |index|
      server.call(method: "POST", path: "/api/v1/namespaces/dev/configmaps",
                  body: {"metadata" => {"name" => index.to_s}})
    end

    error = assert_raises(Rubernetes::API::Status::Expired) { watch.to_a }
    assert_equal 410, error.code
    assert_equal "WatchOverflow", error.details.dig("causes", 0, "reason")
  ensure
    watch&.close
  end

  class DiscoveryRest
    attr_reader :calls

    def initialize
      @calls = []
    end

    def request(method, path, body:, headers:, query:)
      @calls << {method: method, path: path, body: body, headers: headers, query: query}
      payload = case path
                when "/api" then {"versions" => ["v1"]}
                when "/api/v1" then {"resources" => []}
                when "/apis"
                  {"groups" => [{"name" => "example.test",
                                 "versions" => [{"groupVersion" => "example.test/v1", "version" => "v1"}],
                                 "preferredVersion" => {"groupVersion" => "example.test/v1", "version" => "v1"}}]}
                when "/apis/example.test/v1"
                  {"resources" => [
                    {"name" => "people", "namespaced" => false, "kind" => "Person",
                     "verbs" => %w[get list watch patch delete]},
                    {"name" => "people/status", "namespaced" => false, "kind" => "Person",
                     "verbs" => %w[get patch]}
                  ]}
                else
                  {"apiVersion" => "example.test/v1", "kind" => "Person", "metadata" => {"name" => "alice"}}
                end
      Response.new(status: 200, headers: {"content-type" => "application/json"}, body: JSON.generate(payload))
    end
  end

  class ReconnectingRest
    attr_reader :queries

    def initialize
      @attempt = 0
      @queries = []
    end

    def stream(_method, _path, query:)
      @queries << query
      @attempt += 1
      if @attempt == 1
        return Enumerator.new do |output|
          output << "#{JSON.generate("type" => "ADDED", "object" => {"metadata" => {"resourceVersion" => "1"}})}\n"
          raise EOFError, "simulated disconnect"
        end
      end

      Enumerator.new do |output|
        output << "#{JSON.generate("type" => "BOOKMARK", "object" => {"metadata" => {"resourceVersion" => "2"}})}\n"
      end
    end
  end

  class ScaleAliasDiscoveryRest
    attr_reader :calls

    def initialize
      @calls = []
    end

    def request(method, path, body:, headers:, query:)
      @calls << {method: method, path: path, body: body, headers: headers, query: query}
      payload = case path
                when "/api" then {"versions" => ["v1"]}
                when "/api/v1" then {"resources" => []}
                when "/apis"
                  {"groups" => [{"name" => "apps",
                                 "versions" => [{"groupVersion" => "apps/v1", "version" => "v1"}],
                                 "preferredVersion" => {"groupVersion" => "apps/v1", "version" => "v1"}}]}
                when "/apis/apps/v1"
                  {"resources" => [
                    {"name" => "deployments", "namespaced" => true, "kind" => "Deployment",
                     "verbs" => %w[get list watch patch delete]},
                    {"name" => "deployments/scale", "namespaced" => true, "kind" => "Scale",
                     "group" => "autoscaling", "version" => "v1", "verbs" => %w[get patch update]}
                  ]}
                else
                  {"apiVersion" => "autoscaling/v1", "kind" => "Scale",
                   "metadata" => {"name" => "demo"}, "spec" => {"replicas" => 2}}
                end
      Response.new(status: 200, headers: {"content-type" => "application/json"}, body: JSON.generate(payload))
    end
  end
end
