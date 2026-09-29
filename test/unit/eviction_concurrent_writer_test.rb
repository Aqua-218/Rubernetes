# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/bootstrap"

# The eviction's own DisruptionTarget write is not a precondition on the
# delete that follows: a writer slipping in between (the node publishing
# status for the Pod it just saw change) must not fail the eviction.  A
# resourceVersion the caller pinned is still honoured.
class EvictionConcurrentWriterTest < Minitest::Test
  class RacingServer < Rubernetes::API::Server
    attr_accessor :race

    def mark_evicted(resource, namespace, name, existing)
      updated = super
      return updated unless @race

      copy = deep_copy(updated)
      copy["metadata"]["labels"] = {"touched" => "by-node"}
      @store.update(resource: resource, namespace: namespace, name: name, object: copy,
                    resource_version: metadata_value(updated, "resourceVersion"))
      updated
    end
  end

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = RacingServer.new(registry: registry, store: Rubernetes::Storage::MemoryStore.new, namespace_lifecycle: true)
    @server.call(method: "POST", path: "/api/v1/namespaces", body: {"metadata" => {"name" => "dev"}})
    @server.call(method: "POST", path: "/api/v1/namespaces/dev/pods",
                 body: {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p"},
                        "spec" => {"containers" => [{"name" => "c", "image" => "i"}]}})
  end

  def evict(body)
    @server.call(method: "POST", path: "/api/v1/namespaces/dev/pods/p/eviction", body: body)
  end

  def test_an_eviction_survives_a_writer_between_its_condition_update_and_its_delete
    @server.race = true

    response = evict({"apiVersion" => "policy/v1", "kind" => "Eviction", "metadata" => {"name" => "p", "namespace" => "dev"}})

    assert_equal 201, response.status, response.body.inspect
    assert_equal 404, @server.call(method: "GET", path: "/api/v1/namespaces/dev/pods/p").status
  end

  def test_a_stale_caller_resource_version_is_still_a_conflict
    response = evict({"apiVersion" => "policy/v1", "kind" => "Eviction", "metadata" => {"name" => "p", "namespace" => "dev"},
                      "deleteOptions" => {"preconditions" => {"resourceVersion" => "1"}}})

    assert_equal 409, response.status
    assert_equal 200, @server.call(method: "GET", path: "/api/v1/namespaces/dev/pods/p").status
  end

  def test_a_matching_caller_resource_version_evicts
    current = @server.call(method: "GET", path: "/api/v1/namespaces/dev/pods/p").body.dig("metadata", "resourceVersion")

    response = evict({"apiVersion" => "policy/v1", "kind" => "Eviction", "metadata" => {"name" => "p", "namespace" => "dev"},
                      "deleteOptions" => {"preconditions" => {"resourceVersion" => current}}})

    assert_equal 201, response.status, response.body.inspect
  end
end
