# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "rubernetes/api"
require "rubernetes/storage/memory_store"

# An update without a resourceVersion is retried against the fresh object when
# it loses a race (storage.Interface#GuaranteedUpdate); one that names a
# resourceVersion still gets the 409.
class APIUnconditionalUpdateRetryTest < Minitest::Test
  API = Rubernetes::API

  class RacingStore < SimpleDelegator
    attr_accessor :races

    def update(*, **keywords)
      if races.to_i.positive?
        self.races -= 1
        raise Rubernetes::Storage::MemoryStore::Conflict, "raced"
      end
      __getobj__.update(*, **keywords)
    end
  end

  def setup
    registry = API::Registry.new(resources: [], defaults: false)
    registry.register(API::Resource.new(group: "", version: "v1", resource: "namespaces", kind: "Namespace", scope: :cluster))
    registry.register(API::Resource.new(group: "", version: "v1", resource: "configmaps", kind: "ConfigMap", scope: :namespaced))
    @store = RacingStore.new(Rubernetes::Storage::MemoryStore.new)
    @server = API::Server.new(registry: registry, store: @store)
    call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "ns"}})

    status = call("POST", "/api/v1/namespaces/ns/configmaps",
                  {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "cm"}, "data" => {"a" => "1"}}).status
    raise "setup: configmap create returned #{status}" unless status == 201
  end

  def call(method, path, body)
    @server.call(API::Request.new(method: method, path: path, headers: {"content-type" => "application/json"},
                                  body: JSON.generate(body), identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def test_unconditional_update_survives_a_race
    @store.races = 2
    response = call("PUT", "/api/v1/namespaces/ns/configmaps/cm",
                    {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "cm"}, "data" => {"a" => "2"}})

    assert_equal 200, response.status, response.body.inspect
    assert_equal({"a" => "2"}, response.body["data"])
  end

  def test_conditional_update_still_conflicts
    @store.races = 1
    current = call("PUT", "/api/v1/namespaces/ns/configmaps/cm",
                   {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "cm"}, "data" => {"a" => "3"}}).body
    @store.races = 1
    response = call("PUT", "/api/v1/namespaces/ns/configmaps/cm", current.merge("data" => {"a" => "4"}))

    assert_equal 409, response.status, response.body.inspect
  end
end
