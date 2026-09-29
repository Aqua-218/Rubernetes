# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "rubernetes/api"
require "rubernetes/controller"
require "rubernetes/storage/memory_store"

# A graceful DELETE of a Pod bumps metadata.generation
# (registry/core/pod/strategy.go, PodObservedGenerationTracking).
class APIPodGenerationDeleteTest < Minitest::Test
  API = Rubernetes::API

  def call(method, path, body = nil)
    @server.call(API::Request.new(method: method, path: path, headers: {"content-type" => "application/json"},
                                  body: body && JSON.generate(body),
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def test_graceful_delete_bumps_the_generation
    @server = API::Server.new(store: Rubernetes::Storage::MemoryStore.new)
    call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "ns"}})
    created = call("POST", "/api/v1/namespaces/ns/pods",
                   {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "generation" => 100},
                    "spec" => {"nodeName" => "n1", "containers" => [{"name" => "c", "image" => "x"}]}})
    assert_equal 1, created.body.dig("metadata", "generation")

    deleted = call("DELETE", "/api/v1/namespaces/ns/pods/p?gracePeriodSeconds=60")
    assert_equal 200, deleted.status
    assert_equal 2, call("GET", "/api/v1/namespaces/ns/pods/p").body.dig("metadata", "generation")
  end
end
