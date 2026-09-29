# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# metadata.generation is server-owned: every strategy that tracks it sets it to
# 1 in PrepareForCreate whatever the client sent, and bumps it only when the
# spec changes.  Ours kept a client-supplied value, so an object created with
# generation 100 kept it -- "[sig-node] Pods Extended (pod generation)
# custom-set generation on new pods and pod updates" expects exactly 1.
class APIGenerationTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @server = API::Server.new(registry: API::Registry.new, store: API::MemoryStore.new,
                              namespace_lifecycle: true)
    call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "dev"}})
  end

  def call(method, path, body = nil)
    @server.call(API::Request.new(method: method, path: path, body: body))
  end

  def pod(generation: nil, image: "busybox")
    metadata = {"name" => "p"}
    metadata["generation"] = generation if generation
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata,
     "spec" => {"containers" => [{"name" => "c", "image" => image}]}}
  end

  def test_a_client_supplied_generation_is_replaced_on_create
    created = call("POST", "/api/v1/namespaces/dev/pods", pod(generation: 100))

    assert_equal(201, created.status)
    assert_equal(1, created.body.dig("metadata", "generation"))
  end

  def test_a_create_without_a_generation_still_starts_at_one
    created = call("POST", "/api/v1/namespaces/dev/pods", pod)

    assert_equal(1, created.body.dig("metadata", "generation"))
  end

  def test_a_spec_change_bumps_the_generation_by_one
    call("POST", "/api/v1/namespaces/dev/pods", pod)
    updated = call("PUT", "/api/v1/namespaces/dev/pods/p", pod(generation: 100, image: "busybox:1.36"))

    assert_equal(200, updated.status)
    assert_equal(2, updated.body.dig("metadata", "generation"))
  end

  def test_an_update_that_does_not_change_the_spec_keeps_the_generation
    call("POST", "/api/v1/namespaces/dev/pods", pod)
    updated = call("PUT", "/api/v1/namespaces/dev/pods/p", pod(generation: 100))

    assert_equal(1, updated.body.dig("metadata", "generation"))
  end

  # A kind that carries no spec carries no generation either.
  def test_a_config_map_has_no_generation
    created = call("POST", "/api/v1/namespaces/dev/configmaps",
                   {"metadata" => {"name" => "cm"}, "data" => {"k" => "v"}})

    assert_nil(created.body.dig("metadata", "generation"))
  end
end
