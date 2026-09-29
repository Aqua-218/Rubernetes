# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes"
require "rubernetes/bootstrap"

# The controller manager builds KubernetesStoreAdapter with the caches hash
# and fills that hash as informers are built.  The adapter dropped it, so
# every controller read went to the API server.
class ControllerStoreAdapterUsesCachesTest < Minitest::Test
  Adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter

  class NoClient
    def method_missing(name, *) = raise("controller read reached the API server: #{name}")
    def respond_to_missing?(*) = true
  end

  class Cache
    def initialize(objects) = @objects = objects
    def synced? = true
    def list = @objects
  end

  def pod(name, namespace)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => namespace}}
  end

  def test_informer_caches_registered_after_construction_serve_reads
    caches = {}
    descriptor = Adapter.descriptor(pod("x", "ns"))
    adapter = Adapter.new(client: NoClient.new, resource_descriptors: [descriptor], caches: caches)
    caches[descriptor.identifier] = Cache.new([pod("a", "ns"), pod("b", "other")])

    assert_equal ["a"], adapter.list(descriptor, namespace: "ns").map { |object| object.dig("metadata", "name") }
    assert_equal "b", adapter.find(descriptor, name: "b", namespace: "other").dig("metadata", "name")
  end
end
