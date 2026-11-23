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

    assert_equal(["a"], adapter.list(descriptor, namespace: "ns").map { |object| object.dig("metadata", "name") })
    assert_equal "b", adapter.find(descriptor, name: "b", namespace: "other").dig("metadata", "name")
  end

  def test_namespace_list_follows_index_changes_without_a_full_scan
    descriptor = Adapter.descriptor(pod("a", "ns"))
    index = Rubernetes::Watch::Indexer.new
    informer = Struct.new(:indexer, :reflector).new(index, Struct.new(:resource_version).new("1"))
    cache = Rubernetes::Bootstrap::InformerCache.new(informer, namespaced: true)
    adapter = Adapter.new(client: NoClient.new, resource_descriptors: [descriptor], caches: {descriptor.identifier => cache})
    index.replace_all([pod("a", "ns"), pod("b", "other")])
    def index.list = raise("unexpected full-cache scan")

    assert_equal(["a"], adapter.list(descriptor, namespace: "ns").map { |object| object.dig("metadata", "name") })
    index.delete("ns/a")

    assert_empty adapter.list(descriptor, namespace: "ns")
    index.add(pod("a", "other"))

    assert_equal(%w[a b], adapter.list(descriptor, namespace: "other").map { |object| object.dig("metadata", "name") })
  end

  def test_point_reads_use_the_metadata_index_after_sync
    descriptor = Adapter.descriptor(pod("p", "ns"))
    index = Rubernetes::Watch::Indexer.new
    index.add(pod("p", "ns"))
    index.add(pod("p", "other"))
    def index.list = raise("unexpected full-cache scan")

    cache = informer_cache(index)
    adapter = Adapter.new(client: NoClient.new, resource_descriptors: [descriptor], caches: {descriptor.identifier => cache})

    assert_same index.get("ns/p"), adapter.find(descriptor, name: "p", namespace: "ns")
    assert_same index.get("other/p"), adapter.find(descriptor, name: "p", namespace: "other")
    assert_nil adapter.find(descriptor, name: "p", namespace: "missing")
  end

  def test_informer_with_custom_keys_still_finds_objects_by_name
    descriptor = Adapter.descriptor(pod("p", "ns"))
    index = Rubernetes::Watch::Indexer.new(key_func: ->(_object) { "custom-key" })
    index.add(pod("p", "ns"))
    adapter = Adapter.new(client: NoClient.new, resource_descriptors: [descriptor], caches: {descriptor.identifier => informer_cache(index)})

    assert_same index.get("custom-key"), adapter.find(descriptor, name: "p", namespace: "ns")
  end

  def test_pod_label_changes_route_using_the_current_service_selectors
    controller = Rubernetes::Controller
    index = Rubernetes::Watch::Indexer.new
    cache = informer_cache(index, namespaced: true, index_selectors: true)
    descriptor = Adapter.descriptor("Service")
    adapter = Adapter.new(client: NoClient.new, resource_descriptors: [descriptor], caches: {descriptor.identifier => cache})
    registry = controller::ControllerRegistry.new(require_corpus: false)
    definition = controller.default_registry.fetch("endpointslice-controller")
    registry.register(definition)
    manager = controller::Manager.new(store: adapter, identity: "pod-events", registry: registry)
    manager.register_definition(definition)
    handler = nil
    events = Object.new
    events.define_singleton_method(:on) { |&block| handler = block }
    manager.register_informer(definition.name, events)
    service = ->(name, selector, ns = "ns") { pod(name, ns).merge("kind" => "Service", "spec" => {"selector" => selector}) }
    old = pod("work", "ns")
    old.fetch("metadata")["labels"] = {"app" => "old"}
    current = pod("work", "ns")
    current.fetch("metadata")["labels"] = {"app" => "new"}
    expression = {"matchExpressions" => [{"key" => "app", "operator" => "Exists"}]}
    index.replace_all([service.call("a", {"app" => "old"}), service.call("b", {"matchLabels" => {"app" => "new"}}),
                       service.call("c", expression), service.call("d", {"app" => "new", "tier" => "other"}),
                       service.call("elsewhere", {}, "other")])
    cache.add(service.call("empty", {}))
    index.update(service.call("a", {"app" => "unused"}))
    index.delete("ns/empty")
    cache.add(service.call("previous", {"app" => "old"}))

    handler.call(current, old, :update)
    keys = Array.new(manager.queue.size) { manager.queue.get(timeout: 0.1).first }

    assert_equal %w[ns/b ns/c ns/previous], keys.sort
  ensure
    manager&.stop
  end

  private

  def informer_cache(index, **)
    reflector = Struct.new(:resource_version).new("1")
    Rubernetes::Bootstrap::InformerCache.new(Struct.new(:indexer, :reflector).new(index, reflector), **)
  end
end
