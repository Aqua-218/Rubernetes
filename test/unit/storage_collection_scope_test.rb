# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/storage/memory_store"

# The production key/value store and Raft both accept byte prefixes. Exercise
# directory boundaries with ConfigMaps in two ordinary sibling namespaces.
class StorageCollectionScopeTest < Minitest::Test
  def setup
    @store = Rubernetes::Storage::MemoryStore.new
    @adapter = Rubernetes::API::StoreAdapter.new(@store)
    @resource = Rubernetes::API::Registry.new.find_gvr(group: "", version: "v1", resource: "configmaps")
    @options = {resource: @resource, namespace: "dev", selectors: nil}
  end

  def create(namespace, name)
    @adapter.create(resource: @resource, namespace: namespace, object: {
                      "apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"namespace" => namespace, "name" => name}
                    })
  end

  def test_list_pagination_and_collection_deletion_use_one_namespace
    create("dev", "one")
    create("dev", "two")
    create("dev-tools", "three")
    page = @adapter.list(**@options, limit: 1)

    assert_equal(["one"], page.items.map { |item| item.dig("metadata", "name") })
    page = @adapter.list(**@options, limit: 1, continue_token: page.continue_token)

    assert_equal(["two"], page.items.map { |item| item.dig("metadata", "name") })
    assert_nil page.continue_token

    @adapter.delete_collection(**@options)

    assert_empty @adapter.list(**@options).items
    assert_equal(["three"], @adapter.list(**@options, namespace: :all).items.map { |item| item.dig("metadata", "name") })
  end

  def test_watch_includes_only_events_in_its_namespace
    revision = create("dev", "one").dig("metadata", "resourceVersion")
    watch = @adapter.watch(**@options, resource_version: revision)
    create("dev-tools", "two")
    create("dev", "three")
    event = watch.next(timeout: 1)

    assert_equal "three", event.object.dig("metadata", "name")
    assert_nil watch.next(timeout: 0.01)
  ensure
    watch&.close
  end
end
