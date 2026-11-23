# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/storage/memory_store"

class StorageKeyLayoutTest < Minitest::Test
  API = Rubernetes::API
  VERSIONS = %w[v1 v1beta1].freeze
  ROOT = "registry/storage.k8s.io"
  NAME = "volumeattributesclasses"
  MARKER = "rubernetes-internal/storage-keys/storage.k8s.io/volumeattributesclasses"

  def setup
    @store = Rubernetes::Storage::MemoryStore.new
    @preferred = API::GVR.new(group: "storage.k8s.io", resource: NAME)
    @legacy = API::GVR.new(group: @preferred.group, version: "v1beta1", resource: NAME)
  end

  def test_empty_and_default_prefix_reads_need_no_marker_write
    2.times do
      layout = API::StorageKeyLayout.new(@store)

      assert_equal @preferred, layout.resolve(@preferred, VERSIONS)
      assert_equal @preferred, layout.resolve(@preferred, VERSIONS, write: true)
    end

    assert_equal 0, @store.revision
  end

  def test_legacy_only_prefix_keeps_object_uid_and_revision_until_a_real_write_pins_it
    key = "#{ROOT}/v1beta1/#{NAME}/_cluster/sample"
    @store.create(key, {"apiVersion" => "storage.k8s.io/v1beta1", "metadata" => {"name" => "sample", "uid" => "legacy-uid"}})
    existing = @store.get(key)
    original_revision = @store.revision
    layout = API::StorageKeyLayout.new(@store)

    assert_equal @legacy, layout.resolve(@preferred, VERSIONS)
    assert_equal original_revision, @store.revision
    assert_equal existing, @store.get(key)
    assert_equal @legacy, layout.resolve(@preferred, VERSIONS, write: true)
    assert_equal "v1beta1", @store.get(MARKER)["version"]
    assert_equal existing, @store.get(key)

    @store.delete(key)

    assert_empty @store.list("#{ROOT}/v1beta1/#{NAME}/").items
    assert_equal @legacy, API::StorageKeyLayout.new(@store).resolve(@preferred, VERSIONS)
  end

  def test_distinct_populated_prefixes_fail_and_preserve_both_records
    VERSIONS.each do |version|
      @store.create("#{ROOT}/#{version}/#{NAME}/_cluster/sample",
                    {"metadata" => {"name" => "sample", "uid" => "uid-#{version}"}})
    end
    revision = @store.revision
    layout = API::StorageKeyLayout.new(@store)

    error = assert_raises(API::Status::Conflict) { layout.resolve(@preferred, VERSIONS, write: true) }

    assert_includes error.message, "#{ROOT}/v1/#{NAME}/"
    assert_includes error.message, "#{ROOT}/v1beta1/#{NAME}/"
    assert_equal revision, @store.revision
    assert_raises(Rubernetes::Storage::NotFound) { @store.get(MARKER) }
    VERSIONS.each do |version|
      assert_equal "uid-#{version}", @store.get("#{ROOT}/#{version}/#{NAME}/_cluster/sample").dig("metadata", "uid")
    end
  end

  def test_warm_empty_selection_observes_legacy_writes_and_later_conflicts
    [@store, API::MemoryStore.new].each do |store|
      layout = API::StorageKeyLayout.new(store)
      object = {"metadata" => {"name" => "sample"}}

      assert_equal @preferred, layout.resolve(@preferred, VERSIONS)

      store.create("#{ROOT}/v1beta1/#{NAME}/_cluster/sample", object)

      assert_equal @legacy, layout.resolve(@preferred, VERSIONS)
      assert_equal @legacy, layout.resolve(@preferred, VERSIONS, write: true)

      store.create("#{ROOT}/v1/#{NAME}/_cluster/another", object)
      assert_raises(API::Status::Conflict) { layout.resolve(@preferred, VERSIONS) }
    end
  end

  def test_retained_delete_history_selects_the_legacy_collection
    key = "#{ROOT}/v1beta1/#{NAME}/_cluster/sample"
    original = @store.create(key, {"metadata" => {"name" => "sample", "uid" => "historical"}})
    rv = original.fetch("metadata").fetch("resourceVersion")
    @store.delete(key)
    layout = API::StorageKeyLayout.new(@store)
    selected = layout.resolve(@preferred, VERSIONS)

    assert_equal @legacy, selected
    prefix = "registry/#{selected}/"
    snapshot = @store.list(prefix, resource_version: rv, resource_version_match: "Exact")

    assert_equal "historical", snapshot.items.fetch(0).dig("metadata", "uid")
    stream = @store.watch(prefix, resource_version: rv)
    event = stream.each.first

    assert_equal "DELETED", event.type.to_s.upcase
  ensure
    stream&.close
  end

  def test_create_compares_the_other_keys_in_the_same_commit
    store = Class.new(Rubernetes::Storage::MemoryStore) do
      attr_accessor :before_create

      def create(key, object, **options)
        hook = before_create
        self.before_create = nil
        hook&.call
        super
      end
    end.new
    adapter = API::StoreAdapter.new(store)
    resource = API::Resource.new(group: @preferred.group, resource: NAME, kind: "VolumeAttributesClass",
                                 storage_key_version: "v1", storage_key_versions: VERSIONS)
    object = {"metadata" => {"name" => "racing", "uid" => "older-server"}}
    legacy_key = "#{ROOT}/v1beta1/#{NAME}/_cluster/racing"
    store.before_create = -> { store.create(legacy_key, object) }

    assert_raises(API::MemoryStore::Conflict) { adapter.create(resource: resource, namespace: :cluster, object: object) }
    assert_equal "older-server", adapter.get(resource: resource, namespace: :cluster, name: "racing").dig("metadata", "uid")
    assert_raises(Rubernetes::Storage::NotFound) { store.get("#{ROOT}/v1/#{NAME}/_cluster/racing") }
  end

  def test_layout_lookup_keeps_the_stores_retry_response
    store = Class.new(Rubernetes::Storage::MemoryStore) do
      def storage_layout_revision(_group)
        raise Rubernetes::Storage::Unavailable.new("waiting for quorum", retry_after_seconds: 3)
      end
    end.new
    adapter = API::StoreAdapter.new(store)
    resource = API::Resource.new(group: @preferred.group, resource: NAME, kind: "VolumeAttributesClass", storage_key_versions: VERSIONS)

    error = assert_raises(API::Status::Error) { adapter.get(resource: resource, namespace: :cluster, name: "sample") }
    assert_equal [503, "ServiceUnavailable", 3], [error.code, error.reason, error.retry_after_seconds]
  end
end
