# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/storage/memory_store"

class MemoryStoreSnapshotKeysTest < Minitest::Test
  Store = Rubernetes::Storage::MemoryStore
  PREFIX = "registry/v1/pods/batch/"
  KEY = "#{PREFIX}worker".freeze

  def new_store
    Store.new(history_revisions: nil, history_seconds: nil)
  end

  def test_missing_reads_do_not_change_durable_state
    store = new_store
    initial = store.export_state

    5.times { |n| assert_raises(Rubernetes::Storage::NotFound) { store.get("#{PREFIX}absent-#{n}") } }

    assert_equal initial, store.export_state
  end

  def test_index_keeps_history_until_deletion_is_compacted_and_allows_name_reuse
    store = new_store
    original = store.create(KEY, {"metadata" => {"name" => "worker", "uid" => "first"}})
    store.delete(KEY)
    store.compact!(revision: 1)
    historical = store.list(PREFIX, resource_version: 1, resource_version_match: "Exact")

    assert_equal [original], historical.items
    assert_equal [KEY], store.export_state.fetch("known_keys")

    store.compact!(revision: 2)

    assert_empty store.export_state.fetch("versions")
    assert_empty store.export_state.fetch("known_keys")
    assert_raises(Rubernetes::Storage::Gone) { store.list(PREFIX, resource_version: 1, resource_version_match: "Exact") }
    assert_empty store.list(PREFIX).items
    replacement = store.create(KEY, {"metadata" => {"name" => "worker", "uid" => "second"}})

    assert_equal [replacement], store.list(PREFIX).items
    assert_equal "3", replacement.dig("metadata", "resourceVersion")
  end

  def test_import_removes_obsolete_entries_from_v1_snapshots
    store = new_store
    live = store.create(KEY, {"metadata" => {"name" => "worker"}})
    store.compact!(revision: 1)
    document = store.export_state
    document.fetch("known_keys").push("old-deletion", "name-only")
    document.fetch("versions").merge!("old-deletion" => [[1, nil]], "failed-read" => [])
    restored = new_store
    restored.import_state(document)

    assert_equal store.export_state, restored.export_state
    assert_equal [live], restored.list(PREFIX).items
  end

  def test_revision_only_retention_collects_keys_even_after_their_last_write
    store = Store.new(history_revisions: 2, history_seconds: nil)
    8.times do |n|
      store.create("#{PREFIX}#{n}", {"metadata" => {"name" => n.to_s}})
      store.delete("#{PREFIX}#{n}")
    end

    state = store.export_state

    assert_equal 14, state.fetch("compacted_revision")
    assert_equal ["#{PREFIX}7"], state.fetch("known_keys")
    assert_equal(["7"], store.list(PREFIX, resource_version: 15, resource_version_match: "Exact").items.map { |pod| pod.dig("metadata", "name") })
    assert_empty store.list(PREFIX).items
  end
end
