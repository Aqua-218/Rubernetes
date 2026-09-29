# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/storage/memory_store"

# The global revision advances on every write to any resource, so a reader
# caching one resource's objects and comparing the global revision rebuilt on
# nearly every request under load.  revision_under(prefix) answers with the
# revision of the last write in that key space only.
class MemoryStoreRevisionUnderTest < Minitest::Test
  Store = Rubernetes::Storage::MemoryStore

  def object(name, namespace: nil)
    metadata = {"name" => name}
    metadata["namespace"] = namespace if namespace
    {"apiVersion" => "v1", "kind" => "Thing", "metadata" => metadata}
  end

  def test_only_writes_under_the_key_space_advance_it
    store = Store.new
    store.create("registry/clusterroles/_cluster/admin", object("admin"))
    role_revision = store.revision
    assert_equal role_revision, store.revision_under("registry/clusterroles/")
    assert_equal role_revision, store.revision_under("registry/clusterroles/_cluster/")

    store.create("registry/pods/ns/p", object("p", namespace: "ns"))
    store.create("registry/pods/ns/q", object("q", namespace: "ns"))
    assert_equal role_revision, store.revision_under("registry/clusterroles/"), "pod writes leave the clusterrole key space alone"
    assert_equal store.revision, store.revision_under("registry/pods/ns/")
    assert_equal 0, store.revision_under("registry/rolebindings/"), "an untouched key space is at zero"
  end

  def test_updates_deletes_and_a_leading_slash_count
    store = Store.new
    store.create("/registry/roles/ns/reader", object("reader", namespace: "ns"))
    store.guaranteed_update("/registry/roles/ns/reader") { |current| current.merge("rules" => []) }
    assert_equal store.revision, store.revision_under("registry/roles/")
    store.delete("/registry/roles/ns/reader")
    assert_equal store.revision, store.revision_under("/registry/roles/other/"), "a delete is a write too"
  end

  def test_a_prefix_shorter_than_a_key_space_answers_with_the_global_revision
    store = Store.new
    store.create("registry/pods/ns/p", object("p", namespace: "ns"))
    assert_equal store.revision, store.revision_under("registry/")
    assert_equal store.revision, store.revision_under("")
  end

  def test_an_imported_state_carries_the_key_space_revisions
    store = Store.new
    store.create("registry/clusterroles/_cluster/admin", object("admin"))
    store.create("registry/pods/ns/p", object("p", namespace: "ns"))
    store.delete("registry/pods/ns/p")
    restored = Store.new
    restored.import_state(store.export_state)
    %w[registry/clusterroles/ registry/pods/ registry/rolebindings/].each do |prefix|
      assert_equal store.revision_under(prefix), restored.revision_under(prefix), prefix
    end
  end
end
