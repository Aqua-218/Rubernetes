# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/storage/memory_store"

# A list used to sort every key the store had ever held and scan the result
# for its prefix, on every call.  The sorted key set is now memoised until a
# key is added, and a prefix is found by binary search.  These tests pin the
# list semantics that the memo must preserve: new keys appear at once,
# deleted keys disappear, continue tokens resume after the right key, and an
# imported state lists correctly.
class MemoryStoreSortedKeysTest < Minitest::Test
  Store = Rubernetes::Storage::MemoryStore

  def object(name)
    {"apiVersion" => "v1", "kind" => "Thing", "metadata" => {"name" => name, "namespace" => "ns"}}
  end

  def names(result)
    result.items.map { |item| item.dig("metadata", "name") }
  end

  def test_new_and_deleted_keys_are_reflected_immediately
    store = Store.new
    store.create("registry/things/ns/b", object("b"))

    assert_equal %w[b], names(store.list("registry/things/"))
    store.create("registry/things/ns/a", object("a"))
    store.create("registry/others/ns/z", object("z"))

    assert_equal %w[a b], names(store.list("registry/things/"))
    store.delete("registry/things/ns/a")

    assert_equal %w[b], names(store.list("registry/things/"))
    assert_equal %w[z], names(store.list("registry/others/"))
    assert_equal %w[b], names(store.list("registry/thing")), "a plain string prefix, not only a key space"
  end

  def test_a_prefix_between_other_keys_lists_only_its_own
    store = Store.new
    %w[registry/a/ns/x registry/things/ns/a registry/things/ns/b registry/thingsx/ns/c registry/z/ns/y].each do |key|
      store.create(key, object(key.split("/").last))
    end

    assert_equal %w[a b], names(store.list("registry/things/"))
    assert_equal %w[a b c], names(store.list("registry/things"))
    assert_equal [], names(store.list("registry/nothing/"))
  end

  def test_continue_tokens_resume_after_the_last_key
    store = Store.new
    %w[a b c d e].each { |name| store.create("registry/things/ns/#{name}", object(name)) }
    first = store.list("registry/things/", limit: 2)

    assert_equal %w[a b], names(first)
    second = store.list("registry/things/", limit: 2, continue: first.continue_token)

    assert_equal %w[c d], names(second)
    third = store.list("registry/things/", limit: 2, continue: second.continue_token)

    assert_equal %w[e], names(third)
    assert_nil third.continue_token
  end

  def test_an_imported_state_lists_correctly
    store = Store.new
    %w[b a].each { |name| store.create("registry/things/ns/#{name}", object(name)) }
    store.delete("registry/things/ns/b")
    restored = Store.new
    restored.import_state(store.export_state)

    assert_equal %w[a], names(restored.list("registry/things/"))
    restored.create("registry/things/ns/c", object("c"))

    assert_equal %w[a c], names(restored.list("registry/things/"))
  end
end
