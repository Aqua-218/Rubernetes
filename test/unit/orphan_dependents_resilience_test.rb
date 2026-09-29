# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# An orphaning delete promises the dependents will outlive their owner.  A
# dependent that could not be released keeps an owner reference to an object
# that is about to stop existing, and the garbage collector then deletes it --
# the exact opposite of what was asked.  One rescue covered the whole
# collection, so a single conflicting Pod abandoned every Pod after it in the
# list: "[sig-api-machinery] Garbage collector should orphan pods created by rc
# if delete options say so" creates 100 Pods and kept 35.
class OrphanDependentsResilienceTest < Minitest::Test
  Server = Rubernetes::API::Server
  Store = Rubernetes::API::MemoryStore

  OWNER_UID = "owner-uid"

  class FakeStore
    attr_reader :updated, :gets

    # `conflict_on` names the objects whose first update attempt conflicts.
    def initialize(items, conflict_on: [])
      @items = items
      @conflict_on = conflict_on.dup
      @updated = []
      @gets = []
    end

    def list(resource:, namespace: nil, selectors: nil)
      {"items" => @items}
    end

    def get(resource:, namespace: nil, name: nil)
      @gets << name
      found = @items.find { |item| item.dig("metadata", "name") == name }
      raise Store::NotFound, name unless found

      found
    end

    def update(resource:, namespace:, name:, object:, resource_version: nil)
      if @conflict_on.delete(name)
        raise Store::Conflict, name
      end

      @updated << name
      object
    end
  end

  def pod(name, owner_uid: OWNER_UID)
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "ns", "resourceVersion" => "1",
                    "ownerReferences" => [{"uid" => owner_uid, "name" => "rc", "controller" => true}]}}
  end

  def descriptor
    Rubernetes::Controller::ResourceDescriptor.parse("Pod")
  end

  def server_for(store)
    subject = Server.allocate
    subject.instance_variable_set(:@store, store)
    subject.instance_variable_set(:@logger, nil)
    subject
  end

  def orphan_each(store, items)
    subject = server_for(store)
    items.each { |item| subject.send(:orphan_one_dependent, descriptor, item, OWNER_UID) }
  end

  def test_every_dependent_is_released
    items = Array.new(5) { |i| pod("p#{i}") }
    store = FakeStore.new(items)

    orphan_each(store, items)

    assert_equal %w[p0 p1 p2 p3 p4], store.updated
  end

  def test_one_conflicting_dependent_does_not_abandon_the_rest
    items = Array.new(5) { |i| pod("p#{i}") }
    store = FakeStore.new(items, conflict_on: %w[p1])

    orphan_each(store, items)

    assert_equal %w[p0 p1 p2 p3 p4], store.updated.sort,
                 "a conflict is re-read and retried, and never costs the other dependents"
    assert_includes store.gets, "p1", "the conflicted dependent is read again before the retry"
  end

  def test_the_owner_reference_is_the_only_one_removed
    item = pod("p0")
    item["metadata"]["ownerReferences"] << {"uid" => "other", "name" => "keep"}
    store = FakeStore.new([item])
    written = nil
    store.define_singleton_method(:update) { |resource:, namespace:, name:, object:, resource_version: nil| written = object }

    orphan_each(store, [item])

    assert_equal ["other"], Array(written.dig("metadata", "ownerReferences")).map { |r| r["uid"] }
  end

  def test_a_dependent_that_vanished_is_not_an_error
    item = pod("gone")
    store = FakeStore.new([item], conflict_on: %w[gone])
    store.define_singleton_method(:get) { |resource:, namespace: nil, name: nil| raise Store::NotFound, name }

    orphan_each(store, [item])

    assert_empty store.updated
  end

  def test_a_dependent_this_owner_does_not_own_is_left_alone
    item = pod("p0", owner_uid: "someone-else")
    store = FakeStore.new([item])

    orphan_each(store, [item])

    assert_empty store.updated
  end
end
