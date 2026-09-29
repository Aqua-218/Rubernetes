# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# An orphaning delete has to mark the owner as being deleted BEFORE it
# releases the dependents.  A controller that sees a released Pod matching its
# selector re-reads its owner before adopting it, and refuses only if the owner
# is going away.  Releasing the dependents of a still-live owner raced that
# guard: the ReplicationController adopted its own orphaned Pods back, was
# deleted, and the garbage collector then removed every Pod it had just
# re-adopted.  "[sig-api-machinery] Garbage collector should orphan pods
# created by rc if delete options say so" kept 0 of 100.
class OrphanDeletionOrderTest < Minitest::Test
  # Records each write: the owner's deletionTimestamp as its dependents are
  # released.
  class RecordingStore < Rubernetes::API::MemoryStore
    attr_reader :writes

    def update(resource:, namespace:, name:, object:, **options)
      (@writes ||= []) << [resource.kind, name, !object.dig("metadata", "deletionTimestamp").nil?,
                           Array(object.dig("metadata", "ownerReferences")).length]
      super
    end
  end

  def setup
    @store = RecordingStore.new(clock: -> { Time.utc(2026, 1, 1) })
    @server = Rubernetes::API::Server.new(registry: Rubernetes::API::Registry.new, store: @store,
                                          namespace_lifecycle: true)
    call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "dev"}})
    # The mechanism does not depend on the owner's kind; the minimal registry
    # serves ConfigMaps, so one stands in for the ReplicationController.
    owner = call("POST", "/api/v1/namespaces/dev/configmaps", {
      "apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "owner"}
    }).body
    @owner_uid = owner.dig("metadata", "uid")
    2.times do |index|
      call("POST", "/api/v1/namespaces/dev/pods", {
        "apiVersion" => "v1", "kind" => "Pod",
        "metadata" => {"name" => "p#{index}", "labels" => {"app" => "a"},
                       "ownerReferences" => [{"apiVersion" => "v1", "kind" => "ConfigMap",
                                              "name" => "owner", "uid" => @owner_uid, "controller" => true}]},
        "spec" => {"containers" => [{"name" => "c", "image" => "i"}]}
      })
    end
    @store.writes&.clear
  end

  def call(method, path, body = nil, query: nil)
    @server.call(method: method, path: path, body: body, query: query, headers: {})
  end

  def orphan_delete
    call("DELETE", "/api/v1/namespaces/dev/configmaps/owner",
         {"kind" => "DeleteOptions", "apiVersion" => "v1", "propagationPolicy" => "Orphan"})
  end

  def test_the_owner_is_marked_as_deleting_before_any_dependent_is_released
    response = orphan_delete

    assert_includes [200, 202], response.status
    owner_mark = @store.writes.index { |kind, _name, deleting, _refs| kind == "ConfigMap" && deleting }
    first_release = @store.writes.index { |kind, _name, _deleting, refs| kind == "Pod" && refs.zero? }
    refute_nil owner_mark, "the owner must be marked as being deleted"
    refute_nil first_release, "the dependents must be released"
    assert_operator owner_mark, :<, first_release, "the owner is marked first, so adoption guards refuse"
  end

  # Once marked, the owner has a deletionTimestamp and no finalizers, so any
  # write to it -- its controller's status update -- completes the removal
  # before this request's own delete.  That is the outcome asked for, and it
  # must be reported as a success, not 404 ("failed to delete the rc").
  def test_an_owner_removed_concurrently_after_marking_is_a_successful_delete
    adapter = @server.instance_variable_get(:@store)
    original = adapter.method(:delete)
    adapter.define_singleton_method(:delete) do |resource:, namespace:, name:, **options|
      if resource.kind == "ConfigMap" && name == "owner"
        original.call(resource: resource, namespace: namespace, name: name)
        raise Rubernetes::API::MemoryStore::NotFound, "configmaps \"owner\" not found"
      end
      original.call(resource: resource, namespace: namespace, name: name, **options)
    end

    response = orphan_delete

    assert_includes [200, 202], response.status, response.body.inspect
    assert_equal 404, call("GET", "/api/v1/namespaces/dev/configmaps/owner").status
  end

  def test_the_dependents_outlive_their_owner
    orphan_delete

    pods = call("GET", "/api/v1/namespaces/dev/pods").body.fetch("items")
    assert_equal %w[p0 p1], pods.map { |pod| pod.dig("metadata", "name") }.sort
    assert(pods.all? { |pod| Array(pod.dig("metadata", "ownerReferences")).empty? })
    assert_equal 404, call("GET", "/api/v1/namespaces/dev/configmaps/owner").status
  end
end
