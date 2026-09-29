# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/controller"

# propagationPolicy=Foreground keeps the owner, with the foregroundDeletion
# finalizer, until the garbage collector has seen every dependent gone
# (registry/generic/registry/store.go deletionFinalizersForGarbageCollection,
# garbagecollector.go processDeletingDependentsItem).  The API server removed
# the owner right after its synchronous cascade instead, and a creation batch
# the ReplicationController had already started landed Pods after the cascade
# had listed them: "[sig-api-machinery] Garbage collector should keep the rc
# around until all its pods are deleted if the deleteOptions says so" found
# five Pods outliving the rc.
class ForegroundDeletionFinalizerTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @store = API::MemoryStore.new(clock: -> { Time.utc(2026, 1, 1) })
    registry = API::Registry.new
    registry.register(API::Resource.new(group: "", version: "v1", resource: "replicationcontrollers",
                                        kind: "ReplicationController", scope: :namespace))
    @server = API::Server.new(registry: registry, store: @store, namespace_lifecycle: true)
    call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "dev"}})
    rc = call("POST", "/api/v1/namespaces/dev/replicationcontrollers", {
      "apiVersion" => "v1", "kind" => "ReplicationController", "metadata" => {"name" => "rc"},
      "spec" => {"replicas" => 1, "selector" => {"app" => "a"}}
    }).body
    @rc_uid = rc.dig("metadata", "uid")
    add_pod("p0")
  end

  def call(method, path, body = nil)
    @server.call(method: method, path: path, body: body, query: nil, headers: {})
  end

  def add_pod(name)
    call("POST", "/api/v1/namespaces/dev/pods", {
      "apiVersion" => "v1", "kind" => "Pod",
      "metadata" => {"name" => name, "labels" => {"app" => "a"},
                     "ownerReferences" => [{"apiVersion" => "v1", "kind" => "ReplicationController", "name" => "rc",
                                            "uid" => @rc_uid, "controller" => true, "blockOwnerDeletion" => true}]},
      "spec" => {"containers" => [{"name" => "c", "image" => "i"}]}
    })
  end

  def delete_rc(policy)
    call("DELETE", "/api/v1/namespaces/dev/replicationcontrollers/rc",
         {"kind" => "DeleteOptions", "apiVersion" => "v1", "propagationPolicy" => policy})
  end

  def rc
    call("GET", "/api/v1/namespaces/dev/replicationcontrollers/rc")
  end

  def test_a_foreground_delete_keeps_the_owner_with_the_finalizer
    response = delete_rc("Foreground")

    assert_equal 200, response.status
    current = rc
    assert_equal 200, current.status, "the owner stays until its dependents are gone"
    refute_nil current.body.dig("metadata", "deletionTimestamp")
    assert_includes current.body.dig("metadata", "finalizers"), "foregroundDeletion"
    assert_empty call("GET", "/api/v1/namespaces/dev/pods").body.fetch("items")
  end

  def test_removing_the_finalizer_completes_the_removal
    delete_rc("Foreground")
    current = Marshal.load(Marshal.dump(rc.body))
    current["metadata"]["finalizers"] = []

    call("PUT", "/api/v1/namespaces/dev/replicationcontrollers/rc", current)

    assert_equal 404, rc.status
  end

  # "[sig-api-machinery] Garbage collector should not delete dependents that
  # have both valid owner and owner that's waiting for dependents to be
  # deleted": a Pod a second, live owner still holds loses only the reference.
  def test_a_dependent_with_another_live_owner_is_released_not_deleted
    stay = call("POST", "/api/v1/namespaces/dev/replicationcontrollers", {
      "apiVersion" => "v1", "kind" => "ReplicationController", "metadata" => {"name" => "stay"},
      "spec" => {"replicas" => 0, "selector" => {"app" => "b"}}
    }).body
    shared = Marshal.load(Marshal.dump(call("GET", "/api/v1/namespaces/dev/pods/p0").body))
    shared["metadata"]["ownerReferences"] << {"apiVersion" => "v1", "kind" => "ReplicationController", "name" => "stay",
                                              "uid" => stay.dig("metadata", "uid")}
    call("PUT", "/api/v1/namespaces/dev/pods/p0", shared)

    delete_rc("Foreground")

    pod = call("GET", "/api/v1/namespaces/dev/pods/p0")
    assert_equal 200, pod.status
    assert_nil pod.body.dig("metadata", "deletionTimestamp")
    assert_equal ["stay"], pod.body.dig("metadata", "ownerReferences").map { |reference| reference["name"] }
  end

  def test_a_background_delete_still_removes_the_owner_at_once
    delete_rc("Background")

    assert_equal 404, rc.status
  end
end

class ForegroundGarbageCollectorTest < Minitest::Test
  GC = Rubernetes::Controller::GarbageCollectorController
  NOW = Time.utc(2026, 1, 1, 0, 1, 0)

  def owner(marked_at: "2026-01-01T00:00:00Z")
    {"apiVersion" => "v1", "kind" => "ReplicationController",
     "metadata" => {"name" => "rc", "namespace" => "dev", "uid" => "rc-uid", "resourceVersion" => "5",
                    "deletionTimestamp" => marked_at, "finalizers" => ["foregroundDeletion"]}}
  end

  def pod(name, owners: [["ReplicationController", "rc", "rc-uid"]], deleting: false)
    metadata = {"name" => name, "namespace" => "dev", "uid" => "#{name}-uid", "resourceVersion" => "7",
                "ownerReferences" => owners.map { |kind, owner_name, uid| {"apiVersion" => "v1", "kind" => kind, "name" => owner_name, "uid" => uid} }}
    metadata["deletionTimestamp"] = "2026-01-01T00:00:30Z" if deleting
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata}
  end

  def operations(objects, now: NOW)
    GC.new.send(:foreground_operations, objects, now)
  end

  def test_a_dependent_created_after_the_cascade_is_deleted
    ops = operations([owner, pod("late")])

    assert_equal [[:delete, "late"]], ops.map { |operation| [operation.action, Support.name(operation.object)] }
  end

  def test_the_owner_waits_for_a_terminating_dependent
    assert_empty operations([owner, pod("going", deleting: true)])
  end

  def test_the_finalizer_is_removed_once_no_dependent_is_left
    ops = operations([owner])

    assert_equal [:update], ops.map(&:action)
    assert_empty Array(ops.first.object.dig("metadata", "finalizers"))
  end

  def test_an_owner_marked_moments_ago_is_not_released_yet
    assert_empty operations([owner(marked_at: "2026-01-01T00:00:58Z")])
  end

  def test_a_dependent_with_another_live_owner_is_released_not_deleted
    other = {"apiVersion" => "v1", "kind" => "ReplicationController",
             "metadata" => {"name" => "stay", "namespace" => "dev", "uid" => "stay-uid"}}
    shared = pod("shared", owners: [["ReplicationController", "rc", "rc-uid"], ["ReplicationController", "stay", "stay-uid"]])

    ops = operations([owner, other, shared])

    assert_equal [:update], ops.map(&:action)
    assert_equal ["stay-uid"], ops.first.object.dig("metadata", "ownerReferences").map { |reference| reference["uid"] }
  end

  # The sweep's copy is stale: the live Pod has gained a second owner since,
  # so it is released, not deleted; a Pod the API no longer has is skipped.
  def test_the_decision_is_made_on_the_live_dependent
    other = {"apiVersion" => "v1", "kind" => "ReplicationController",
             "metadata" => {"name" => "stay", "namespace" => "dev", "uid" => "stay-uid"}}
    stale = pod("shared")
    fresh = pod("shared", owners: [["ReplicationController", "rc", "rc-uid"], ["ReplicationController", "stay", "stay-uid"]])
    gone = pod("gone")
    live = ->(object) { Support.name(object) == "shared" ? fresh : nil }

    ops = GC.new.send(:foreground_operations, [owner, other, stale, gone], NOW, live: live)

    assert_equal [:update], ops.map(&:action)
    assert_equal ["stay-uid"], ops.first.object.dig("metadata", "ownerReferences").map { |reference| reference["uid"] }
  end

  def test_a_live_dependent_that_still_has_only_the_owner_is_deleted
    stale = pod("only")
    live = ->(object) { object }

    ops = GC.new.send(:foreground_operations, [owner, stale], NOW, live: live)

    assert_equal [[:delete, "only"]], ops.map { |operation| [operation.action, Support.name(operation.object)] }
  end

  # A live read that fails keeps the cached copy: the dependent is still
  # acted on rather than silently skipped.
  def test_a_failed_live_read_falls_back_to_the_cached_dependent
    live = ->(_object) { raise IOError, "connection dropped" }

    ops = GC.new.send(:foreground_operations, [owner, pod("only")], NOW, live: live)

    assert_equal [[:delete, "only"]], ops.map { |operation| [operation.action, Support.name(operation.object)] }
  end

  # Dependents the API has already released no longer count: the owner is
  # empty and loses its finalizer.
  def test_released_dependents_let_the_finalizer_go
    other = {"apiVersion" => "v1", "kind" => "ReplicationController",
             "metadata" => {"name" => "stay", "namespace" => "dev", "uid" => "stay-uid"}}
    cached = pod("shared", owners: [["ReplicationController", "rc", "rc-uid"], ["ReplicationController", "stay", "stay-uid"]])
    released = pod("shared", owners: [["ReplicationController", "stay", "stay-uid"]])

    ops = GC.new.send(:foreground_operations, [owner, other, cached], NOW, live: ->(_object) { released })

    assert_equal [:update], ops.map(&:action)
    assert_equal "rc", Support.name(ops.first.object), "the owner's finalizer is removed"
    assert_empty Array(ops.first.object.dig("metadata", "finalizers"))
  end

  Support = Rubernetes::Controller::Support
end
