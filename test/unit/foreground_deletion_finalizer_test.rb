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

  def call(method, path, body = nil, headers: {})
    @server.call(method: method, path: path, body: body, query: nil, headers: headers)
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

  def test_an_update_to_the_owner_after_the_sweep_does_not_block_finalization
    delete_rc("Foreground")
    path = "/api/v1/namespaces/dev/replicationcontrollers/rc"
    cached = rc.body
    changed = Marshal.load(Marshal.dump(cached))
    changed["metadata"]["annotations"] = {"example.com/progress" => "observed"}

    assert_equal 200, call("PUT", path, changed).status

    stale_removal = Marshal.load(Marshal.dump(cached))
    stale_removal["metadata"]["finalizers"] = []

    assert_equal 409, call("PUT", path, stale_removal).status

    collector = Rubernetes::Controller::GarbageCollectorController.new
    now = Time.iso8601(cached.dig("metadata", "deletionTimestamp")) + 60
    operations = collector.send(:gc_finalizer_operations, [cached], now, live: ->(_object) { rc.body })

    assert_equal [:json_patch], operations.map(&:action)

    changed = Marshal.load(Marshal.dump(rc.body))
    changed["metadata"]["annotations"]["example.com/progress"] = "updated again"

    assert_equal 200, call("PUT", path, changed).status
    assert_equal 200, call("PATCH", path, operations.first.patch, headers: {"Content-Type" => "application/json-patch+json"}).status
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
    assert_equal(["stay"], pod.body.dig("metadata", "ownerReferences").map { |reference| reference["name"] })
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

  def pod(name, owners: [%w[ReplicationController rc rc-uid]], deleting: false)
    metadata = {"name" => name, "namespace" => "dev", "uid" => "#{name}-uid", "resourceVersion" => "7",
                "ownerReferences" => owners.map do |kind, owner_name, uid|
                  {"apiVersion" => "v1", "kind" => kind, "name" => owner_name, "uid" => uid, "blockOwnerDeletion" => true}
                end}
    metadata["deletionTimestamp"] = "2026-01-01T00:00:30Z" if deleting
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata}
  end

  def operations(objects, now: NOW)
    GC.new.send(:gc_finalizer_operations, objects, now)
  end

  def patched_owner(operation)
    Rubernetes::API::Patch.apply(operation.object, operation.patch, type: :json)
  end

  def test_a_dependent_created_after_the_cascade_is_deleted
    ops = operations([owner, pod("late")])

    assert_equal([[:delete, "late"]], ops.map { |operation| [operation.action, Support.name(operation.object)] })
  end

  def test_nonblocking_reference_does_not_hold_the_foreground_owner
    child = pod("late")
    child.dig("metadata", "ownerReferences").first.delete("blockOwnerDeletion")

    ops = operations([owner, child])

    assert_equal [:json_patch], ops.map(&:action)
    assert_equal "rc", ops.first.object.dig("metadata", "name")
    assert_empty patched_owner(ops.first).dig("metadata", "finalizers")
  end

  def test_orphaning_releases_only_the_matching_reference_even_from_a_terminating_child
    marked = owner
    marked["metadata"]["finalizers"] = ["example.com/hold", "orphan"]
    child = pod("going", owners: [%w[ReplicationController rc rc-uid], %w[ReplicationController other other-uid]], deleting: true)
    release = operations([marked, child])

    assert_equal [:update], release.map(&:action)
    assert_equal(["other-uid"], release.first.object.dig("metadata", "ownerReferences").map { |reference| reference["uid"] })
    finish = operations([marked, release.first.object])

    assert_equal ["example.com/hold"], patched_owner(finish.first).dig("metadata", "finalizers")
  end

  def test_the_owner_waits_for_a_terminating_dependent
    assert_empty operations([owner, pod("going", deleting: true)])
  end

  def test_the_finalizer_is_removed_once_no_dependent_is_left
    ops = operations([owner])

    assert_equal [:json_patch], ops.map(&:action)
    assert_empty patched_owner(ops.first).dig("metadata", "finalizers")
  end

  def test_finalizer_removal_uses_the_live_owner_version_and_preserves_other_changes
    cached = owner
    current = owner
    current["metadata"]["resourceVersion"] = "12"
    current["metadata"]["finalizers"] << "operator.example/hold"
    current["status"] = {"phase" => "Terminating"}

    ops = GC.new.send(:gc_finalizer_operations, [cached], NOW, live: ->(_object) { current })

    assert_equal [:json_patch], ops.map(&:action)
    updated = patched_owner(ops.first)

    assert_equal "12", updated.dig("metadata", "resourceVersion")
    assert_equal ["operator.example/hold"], updated.dig("metadata", "finalizers")
    assert_equal({"phase" => "Terminating"}, updated.fetch("status"))
  end

  def test_finalizer_removal_requires_the_same_finalizer_list_at_commit
    cached = owner
    cached["metadata"]["finalizers"] << "operator.example/hold"
    plan = operations([cached]).first
    live = owner
    live["metadata"]["resourceVersion"] = "11"

    assert_raises(Rubernetes::API::Patch::Error) do
      Rubernetes::API::Patch.apply(live, plan.patch, type: :json)
    end
  end

  def test_finalizer_removal_ignores_a_same_name_replacement
    replacement = owner
    replacement["metadata"]["uid"] = "other-uid"

    ops = GC.new.send(:gc_finalizer_operations, [owner], NOW, live: ->(_object) { replacement })

    assert_empty ops
  end

  def test_an_owner_read_failure_aborts_the_sweep
    live = ->(_object) { raise IOError, "owner read failed" }

    error = assert_raises(IOError) { GC.new.send(:gc_finalizer_operations, [owner], NOW, live: live) }

    assert_equal "owner read failed", error.message
  end

  def test_an_owner_marked_moments_ago_is_not_released_yet
    assert_empty operations([owner(marked_at: "2026-01-01T00:00:58Z")])
  end

  def test_a_dependent_with_another_live_owner_is_released_not_deleted
    other = {"apiVersion" => "v1", "kind" => "ReplicationController",
             "metadata" => {"name" => "stay", "namespace" => "dev", "uid" => "stay-uid"}}
    shared = pod("shared", owners: [%w[ReplicationController rc rc-uid], %w[ReplicationController stay stay-uid]])

    ops = operations([owner, other, shared])

    assert_equal [:update], ops.map(&:action)
    assert_equal(["stay-uid"], ops.first.object.dig("metadata", "ownerReferences").map { |reference| reference["uid"] })
  end

  # The sweep's copy is stale: the live Pod has gained a second owner since,
  # so it is released, not deleted; a Pod the API no longer has is skipped.
  def test_the_decision_is_made_on_the_live_dependent
    other = {"apiVersion" => "v1", "kind" => "ReplicationController",
             "metadata" => {"name" => "stay", "namespace" => "dev", "uid" => "stay-uid"}}
    stale = pod("shared")
    fresh = pod("shared", owners: [%w[ReplicationController rc rc-uid], %w[ReplicationController stay stay-uid]])
    gone = pod("gone")
    live = ->(object) { Support.name(object) == "shared" ? fresh : nil }

    ops = GC.new.send(:gc_finalizer_operations, [owner, other, stale, gone], NOW, live: live)

    assert_equal [:update], ops.map(&:action)
    assert_equal(["stay-uid"], ops.first.object.dig("metadata", "ownerReferences").map { |reference| reference["uid"] })
  end

  def test_a_live_dependent_that_still_has_only_the_owner_is_deleted
    stale = pod("only")
    live = ->(object) { object }

    ops = GC.new.send(:gc_finalizer_operations, [owner, stale], NOW, live: live)

    assert_equal([[:delete, "only"]], ops.map { |operation| [operation.action, Support.name(operation.object)] })
  end

  # A live read that fails keeps the cached copy: the dependent is still
  # acted on rather than silently skipped.
  def test_a_failed_live_read_falls_back_to_the_cached_dependent
    live = ->(_object) { raise IOError, "connection dropped" }

    ops = GC.new.send(:gc_finalizer_operations, [owner, pod("only")], NOW, live: live)

    assert_equal([[:delete, "only"]], ops.map { |operation| [operation.action, Support.name(operation.object)] })
  end

  # Dependents the API has already released no longer count: the owner is
  # empty and loses its finalizer.
  def test_released_dependents_let_the_finalizer_go
    other = {"apiVersion" => "v1", "kind" => "ReplicationController",
             "metadata" => {"name" => "stay", "namespace" => "dev", "uid" => "stay-uid"}}
    cached = pod("shared", owners: [%w[ReplicationController rc rc-uid], %w[ReplicationController stay stay-uid]])
    released = pod("shared", owners: [%w[ReplicationController stay stay-uid]])
    live = ->(object) { Support.kind(object) == "Pod" ? released : object }

    ops = GC.new.send(:gc_finalizer_operations, [owner, other, cached], NOW, live: live)

    assert_equal [:json_patch], ops.map(&:action)
    assert_equal "rc", Support.name(ops.first.object), "the owner's finalizer is removed"
    assert_empty patched_owner(ops.first).dig("metadata", "finalizers")
  end

  Support = Rubernetes::Controller::Support
end
