# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# Once the last finalizer is gone from an object already marked for deletion,
# the object itself is removed.  That rule belongs to every kind:
# registry/generic/registry/store.go updateForGracefulDeletionAndFinalizers
# deletes immediately when "the object has a deletionTimestamp and no
# finalizers", and the generic store is what every resource is served from.
#
# Restricting it to Namespace left every other finalizer-protected object in
# the API for ever after its controller had done its work -- a
# PersistentVolumeClaim whose pvc-protection finalizer had been removed stayed
# Terminating, and every spec that waits for one to disappear timed out.
class FinalizerCompletionTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    @registry = API::Registry.new(resources: [], defaults: false)
    @registry.register(API::Resource.new(group: "", version: "v1", resource: "namespaces",
                                         kind: "Namespace", scope: :cluster))
    @registry.register(API::Resource.new(group: "", version: "v1", resource: "persistentvolumeclaims",
                                         kind: "PersistentVolumeClaim", scope: :namespaced,
                                         subresources: [{resource: "status", verbs: %w[get patch update]}]))
    @registry.register(API::Resource.new(group: "", version: "v1", resource: "configmaps",
                                         kind: "ConfigMap", scope: :namespaced))
    @server = API::Server.new(registry: @registry, store: @store)
    call("POST", "/api/v1/namespaces",
         body: {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "ns"}})
  end

  def call(method, path, body: nil, content_type: "application/json")
    @server.call(API::Request.new(method: method, path: path,
                                  headers: body ? {"content-type" => content_type} : {},
                                  body: body && JSON.generate(body),
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def create_pvc(finalizers: ["kubernetes.io/pvc-protection"])
    response = call("POST", "/api/v1/namespaces/ns/persistentvolumeclaims",
                    body: {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim",
                           "metadata" => {"name" => "probe", "finalizers" => finalizers},
                           "spec" => {"accessModes" => ["ReadWriteOnce"],
                                      "resources" => {"requests" => {"storage" => "1Gi"}}}})
    assert_equal(201, response.status, response.body.inspect)
    response.body
  end

  def get_pvc
    call("GET", "/api/v1/namespaces/ns/persistentvolumeclaims/probe")
  end

  def test_a_finalizer_keeps_the_object_after_delete
    create_pvc
    call("DELETE", "/api/v1/namespaces/ns/persistentvolumeclaims/probe")

    response = get_pvc

    assert_equal(200, response.status)
    refute_nil(response.body.dig("metadata", "deletionTimestamp"))
  end

  # The controller removes the finalizer; the API server must then remove the
  # object, without anybody sending a second DELETE.
  def test_removing_the_last_finalizer_removes_the_object
    create_pvc
    call("DELETE", "/api/v1/namespaces/ns/persistentvolumeclaims/probe")

    response = call("PATCH", "/api/v1/namespaces/ns/persistentvolumeclaims/probe",
                    body: {"metadata" => {"finalizers" => []}},
                    content_type: "application/merge-patch+json")

    assert_equal(200, response.status, response.body.inspect)
    assert_equal(404, get_pvc.status, "the object must be gone once its last finalizer is")
  end

  # One of two finalizers is not the last one.
  def test_removing_one_of_two_finalizers_keeps_the_object
    create_pvc(finalizers: %w[kubernetes.io/pvc-protection example.com/other])
    call("DELETE", "/api/v1/namespaces/ns/persistentvolumeclaims/probe")

    call("PATCH", "/api/v1/namespaces/ns/persistentvolumeclaims/probe",
         body: {"metadata" => {"finalizers" => ["example.com/other"]}},
         content_type: "application/merge-patch+json")

    assert_equal(200, get_pvc.status)
  end

  # An object that was never marked for deletion is untouched by losing a
  # finalizer.
  def test_removing_a_finalizer_without_a_deletion_is_not_a_delete
    create_pvc

    call("PATCH", "/api/v1/namespaces/ns/persistentvolumeclaims/probe",
         body: {"metadata" => {"finalizers" => []}},
         content_type: "application/merge-patch+json")

    assert_equal(200, get_pvc.status)
  end

  # A PUT is the other way a controller clears a finalizer.
  def test_an_update_that_clears_the_last_finalizer_also_removes_the_object
    create_pvc
    call("DELETE", "/api/v1/namespaces/ns/persistentvolumeclaims/probe")
    current = JSON.parse(JSON.generate(get_pvc.body))
    current["metadata"]["finalizers"] = []

    response = call("PUT", "/api/v1/namespaces/ns/persistentvolumeclaims/probe", body: current)

    assert_equal(200, response.status, response.body.inspect)
    assert_equal(404, get_pvc.status)
  end

  # A Namespace keeps its own extra rule: spec.finalizers holds it as well as
  # metadata.finalizers, and it goes only when BOTH are empty.
  def test_a_namespace_is_held_by_its_spec_finalizers_too
    call("POST", "/api/v1/namespaces",
         body: {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "doomed"}})
    call("DELETE", "/api/v1/namespaces/doomed")
    held = call("GET", "/api/v1/namespaces/doomed")

    assert_equal(200, held.status)
    assert_equal(%w[kubernetes], Array(held.body.dig("spec", "finalizers")))

    current = JSON.parse(JSON.generate(held.body))
    current["metadata"]["finalizers"] = []
    current["spec"]["finalizers"] = []

    assert_equal(200, call("PUT", "/api/v1/namespaces/doomed", body: current).status)
    assert_equal(404, call("GET", "/api/v1/namespaces/doomed").status)
  end
end
