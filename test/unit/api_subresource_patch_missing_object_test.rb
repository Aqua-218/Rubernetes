# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# handlers/patch.go: an apply patch may create a missing object, but only
# through the main resource.  A subresource has no create path, and
# kube-apiserver answers 404 (verified against a live cluster: a status apply
# for a missing Namespace is NotFound and creates nothing).  Creating here
# resurrected every namespace the e2e suite deleted, because the controller
# manager's status apply for its stale cached Namespace landed after the
# namespace had been finalized away.
class APISubresourcePatchMissingObjectTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @store = API::MemoryStore.new(clock: -> { Time.utc(2026, 1, 1) })
    registry = API::Registry.new
    registry.register(resource: "services", kind: "Service", scope: :namespaced, subresources: ["status"])
    @server = API::Server.new(registry: registry, store: @store, namespace_lifecycle: true)
    call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "dev"}})
  end

  def call(method, path, body = nil, query: nil, headers: {})
    @server.call(method: method, path: path, body: body, query: query, headers: headers)
  end

  def apply(path, body)
    call("PATCH", path, body, query: {"fieldManager" => "cm", "force" => "true"},
                              headers: {"Content-Type" => "application/apply-patch+yaml"})
  end

  def test_a_status_apply_for_a_missing_namespace_is_not_found_and_creates_nothing
    response = apply("/api/v1/namespaces/gone/status",
                     {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "gone"},
                      "status" => {"phase" => "Active"}})

    assert_equal 404, response.status
    assert_equal 404, call("GET", "/api/v1/namespaces/gone").status
  end

  def test_a_status_apply_for_a_missing_namespaced_object_is_not_found
    response = apply("/api/v1/namespaces/dev/replicationcontrollers/absent/status",
                     {"apiVersion" => "v1", "kind" => "ReplicationController", "metadata" => {"name" => "absent", "namespace" => "dev"},
                      "status" => {"replicas" => 0}})

    assert_equal 404, response.status
  end

  def test_a_main_resource_apply_still_creates_a_missing_object
    response = apply("/api/v1/namespaces/dev/configmaps/fresh",
                     {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "fresh", "namespace" => "dev"},
                      "data" => {"a" => "1"}})

    assert_equal 201, response.status
    assert_equal({"a" => "1"}, call("GET", "/api/v1/namespaces/dev/configmaps/fresh").body["data"])
  end

  def test_a_merge_patch_to_a_missing_status_is_still_not_found
    response = call("PATCH", "/api/v1/namespaces/gone/status", {"status" => {"phase" => "Active"}},
                    headers: {"Content-Type" => "application/merge-patch+json"})

    assert_equal 404, response.status
  end

  def test_service_status_strategic_patch_preserves_other_finalizers_and_can_remove_the_last_one
    path = "/api/v1/namespaces/dev/services/with-finalizers"
    service = {"metadata" => {"name" => "with-finalizers", "finalizers" => ["example.test/hold"]},
               "spec" => {"ports" => [{"port" => 80}]}}

    assert_equal 201, call("POST", "/api/v1/namespaces/dev/services", service).status

    cloud = "service.kubernetes.io/load-balancer-cleanup"
    strategic = {"Content-Type" => "application/strategic-merge-patch+json"}
    added = call("PATCH", "#{path}/status", {"metadata" => {"finalizers" => [cloud]}}, headers: strategic)

    assert_equal 200, added.status
    assert_equal ["example.test/hold", cloud].sort, added.body.dig("metadata", "finalizers").sort
    call("DELETE", path)

    update = call("PATCH", "#{path}/status", {"metadata" => {"$deleteFromPrimitiveList/finalizers" => [cloud]}}, headers: strategic)

    assert_equal 200, update.status
    assert_equal ["example.test/hold"], update.body.dig("metadata", "finalizers")
    assert_equal 200, call("GET", path).status

    assert_equal 200, call("PATCH", "#{path}/status", {"metadata" => {"finalizers" => nil}}, headers: strategic).status
    assert_equal 404, call("GET", path).status
  end
end
