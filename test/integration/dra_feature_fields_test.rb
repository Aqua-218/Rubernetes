# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class DRAFeatureFieldsTest < Minitest::Test
  API = Rubernetes::API
  SLICES = "/apis/resource.k8s.io/v1/resourceslices"
  PODS = "/api/v1/namespaces/default/pods"

  def server(gates, store = API::MemoryStore.new)
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    API::Server.new(store: store, registry: registry, feature_gates: gates)
  end

  def request(server, method, path, object)
    content_type = method == "PATCH" ? "application/merge-patch+json" : "application/json"
    server.call(API::Request.new(method: method, path: path, headers: {"content-type" => content_type},
                                 body: JSON.generate(object), identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def slice(device, name: "node-a")
    {"apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceSlice", "metadata" => {"name" => name},
     "spec" => {"driver" => "driver.example.com", "nodeName" => "node-a", "devices" => [device.merge("name" => "device-a")],
                "pool" => {"name" => "pool-a", "generation" => 1, "resourceSliceCount" => 1}}}
  end

  def pod
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "consumer"},
     "spec" => {"containers" => [{"name" => "main", "image" => "nginx", "resources" => {"claims" => [{"name" => "gpu"}]}}],
                "resourceClaims" => [{"name" => "gpu", "resourceClaimName" => "gpu-instance"}]}}
  end

  def test_list_attributes_are_validated_and_persisted_when_enabled
    device = {"attributes" => {"zones" => {"strings" => %w[blue red]}}}
    disabled = server({"DRAListTypeAttributes" => false})
    enabled = server({"DRAListTypeAttributes" => true})

    rejected = request(disabled, "POST", SLICES, slice(device))

    assert_equal 422, rejected.status, rejected.body.inspect
    created = request(enabled, "POST", SLICES, slice(device))

    assert_equal 201, created.status, created.body.inspect
    assert_equal %w[blue red], created.body.dig("spec", "devices", 0, "attributes", "zones", "strings")
  end

  def test_node_allocatable_fields_are_gated_on_slice_and_pod_status_writes
    store = API::MemoryStore.new
    disabled = server({"DRANodeAllocatableResources" => false}, store)
    enabled = server({"DRANodeAllocatableResources" => true}, store)
    device = {"nodeAllocatableResourceMappings" => {"cpu" => {"allocationMultiplier" => "2"}}}
    response = request(disabled, "POST", SLICES, slice(device))

    assert_equal 201, response.status, response.body.inspect
    assert_nil response.body.dig("spec", "devices", 0, "nodeAllocatableResourceMappings")
    response = request(enabled, "POST", SLICES, slice(device, name: "node-b"))

    assert_equal 201, response.status, response.body.inspect
    assert_equal "2", response.body.dig("spec", "devices", 0, "nodeAllocatableResourceMappings", "cpu", "allocationMultiplier")

    created = request(disabled, "POST", PODS, pod)

    assert_equal 201, created.status, created.body.inspect
    path = "#{PODS}/consumer/status"
    claims = [{"resourceClaimName" => "gpu-instance", "containers" => ["main"], "resources" => {"cpu" => "2"}}]
    patch = {"status" => {"nodeAllocatableResourceClaimStatuses" => claims}}
    response = request(disabled, "PATCH", path, patch)

    assert_equal 200, response.status, response.body.inspect
    assert_nil response.body.dig("status", "nodeAllocatableResourceClaimStatuses")
    response = request(enabled, "PATCH", path, patch)

    assert_equal 200, response.status, response.body.inspect
    assert_equal claims, response.body.dig("status", "nodeAllocatableResourceClaimStatuses")

    response = request(disabled, "PATCH", path, {"status" => {"message" => "ready"}})

    assert_equal 200, response.status, response.body.inspect
    assert_equal claims, response.body.dig("status", "nodeAllocatableResourceClaimStatuses")
  end
end
