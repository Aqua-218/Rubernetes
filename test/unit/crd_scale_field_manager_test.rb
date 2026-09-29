# frozen_string_literal: true

# A custom resource's scale subresource (apiextensions customresource
# ScaleREST, v1.36.2): the Scale reads specReplicasPath, statusReplicasPath
# and labelSelectorPath, writes go to specReplicasPath, the field manager's
# scale entries map onto that path, and a resource that never had replicas
# answers GET with an internal error.

require_relative "../test_helper"
require_relative "../support/crd_aggregation_harness"

class CRDScaleFieldManagerTest < Minitest::Test
  include CRDAggregationHarness

  def scaled_crd
    schema = {"type" => "object", "properties" => {
      "spec" => {"type" => "object", "properties" => {"count" => {"type" => "integer"}, "size" => {"type" => "integer"}}},
      "status" => {"type" => "object", "properties" => {"count" => {"type" => "integer"}, "selector" => {"type" => "string"}}}
    }}
    {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition", "metadata" => {"name" => "pools.example.com"},
     "spec" => {"group" => "example.com", "scope" => "Namespaced",
                "names" => {"plural" => "pools", "singular" => "pool", "kind" => "Pool"},
                "versions" => [{"name" => "v1", "served" => true, "storage" => true, "schema" => {"openAPIV3Schema" => schema},
                                "subresources" => {"status" => {}, "scale" => {"specReplicasPath" => ".spec.count",
                                                                               "statusReplicasPath" => ".status.count",
                                                                               "labelSelectorPath" => ".status.selector"}}}]}}
  end

  POOLS = "/apis/example.com/v1/namespaces/team/pools"

  def setup_pool
    call("POST", "/api/v1/namespaces", body: {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "team"}})
    assert_equal 201, call("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", body: scaled_crd).status
    assert wait_until { call("GET", POOLS).status == 200 }
  end

  def test_scale_reads_and_writes_the_crd_paths
    setup_pool
    pool = {"apiVersion" => "example.com/v1", "kind" => "Pool", "metadata" => {"name" => "p"}, "spec" => {"count" => 2, "size" => 1}}
    assert_equal 201, call("POST", "#{POOLS}?fieldManager=creator", body: pool).status
    call("PATCH", "#{POOLS}/p/status", body: {"status" => {"count" => 1, "selector" => "app=p"}},
                                       headers: {"content-type" => "application/merge-patch+json"})

    scale = call("GET", "#{POOLS}/p/scale").body
    assert_equal({"replicas" => 2}, scale["spec"])
    assert_equal({"replicas" => 1, "selector" => "app=p"}, scale["status"])

    scale["spec"]["replicas"] = 5
    response = call("PUT", "#{POOLS}/p/scale?fieldManager=scaler", body: scale)
    assert_equal 200, response.status, response.body.inspect
    stored = call("GET", "#{POOLS}/p").body
    assert_equal 5, stored.dig("spec", "count")
    refute stored["spec"].key?("replicas")
    entry = stored.dig("metadata", "managedFields").find { |item| item["manager"] == "scaler" }
    assert_equal({"f:spec" => {"f:count" => {}}}, entry["fieldsV1"])
    assert_equal ["example.com/v1", "scale"], entry.values_at("apiVersion", "subresource")
    creator = stored.dig("metadata", "managedFields").find { |item| item["manager"] == "creator" }
    refute creator["fieldsV1"]["f:spec"].key?("f:count"), "the scaler took .spec.count from the creator"
  end

  def test_a_resource_without_replicas
    setup_pool
    pool = {"apiVersion" => "example.com/v1", "kind" => "Pool", "metadata" => {"name" => "empty"}, "spec" => {"size" => 1}}
    assert_equal 201, call("POST", POOLS, body: pool).status
    response = call("GET", "#{POOLS}/empty/scale")
    assert_equal 500, response.status
    assert_equal "Internal error occurred: the spec replicas field \".spec.count\" does not exist", response.body["message"]

    patched = call("PATCH", "#{POOLS}/empty/scale", body: {"metadata" => {"labels" => {"a" => "b"}}},
                                                    headers: {"content-type" => "application/merge-patch+json"})
    assert_equal 400, patched.status
    assert_equal "the spec replicas field \".spec.count\" cannot be empty", patched.body["message"]
  end
end
