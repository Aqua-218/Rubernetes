# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/crd_aggregation_harness"

class CRDOpenAPIRoutesTest < Minitest::Test
  include CRDAggregationHarness

  GROUP = "alerts-east.example"
  API_PATH = "/apis/#{GROUP}/v1".freeze
  ALARM = "example.alerts-east.v1.Alarm"
  METADATA = "io.k8s.apimachinery.pkg.apis.meta.v1"
  SCALE = "io.k8s.api.autoscaling.v1.Scale"

  def test_namespaced_public_document_carries_all_collection_and_item_operations
    doc = publish_document("Namespaced", subresources: true)
    namespace = "#{API_PATH}/namespaces/{namespace}/alarms"
    cluster = doc.fetch("paths").fetch("#{API_PATH}/alarms")
    collection = doc.fetch("paths").fetch(namespace)
    item = doc.fetch("paths").fetch("#{namespace}/{name}")

    assert_equal %w[get parameters], cluster.keys.sort
    assert_equal "listAlertsEastExampleV1AlarmForAllNamespaces", cluster.dig("get", "operationId")
    assert_equal ["alertsEastExample_v1"], cluster.dig("get", "tags")
    assert_equal "#/components/schemas/example.alerts-east.v1.AlarmBag", schema_ref(cluster.dig("get", "responses", "200"))
    refute cluster.fetch("get").key?("parameters")
    assert_includes parameter_names(cluster), "shardSelector"
    assert_equal %w[delete get parameters post], collection.keys.sort
    assert_equal %w[namespace pretty], parameter_names(collection)
    assert_equal parameter_names(collection.fetch("get")), parameter_names(collection.fetch("delete"))
    assert_equal "deleteAlertsEastExampleV1CollectionNamespacedAlarm", collection.dig("delete", "operationId")
    refute collection.fetch("delete").key?("requestBody")
    assert_equal "create an Alarm", collection.dig("post", "description")
    assert_equal %w[200 201 202 401], collection.dig("post", "responses").keys.sort
    assert_equal %w[application/json application/yaml], collection.dig("post", "requestBody", "content").keys.sort
    assert_equal "#/components/schemas/#{METADATA}.DeleteOptions", schema_ref(item.dig("delete", "requestBody"))
    refute item.dig("delete", "requestBody").key?("required")
    assert_equal "#/components/schemas/#{METADATA}.Status", schema_ref(item.dig("delete", "responses", "202"))
    assert_equal ["resourceVersion"], parameter_names(item.fetch("get"))
    assert_equal %w[dryRun fieldManager fieldValidation force], parameter_names(item.fetch("patch"))
  end

  def test_subresources_document_scale_bodies_patch_media_and_transitive_references
    doc = publish_document("Namespaced", subresources: true)
    paths = doc.fetch("paths")
    name = "#{API_PATH}/namespaces/{namespace}/alarms/{name}"
    status = paths.fetch("#{name}/status")
    scale = paths.fetch("#{name}/scale")

    assert_equal %w[get parameters patch put], status.keys.sort
    assert_equal %w[get parameters patch put], scale.keys.sort
    assert_equal "readAlertsEastExampleV1NamespacedAlarmScale", scale.dig("get", "operationId")
    assert_equal({"group" => GROUP, "version" => "v1", "kind" => "Alarm"}, scale.dig("get", "x-kubernetes-group-version-kind"))
    assert_equal "read scale of the specified Alarm", scale.dig("get", "description")
    assert_equal "#/components/schemas/#{ALARM}", schema_ref(status.dig("put", "requestBody"))
    assert_equal "#/components/schemas/#{SCALE}", schema_ref(scale.dig("put", "requestBody"))
    assert_equal "#/components/schemas/#{SCALE}", schema_ref(scale.dig("put", "responses", "201"), "application/yaml")
    patch_body = scale.dig("patch", "requestBody")
    media = %w[application/apply-patch+yaml application/json-patch+json application/merge-patch+json]

    assert_equal media, patch_body.fetch("content").keys.sort
    media.each { |type| assert_equal "#/components/schemas/#{METADATA}.Patch", schema_ref(patch_body, type) }
    schemas = doc.dig("components", "schemas")
    references = JSON.generate(doc).scan(%r{"\$ref":"#/components/schemas/([^"]+)"}).flatten.uniq

    assert_empty references - schemas.keys
    assert schemas.key?("io.k8s.api.autoscaling.v1.ScaleSpec")
    assert schemas.key?("io.k8s.api.autoscaling.v1.ScaleStatus")
    delete_gvks = schemas.dig("#{METADATA}.DeleteOptions", "x-kubernetes-group-version-kind")

    assert_includes delete_gvks, {"group" => "apps", "version" => "v1beta2", "kind" => "DeleteOptions"}
    refute_includes delete_gvks, {"group" => "apiextensions.k8s.io", "version" => "v1", "kind" => "DeleteOptions"}
  end

  def test_cluster_scoped_document_has_one_collection_and_no_unserved_subresources
    document = publish_document("Cluster", subresources: false)
    collection = "#{API_PATH}/alarms"
    paths = document.fetch("paths")

    assert_equal [collection, "#{collection}/{name}"], paths.keys.sort
    assert_equal "listAlertsEastExampleV1Alarm", paths.dig(collection, "get", "operationId")
    assert_equal ["pretty"], parameter_names(paths.fetch(collection))
    assert_equal %w[name pretty], parameter_names(paths.fetch("#{collection}/{name}"))
    refute document.fetch("components").fetch("schemas").key?(SCALE)
  end

  private

  def publish_document(scope, subresources:)
    object = crd(name: "alarms.#{GROUP}")
    spec = object.fetch("spec")
    spec["group"] = GROUP
    spec["scope"] = scope
    spec["names"] = {"plural" => "alarms", "singular" => "alarm", "kind" => "Alarm", "listKind" => "AlarmBag"}
    version = spec.fetch("versions").first
    if subresources
      version.dig("schema", "openAPIV3Schema", "properties", "status", "properties")["replicas"] = {"type" => "integer"}
      version.fetch("subresources")["scale"] = {"specReplicasPath" => ".spec.size", "statusReplicasPath" => ".status.replicas"}
    else
      version.delete("subresources")
    end
    response = call("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", body: object)

    assert_equal 201, response.status, response.body.inspect
    published = call("GET", "/openapi/v3#{API_PATH}")

    assert_equal 200, published.status, published.body.inspect
    published.body
  end

  def parameter_names(item) = item.fetch("parameters").map { |option| option.fetch("name") }

  def schema_ref(property, media = "application/json") = property.dig("content", media, "schema", "$ref")
end
