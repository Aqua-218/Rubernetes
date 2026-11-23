# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

class CRDObjectMetaTimeTest < Minitest::Test
  API = Rubernetes::API
  CRDS = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions"
  CUSTOM = "/apis/apps.example.com/v1/deployments"
  FRACTIONAL = "2026-09-18T05:45:58.843311+02:00"
  SECONDS = "2026-09-18T03:45:58Z"

  def setup
    registry = API::Registry.new(resources: [], defaults: false)
    registry.register(API::Resource.new(group: "apiextensions.k8s.io", version: "v1",
                                        resource: "customresourcedefinitions", kind: "CustomResourceDefinition", scope: :cluster))
    @store = Rubernetes::Storage::MemoryStore.new
    openapi = API::OpenAPIRepository.new
    crd_manager = API::CRD::Manager.new(registry: registry, store: @store, openapi: openapi)
    @server = API::Server.new(registry: registry, store: @store, crd_manager: crd_manager, openapi_repository: openapi,
                              clock: -> { Time.iso8601(FRACTIONAL) })

    response = request("POST", CRDS, body: crd)
    raise response.body.inspect unless response.status == 201
  end

  def test_creation_persists_second_precision_and_preserves_cr_payload
    preview = request("POST", "#{CUSTOM}?dryRun=All", body: widget("new"))
    actual = request("POST", CUSTOM, body: widget("new"))

    assert_equal 201, preview.status, preview.body.inspect
    assert_equal 201, actual.status, actual.body.inspect
    assert_equal SECONDS, preview.body.dig("metadata", "creationTimestamp")
    assert_equal SECONDS, actual.body.dig("metadata", "creationTimestamp")
    assert_equal SECONDS, @store.get(key("new")).dig("metadata", "creationTimestamp")
    assert_payload actual.body
  end

  def test_update_preserves_custom_payload_timestamps_for_an_overlapping_builtin_kind
    response = request("POST", CUSTOM, body: widget("test"))

    assert_equal 201, response.status, response.body.inspect

    created = response.body
    resource_version = created.dig("metadata", "resourceVersion")
    candidate = created.merge("metadata" => created.fetch("metadata").merge("creationTimestamp" => FRACTIONAL))
    unchanged = request("PUT", "#{CUSTOM}/test", body: candidate)

    assert_equal 200, unchanged.status, unchanged.body.inspect
    assert_equal resource_version, unchanged.body.dig("metadata", "resourceVersion")
    assert_payload unchanged.body

    candidate = candidate.merge("spec" => candidate.fetch("spec").merge("updated" => true))
    updated = request("PUT", "#{CUSTOM}/test", body: candidate)

    assert_equal 200, updated.status, updated.body.inspect
    refute_equal resource_version, updated.body.dig("metadata", "resourceVersion")
    assert updated.body.dig("spec", "updated")
    assert_equal SECONDS, updated.body.dig("metadata", "creationTimestamp")
    assert_payload updated.body
    assert_payload @store.get(key("test"))
  end

  def test_legacy_root_times_are_normalized_for_get_list_watch_and_partial_metadata
    revision = @store.revision
    @store.create(key("legacy"), legacy_widget)
    response = request("GET", "#{CUSTOM}/legacy")
    list = request("GET", CUSTOM)
    watch = request("GET", "#{CUSTOM}?watch=true&resourceVersion=#{revision}")
    event = watch.body.next(timeout: 0)
    partial = request("GET", "#{CUSTOM}/legacy", headers: {
                        "accept" => "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"
                      })

    assert_equal 200, response.status, response.body.inspect
    assert_equal 200, list.status, list.body.inspect
    assert_equal 200, watch.status
    assert_equal "ADDED", event.type
    assert_equal 200, partial.status, partial.body.inspect
    assert_equal "PartialObjectMetadata", partial.body.fetch("kind")
    [response.body, list.body.fetch("items").first, event.object].each do |object|
      assert_object_times object
      assert_payload object
    end
    assert_object_times partial.body
    assert_equal FRACTIONAL, @store.get(key("legacy")).dig("metadata", "creationTimestamp")
  ensure
    watch&.body&.close
  end

  def test_legacy_zero_and_null_values_follow_object_meta_wire_rules
    metadata = {
      "name" => "zero", "creationTimestamp" => "0001-01-01T01:00:00+01:00", "deletionTimestamp" => nil,
      "managedFields" => [
        {"manager" => "zero", "time" => "0001-01-01T00:00:00Z"},
        {"manager" => "unset", "time" => nil}
      ]
    }
    @store.create(key("zero"), widget("zero").merge("metadata" => metadata))
    response = request("GET", "#{CUSTOM}/zero")
    metadata = response.body.fetch("metadata")

    assert_equal 200, response.status
    refute metadata.key?("creationTimestamp")
    refute metadata.key?("deletionTimestamp")
    assert metadata.fetch("managedFields").first.key?("time")
    assert_nil metadata.dig("managedFields", 0, "time")
    refute metadata.fetch("managedFields").last.key?("time")
  end

  private

  def request(method, path, body: nil, headers: {})
    headers = {"content-type" => "application/json"}.merge(headers) if body
    @server.call(API::Request.new(method: method, path: path, body: body && JSON.generate(body), headers: headers))
  end

  def crd
    schema = {"type" => "object", "x-kubernetes-preserve-unknown-fields" => true}
    version = {"name" => "v1", "served" => true, "storage" => true, "schema" => {"openAPIV3Schema" => schema}}
    names = {"kind" => "Deployment", "plural" => "deployments", "singular" => "deployment"}
    {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition",
     "metadata" => {"name" => "deployments.apps.example.com"},
     "spec" => {"group" => "apps.example.com", "scope" => "Cluster", "names" => names, "versions" => [version]}}
  end

  def widget(name)
    template = {"metadata" => {"creationTimestamp" => FRACTIONAL},
                "spec" => {"containers" => [{"name" => "app", "image" => "example/app"}]}}
    {"apiVersion" => "apps.example.com/v1", "kind" => "Deployment", "metadata" => {"name" => name},
     "spec" => {"template" => template},
     "status" => {"conditions" => [{"lastUpdateTime" => FRACTIONAL}]}}
  end

  def key(name)
    "registry/apps.example.com/__stored__/deployments/_cluster/#{name}"
  end

  def legacy_widget
    metadata = {
      "name" => "legacy", "creationTimestamp" => FRACTIONAL, "deletionTimestamp" => "2026-09-18T05:45:58+02:00",
      "managedFields" => [{"manager" => "legacy", "time" => FRACTIONAL, "fieldsV1" => {"f:time" => {}}}]
    }
    widget("legacy").merge("metadata" => metadata)
  end

  def assert_object_times(object)
    assert_equal SECONDS, object.dig("metadata", "creationTimestamp")
    assert_equal SECONDS, object.dig("metadata", "deletionTimestamp")
    assert_equal SECONDS, object.dig("metadata", "managedFields", 0, "time")
    assert_equal({"f:time" => {}}, object.dig("metadata", "managedFields", 0, "fieldsV1"))
  end

  def assert_payload(object)
    assert_equal FRACTIONAL, object.dig("spec", "template", "metadata", "creationTimestamp")
    assert_equal FRACTIONAL, object.dig("status", "conditions", 0, "lastUpdateTime")
  end
end
