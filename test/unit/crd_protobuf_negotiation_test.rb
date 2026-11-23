# frozen_string_literal: true

require "json"
require "timeout"
require_relative "../test_helper"
require "rubernetes/api"

class CRDProtobufNegotiationTest < Minitest::Test
  API = Rubernetes::API
  PROTOBUF = API::Negotiation::PROTOBUF_TYPE
  JSON_TYPE = API::Negotiation::JSON_TYPE
  GROUP = "apps.example.com"
  COLLECTION = "/apis/#{GROUP}/v1/deployments".freeze
  MEMBER = "#{COLLECTION}/example".freeze
  CRDS = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions"

  def setup
    registry = API::Registry.new(resources: [], defaults: false)
    registry.register(API::Resource.new(group: "apiextensions.k8s.io", version: "v1",
                                        resource: "customresourcedefinitions", kind: "CustomResourceDefinition", scope: :cluster))
    @store = Rubernetes::Storage::MemoryStore.new
    openapi = API::OpenAPIRepository.new
    manager = API::CRD::Manager.new(registry: registry, store: @store, openapi: openapi)
    @server = API::Server.new(registry: registry, store: @store, crd_manager: manager, openapi_repository: openapi)
    @codec = API::StoreAdapter.time_codec
    scale = {"specReplicasPath" => ".spec.replicas", "statusReplicasPath" => ".status.replicas"}
    register_crd("Deployment", "deployments", subresources: {"status" => {}, "scale" => scale})
    seed("Deployment", "deployments")
  end

  def test_custom_get_list_and_subresources_reject_plain_protobuf_and_fall_back_to_json
    [MEMBER, COLLECTION, "#{MEMBER}/status", "#{MEMBER}/scale"].each do |path|
      assert_not_acceptable get(path, accept: PROTOBUF)
      response = get(path, accept: "#{PROTOBUF}, #{JSON_TYPE}")

      assert_equal 200, response.status, path
      assert_equal JSON_TYPE, response.header("content-type"), path
      assert_equal 2, response.body.dig("spec", "replicas") if path == "#{MEMBER}/scale"
    end

    assert_equal "opaque", get(MEMBER, accept: "#{PROTOBUF}, #{JSON_TYPE}").body.dig("spec", "extension")
  end

  def test_custom_watch_rejects_plain_protobuf_and_json_fallback_keeps_the_object
    path = "#{COLLECTION}?watch=1&resourceVersion=0"

    assert_not_acceptable get(path, accept: PROTOBUF)
    response = get(path, accept: "#{PROTOBUF}, #{JSON_TYPE}")
    event = response.body.next(timeout: 0)

    assert_equal 200, response.status
    assert_equal JSON_TYPE, response.header("content-type")
    assert_equal "ADDED", event.type
    assert_equal "opaque", event.object.dig("spec", "extension")
  ensure
    response&.body&.close
  end

  def test_typed_protobuf_metadata_and_errors_are_still_available
    response = get(MEMBER, accept: "#{PROTOBUF}, #{metadata_accept}, #{JSON_TYPE}")
    list = get(COLLECTION, accept: metadata_accept("PartialObjectMetadataList"))
    error = get("#{COLLECTION}/missing", accept: "#{PROTOBUF}, #{JSON_TYPE}")

    assert_equal 200, response.status
    assert_equal PROTOBUF, response.header("content-type")
    assert_metadata(@codec.decode(response.body))
    assert_equal 200, list.status
    assert_equal PROTOBUF, list.header("content-type")
    decoded_list = @codec.decode(list.body)

    assert_equal "PartialObjectMetadataList", decoded_list.fetch("kind")
    assert_equal "example", decoded_list.dig("items", 0, "metadata", "name")
    assert_equal 404, error.status
    assert_equal PROTOBUF, error.header("content-type")
    assert_equal "NotFound", @codec.decode(error.body).fetch("reason")
  end

  def test_missing_custom_resource_keeps_the_error_when_metadata_is_requested
    path = "#{COLLECTION}/missing"
    [metadata_accept, "#{metadata_accept}, #{JSON_TYPE}"].each do |accept|
      response = get(path, accept: accept)

      assert_equal 404, response.status
      assert_equal JSON_TYPE, response.header("content-type")
      assert_equal "Status", response.body.fetch("kind")
      assert_equal "NotFound", response.body.fetch("reason")
    end
  end

  def test_a_custom_kind_named_status_can_be_transformed_in_get_and_watch
    register_crd("Status", "statuses")
    seed("Status", "statuses")
    path = "/apis/#{GROUP}/v1/statuses"

    assert_not_acceptable get("#{path}/example", accept: PROTOBUF)
    response = get("#{path}/example", accept: metadata_accept)
    watch = get("#{path}?watch=1&resourceVersion=0", accept: metadata_accept)
    frame = Timeout.timeout(2) { watch.body.next }

    assert_equal 200, response.status
    assert_metadata(@codec.decode(response.body))
    assert_equal 200, watch.status
    assert_equal "#{PROTOBUF};stream=watch", watch.header("content-type")
    event = @codec.decode_watch_frames(frame).first

    assert_equal "ADDED", event.fetch("type")
    assert_metadata(event.fetch("object"))
  ensure
    watch&.body&.close
  end

  private

  def metadata_accept(kind = "PartialObjectMetadata")
    "#{PROTOBUF};as=#{kind};g=meta.k8s.io;v=v1"
  end

  def get(path, accept:)
    @server.call(API::Request.new(method: "GET", path: path, headers: {"accept" => accept}))
  end

  def register_crd(kind, plural, subresources: nil)
    schema = {"type" => "object", "x-kubernetes-preserve-unknown-fields" => true}
    version = {"name" => "v1", "served" => true, "storage" => true, "schema" => {"openAPIV3Schema" => schema}}
    version["subresources"] = subresources if subresources
    names = {"kind" => kind, "plural" => plural, "singular" => kind.downcase}
    body = {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition",
            "metadata" => {"name" => "#{plural}.#{GROUP}"},
            "spec" => {"group" => GROUP, "scope" => "Cluster", "names" => names, "versions" => [version]}}
    response = @server.call(API::Request.new(method: "POST", path: CRDS, body: JSON.generate(body),
                                             headers: {"content-type" => JSON_TYPE}))
    raise response.body.inspect unless response.status == 201
  end

  def seed(kind, plural)
    @store.create("registry/#{GROUP}/__stored__/#{plural}/_cluster/example",
                  {"apiVersion" => "#{GROUP}/v1", "kind" => kind, "metadata" => {"name" => "example"},
                   "spec" => {"replicas" => 2, "extension" => "opaque"}, "status" => {"replicas" => 1}})
  end

  def assert_not_acceptable(response)
    assert_equal 406, response.status
    assert_equal PROTOBUF, response.header("content-type")
    status = @codec.decode(response.body)

    assert_equal "Status", status.fetch("kind")
    assert_equal "NotAcceptable", status.fetch("reason")
  end

  def assert_metadata(object)
    assert_equal "PartialObjectMetadata", object.fetch("kind")
    assert_equal "example", object.dig("metadata", "name")
    refute object.key?("spec")
  end
end
