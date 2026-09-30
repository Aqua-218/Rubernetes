# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# Server-side printing through the API: `kubectl get` asks for
# application/json;as=Table;v=v1;g=meta.k8s.io.  The cells themselves are
# checked against upstream by tools/differential/printers_differential.rb;
# these cover what the server adds around the convertor: the includeObject
# check, meta.k8s.io/v1beta1, the default convertor, watch events (headers
# on the first only), and the PartialObjectMetadata kind checks.
class APITableConversionTest < Minitest::Test
  API = Rubernetes::API
  TABLE = "application/json;as=Table;v=v1;g=meta.k8s.io"

  def setup
    registry = API::Registry.new(resources: API::Registry.new.resources + [API::Resource.new(version: "v1", resource: "limitranges",
                                                                                             kind: "LimitRange", namespaced: true)])
    @server = API::Server.new(registry: registry, store: API::MemoryStore.new, namespace_lifecycle: true)
    call("POST", "/api/v1/namespaces", body: {"metadata" => {"name" => "dev"}})
    call("POST", "/api/v1/namespaces/dev/configmaps", body: {"metadata" => {"name" => "one"}, "data" => {"a" => "1", "b" => "2"}})
  end

  def call(method, path, body: nil, accept: nil)
    headers = accept ? {"accept" => accept} : {}
    @server.call(API::Request.new(method: method, path: path, body: body, headers: headers))
  end

  def test_configmap_list_prints_upstream_columns
    response = call("GET", "/api/v1/namespaces/dev/configmaps", accept: TABLE)

    assert_equal 200, response.status
    table = response.body

    assert_equal %w[Table meta.k8s.io/v1], table.values_at("kind", "apiVersion")
    assert_equal(%w[Name Data Age], table["columnDefinitions"].map { |column| column["name"] })
    assert_equal ["one", 2], table["rows"].first["cells"].first(2)
    assert_equal "PartialObjectMetadata", table["rows"].first.dig("object", "kind")
  end

  def test_include_object_none_and_object
    none = call("GET", "/api/v1/namespaces/dev/configmaps/one?includeObject=None", accept: TABLE).body

    refute none["rows"].first.key?("object")
    object = call("GET", "/api/v1/namespaces/dev/configmaps/one?includeObject=Object", accept: TABLE).body

    assert_equal "ConfigMap", object["rows"].first.dig("object", "kind")
  end

  def test_an_unknown_include_object_is_a_bad_request
    response = call("GET", "/api/v1/namespaces/dev/configmaps?includeObject=Everything", accept: TABLE)

    assert_equal 400, response.status
    assert_includes response.body["message"], "Unable to convert to Table as requested: includeObject: Invalid value: \"Everything\""
  end

  def test_v1beta1_table_and_partial_rows
    table = call("GET", "/api/v1/namespaces/dev/configmaps", accept: "application/json;as=Table;v=v1beta1;g=meta.k8s.io").body

    assert_equal "meta.k8s.io/v1beta1", table["apiVersion"]
    assert_equal "meta.k8s.io/v1beta1", table["rows"].first.dig("object", "apiVersion")
  end

  def test_kinds_without_a_printer_use_the_default_convertor
    call("POST", "/api/v1/namespaces/dev/limitranges", body: {"metadata" => {"name" => "r"}, "spec" => {"limits" => []}})
    table = call("GET", "/api/v1/namespaces/dev/limitranges", accept: TABLE).body

    assert_equal(["Name", "Created At"], table["columnDefinitions"].map { |column| column["name"] })
    assert_match(/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\z/, table["rows"].first["cells"][1])
  end

  def test_watch_events_are_tables_with_headers_on_the_first_only
    call("POST", "/api/v1/namespaces/dev/configmaps", body: {"metadata" => {"name" => "two"}})
    response = call("GET", "/api/v1/namespaces/dev/configmaps?watch=true&timeoutSeconds=0", accept: TABLE)
    events = response.body.to_a

    assert_operator events.length, :>=, 2
    tables = events.map { |event| event["object"] }

    assert(tables.all? { |table| table["kind"] == "Table" })
    refute_nil tables.first["columnDefinitions"]
    assert(tables.drop(1).all? { |table| table["columnDefinitions"].nil? })
  end

  def test_watch_events_as_partial_object_metadata
    response = call("GET", "/api/v1/namespaces/dev/configmaps?watch=true&timeoutSeconds=0",
                    accept: "application/json;as=PartialObjectMetadata;v=v1;g=meta.k8s.io")
    object = response.body.to_a.first["object"]

    assert_equal %w[PartialObjectMetadata meta.k8s.io/v1], object.values_at("kind", "apiVersion")
    assert_equal "one", object.dig("metadata", "name")
  end

  def test_partial_object_metadata_kind_must_match_list_or_object
    list_as_object = call("GET", "/api/v1/namespaces/dev/configmaps",
                          accept: "application/json;as=PartialObjectMetadata;v=v1;g=meta.k8s.io")

    assert_equal 406, list_as_object.status
    object_as_list = call("GET", "/api/v1/namespaces/dev/configmaps/one",
                          accept: "application/json;as=PartialObjectMetadataList;v=v1;g=meta.k8s.io")

    assert_equal 406, object_as_list.status
    list = call("GET", "/api/v1/namespaces/dev/configmaps", accept: "application/json;as=PartialObjectMetadataList;v=v1;g=meta.k8s.io").body

    assert_equal "PartialObjectMetadataList", list["kind"]
    assert_equal ["resourceVersion"], list["metadata"].keys
  end
end
