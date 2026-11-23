# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

class SecretStringDataTest < Minitest::Test
  SECRETS = "/api/v1/namespaces/default/secrets"
  PATCH = {"content-type" => "application/merge-patch+json"}.freeze

  def setup
    @registry = Rubernetes::API::Registry.new
    @store = Rubernetes::API::MemoryStore.new
    @server = Rubernetes::API::Server.new(registry: @registry, store: @store)
  end

  def call(method, path = SECRETS, body: nil, headers: {}, query: {})
    @server.call(Rubernetes::API::Request.new(method: method, path: path, body: body, headers: headers, query: query))
  end

  def test_post_and_merge_patch_encode_plaintext_before_managed_fields_and_validation
    body = {"metadata" => {"name" => "config"}, "data" => {"duplicate" => "b2xk", "kept" => "AQI="},
            "stringData" => {"duplicate" => "new", "unicode" => "雪", "empty" => ""}}
    created = call("POST", body: body, query: {"fieldManager" => "creator"})

    assert_equal(201, created.status)
    assert_equal({"duplicate" => "bmV3", "kept" => "AQI=", "unicode" => "6Zuq", "empty" => ""}, created.body.fetch("data"))
    refute(created.body.key?("stringData"))
    fields = created.body.dig("metadata", "managedFields", 0, "fieldsV1")

    assert(fields.dig("f:data", "f:duplicate"))
    refute(fields.key?("f:stringData"))

    update = call("PATCH", "#{SECRETS}/config", headers: PATCH, body: {"stringData" => {"duplicate" => "changed"}})

    assert_equal(200, update.status)
    assert_equal("Y2hhbmdlZA==", update.body.dig("data", "duplicate"))
    assert_equal("AQI=", update.body.dig("data", "kept"))
    refute(update.body.key?("stringData"))
  end

  def test_immutable_secret_accepts_equivalent_plaintext_and_rejects_a_changed_value
    created = call("POST", body: {"metadata" => {"name" => "fixed"}, "immutable" => true, "stringData" => {"key" => "same"}})

    assert_equal(201, created.status)
    same = call("PATCH", "#{SECRETS}/fixed", headers: PATCH, body: {"stringData" => {"key" => "same"}})
    changed = call("PATCH", "#{SECRETS}/fixed", headers: PATCH, body: {"stringData" => {"key" => "new"}})

    assert_equal(200, same.status)
    assert_equal(422, changed.status)
    assert_equal("data", changed.body.dig("details", "causes", 0, "field"))
  end

  def test_typed_decoding_precedes_the_plaintext_overwrite
    body = {"metadata" => {"name" => "decode"}, "data" => {"null" => "b2xk", "wrapped" => "YQ==\n"},
            "stringData" => {"null" => nil}}
    decoded = call("POST", body: body)

    assert_equal(201, decoded.status)
    assert_equal({"null" => "", "wrapped" => "YQ=="}, decoded.body.fetch("data"))
    invalid = call("POST", body: {"metadata" => {"name" => "invalid"}, "data" => {"key" => "invalid spelling"},
                                  "stringData" => {"key" => "valid"}})

    assert_equal(400, invalid.status)
    assert_match(/illegal base64 data at input byte 7/, invalid.body.fetch("message"))
  end

  def test_apply_owns_plaintext_fields_separately_and_preserves_the_results_of_an_omitted_plaintext_field
    first = apply("one", {"key" => "owned", "legacy" => "retained"})

    assert_equal(201, first.status)
    assert_equal("b3duZWQ=", first.body.dig("data", "key"))
    assert(first.body.dig("metadata", "managedFields", 0, "fieldsV1", "f:stringData", "f:key"))

    conflict = apply("two", {"key" => "conflicting"})

    assert_equal(409, conflict.status)
    assert_match(/\.stringData\.key/, conflict.body.fetch("message"))

    reapplied = apply("one", {"key" => "replacement"})

    assert_equal(200, reapplied.status)
    assert_equal({"key" => "cmVwbGFjZW1lbnQ=", "legacy" => "cmV0YWluZWQ="}, reapplied.body.fetch("data"))
    refute(reapplied.body.key?("stringData"))
  end

  def test_legacy_secret_is_normalized_on_get_list_and_watch
    secret = @registry.find_gvr(group: "", version: "v1", resource: "secrets")
    @store.create("registry/#{secret.gvr}/default/legacy",
                  {"apiVersion" => "v1", "kind" => "Secret", "metadata" => {"name" => "legacy", "namespace" => "default"},
                   "data" => {"key" => "b2xk"}, "stringData" => {"key" => "old plaintext"}})
    fetched = call("GET", "#{SECRETS}/legacy").body
    listed = call("GET").body.fetch("items").first
    watched = call("GET", query: {"watch" => "true", "resourceVersion" => "0"}).body.to_a.first.object
    [fetched, listed, watched].each do |object|
      assert_equal("b2xkIHBsYWludGV4dA==", object.dig("data", "key"))
      refute(object.key?("stringData"))
    end
  end

  private

  def apply(manager, data)
    body = {"apiVersion" => "v1", "kind" => "Secret", "metadata" => {"name" => "apply"}, "stringData" => data}
    call("PATCH", "#{SECRETS}/apply", body: body, query: {"fieldManager" => manager}, headers: {"content-type" => "application/apply-patch+yaml"})
  end
end
