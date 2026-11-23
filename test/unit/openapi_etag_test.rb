# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# /openapi/v2 carries an ETag and answers a matching If-None-Match with 304,
# and the document (with CRD definitions merged in) is built and encoded once
# per change instead of once per request.
class OpenAPIETagTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @openapi = API::OpenAPIRepository.new
    @server = API::Server.new(registry: API::Registry.new(resources: [], defaults: false),
                              store: Rubernetes::Storage::MemoryStore.new, openapi_repository: @openapi)
  end

  def get(headers = {})
    @server.call(API::Request.new(method: "GET", path: "/openapi/v2", headers: headers, body: nil,
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def publish(kind)
    @openapi.publish(group: "example.com", version: "v1", owner: "#{kind.downcase}s.example.com",
                     document: {"paths" => {}, "components" => {"schemas" => {"com.example.v1.#{kind}" => {"type" => "object"}}}})
  end

  def test_etag_and_not_modified
    first = get

    assert_equal 200, first.status
    etag = first.header("etag")

    assert_match(/\A"[0-9A-F]{128}"\z/, etag)
    assert_kind_of Hash, first.body, "in-process callers still get the decoded document"
    assert_equal JSON.generate(first.body), first.encoded_body

    again = get("if-none-match" => etag)

    assert_equal 304, again.status
    assert_equal etag, again.header("etag")
  end

  def test_swagger_media_selection_and_conditional_get_match_kube_openapi
    canonical = API::OpenAPIV2Protobuf::CONTENT_TYPE
    legacy = API::OpenAPIV2Protobuf::DEPRECATED_TYPE
    json = get("accept" => "application/json;q=0.9, #{legacy};q=0.1")
    proto = get("accept" => legacy)

    assert_equal "application/json", json.content_type
    assert_equal canonical, proto.content_type
    assert_equal "Accept-Encoding, Accept", proto.header("vary")
    assert_equal json.header("etag"), proto.header("etag")
    assert_equal canonical, get("accept" => "#{canonical};q=0").content_type
    cached = get("accept" => legacy, "if-none-match" => json.header("etag"))

    assert_equal 304, cached.status
    assert_nil cached.content_type
    missing = get("accept" => "text/plain")

    assert_equal 406, missing.status
    assert_nil missing.content_type
    assert_equal "", missing.body
    assert_equal "Accept-Encoding, Accept", missing.header("vary")
  end

  def test_publishing_a_definition_changes_the_etag_and_the_document
    publish("Widget")
    before = get

    assert before.body["definitions"].key?("com.example.v1.Widget")

    publish("Gadget")
    after = get("if-none-match" => before.header("etag"))

    assert_equal 200, after.status, "a stale ETag gets the new document"
    refute_equal before.header("etag"), after.header("etag")
    assert after.body["definitions"].key?("com.example.v1.Gadget")
  end

  def test_group_caches_follow_the_document_across_publish_and_withdraw
    path = "/openapi/v3/apis/example.com/v1"
    index_url = -> { @openapi.document_for("/openapi/v3").dig("paths", "apis/example.com/v1", "serverRelativeURL") }
    publish("Widget")
    original = @openapi.document_for(path)
    original_url = index_url.call
    bytes, etag = @openapi.encoded_group(path, original, :json) { flunk "published JSON should be reused" }

    assert_equal JSON.generate(original), bytes
    assert_equal "#{path}?hash=#{etag}", original_url
    publish("Gadget")

    refute_equal original_url, index_url.call
    assert_equal :unpublished, @openapi.encoded_group(path, original, :json) { :unpublished }
    @openapi.withdraw(group: "example.com", version: "v1", owner: "gadgets.example.com")

    assert_equal original_url, index_url.call
    current = @openapi.document_for(path)
    @openapi.withdraw(group: "example.com", version: "v1")

    assert_nil index_url.call
    assert_equal :unpublished, @openapi.encoded_group(path, current, :json) { :unpublished }
  end

  def test_the_merged_document_is_reused_until_something_changes
    publish("Widget")

    assert_same @openapi.document_for("/openapi/v2"), @openapi.document_for("/openapi/v2")
    first = @openapi.document_for("/openapi/v2")
    @openapi.withdraw(group: "example.com", version: "v1", owner: "widgets.example.com")

    refute_same first, @openapi.document_for("/openapi/v2")
    refute @openapi.document_for("/openapi/v2")["definitions"].key?("com.example.v1.Widget")
  end
end

# The HTTP layer sends a response's pre-encoded bytes instead of generating
# the JSON of its decoded body again.
class TransportEncodedBodyTest < Minitest::Test
  def test_pre_encoded_bytes_are_sent
    require "rubernetes/transport"
    server = Rubernetes::Transport::HTTPServer.allocate
    api_response = Rubernetes::API::Response.new(status: 200, headers: {"content-type" => "application/json"},
                                                 body: {"a" => 1}, encoded_body: "{\"a\":1}")
    normalized = server.send(:normalize_response, api_response)

    assert_equal "{\"a\":1}", normalized.body
  end
end

class OpenAPIV3ProtobufTest < Minitest::Test
  API = Rubernetes::API
  WIRE = Rubernetes::Schema::Codec::Protobuf
  PODS_PATH = "/openapi/v3/api/v1"

  def setup
    @server = API::Server.new(openapi_repository: API::OpenAPIRepository.new)
  end

  def get(path, headers = {})
    @server.call(API::Request.new(method: "GET", path: path, headers: headers,
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def test_group_document_protobuf_shares_json_etag
    json = get(PODS_PATH)
    headers = {"accept" => API::OpenAPIV3Protobuf::DEPRECATED_TYPE}
    binary = get(PODS_PATH, headers)

    assert_equal 200, binary.status
    assert_equal API::OpenAPIV3Protobuf::CONTENT_TYPE, binary.content_type
    assert_equal "Accept", binary.header("vary")
    assert_equal json.header("etag"), binary.header("etag")
    assert_equal "3.0.0", WIRE.parse_fields(binary.body).first.fetch(:value)
    assert_equal 304, get(PODS_PATH, headers.merge("if-none-match" => json.header("etag"))).status
  end

  def test_discovery_url_identifies_the_served_document_and_controls_its_cache
    etag = get(PODS_PATH).header("etag")
    url = get("/openapi/v3").body.fetch("paths").fetch("api/v1").fetch("serverRelativeURL")

    assert_equal "#{PODS_PATH}?hash=#{etag.delete('"')}", url
    cached = get(url, {"if-none-match" => etag})

    assert_equal 304, cached.status
    assert_equal "public, immutable", cached.header("cache-control")
    assert_in_delta Time.now.to_i + (365 * 86_400), Time.httpdate(cached.header("expires")).to_i, 86_401
    stale = get("#{PODS_PATH}?hash=outdated", {"if-none-match" => etag})

    assert_equal 301, stale.status
    assert_equal url, stale.header("location")
    assert_equal "no-cache, private", stale.header("cache-control")
  end

  def test_accept_preference_and_json_discovery_index
    json_preferred = {"accept" => "#{API::OpenAPIV3Protobuf::CONTENT_TYPE};q=0.2, application/json;q=0.8"}

    assert_equal "application/json", get(PODS_PATH, json_preferred).content_type
    assert_equal 406, get(PODS_PATH, {"accept" => "image/png"}).status
    index = get("/openapi/v3", {"accept" => API::OpenAPIV3Protobuf::CONTENT_TYPE})

    assert_equal "application/json", index.content_type
    assert index.body.dig("paths", "api/v1", "serverRelativeURL")
  end
end
