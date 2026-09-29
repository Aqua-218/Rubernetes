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
