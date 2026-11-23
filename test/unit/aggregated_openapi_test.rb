# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

class AggregatedOpenAPITest < Minitest::Test
  API = Rubernetes::API
  KEY = "apis/wardle.example.com/v1"
  PATH = "/openapi/v3/#{KEY}".freeze
  NAME = "v1.wardle.example.com"

  class HTTP
    Reply = Struct.new(:code, :body, :headers) do
      def [](name) = headers[name]
      def read_body = yield(body)
    end

    attr_accessor :url, :schema_response
    attr_reader :requests

    def initialize
      @requests = []
      @url = "#{PATH}?hash=123"
    end

    def request(request)
      @requests << request
      index = request.path == "/openapi/v3"
      response = if index
                   Reply.new("200", JSON.generate("paths" => {KEY => {"serverRelativeURL" => @url}}), {"content-type" => "application/json"})
                 elsif schema_response
                   schema_response.call(request)
                 else
                   Reply.new("200", "schema bytes", {"content-type" => "application/octet-stream"})
                 end
      yield response
      response
    end
  end

  def setup
    @http = HTTP.new
    @aggregator = API::Aggregator.new(http_factory: ->(*) { @http })
    @registration = {"metadata" => {"name" => NAME}, "spec" => {"group" => "wardle.example.com", "version" => "v1",
                                                                "service" => {"name" => "wardle", "namespace" => "default"}}}
    @backend = @aggregator.sync(@registration)
    @aggregator.mark_available(NAME, true)
    @api = API::Server.new(aggregator: @aggregator)
  end

  def get(path, headers = {})
    @api.call(API::Request.new(method: "GET", path: path, headers: headers, identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def test_index_and_schema_follow_the_registered_service
    @aggregator.refresh_openapi(@backend)

    assert_equal @http.url, get("/openapi/v3").body.dig("paths", KEY, "serverRelativeURL")
    accept = API::OpenAPIV3Protobuf::DEPRECATED_TYPE
    schema = get(PATH, {"accept" => accept, "authorization" => "Bearer example"})

    assert_equal 200, schema.status
    assert_equal "schema bytes", schema.encoded_body
    assert_equal "application/octet-stream", schema.content_type
    outbound = @http.requests.last

    assert_equal PATH, outbound.path
    assert_equal accept, outbound["accept"]
    assert_equal "system:kube-aggregator", outbound["X-Remote-User"]
    assert_nil outbound["authorization"]
    @aggregator.remove(NAME)

    refute get("/openapi/v3").body.fetch("paths").key?(KEY)
    assert_equal 404, get(PATH).status
  end

  def test_original_hash_reaches_the_native_handler_when_discovery_is_stale
    @aggregator.refresh_openapi(@backend)
    expiry = "Sun, 01 Nov 2027 00:00:00 GMT"
    @http.schema_response = lambda do |request|
      hash = URI.decode_www_form(URI.parse(request.path).query.to_s).to_h["hash"]
      if hash == "123"
        HTTP::Reply.new("301", "", {"location" => "#{PATH}?hash=456"})
      else
        headers = {"etag" => '"456"', "cache-control" => "public, immutable", "expires" => expiry, "vary" => "Accept"}
        status = request["if-none-match"] == '"456"' ? "304" : "200"
        headers["content-type"] = "application/json" if status == "200"
        HTTP::Reply.new(status, status == "200" ? "{}" : "", headers)
      end
    end

    stale = get(@http.url, {"if-none-match" => '"456"'})

    assert_equal 502, stale.status
    assert_equal "the backend attempted to redirect this request, which is not permitted", stale.body
    assert_nil stale.header("location")
    assert_nil stale.header("expires")

    current = get("#{PATH}?z=last&hash=456&a=%2Fvalue")

    assert_equal "#{PATH}?a=%2Fvalue&hash=456&z=last", @http.requests.last.path
    assert_equal 200, current.status
    assert_equal "no-cache, private, public, immutable", current.header("cache-control")
    assert_equal expiry, current.header("expires")
    assert_equal @http.url, get("/openapi/v3").body.dig("paths", KEY, "serverRelativeURL")
    cached = get("#{PATH}?hash=456", {"if-none-match" => '"456"'})

    assert_equal 304, cached.status
    assert_equal '"456"', cached.header("etag")
    assert_equal current.header("cache-control"), cached.header("cache-control")
    assert_equal expiry, cached.header("expires")
    assert_nil cached.content_type
  end

  def test_a_backend_redirect_cannot_select_another_discovery_path
    @aggregator.refresh_openapi(@backend)
    @http.schema_response = ->(_) { HTTP::Reply.new("307", "", {"location" => "https://other.invalid/openapi/v3/apis/elsewhere/v1"}) }
    response = get(@http.url)

    assert_equal 502, response.status
    assert_nil response.header("location")
    assert_equal ["/openapi/v3", @http.url], @http.requests.map(&:path)
  end

  def test_index_changes_are_bound_to_the_service_and_its_own_group_version
    @aggregator.refresh_openapi(@backend)
    @http.url = "https://other.invalid#{PATH}"
    @aggregator.refresh_openapi(@backend)

    assert_empty @aggregator.openapi_paths
    @http.url = "/openapi/v3/api/v1"
    @aggregator.refresh_openapi(@backend)

    assert_empty @aggregator.openapi_paths
    @http.url = "#{PATH}?hash=456"
    @aggregator.refresh_openapi(@backend)
    @registration["spec"]["service"]["name"] = "replacement"
    @aggregator.sync(@registration)

    assert_empty @aggregator.openapi_paths
    @aggregator.refresh_openapi(@backend)

    assert_empty @aggregator.openapi_paths
  end
end
