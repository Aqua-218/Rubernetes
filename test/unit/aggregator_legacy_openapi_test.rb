# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

class AggregatorLegacyOpenAPITest < Minitest::Test
  API = Rubernetes::API
  KEY = "apis/legacy.example/v1"
  PATH = "/openapi/v3/#{KEY}".freeze
  RESOURCE_PATH = "/#{KEY}/widgets".freeze
  DEFINITION = "com.example.legacy.Widget"
  REF = "#/components/schemas/#{DEFINITION}".freeze
  CLOCK = Time.utc(2024, 2, 29, 12).freeze

  BackendResponse = Struct.new(:code, :body, :headers) do
    def [](name) = headers[name]
    def read_body = yield(body)
  end

  BackendHTTP = Struct.new(:serve) do
    def request(outbound, &block) = serve.call(outbound, block)
  end

  def setup
    @requests = []
    http = BackendHTTP.new(method(:serve))
    @aggregator = API::Aggregator.new(http_factory: ->(_uri, _backend) { http }, clock: -> { CLOCK })
    @backend = @aggregator.sync({"metadata" => {"name" => "v1.legacy.example"},
                                 "spec" => {"group" => "legacy.example", "version" => "v1",
                                            "service" => {"namespace" => "test", "name" => "legacy"}}})
    @aggregator.mark_available(@backend.name, true)
    @server = API::Server.new(registry: API::Registry.new(resources: [], defaults: false), aggregator: @aggregator,
                              store: Rubernetes::Storage::MemoryStore.new, openapi_repository: API::OpenAPIRepository.new)
    @v3_code = 404
    @v2_code = 200
    @source_etag = '"legacy-v2"'
  end

  def swagger
    ref = {"$ref" => "#/definitions/#{DEFINITION}"}
    {"swagger" => "2.0", "info" => {"title" => "Legacy", "version" => "v1"},
     "paths" => {RESOURCE_PATH => {"post" => {
       "operationId" => "createWidget", "consumes" => ["application/json"], "produces" => ["application/json"],
       "parameters" => [{"name" => "body", "in" => "body", "schema" => ref}, {"name" => "pretty", "in" => "query", "type" => "string"}],
       "responses" => {"201" => {"description" => "Created", "schema" => ref}}
     }}}, "definitions" => {DEFINITION => {"type" => "object", "properties" => {
       "other" => ref.merge("description" => "Nested widget")
     }}}}
  end

  def serve(request, block)
    @requests << request
    code, body, headers = case request.path
                          when "/openapi/v3" then [@v3_code, @v3_body || "{}", {}]
                          when "/openapi/v2" then [@v2_code, @v2_body || JSON.generate(swagger), {"etag" => @source_etag}]
                          when "#{PATH}?hash=native" then [200, '{"openapi":"3.0.0","info":{"title":"Native"}}', {}]
                          else raise "unexpected backend request #{request.path}"
                          end
    response = BackendResponse.new(code.to_s, body, headers)
    block.call(response)
    response
  end

  def get(path, headers: {})
    @server.call(API::Request.new(method: "GET", path: path, headers: headers,
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def published_url
    get("/openapi/v3").body.dig("paths", KEY, "serverRelativeURL")
  end

  def test_v3_discovery_publishes_and_serves_the_converted_v2_document
    @aggregator.refresh_openapi(@backend)

    assert_equal %w[/openapi/v3 /openapi/v2], @requests.map(&:path)
    assert_equal "system:kube-aggregator", @requests.last["x-remote-user"]
    assert_equal "application/json", @requests.last["accept"]

    url = published_url
    result = get(url)

    assert_equal 200, result.status
    assert_equal "application/json", result.content_type
    assert_equal "public, immutable", result.header("cache-control")
    assert_equal Time.utc(2025, 3, 1, 12).httpdate, result.header("expires")
    hash = Digest::SHA512.hexdigest(result.encoded_body).upcase

    assert_equal "#{PATH}?hash=#{hash}", url
    assert_equal %("#{hash}"), result.header("etag")
    doc = JSON.parse(result.encoded_body)

    assert_equal "3.0.0", doc["openapi"]
    operation = doc.dig("paths", RESOURCE_PATH, "post")

    assert_equal({"$ref" => REF}, operation.dig("requestBody", "content", "application/json", "schema"))
    assert_equal({"$ref" => REF}, operation.dig("responses", "201", "content", "application/json", "schema"))
    assert_equal({"name" => "pretty", "in" => "query", "schema" => {"type" => "string"}}, operation.fetch("parameters").first)
    assert_equal({"description" => "Nested widget", "allOf" => [{"$ref" => REF}]},
                 doc.dig("components", "schemas", DEFINITION, "properties", "other"))

    cached = get(url, headers: {"if-none-match" => result.header("etag")})

    assert_equal 304, cached.status
    assert_equal result.header("cache-control"), cached.header("cache-control")
    assert_equal result.header("expires"), cached.header("expires")
    assert_nil cached.content_type
    plain = get(PATH)

    assert_equal "no-cache, private", plain.header("cache-control")
    assert_nil plain.header("expires")
    assert_equal 2, @requests.size

    binary = get(url, headers: {"accept" => API::OpenAPIV3Protobuf::DEPRECATED_TYPE})

    assert_equal 200, binary.status
    assert_equal result.header("etag"), binary.header("etag")
    assert_equal API::OpenAPIV3Protobuf::CONTENT_TYPE, binary.content_type
    assert_equal "3.0.0", Rubernetes::Schema::Codec::Protobuf.parse_fields(binary.encoded_body).first.fetch(:value)
    assert_equal 2, @requests.size
  end

  def test_backend_etag_refresh_and_path_removal
    @aggregator.refresh_openapi(@backend)
    original_url = published_url
    @v2_code = 304
    @aggregator.refresh_openapi(@backend)

    assert_equal @source_etag, @requests.last["if-none-match"]
    assert_equal original_url, published_url

    @v2_code = 200
    @v2_body = JSON.generate(swagger.merge("info" => {"title" => "Updated", "version" => "v1"}))
    @source_etag = '"updated-v2"'
    @aggregator.refresh_openapi(@backend)
    updated_url = published_url

    refute_equal original_url, updated_url
    current_etag = %("#{URI.parse(updated_url).query.delete_prefix("hash=")}")
    stale = get(original_url, headers: {"if-none-match" => current_etag})

    assert_equal 301, stale.status
    assert_equal updated_url, stale.header("location")
    assert_equal "no-cache, private", stale.header("cache-control")
    assert_nil stale.header("expires")

    @aggregator.mark_available(@backend.name, false)

    assert_nil published_url
    assert_equal 404, get(updated_url).status
  end

  def test_v2_is_not_requested_without_a_v3_404
    [200, 401, 403, 500].each do |code|
      @v3_code = code
      @aggregator.refresh_openapi(@backend)

      assert_nil published_url
    end
    @v3_code = 200
    @v3_body = "invalid JSON"
    @aggregator.refresh_openapi(@backend)

    assert_nil published_url
    assert_equal ["/openapi/v3"], @requests.map(&:path).uniq
  end

  def test_native_v3_replaces_a_previously_converted_document
    @aggregator.refresh_openapi(@backend)

    refute_nil published_url
    @v3_code = 200
    @v3_body = JSON.generate({"paths" => {KEY => {"serverRelativeURL" => "#{PATH}?hash=native"}}})
    @aggregator.refresh_openapi(@backend)

    result = get(published_url)

    assert_equal "Native", JSON.parse(result.body).dig("info", "title")
    assert_equal %W[/openapi/v3 /openapi/v2 /openapi/v3 #{PATH}?hash=native], @requests.map(&:path)
  end

  def test_unparseable_v2_retains_previous_data_until_the_spec_is_withdrawn
    @aggregator.refresh_openapi(@backend)
    original_url = published_url
    @v2_body = '"not a Swagger document"'
    @aggregator.refresh_openapi(@backend)

    assert_equal original_url, published_url

    @v2_code = 404
    @aggregator.refresh_openapi(@backend)

    assert_nil published_url
    assert_equal 404, get(original_url).status
  end
end
