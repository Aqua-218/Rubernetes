# frozen_string_literal: true

require "net/http"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/transport"

class APIUnknownResourceHTTPTest < Minitest::Test
  API = Rubernetes::API
  AUTHENTICATION = "authentication.k8s.io"
  CODEC = Rubernetes::Schema::Codec::KubernetesProtobuf
  JSON_MEDIA = "application/json"
  NOT_FOUND = {
    "kind" => "Status", "apiVersion" => "v1", "metadata" => {},
    "status" => "Failure", "message" => "the server could not find the requested resource",
    "reason" => "NotFound", "details" => {}, "code" => 404
  }.freeze

  def setup
    registry = API::Registry.new
    registry.register(group: AUTHENTICATION, resource: "selfsubjectreviews", kind: "SelfSubjectReview", verbs: ["create"])
    api = API::Server.new(registry: registry, runtime_config: {"#{AUTHENTICATION}/v1beta1" => true},
                          identity_resolver: ->(_request) { {"username" => "example-user"} })
    @codec = CODEC.new
    @listener = Rubernetes::Transport::HTTPServer.new(lambda do |request|
      api.call(API::Request.new(method: request.method, path: request.target, body: request.body, headers: request.headers.to_h))
    end, host: "127.0.0.1", port: 0, shutdown_timeout: 1)
    @listener.start
    @client = Net::HTTP.new("127.0.0.1", @listener.port, nil)
  end

  def teardown
    @listener&.stop(timeout: 1)
  end

  def test_removed_versions_return_the_negotiated_status
    %w[v1beta1 v1alpha1].each do |version|
      [JSON_MEDIA, CODEC::CONTENT_TYPE].each do |media|
        response = post_review(version, media)

        assert_equal "404", response.code
        assert_equal media, response["content-type"]
        assert_equal NOT_FOUND, decode(response)
      end
    end

    core = @client.get("/api/v9/missing")

    assert_equal "404", core.code
    assert_equal NOT_FOUND, decode(core)
  end

  def test_plain_not_found_outside_an_installed_api_group
    %w[/elsewhere /readyz/no-check /apis/unknown.example/v1/resources].each do |path|
      response = @client.get(path, "Accept" => CODEC::CONTENT_TYPE)

      assert_equal "404", response.code
      assert_equal "text/plain; charset=utf-8", response["content-type"]
      assert_equal "404 page not found\n", response.body
    end
  end

  def test_ga_review_and_a_missing_named_object_keep_their_resource_semantics
    [JSON_MEDIA, CODEC::CONTENT_TYPE].each do |media|
      review = post_review("v1", media)

      assert_equal "201", review.code
      assert_equal media, review["content-type"]
      assert_equal "example-user", decode(review).dig("status", "userInfo", "username")
    end

    absent = @client.get("/api/v1/namespaces/default/configmaps/absent")

    assert_equal "404", absent.code
    assert_equal "absent", decode(absent).dig("details", "name")
  end

  private

  def post_review(version, media)
    api_version = "#{AUTHENTICATION}/#{version}"
    object = {"apiVersion" => api_version, "kind" => "SelfSubjectReview"}
    body = media == JSON_MEDIA ? JSON.generate(object) : @codec.encode(object)
    @client.post("/apis/#{api_version}/selfsubjectreviews", body, "Accept" => media, "Content-Type" => media)
  end

  def decode(response)
    response["content-type"] == CODEC::CONTENT_TYPE ? @codec.decode(response.body) : JSON.parse(response.body)
  end
end
