# frozen_string_literal: true

require "digest"
require "json"
require "base64"
require "stringio"
require "tmpdir"

require_relative "../test_helper"
require "rubernetes/image"

class OCIRegistryTest < Minitest::Test
  class FakeTransport
    attr_reader :requests

    def initialize(responses)
      @responses = responses
      @requests = []
    end

    def request(method:, uri:, headers:, body:, max_bytes:)
      @requests << {method: method, uri: uri.to_s, headers: headers.dup, body: body, max_bytes: max_bytes}
      response = @responses.shift
      raise "unexpected registry request" unless response

      response
    end
  end

  class StreamingFakeTransport < FakeTransport
    def stream(method:, uri:, headers:, body:, max_bytes:, &)
      @requests << {method: method, uri: uri.to_s, headers: headers.dup, body: body, max_bytes: max_bytes}
      response = @responses.shift
      raise "unexpected registry stream request" unless response

      payload = response.fetch(:body).to_s.b
      payload.scan(/.{1,5}/m, &)
      {status: response.fetch(:status), headers: response.fetch(:headers, {}), body: ""}
    end
  end

  # Docker Hub references normalise to docker.io, whose host answers the v2 API
  # with an HTML page; the distribution endpoint is registry-1.docker.io.
  def test_docker_hub_references_use_the_distribution_endpoint
    transport = FakeTransport.new([])
    %w[rancher/local-path-provisioner:v0.0.31 docker.io/library/redis:7 index.docker.io/library/postgres:16].each do |reference|
      client = Rubernetes::Image::RegistryClient.new(reference, transport: transport)

      assert_equal "https://registry-1.docker.io", client.instance_variable_get(:@endpoint).to_s, reference
    end
    other = Rubernetes::Image::RegistryClient.new("registry.k8s.io/pause:3.10", transport: transport)

    assert_equal "https://registry.k8s.io", other.instance_variable_get(:@endpoint).to_s
  end

  def test_manifest_and_blob_requests_are_injectable_and_digest_checked
    config_bytes = "{}"
    config_digest = digest_for(config_bytes)
    manifest = JSON.generate(
      "schemaVersion" => 2,
      "mediaType" => Rubernetes::Image::MediaTypes::OCI_IMAGE_MANIFEST,
      "config" => {
        "mediaType" => Rubernetes::Image::MediaTypes::OCI_IMAGE_CONFIG,
        "digest" => config_digest,
        "size" => config_bytes.bytesize
      },
      "layers" => []
    )
    transport = FakeTransport.new([
                                    {status: 200, headers: {"content-type" => "application/json"}, body: manifest},
                                    {status: 200, headers: {"docker-content-digest" => config_digest}, body: config_bytes}
                                  ])
    client = Rubernetes::Image::RegistryClient.new(
      "registry.example/team/app:stable",
      transport: transport
    )

    parsed = client.manifest

    assert_instance_of Rubernetes::Image::Manifest, parsed
    assert_equal config_bytes, client.fetch_blob(nil, config_digest, expected_size: config_bytes.bytesize)
    assert_equal "/v2/team/app/manifests/stable", URI.parse(transport.requests.first[:uri]).path
    assert_equal "/v2/team/app/blobs/#{config_digest}", URI.parse(transport.requests.last[:uri]).path
  end

  def test_bearer_challenge_fetches_token_then_retries_without_leaking_basic_header
    token = "signed-token"
    transport = FakeTransport.new([
                                    {status: 401,
                                     headers: {"www-authenticate" => 'Bearer realm="https://auth.example/token",service="registry.example"'}, body: ""},
                                    {status: 200, headers: {}, body: JSON.generate("token" => token, "expires_in" => 60)},
                                    {status: 200, headers: {}, body: "{}"}
                                  ])
    client = Rubernetes::Image::RegistryClient.new(
      "registry.example/team/app:stable",
      username: "user",
      password: "secret",
      token_realm_allowlist: ["https://auth.example/token"],
      transport: transport
    )

    assert_raises(Rubernetes::Image::ManifestError) { client.manifest }
    assert_nil transport.requests.first[:headers]["Authorization"]
    assert_equal "Basic #{Base64.strict_encode64("user:secret")}", transport.requests[1][:headers]["Authorization"]
    assert_equal "Bearer #{token}", transport.requests[2][:headers]["Authorization"]
  end

  # An anonymous pull sends no secret to the realm, so a cross-origin realm is
  # accepted (Docker Hub: registry-1.docker.io challenges with auth.docker.io).
  def test_anonymous_bearer_challenge_accepts_a_cross_origin_realm_without_credentials
    config_bytes = "{}"
    config_digest = digest_for(config_bytes)
    manifest = JSON.generate("schemaVersion" => 2, "mediaType" => Rubernetes::Image::MediaTypes::OCI_IMAGE_MANIFEST,
                             "config" => {"mediaType" => Rubernetes::Image::MediaTypes::OCI_IMAGE_CONFIG, "digest" => config_digest, "size" => 2},
                             "layers" => [])
    transport = FakeTransport.new([
                                    {status: 401,
                                     headers: {"www-authenticate" => 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"'}, body: ""},
                                    {status: 200, headers: {"content-type" => "application/json"},
                                     body: JSON.generate("token" => "anon-token")},
                                    {status: 200, headers: {"content-type" => "application/json"}, body: manifest}
                                  ])
    client = Rubernetes::Image::RegistryClient.new("rancher/local-path-provisioner:v0.0.31", transport: transport)
    client.manifest
    token_request = transport.requests[1]

    assert_equal "auth.docker.io", URI.parse(token_request[:uri]).host
    refute token_request[:headers].keys.any? { |key| key.to_s.casecmp?("authorization") }, "no credentials go to the realm"
    assert_match(/Bearer anon-token/, transport.requests[2][:headers].find { |key, _| key.to_s.casecmp?("authorization") }&.last.to_s)
  end

  def test_credentialed_docker_hub_pull_may_use_the_well_known_realm
    transport = FakeTransport.new([
                                    {status: 401,
                                     headers: {"www-authenticate" => 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"'}, body: ""},
                                    {status: 200, headers: {"content-type" => "application/json"}, body: JSON.generate("token" => "t")},
                                    {status: 404, headers: {"content-type" => "application/json"}, body: "{}"}
                                  ])
    client = Rubernetes::Image::RegistryClient.new("docker.io/library/redis:7", username: "u", password: "p", transport: transport)
    assert_raises(Rubernetes::Image::RegistryError) { client.manifest }
    assert_equal "auth.docker.io", URI.parse(transport.requests[1][:uri]).host
  end

  def test_bearer_challenge_rejects_cross_origin_realm_before_sending_basic_credentials
    transport = FakeTransport.new([
                                    {status: 401, headers: {"www-authenticate" => 'Bearer realm="https://auth.example/token",service="registry.example"'},
                                     body: ""}
                                  ])
    client = Rubernetes::Image::RegistryClient.new(
      "registry.example/team/app:stable",
      username: "user",
      password: "secret",
      transport: transport
    )

    assert_raises(Rubernetes::Image::AuthenticationError) { client.manifest }
    assert_equal 1, transport.requests.length
    assert_nil transport.requests.first[:headers]["Authorization"]
  end

  def test_authenticate_parser_rejects_duplicate_and_malformed_parameters
    transport = FakeTransport.new([
                                    {status: 401, headers: {"www-authenticate" => 'Bearer realm="https://registry.example/token",realm="https://evil.example/token"'},
                                     body: ""},
                                    {status: 401, headers: {"www-authenticate" => 'Bearer realm="https://registry.example/token",service'}, body: ""}
                                  ])
    client = Rubernetes::Image::RegistryClient.new(
      "registry.example/team/app:stable",
      transport: transport
    )

    assert_raises(Rubernetes::Image::AuthenticationError) { client.manifest }
    assert_equal 1, transport.requests.length
  end

  def test_registry_credentials_require_tls
    assert_raises(Rubernetes::Image::RegistryError) do
      Rubernetes::Image::RegistryClient.new(
        "registry.example/team/app:stable",
        endpoint: "http://registry.example",
        bearer_token: "secret"
      )
    end
  end

  def test_streaming_blob_requires_stream_capable_transport
    transport = FakeTransport.new([
                                    {status: 200, headers: {}, body: "payload"}
                                  ])
    client = Rubernetes::Image::RegistryClient.new(
      "registry.example/team/app:stable",
      transport: transport
    )

    assert_raises(Rubernetes::Image::RegistryError) do
      client.fetch_blob(nil, digest_for("payload"), io: StringIO.new)
    end
    assert_empty transport.requests
  end

  def test_streaming_blob_verifies_incremental_digest_and_writes_destination
    payload = "streamed payload" * 64
    digest = digest_for(payload)
    transport = Class.new do
      attr_reader :requests

      define_method(:initialize) do |body|
        @body = body
        @requests = []
      end

      define_method(:stream) do |method:, uri:, headers:, body:, max_bytes:, &block|
        @requests << {method: method, uri: uri.to_s, headers: headers, body: body, max_bytes: max_bytes}
        block.call(@body.byteslice(0, 7))
        block.call(@body.byteslice(7, @body.bytesize))
        {status: 200, headers: {"docker-content-digest" => digest_for(@body)}, body: ""}
      end

      define_method(:digest_for) do |bytes|
        "sha256:#{Digest::SHA256.hexdigest(bytes)}"
      end
    end.new(payload)
    destination = StringIO.new
    client = Rubernetes::Image::RegistryClient.new("registry.example/team/app:stable", transport: transport)

    assert_equal payload.bytesize, client.fetch_blob(nil, digest, io: destination)
    assert_equal payload, destination.string
    assert_equal 1, transport.requests.length
  end

  def test_pull_with_content_store_streams_layers_without_retaining_blob_strings
    config_bytes = "{}"
    layer_bytes = "stored layer payload"
    config_digest = digest_for(config_bytes)
    layer_digest = digest_for(layer_bytes)
    manifest = JSON.generate(
      "schemaVersion" => 2,
      "mediaType" => Rubernetes::Image::MediaTypes::OCI_IMAGE_MANIFEST,
      "config" => {
        "mediaType" => Rubernetes::Image::MediaTypes::OCI_IMAGE_CONFIG,
        "digest" => config_digest,
        "size" => config_bytes.bytesize
      },
      "layers" => [{
        "mediaType" => Rubernetes::Image::MediaTypes::OCI_IMAGE_LAYER,
        "digest" => layer_digest,
        "size" => layer_bytes.bytesize
      }]
    )
    transport = StreamingFakeTransport.new([
                                             {status: 200, headers: {}, body: manifest},
                                             {status: 200, headers: {"docker-content-digest" => config_digest}, body: config_bytes},
                                             {status: 200, headers: {"docker-content-digest" => layer_digest}, body: layer_bytes}
                                           ])

    Dir.mktmpdir("rubernetes-registry-store-") do |directory|
      store = Rubernetes::Image::ContentStore.new(directory)
      image = Rubernetes::Image::RegistryClient.new(
        "registry.example/team/app:stable",
        transport: transport
      ).pull(store: store)

      assert_equal config_bytes, image.config
      assert_nil image.layers.fetch(0).fetch(:bytes)
      assert_equal layer_bytes, store.fetch(layer_digest)
      assert_equal(2, transport.requests.count { |request| request.fetch(:method) == "GET" && request.fetch(:uri).include?("/blobs/") })
    end
  end

  def test_bearer_token_response_rejects_duplicate_json_keys
    transport = FakeTransport.new([
                                    {status: 401,
                                     headers: {"www-authenticate" => 'Bearer realm="https://auth.example/token",service="registry.example"'}, body: ""},
                                    {status: 200, headers: {}, body: '{"token":"trusted","token":"attacker"}'}
                                  ])
    client = Rubernetes::Image::RegistryClient.new(
      "registry.example/team/app:stable",
      username: "user",
      password: "secret",
      transport: transport
    )

    assert_raises(Rubernetes::Image::AuthenticationError) { client.manifest }
  end

  private

  def digest_for(bytes)
    "sha256:#{Digest::SHA256.hexdigest(bytes)}"
  end
end
