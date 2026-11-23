# frozen_string_literal: true

require "digest"
require "json"
require "base64"
require "socket"
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

  def test_inferred_loopback_registry_accepts_http_basic_challenge
    manifest = JSON.generate("schemaVersion" => 2, "mediaType" => Rubernetes::Image::MediaTypes::OCI_IMAGE_MANIFEST,
                             "config" => {"mediaType" => Rubernetes::Image::MediaTypes::OCI_IMAGE_CONFIG,
                                          "digest" => digest_for("{}"), "size" => 2},
                             "layers" => [])
    with_plaintext_registry(manifest) do |port, requests|
      registry = "127.0.0.1:#{port}"
      client = Rubernetes::Image::RegistryClient.new("#{registry}/test:stable", username: "user", password: "secret")

      assert_instance_of Rubernetes::Image::Manifest, client.manifest
      received = Array.new(3) { requests.pop(true) }

      assert_equal [:tls, {authorization: nil}, {authorization: "Basic dXNlcjpzZWNyZXQ="}], received

      explicit = Rubernetes::Image::RegistryClient.new("#{registry}/test:stable", endpoint: "https://#{registry}")
      assert_raises(Rubernetes::Image::RegistryError) { explicit.manifest }
      assert_equal :tls, requests.pop(true)
      assert_empty requests
    end
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
                                    {status: 401,
                                     headers: {"www-authenticate" => 'Bearer realm="https://registry.example/token",realm="https://evil.example/token"'},
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
    file = client.download_blob(nil, digest, expected_size: payload.bytesize)

    assert_equal payload, file.read
    assert_equal 2, transport.requests.length
    assert_raises(Rubernetes::Image::RegistryError) { client.fetch_blob(nil, digest, expected_size: 1, io: destination) }
    assert_equal payload, destination.string
  ensure
    file&.close!
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
    manifest_response = {status: 200, headers: {}, body: manifest}
    config_head = {status: 200, headers: {"docker-content-digest" => config_digest, "content-length" => config_bytes.bytesize}, body: ""}
    layer_head = {status: 200, headers: {"docker-content-digest" => layer_digest, "content-length" => layer_bytes.bytesize}, body: ""}
    transport = StreamingFakeTransport.new([
                                             manifest_response,
                                             {status: 200, headers: {"docker-content-digest" => config_digest}, body: config_bytes},
                                             {status: 401, headers: {"www-authenticate" => 'Basic realm="test"'}, body: "auth body"},
                                             {status: 307, headers: {"location" => "/download"}, body: "redirect body"},
                                             {status: 200, headers: {"docker-content-digest" => layer_digest}, body: layer_bytes},
                                             manifest_response, config_head, layer_head,
                                             manifest_response, config_head,
                                             {status: 403, headers: {}, body: ""},
                                             {status: 403, headers: {}, body: ""},
                                             manifest_response,
                                             {status: 200, headers: config_head.fetch(:headers), body: config_bytes},
                                             {status: 403, headers: {}, body: ""}
                                           ])

    Dir.mktmpdir("rubernetes-registry-store-") do |directory|
      store = Rubernetes::Image::ContentStore.new(directory)
      client = Rubernetes::Image::RegistryClient.new(
        "registry.example/team/app:stable",
        transport: transport, username: "user", password: "secret"
      )
      image = client.pull(store: store)

      assert_equal config_bytes, image.config
      assert_nil image.layers.fetch(0).fetch(:bytes)
      assert_equal layer_bytes, store.fetch(layer_digest)
      assert_equal(5, transport.requests.size)

      warm = Rubernetes::Image::Puller.new(registry_client: client, store: store).pull("registry.example/team/app:stable")
      warm_methods = transport.requests.drop(5).map { |request| request.fetch(:method) }

      assert_equal image.layers.first.fetch(:path), warm.layers.first.fetch(:path)
      assert_equal %w[GET HEAD HEAD], warm_methods

      assert_raises(Rubernetes::Image::RegistryError) { client.pull(store: store) }
      denied_methods = transport.requests.drop(8).map { |request| request.fetch(:method) }

      assert_equal %w[GET HEAD HEAD GET], denied_methods
      assert_equal layer_bytes, store.fetch(layer_digest)
      assert_equal [config_digest.split(":").last, layer_digest.split(":").last].sort, Dir.children(File.join(directory, "sha256")).sort

      assert_raises(Rubernetes::Image::RegistryError) { client.pull("registry.example/other:stable", store: store) }
      other_requests = transport.requests.drop(12)
      other_methods = other_requests.map { |request| request.fetch(:method) }

      assert_equal %w[GET GET GET], other_methods
      assert(other_requests.all? { |request| request.fetch(:uri).include?("/v2/other/") })
    end
  end

  def test_cache_uses_verified_get_when_head_does_not_confirm_the_descriptor
    image = Rubernetes::Image
    reference = "registry.example/team/app:stable"
    contents = "verified layer"
    digest = digest_for(contents)
    descriptor = image::Descriptor.from_h({"mediaType" => image::MediaTypes::OCI_IMAGE_LAYER, "size" => contents.bytesize, "digest" => digest})
    body = {status: 200, headers: {"docker-content-digest" => digest}, body: contents}
    transport = StreamingFakeTransport.new([body, {status: 200, headers: {"docker-content-digest" => digest}, body: ""}, body])
    client = image::RegistryClient.new(reference, transport: transport)

    Dir.mktmpdir do |directory|
      store = image::ContentStore.new(directory)
      cached = client.store_blob(reference, descriptor, store: store)
      path = client.store_blob(reference, descriptor, store: store)
      methods = transport.requests.map { |request| request.fetch(:method) }

      assert_equal cached, path
      assert_equal %w[GET HEAD GET], methods
      assert_equal contents, store.fetch(digest)
      assert_equal [File.basename(cached)], Dir.children(File.dirname(cached))
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

  def with_plaintext_registry(manifest)
    server = TCPServer.new("127.0.0.1", 0)
    requests = Queue.new
    worker = Thread.new do
      loop do
        client = server.accept
        begin
          answer_plaintext_registry(client, manifest, requests)
        ensure
          client.close
        end
      end
    rescue IOError, Errno::EBADF
      nil
    end
    yield server.addr[1], requests
  ensure
    server&.close
    worker&.join(2)
  end

  def answer_plaintext_registry(client, manifest, requests)
    if client.read(5).start_with?("\x16\x03".b)
      requests << :tls
      client.write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
      return
    end
    headers = client.gets("\r\n\r\n")
    authorization = headers[/^Authorization: ([^\r\n]+)/i, 1]
    requests << {authorization: authorization}
    if authorization
      client.write("HTTP/1.1 200 OK\r\nContent-Length: #{manifest.bytesize}\r\nConnection: close\r\n\r\n#{manifest}")
    else
      client.write("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    end
  end

  def digest_for(bytes)
    "sha256:#{Digest::SHA256.hexdigest(bytes)}"
  end
end
