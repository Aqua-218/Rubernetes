# frozen_string_literal: true

require "base64"
require "json"
require "open3"
require "openssl"
require "socket"
require "stringio"
require "tempfile"
require "timeout"
require "tmpdir"

require_relative "../test_helper"
require "rubernetes/bootstrap"
require "rubernetes/client"
require "rubernetes/rubectl"

class RubectlClientTest < Minitest::Test
  class RecordingHTTP
    attr_accessor :use_ssl, :verify_mode, :ca_file, :cert, :key, :cert_store
    attr_reader :requests

    def initialize(_host, _port)
      @requests = []
    end

    def use_ssl?
      @use_ssl == true
    end

    def request(request)
      @requests << request
      fake_response = Struct.new(:code, :body) do
        def each_header
          yield "content-type", "application/json"
        end
      end
      fake_response.new("200", JSON.generate("kind" => "Status", "status" => "Success"))
    end
  end

  class RecordingRest
    attr_reader :calls

    def initialize(body: {"kind" => "Pod", "metadata" => {"name" => "web"}}, raw_body: nil)
      @body = body
      @raw_body = raw_body
      @calls = []
    end

    def request(method, path, body:, headers:, query:)
      @calls << {method: method, path: path, body: body, headers: headers, query: query}
      Rubernetes::Client::HTTPClient::Response.new(
        status: 200,
        headers: {"content-type" => "application/json"},
        body: @raw_body || JSON.generate(@body)
      )
    end

    def raise_for_status!(*)
      raise "unexpected error response"
    end
  end

  class BlockingStreamingHTTP
    attr_reader :close_calls, :started

    def initialize
      @close_calls = 0
      @mutex = Mutex.new
      @condition = ConditionVariable.new
      @started = Queue.new
      @closed = false
    end

    def request(_request)
      @started << true
      @mutex.synchronize { @condition.wait(@mutex) until @closed }
      raise IOError, "stream closed"
    end

    def close
      @mutex.synchronize do
        @close_calls += 1
        @closed = true
        @condition.broadcast
      end
      self
    end
  end

  class RetryCloseResource
    attr_reader :close_calls
    attr_accessor :fail_close

    def initialize
      @close_calls = 0
      @fail_close = true
    end

    def close
      @close_calls += 1
      raise IOError, "transient close failure" if @fail_close

      self
    end
  end

  def test_kubeconfig_safe_load_resolves_context_credentials
    yaml = <<~YAML
      apiVersion: v1
      kind: Config
      current-context: local
      clusters:
      - name: local
        cluster:
          server: https://kube.example.test
          certificate-authority-data: #{Base64.strict_encode64("CA")}
      users:
      - name: local
        user:
          token: bearer-token
          client-certificate-data: #{Base64.strict_encode64("CERT")}
          client-key-data: #{Base64.strict_encode64("KEY")}
      contexts:
      - name: local
        context:
          cluster: local
          user: local
          namespace: development
    YAML

    context = Rubernetes::Client::Kubeconfig.from_yaml(yaml).resolve

    assert_equal("https://kube.example.test", context.server)
    assert_equal("development", context.namespace)
    assert_equal("CA", context.ca_data)
    assert_equal("CERT", context.client_certificate_data)
    assert_equal("KEY", context.client_key_data)
    assert_equal("bearer-token", context.bearer_token)
  end

  def test_kubeconfig_rejects_aliases_and_exec_credentials
    aliases = <<~YAML
      current-context: local
      common: &common
        server: https://kube.example.test
      clusters:
      - name: local
        cluster: *common
      contexts: []
      users: []
    YAML
    assert_raises(Rubernetes::Client::ConfigurationError) do
      Rubernetes::Client::Kubeconfig.from_yaml(aliases)
    end

    config = Rubernetes::Client::Kubeconfig.from_hash(
      "current-context" => "local",
      "clusters" => [{"name" => "local", "cluster" => {"server" => "https://kube.example.test"}}],
      "users" => [{"name" => "local", "user" => {"exec" => {"command" => "credential-helper"}}}],
      "contexts" => [{"name" => "local", "context" => {"cluster" => "local", "user" => "local"}}]
    )
    assert_raises(Rubernetes::Client::UnsupportedCredentialError) { config.resolve }
  end

  def test_http_client_sends_bearer_token_and_preserves_raw_path
    context = Rubernetes::Client::Kubeconfig::KubeContext.new(
      server: "https://kube.example.test/base",
      bearer_token: "secret-token",
      insecure_skip_tls_verify: true
    )
    http = RecordingHTTP.new("kube.example.test", 443)
    client = Rubernetes::Client::HTTPClient.new(context: context, http: http)

    response = client.request("PATCH", "/api/v1/pods/web?watch=false", body: {"spec" => {}}, headers: {"X-Test" => "yes"})
    request = http.requests.fetch(0)

    assert_equal(200, response.status)
    assert_equal("/base/api/v1/pods/web?watch=false", request.path)
    assert_equal("Bearer secret-token", request["Authorization"])
    assert_equal("application/json", request["Content-Type"])
    assert_equal("yes", request["X-Test"])
  end

  def test_http_client_close_interrupts_a_zero_timeout_blocking_stream
    http = BlockingStreamingHTTP.new
    client = Rubernetes::Client::HTTPClient.new(
      context: {server: "http://kube.example.test"},
      http: http,
      read_timeout: 0
    )
    stream_error = nil
    worker = Thread.new do
      client.stream("GET", "/watch") { |_chunk| nil }
    rescue StandardError => error
      stream_error = error
    end

    Timeout.timeout(1) { http.started.pop }
    Timeout.timeout(1) { client.close }
    worker.join(1)

    refute_predicate worker, :alive?, "closing the client must interrupt the blocking stream"
    assert_instance_of(Rubernetes::Client::TransportError, stream_error)
    assert_equal 1, http.close_calls
  ensure
    worker&.kill if worker&.alive?
  end

  # Requirement: read_timeout=0 disables Net::HTTP read deadlines. This uses
  # a real delayed TCP response so assigning literal zero (Ruby 3.4's
  # immediate-timeout behavior) fails deterministically.
  def test_http_client_zero_read_timeout_allows_delayed_tcp_response
    listener = TCPServer.new("127.0.0.1", 0)
    port = listener.addr.fetch(1)
    server_thread = Thread.new do
      socket = listener.accept
      begin
        # Read the request head to its blank line whatever the header count
        # (a kept-alive session sends one header fewer than a one-shot one).
        while (line = socket.gets) && line != "\r\n"; end
        sleep 0.15
        socket.write("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow")
      ensure
        socket.close unless socket.closed?
      end
    end

    client = Rubernetes::Client::HTTPClient.new(
      context: {server: "http://127.0.0.1:#{port}"},
      read_timeout: 0
    )
    response = Timeout.timeout(2) { client.request("GET", "/delayed") }

    assert_equal 200, response.status
    assert_equal "slow", response.body
  ensure
    listener&.close unless listener&.closed?
    server_thread&.join(2)
    server_thread&.kill if server_thread&.alive?
  end

  # Requirement: a close failure leaves ownership registered for a later
  # retry, while a successful retry records the release.
  def test_http_client_retries_stream_close_failure
    resource = RetryCloseResource.new
    client = Rubernetes::Client::HTTPClient.new(
      context: {server: "http://kube.example.test"},
      http_factory: ->(_uri) { resource }
    )
    session = client.send(:register_stream, resource)

    assert_raises(Rubernetes::CleanupError) { client.close }
    assert_equal 1, client.instance_variable_get(:@active_streams).length
    assert_equal 1, resource.close_calls

    resource.fail_close = false
    client.close

    assert_equal 2, resource.close_calls
    client.send(:unregister_stream, session)

    assert_empty client.instance_variable_get(:@active_streams)
  end

  # Requirement: close and stream initialization are linearized under one
  # lifecycle lock, so close cannot miss a factory-created resource.
  def test_http_client_close_waits_for_stream_factory_initialization
    factory_started = Queue.new
    release_factory = Queue.new
    resource = RetryCloseResource.new
    resource.fail_close = false
    client = Rubernetes::Client::HTTPClient.new(
      context: {server: "http://kube.example.test"},
      http_factory: lambda do |_uri|
        factory_started << true
        release_factory.pop
        resource
      end
    )
    stream_error = nil
    worker = Thread.new do
      client.stream("GET", "/watch") { |_chunk| }
    rescue StandardError => error
      stream_error = error
    end
    Timeout.timeout(1) { factory_started.pop }
    closer = Thread.new { client.close }

    sleep 0.02

    assert_predicate closer, :alive?, "close must wait for an in-flight stream factory"
    release_factory << true
    closer.join(1)
    worker.join(1)

    refute_predicate closer, :alive?
    refute_predicate worker, :alive?
    assert_instance_of Rubernetes::Client::TransportError, stream_error
    assert_empty client.instance_variable_get(:@active_streams)
  ensure
    release_factory << true if release_factory && factory_started && !factory_started.empty?
    closer&.kill if closer&.alive?
    worker&.kill if worker&.alive?
  end

  def test_kubernetes_client_supports_get_create_apply_patch_delete
    rest = RecordingRest.new
    context = Rubernetes::Client::Kubeconfig::KubeContext.new(namespace: "prod")
    client = Rubernetes::Client::KubernetesClient.new(rest_client: rest, context: context)
    manifest = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "web"}}

    client.get("pods", "web")
    client.create(manifest)
    client.apply(manifest, force: true)
    client.patch("/api/v1/namespaces/prod/pods/web", {"metadata" => {"labels" => {"app" => "web"}}})
    client.delete("pods", "web")

    assert_equal(%w[GET POST PATCH PATCH DELETE], rest.calls.map { |call| call.fetch(:method) })
    assert_equal("/api/v1/namespaces/prod/pods/web", rest.calls.fetch(0).fetch(:path))
    assert_equal("/api/v1/namespaces/prod/pods", rest.calls.fetch(1).fetch(:path))
    assert_equal("application/apply-patch+yaml", rest.calls.fetch(2).fetch(:headers).fetch("Content-Type"))
    assert_equal("true", rest.calls.fetch(2).fetch(:query).fetch("force"))
    assert_equal("application/merge-patch+json", rest.calls.fetch(3).fetch(:headers).fetch("Content-Type"))
  end

  def test_manifest_reader_loads_yaml_list_and_rejects_ruby
    reader = Rubernetes::Client::ManifestReader.new
    resources = reader.load_content(<<~YAML)
      apiVersion: v1
      kind: List
      items:
      - apiVersion: v1
        kind: ConfigMap
        metadata:
          name: one
      ---
      {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"two"}}
    YAML

    assert_equal(%w[one two], resources.map { |resource| resource.dig("metadata", "name") })
    error = assert_raises(Rubernetes::Client::RubyManifestIsolationError) do
      Tempfile.create(["manifest", ".rb"]) { |file| reader.load(file.path) }
    end
    assert_match(/isolated child process/, error.message)
  end

  def test_rubectl_cli_apply_writes_json_and_returns_success
    rest = RecordingRest.new
    context = Rubernetes::Client::Kubeconfig::KubeContext.new(namespace: "prod")
    client = Rubernetes::Client::KubernetesClient.new(rest_client: rest, context: context)
    stdout = StringIO.new
    stderr = StringIO.new

    Tempfile.create(["manifest", ".yaml"]) do |file|
      file.write("apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n")
      file.flush
      status = Rubernetes::Rubectl::CLI.run(
        ["apply", "-f", file.path],
        stdout: stdout,
        stderr: stderr,
        client: client
      )

      assert_equal(0, status)
    end

    assert_empty(stderr.string)
    assert_equal("Pod", JSON.parse(stdout.string).fetch("kind"))
    assert_equal("PATCH", rest.calls.fetch(0).fetch(:method))
  end

  def test_kubeconfig_rejects_token_file_traversal_permission_and_symlink
    Dir.mktmpdir("rubernetes-kubeconfig-") do |directory|
      config_path = File.join(directory, "config")
      token_path = File.join(directory, "token")
      File.write(config_path, "{}")

      traversal = kubeconfig_with_token_file(config_path, "../token")
      assert_raises(Rubernetes::Client::ConfigurationError) { traversal.resolve }

      File.write(token_path, "secret-token\n")
      File.chmod(0o000, token_path)
      denied = kubeconfig_with_token_file(config_path, "token")
      assert_raises(Rubernetes::Client::ConfigurationError) { denied.resolve }

      File.chmod(0o600, token_path)
      symlink_path = File.join(directory, "token-link")
      File.symlink(token_path, symlink_path)
      symlinked = kubeconfig_with_token_file(config_path, "token-link")
      assert_raises(Rubernetes::Client::ConfigurationError) { symlinked.resolve }

      File.write(token_path, "x" * (Rubernetes::Client::Kubeconfig::MAX_TOKEN_FILE_BYTES + 1))
      oversized = kubeconfig_with_token_file(config_path, "token")
      assert_raises(Rubernetes::Client::ConfigurationError) { oversized.resolve }
    end
  end

  def test_https_tls_configures_ca_and_client_certificate_material
    Dir.mktmpdir("rubernetes-tls-") do |directory|
      certificate, key = certificate_material
      ca_path = File.join(directory, "ca.pem")
      certificate_path = File.join(directory, "client.pem")
      key_path = File.join(directory, "client-key.pem")
      File.write(ca_path, certificate.to_pem)
      File.write(certificate_path, certificate.to_pem)
      File.write(key_path, key.to_pem)
      File.chmod(0o600, key_path)

      context = Rubernetes::Client::Kubeconfig::KubeContext.new(
        server: "https://kube.example.test",
        ca_file: ca_path,
        client_certificate_file: certificate_path,
        client_key_file: key_path
      )
      http = RecordingHTTP.new("kube.example.test", 443)
      Rubernetes::Client::HTTPClient.new(context: context, http: http).request("GET", "/version")

      assert_equal(true, http.use_ssl)
      assert(http.cert_store.verify(certificate))
      assert_instance_of(OpenSSL::X509::Certificate, http.cert)
      assert_instance_of(OpenSSL::PKey::RSA, http.key)
    end
  end

  def test_http_client_does_not_follow_redirects_with_authorization
    redirect_http = Class.new(RecordingHTTP) do
      def request(request)
        @requests << request
        response = Struct.new(:code, :body, :headers) do
          def each_header(&)
            headers.each(&)
          end
        end
        response.new("302", "", {"location" => "https://other.example.test/"})
      end
    end.new("kube.example.test", 443)
    context = Rubernetes::Client::Kubeconfig::KubeContext.new(
      server: "https://kube.example.test",
      bearer_token: "secret-token"
    )
    client = Rubernetes::Client::HTTPClient.new(context: context, http: redirect_http)

    response = client.request("GET", "/version")

    assert_equal(302, response.status)
    assert_equal(1, redirect_http.requests.length)
    assert_equal("Bearer secret-token", redirect_http.requests.fetch(0)["Authorization"])
  end

  def test_http_client_rejects_crlf_and_absolute_raw_paths
    http = RecordingHTTP.new("kube.example.test", 443)
    client = Rubernetes::Client::HTTPClient.new(
      context: {server: "https://kube.example.test", insecure_skip_tls_verify: true},
      http: http
    )

    assert_raises(Rubernetes::Client::UsageError) { client.request("GET", "/api/v1\r\nHost: evil.example") }
    assert_raises(Rubernetes::Client::UsageError) { client.request("GET", "https://evil.example/api/v1") }
    assert_raises(Rubernetes::Client::UsageError) { client.request("GET", "//evil.example/api/v1") }
  end

  def test_manifest_reader_rejects_duplicate_json_and_yaml_keys
    reader = Rubernetes::Client::ManifestReader.new

    assert_raises(Rubernetes::Client::ManifestError) do
      reader.load_content('{"apiVersion":"v1","kind":"Pod","kind":"Service"}', filename: "duplicate.json")
    end
    assert_raises(Rubernetes::Client::ManifestError) do
      reader.load_content("apiVersion: v1\nkind: Pod\nmetadata:\n  name: one\n  name: two\n", filename: "duplicate.yaml")
    end
  end

  def test_watch_events_reject_malformed_stream_and_enforce_limits
    event = JSON.generate("type" => "ADDED", "object" => {"kind" => "Pod"})
    rest = RecordingRest.new(raw_body: "#{event}\n")
    client = Rubernetes::Client::KubernetesClient.new(rest_client: rest, context: {namespace: "prod"})

    assert_equal(["ADDED"], client.watch_events("pods").map { |item| item.fetch("type") })

    malformed = Rubernetes::Client::KubernetesClient.new(
      rest_client: RecordingRest.new(raw_body: "not-json\n"),
      context: {namespace: "prod"}
    )
    assert_raises(Rubernetes::Client::WatchStreamError) { malformed.watch_events("pods") }
    assert_raises(Rubernetes::Client::WatchLimitError) { client.watch_events("pods", max_bytes: event.bytesize - 1) }
    assert_raises(Rubernetes::Client::UsageError) { client.watch_events("pods", max_events: 0) }
  end

  def test_rubectl_cli_injects_sandbox_factory_for_ruby_manifests
    rest = RecordingRest.new
    client = Rubernetes::Client::KubernetesClient.new(
      rest_client: rest,
      context: Rubernetes::Client::Kubeconfig::KubeContext.new(namespace: "prod")
    )
    sandbox = Class.new do
      attr_reader :calls

      def initialize
        @calls = []
      end

      def compile(path, **options)
        @calls << [path, options]
        [{"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "sandboxed"}}]
      end
    end.new

    Tempfile.create(["manifest", ".rb"]) do |file|
      file.write("raise 'must not run in parent'\n")
      file.flush
      status = Rubernetes::Rubectl::CLI.run(
        ["apply", "--allow-code", "-f", file.path],
        client: client,
        sandbox_factory: ->(_options) { sandbox },
        stdout: StringIO.new
      )

      assert_equal(0, status)
    end

    assert_equal(true, sandbox.calls.fetch(0).last.fetch(:allow_code))
    assert_equal("sandboxed", JSON.parse(rest.calls.fetch(0).fetch(:body)).dig("metadata", "name"))
  end

  def test_kubeconfig_rejects_unsafe_source_file_and_duplicate_keys
    Dir.mktmpdir("rubernetes-kubeconfig-source-") do |directory|
      real_directory = File.join(directory, "real")
      linked_directory = File.join(directory, "linked")
      Dir.mkdir(real_directory)
      config_path = File.join(real_directory, "config")
      File.write(config_path, minimal_kubeconfig_yaml)
      File.chmod(0o600, config_path)

      assert_instance_of(Rubernetes::Client::Kubeconfig, Rubernetes::Client::Kubeconfig.load(path: config_path))

      File.chmod(0o644, config_path)
      assert_raises(Rubernetes::Client::ConfigurationError) do
        Rubernetes::Client::Kubeconfig.load(path: config_path)
      end
      File.chmod(0o600, config_path)

      File.symlink(real_directory, linked_directory)
      assert_raises(Rubernetes::Client::ConfigurationError) do
        Rubernetes::Client::Kubeconfig.load(path: File.join(linked_directory, "config"))
      end
      assert_raises(Rubernetes::Client::ConfigurationError) do
        Rubernetes::Client::Kubeconfig.load(path: "#{config_path}\0suffix")
      end
    end

    duplicate = minimal_kubeconfig_yaml.sub(
      "current-context: local\n",
      "current-context: attacker\ncurrent-context: local\n"
    )
    assert_raises(Rubernetes::Client::ConfigurationError) do
      Rubernetes::Client::Kubeconfig.from_yaml(duplicate)
    end
  end

  def test_kubeconfig_rejects_token_header_injection_and_symlinked_directory
    injected = kubeconfig_with_inline_token("safe-token\r\nX-Injected: true")
    assert_raises(Rubernetes::Client::ConfigurationError) { injected.resolve }

    Dir.mktmpdir("rubernetes-token-directory-") do |directory|
      config_path = File.join(directory, "config")
      credential_directory = File.join(directory, "credentials-real")
      Dir.mkdir(credential_directory)
      token_path = File.join(credential_directory, "token")
      File.write(config_path, "{}")
      File.write(token_path, "private-token\n")
      File.chmod(0o600, token_path)
      File.symlink(credential_directory, File.join(directory, "credentials"))

      config = kubeconfig_with_token_file(config_path, "credentials/token")
      assert_raises(Rubernetes::Client::ConfigurationError) { config.resolve }
    end

    http = RecordingHTTP.new("kube.example.test", 443)
    assert_raises(Rubernetes::Client::ConfigurationError) do
      Rubernetes::Client::HTTPClient.new(
        context: {server: "https://kube.example.test", bearer_token: "safe\nInjected: true"},
        http: http
      )
    end
    assert_empty(http.requests)

    assert_raises(Rubernetes::Client::ConfigurationError) do
      Rubernetes::Client::HTTPClient.new(
        context: {server: "http://kube.example.test", bearer_token: "plain-text-secret"},
        http: RecordingHTTP.new("kube.example.test", 80)
      )
    end
    loopback_http = RecordingHTTP.new("127.0.0.1", 80)
    Rubernetes::Client::HTTPClient.new(
      context: {server: "http://127.0.0.1", bearer_token: "local-development-token"},
      http: loopback_http
    ).request("GET", "/version")

    assert_equal("Bearer local-development-token", loopback_http.requests.fetch(0)["Authorization"])
  end

  def test_tls_rejects_conflicting_or_mismatched_credentials_and_insecure_key_permissions
    certificate, _key = certificate_material
    _other_certificate, other_key = certificate_material
    context = Rubernetes::Client::Kubeconfig::KubeContext.new(
      server: "https://kube.example.test",
      client_certificate_data: certificate.to_pem,
      client_key_data: other_key.to_pem
    )
    assert_raises(Rubernetes::Client::ConfigurationError) do
      Rubernetes::Client::HTTPClient.new(
        context: context,
        http: RecordingHTTP.new("kube.example.test", 443)
      ).request("GET", "/version")
    end

    conflicting = Rubernetes::Client::Kubeconfig.from_hash(
      "current-context" => "local",
      "clusters" => [{
        "name" => "local",
        "cluster" => {
          "server" => "https://kube.example.test",
          "certificate-authority-data" => Base64.strict_encode64(certificate.to_pem),
          "insecure-skip-tls-verify" => true
        }
      }],
      "users" => [],
      "contexts" => [{"name" => "local", "context" => {"cluster" => "local"}}]
    )
    assert_raises(Rubernetes::Client::ConfigurationError) { conflicting.resolve }

    direct_conflict = Rubernetes::Client::HTTPClient.new(
      context: {
        server: "https://kube.example.test",
        ca_data: certificate.to_pem,
        insecure_skip_tls_verify: true
      },
      http: RecordingHTTP.new("kube.example.test", 443)
    )
    assert_raises(Rubernetes::Client::ConfigurationError) { direct_conflict.request("GET", "/version") }

    non_boolean = Rubernetes::Client::HTTPClient.new(
      context: {server: "https://kube.example.test", insecure_skip_tls_verify: "true"},
      http: RecordingHTTP.new("kube.example.test", 443)
    )
    assert_raises(Rubernetes::Client::ConfigurationError) { non_boolean.request("GET", "/version") }

    plaintext_tls = Rubernetes::Client::HTTPClient.new(
      context: {server: "http://kube.example.test", ca_data: certificate.to_pem},
      http: RecordingHTTP.new("kube.example.test", 80)
    )
    assert_raises(Rubernetes::Client::ConfigurationError) { plaintext_tls.request("GET", "/version") }

    Dir.mktmpdir("rubernetes-private-key-") do |directory|
      matching_certificate, matching_key = certificate_material
      certificate_path = File.join(directory, "client.pem")
      key_path = File.join(directory, "client-key.pem")
      File.write(certificate_path, matching_certificate.to_pem)
      File.write(key_path, matching_key.to_pem)
      File.chmod(0o644, key_path)
      insecure_context = Rubernetes::Client::Kubeconfig::KubeContext.new(
        server: "https://kube.example.test",
        client_certificate_file: certificate_path,
        client_key_file: key_path
      )

      assert_raises(Rubernetes::Client::ConfigurationError) do
        Rubernetes::Client::HTTPClient.new(
          context: insecure_context,
          http: RecordingHTTP.new("kube.example.test", 443)
        ).request("GET", "/version")
      end
    end
  end

  def test_tls_ca_data_uses_every_certificate_in_the_explicit_bundle
    first_ca, = certificate_material(common_name: "first-ca", ca: true)
    second_ca, = certificate_material(common_name: "second-ca", ca: true)
    http = RecordingHTTP.new("kube.example.test", 443)
    context = Rubernetes::Client::Kubeconfig::KubeContext.new(
      server: "https://kube.example.test",
      ca_data: first_ca.to_pem + second_ca.to_pem
    )

    Rubernetes::Client::HTTPClient.new(context: context, http: http).request("GET", "/version")

    assert(http.cert_store.verify(first_ca))
    assert(http.cert_store.verify(second_ca))
  end

  def test_http_client_rejects_ambiguous_paths_headers_and_encodes_query_controls
    http = RecordingHTTP.new("kube.example.test", 443)
    client = Rubernetes::Client::HTTPClient.new(
      context: {server: "https://kube.example.test", insecure_skip_tls_verify: true},
      http: http
    )

    assert_raises(Rubernetes::Client::UsageError) { client.request("GET", "/api/v1#ignored") }
    assert_raises(Rubernetes::Client::UsageError) { client.request("GET", "/api\\v1") }
    assert_raises(Rubernetes::Client::UsageError) do
      client.request("GET", "/api/v1", headers: {"X-Test\0Injected" => "value"})
    end

    client.request("GET", "/api/v1", query: {"labelSelector" => "app=web\r\nX-Test: injected"})
    request_path = http.requests.fetch(0).path

    refute_match(/[\r\n]/, request_path)
    assert_includes(request_path, "%0D%0A")

    client.request("GET", "/api/v1?watch=false&resourceVersion=1", query: {"watch" => "true"})
    authoritative_path = http.requests.fetch(1).path

    assert_equal(["true"], URI.decode_www_form(URI.parse(authoritative_path).query).to_h.values_at("watch"))
    assert_includes(authoritative_path, "resourceVersion=1")
  end

  def test_http_stream_refuses_redirect_without_leaking_authorization
    token = "stream-redirect-secret"
    redirect_http = Class.new(RecordingHTTP) do
      def request(request)
        @requests << request
        response = Struct.new(:code, :body, :headers) do
          def each_header(&)
            headers.each(&)
          end
        end
        response.new("307", "redirected", {"location" => "https://attacker.example.test/"})
      end
    end.new("kube.example.test", 443)
    client = Rubernetes::Client::HTTPClient.new(
      context: {server: "https://kube.example.test", bearer_token: token},
      http: redirect_http
    )

    error = assert_raises(Rubernetes::Client::APIError) do
      client.stream("GET", "/watch").to_a
    end

    assert_equal(1, redirect_http.requests.length)
    assert_equal("Bearer #{token}", redirect_http.requests.fetch(0)["Authorization"])
    refute_includes(error.message, token)

    reflected = Rubernetes::Client::HTTPClient::Response.new(
      status: 401,
      headers: {"content-type" => "application/json"},
      body: JSON.generate("kind" => "Status", "message" => "reflected #{token}")
    )
    reflected_error = assert_raises(Rubernetes::Client::APIError) do
      client.raise_for_status!(reflected, "GET", "/watch")
    end
    refute_includes(reflected_error.message, token)
    assert_includes(reflected_error.message, "[REDACTED]")
  end

  def test_watch_stream_handles_adversarial_framing_and_limits
    event = JSON.generate(
      "type" => "ADDED",
      "object" => {"kind" => "Pod", "metadata" => {"name" => "snow-雪"}}
    ) + "\n"
    split_at = event.b.index("\xE9".b) + 1
    chunks = [event.b.byteslice(0, split_at), event.b.byteslice(split_at, event.bytesize)]
    streaming_rest = streaming_rest_for(chunks)
    client = Rubernetes::Client::KubernetesClient.new(rest_client: streaming_rest, context: {namespace: "prod"})

    assert_equal("snow-雪", client.watch_each("pods").to_a.fetch(0).dig("object", "metadata", "name"))
    assert_raises(Rubernetes::Client::WatchLimitError) do
      client.watch_each("pods", max_bytes: event.bytesize - 1).to_a
    end

    duplicate = '{"type":"ADDED","type":"DELETED","object":{}}' + "\n"
    duplicate_client = Rubernetes::Client::KubernetesClient.new(
      rest_client: streaming_rest_for([duplicate]),
      context: {namespace: "prod"}
    )
    assert_raises(Rubernetes::Client::WatchStreamError) { duplicate_client.watch_each("pods").to_a }

    non_string_client = Rubernetes::Client::KubernetesClient.new(
      rest_client: streaming_rest_for([123]),
      context: {namespace: "prod"}
    )
    assert_raises(Rubernetes::Client::WatchStreamError) { non_string_client.watch_each("pods").to_a }
  end

  def test_rubectl_redacts_credentials_from_api_and_manifest_errors
    token = "reflected-bearer-token\\segment"
    response_body = JSON.generate(
      "apiVersion" => "v1",
      "kind" => "Status",
      "status" => "Failure",
      "message" => "upstream reflected #{token}",
      "reason" => "Unauthorized",
      "code" => 401
    )
    failing_rest = Class.new do
      define_method(:initialize) { |body| @body = body }
      define_method(:request) do |*_arguments, **_options|
        Rubernetes::Client::HTTPClient::Response.new(
          status: 401,
          headers: {"content-type" => "application/json"},
          body: @body
        )
      end
    end.new(response_body)
    client = Rubernetes::Client::KubernetesClient.new(
      rest_client: failing_rest,
      context: Rubernetes::Client::Kubeconfig::KubeContext.new(namespace: "prod", bearer_token: token)
    )
    stdout = StringIO.new
    stderr = StringIO.new

    status = Rubernetes::Rubectl::CLI.run(
      %w[get pods],
      client: client,
      stdout: stdout,
      stderr: stderr
    )

    assert_equal(1, status)
    assert_empty(stdout.string)
    refute_includes(stderr.string, token)
    assert_includes(stderr.string, "[REDACTED]")

    environment_secret = "manifest-environment-secret"
    sandbox = Class.new do
      define_method(:initialize) { |secret| @secret = secret }
      define_method(:compile) do |*_arguments, **_options|
        raise Rubernetes::Manifest::Error, "worker echoed #{@secret}"
      end
    end.new(environment_secret)
    manifest_stderr = StringIO.new
    Tempfile.create(["hostile-manifest", ".rb"]) do |file|
      file.write("raise 'must not execute in parent'\n")
      file.flush
      manifest_status = Rubernetes::Rubectl::CLI.run(
        ["apply", "--allow-code", "--env", "D04_SECRET", "-f", file.path],
        client: client,
        sandbox_factory: ->(_options) { sandbox },
        env: {"D04_SECRET" => environment_secret},
        stdout: StringIO.new,
        stderr: manifest_stderr
      )

      assert_equal(Rubernetes::Rubectl::CLI::EX_DATAERR, manifest_status)
    end
    refute_includes(manifest_stderr.string, environment_secret)
    refute_includes(manifest_stderr.string, "hostile-manifest")
    assert_includes(manifest_stderr.string, "[REDACTED]")

    watch_body = JSON.generate(
      "type" => "ERROR",
      "object" => {"kind" => "Status", "message" => "watch reflected #{token}"}
    ) + "\n"
    watch_client = Rubernetes::Client::KubernetesClient.new(
      rest_client: streaming_rest_for([watch_body]),
      context: Rubernetes::Client::Kubeconfig::KubeContext.new(namespace: "prod", bearer_token: token)
    )
    watch_stdout = StringIO.new
    watch_stderr = StringIO.new
    watch_status = Rubernetes::Rubectl::CLI.run(
      %w[watch pods],
      client: watch_client,
      stdout: watch_stdout,
      stderr: watch_stderr
    )

    assert_equal(Rubernetes::Rubectl::CLI::EX_DATAERR, watch_status)
    assert_empty(watch_stdout.string)
    refute_includes(watch_stderr.string, token)
    assert_includes(watch_stderr.string, "[REDACTED]")
  end

  def test_rubectl_refuses_ruby_without_opt_in_and_reports_usage_before_configuration
    sandbox_calls = 0
    stderr = StringIO.new
    Tempfile.create(["untrusted-manifest", ".rb"]) do |file|
      file.write("raise 'must not execute'\n")
      file.flush
      status = Rubernetes::Rubectl::CLI.run(
        ["apply", "-f", file.path],
        client: Rubernetes::Client::KubernetesClient.new(
          rest_client: RecordingRest.new,
          context: {namespace: "prod"}
        ),
        sandbox_factory: lambda do |_options|
          sandbox_calls += 1
          raise "sandbox must not be initialized"
        end,
        stdout: StringIO.new,
        stderr: stderr
      )

      assert_equal(Rubernetes::Rubectl::CLI::EX_DATAERR, status)
    end
    assert_equal(0, sandbox_calls)
    assert_includes(stderr.string, "explicit --allow-code")

    usage_stderr = StringIO.new
    usage_status = Rubernetes::Rubectl::CLI.run(
      ["--kubeconfig", "/definitely/missing/kubeconfig", "raw", "GET"],
      env: {},
      stdout: StringIO.new,
      stderr: usage_stderr
    )

    assert_equal(Rubernetes::Rubectl::CLI::EX_USAGE, usage_status)
    assert_includes(usage_stderr.string, "raw requires METHOD PATH")
  end

  def test_rubectl_cli_patch_splits_resource_and_name_target
    rest = RecordingRest.new
    client = Rubernetes::Client::KubernetesClient.new(
      rest_client: rest,
      context: Rubernetes::Client::Kubeconfig::KubeContext.new(namespace: "prod")
    )
    stdout = StringIO.new

    status = Rubernetes::Rubectl::CLI.run(
      ["patch", "pods/web", "--patch", '{"metadata":{"labels":{"app":"web"}}}'],
      client: client,
      stdout: stdout
    )

    assert_equal(0, status)
    assert_equal("/api/v1/namespaces/prod/pods/web", rest.calls.fetch(0).fetch(:path))
  end

  def test_rubectl_executable_end_to_end_against_real_api_server
    project_root = File.expand_path("../..", __dir__)
    executable = File.join(project_root, "exe", "rubectl")
    secret_token = "d03-kubeconfig-token-must-not-leak"
    parent_secret = "d03-parent-environment-must-not-leak"
    log_output = StringIO.new
    logger = Rubernetes::Bootstrap::StructuredLogger.new(
      io: log_output,
      process_name: "rubernetes-apiserver",
      level: "info"
    )
    config = Rubernetes::Bootstrap::Config.load(
      process_name: "rubernetes-apiserver"
    ).process.merge("port" => 0)
    service = Rubernetes::Bootstrap::APIServerService.new(config: config, logger: logger)
    service.start

    Dir.mktmpdir("rubernetes-rubectl-e2e-") do |directory|
      kubeconfig_path = File.join(directory, "kubeconfig.yaml")
      json_path = File.join(directory, "json-configmap.json")
      yaml_path = File.join(directory, "yaml-configmap.yaml")
      apply_path = File.join(directory, "apply-configmap.yaml")
      ruby_path = File.join(directory, "ruby-configmap.rb")
      File.write(kubeconfig_path, <<~YAML)
        apiVersion: v1
        kind: Config
        current-context: d03
        clusters:
        - name: d03
          cluster:
            server: #{service.http_server.endpoint}
        users:
        - name: d03
          user:
            token: #{secret_token}
        contexts:
        - name: d03
          context:
            cluster: d03
            user: d03
            namespace: d03
      YAML
      File.chmod(0o600, kubeconfig_path)
      File.write(json_path, JSON.generate(
        "apiVersion" => "v1",
        "kind" => "ConfigMap",
        "metadata" => {"name" => "json-created", "namespace" => "d03"},
        "data" => {"format" => "json"}
      ))
      File.write(yaml_path, <<~YAML)
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: yaml-created
          namespace: d03
        data:
          format: yaml
      YAML
      File.write(apply_path, <<~YAML)
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: applied
          namespace: d03
        data:
          operation: apply
      YAML
      File.write(ruby_path, <<~RUBY)
        config_map "ruby-created", namespace: "d03" do
          data "PARENT_SECRET_VISIBLE" => ENV.key?("D03_PARENT_SECRET").to_s
        end
      RUBY

      transcript = +""
      run = lambda do |*arguments|
        stdout, stderr, status = Open3.capture3(
          {"RUBYLIB" => File.join(project_root, "lib"), "D03_PARENT_SECRET" => parent_secret},
          executable,
          "--kubeconfig", kubeconfig_path,
          *arguments,
          chdir: project_root
        )
        transcript << stdout << stderr

        assert_predicate(status, :success?, "rubectl #{arguments.join(" ")} failed with #{status.exitstatus}: #{stderr}")
        assert_empty(stderr)
        stdout
      end

      version = JSON.parse(run.call("raw", "GET", "/version"))

      assert(version.key?("gitVersion"))

      # NamespaceLifecycle admission in the real API server process.
      namespace_path = File.join(directory, "d03-namespace.json")
      File.write(namespace_path, JSON.generate("apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "d03"}))

      assert_equal("d03", JSON.parse(run.call("create", "-f", namespace_path)).dig("metadata", "name"))

      created_json = JSON.parse(run.call("create", "-f", json_path))

      assert_equal("json-created", created_json.dig("metadata", "name"))
      created_yaml = JSON.parse(run.call("create", "-f", yaml_path))

      assert_equal("yaml", created_yaml.dig("data", "format"))

      applied = JSON.parse(run.call("apply", "-f", apply_path))

      assert_equal("apply", applied.dig("data", "operation"))
      fetched = JSON.parse(run.call("get", "configmaps", "json-created", "-o", "json"))

      assert_equal("json", fetched.dig("data", "format"))

      patched = JSON.parse(run.call(
        "patch", "configmaps/json-created", "--type", "merge",
        "--patch", '{"metadata":{"labels":{"e2e":"true"}}}'
      ))

      assert_equal("true", patched.dig("metadata", "labels", "e2e"))

      watch_path = "/api/v1/namespaces/d03/configmaps?sendInitialEvents=true&resourceVersionMatch=NotOlderThan"
      watch_output = watch_error = watch_wait = nil
      begin
        watch_input, watch_output, watch_error, watch_wait = Open3.popen3(
          {"RUBYLIB" => File.join(project_root, "lib"), "D03_PARENT_SECRET" => parent_secret},
          executable,
          "--kubeconfig", kubeconfig_path,
          "watch", watch_path,
          chdir: project_root
        )
        watch_input.close
        watched = read_until(watch_output, '"name": "json-created"', timeout: 5)
        Process.kill("INT", watch_wait.pid)
        watch_status = Timeout.timeout(5) { watch_wait.value }
        watched << watch_output.read
        watch_errors = watch_error.read
        transcript << watched << watch_errors

        assert_equal(Rubernetes::Rubectl::CLI::EX_INTERRUPTED, watch_status.exitstatus)
        assert_empty(watch_errors)
        assert_includes(watched, '"type": "ADDED"')
        assert_includes(watched, '"name": "json-created"')
      ensure
        if watch_wait&.alive?
          Process.kill("TERM", watch_wait.pid)
          Timeout.timeout(5) { watch_wait.value }
        end
        watch_output&.close
        watch_error&.close
      end

      ruby_created = JSON.parse(run.call("apply", "--allow-code", "-f", ruby_path))

      assert_equal("false", ruby_created.dig("data", "PARENT_SECRET_VISIBLE"))

      deleted = JSON.parse(run.call("delete", "configmaps", "json-created"))

      assert_equal("Status", deleted["kind"])
      assert_equal("Success", deleted["status"])
      assert_equal("json-created", deleted.dig("details", "name"))

      missing_stdout, missing_stderr, missing_status = Open3.capture3(
        {"RUBYLIB" => File.join(project_root, "lib")},
        executable,
        "--kubeconfig", kubeconfig_path,
        "get", "configmaps", "json-created",
        chdir: project_root
      )
      transcript << missing_stdout << missing_stderr

      assert_equal(1, missing_status.exitstatus)
      assert_empty(missing_stdout)
      assert_includes(missing_stderr, '"reason":"NotFound"')

      usage_stdout, usage_stderr, usage_status = Open3.capture3(
        {"RUBYLIB" => File.join(project_root, "lib")},
        executable,
        "--kubeconfig", kubeconfig_path,
        "raw", "GET",
        chdir: project_root
      )
      transcript << usage_stdout << usage_stderr

      assert_equal(Rubernetes::Rubectl::CLI::EX_USAGE, usage_status.exitstatus)
      assert_empty(usage_stdout)
      assert_includes(usage_stderr, "raw requires METHOD PATH")

      config_stdout, config_stderr, config_status = Open3.capture3(
        {"RUBYLIB" => File.join(project_root, "lib")},
        executable,
        "--kubeconfig", File.join(directory, "missing-kubeconfig"),
        "get", "configmaps",
        chdir: project_root
      )
      transcript << config_stdout << config_stderr

      assert_equal(Rubernetes::Rubectl::CLI::EX_CONFIG, config_status.exitstatus)
      assert_empty(config_stdout)
      assert_includes(config_stderr, "cannot read kubeconfig")

      refute_includes(transcript, secret_token)
      refute_includes(transcript, parent_secret)
      refute_includes(log_output.string, secret_token)
      refute_includes(log_output.string, parent_secret)
    end
  ensure
    service&.stop(reason: "test complete")
  end

  private

  def read_until(io, needle, timeout:)
    output = +""
    Timeout.timeout(timeout) do
      output << io.readpartial(4096) until output.include?(needle)
    end
    output
  rescue EOFError
    raise "subprocess output ended before #{needle.inspect}: #{output.inspect}"
  rescue Timeout::Error
    raise "subprocess output did not contain #{needle.inspect} within #{timeout} seconds: #{output.inspect}"
  end

  def kubeconfig_with_token_file(config_path, token_file)
    Rubernetes::Client::Kubeconfig.from_hash(
      {
        "current-context" => "local",
        "clusters" => [{"name" => "local", "cluster" => {"server" => "https://kube.example.test"}}],
        "users" => [{"name" => "local", "user" => {"tokenFile" => token_file}}],
        "contexts" => [{"name" => "local", "context" => {"cluster" => "local", "user" => "local"}}]
      },
      path: config_path
    )
  end

  def minimal_kubeconfig_yaml
    <<~YAML
      apiVersion: v1
      kind: Config
      current-context: local
      clusters:
      - name: local
        cluster:
          server: https://kube.example.test
      users: []
      contexts:
      - name: local
        context:
          cluster: local
    YAML
  end

  def kubeconfig_with_inline_token(token)
    Rubernetes::Client::Kubeconfig.from_hash(
      "current-context" => "local",
      "clusters" => [{"name" => "local", "cluster" => {"server" => "https://kube.example.test"}}],
      "users" => [{"name" => "local", "user" => {"token" => token}}],
      "contexts" => [{"name" => "local", "context" => {"cluster" => "local", "user" => "local"}}]
    )
  end

  def streaming_rest_for(chunks)
    Class.new do
      define_method(:initialize) { |values| @values = values }
      define_method(:stream) do |*_arguments, **_options|
        @values.each
      end
    end.new(chunks)
  end

  def certificate_material(common_name: "rubernetes-test", ca: false)
    key = OpenSSL::PKey::RSA.new(2048)
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = Random.new_seed
    certificate.subject = OpenSSL::X509::Name.parse("/CN=#{common_name}")
    certificate.issuer = certificate.subject
    certificate.public_key = key.public_key
    certificate.not_before = Time.now - 60
    certificate.not_after = Time.now + 3600
    if ca
      extensions = OpenSSL::X509::ExtensionFactory.new
      extensions.subject_certificate = certificate
      extensions.issuer_certificate = certificate
      certificate.add_extension(extensions.create_extension("basicConstraints", "CA:TRUE", true))
      certificate.add_extension(extensions.create_extension("keyUsage", "keyCertSign,digitalSignature", true))
    end
    certificate.sign(key, OpenSSL::Digest.new("SHA256"))
    [certificate, key]
  end
end
