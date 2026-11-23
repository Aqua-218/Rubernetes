# frozen_string_literal: true

require "test_helper"
require "json"
require "socket"
require "tmpdir"
require "yaml"
require "rubernetes/client"

class ClientExecCredentialTest < Minitest::Test
  Client = Rubernetes::Client
  Metrics = Rubernetes::Observability::Metrics
  V1 = "client.authentication.k8s.io/v1"

  def setup
    @dir = Dir.mktmpdir("exec-credential")
    Rubernetes::Client::ExecCredential.reset_cache!
  end

  def teardown
    Client::ExecCredential.reset_cache!
    FileUtils.remove_entry(@dir)
  end

  def plugin(name, body)
    path = File.join(@dir, name)
    File.write(path, "#!/bin/sh\n#{body}\n")
    File.chmod(0o755, path)
    path
  end

  def credential(api_version: V1, **status)
    JSON.generate("apiVersion" => api_version, "kind" => "ExecCredential", "status" => status)
  end

  def config(command, **extra)
    {"apiVersion" => V1, "command" => command, "interactiveMode" => "Never"}.merge(extra.transform_keys(&:to_s))
  end

  def run_plugin(config, **)
    Rubernetes::Client::ExecCredential.new(config, base_directory: @dir, stderr: File::NULL, **).call
  end

  def test_token_and_expiry_are_returned
    path = plugin("token", "echo '#{credential("token" => "abc123", "expirationTimestamp" => "2099-01-01T00:00:00Z")}'")

    result = run_plugin(config(path))

    assert_equal "abc123", result.bearer_token
    assert_equal Time.utc(2099, 1, 1), result.expires_at
    refute_predicate result, :expired?
  end

  def test_arguments_environment_and_exec_info_reach_the_plugin
    seen = File.join(@dir, "seen")
    path = plugin("args", %(printf '%s|%s|%s' "$1" "$REGION" "$KUBERNETES_EXEC_INFO" > #{seen}\necho '#{credential("token" => "t")}'))

    run_plugin(config(path, args: ["get-token"], env: [{"name" => "REGION", "value" => "tokyo"}], provideClusterInfo: true),
               cluster: {"server" => "https://k.example:6443", "certificate-authority-data" => "Q0E="})

    argument, region, info = File.read(seen).split("|", 3)

    assert_equal %w[get-token tokyo], [argument, region]
    spec = JSON.parse(info).fetch("spec")

    assert_equal false, spec.fetch("interactive")
    assert_equal({"server" => "https://k.example:6443", "certificate-authority-data" => "Q0E="}, spec.fetch("cluster"))
  end

  def test_a_relative_command_is_resolved_from_the_kubeconfig_directory
    plugin("local", "echo '#{credential("token" => "local")}'")

    assert_equal "local", run_plugin(config("./local")).bearer_token
  end

  def test_client_certificate_needs_its_key
    path = plugin("half", "echo '#{credential("clientCertificateData" => "CERT")}'")

    error = assert_raises(Rubernetes::Client::UnsupportedCredentialError) { run_plugin(config(path)) }
    assert_match(/without its key/, error.message)
  end

  def test_a_failing_plugin_is_reported_with_its_exit_status
    path = plugin("fail", "exit 3")

    error = assert_raises(Rubernetes::Client::UnsupportedCredentialError) { run_plugin(config(path)) }
    assert_match(/exit 3/, error.message)
  end

  def test_a_missing_plugin_prints_the_install_hint
    error = assert_raises(Rubernetes::Client::UnsupportedCredentialError) do
      run_plugin(config("no-such-credential-plugin", installHint: "install it from example.test"))
    end
    assert_match(/install it from example\.test/, error.message)
  end

  def test_a_mismatched_api_version_is_refused
    path = plugin("old", "echo '#{credential("token" => "t", api_version: "client.authentication.k8s.io/v1beta1")}'")

    error = assert_raises(Rubernetes::Client::UnsupportedCredentialError) { run_plugin(config(path)) }
    assert_match(/apiVersion/, error.message)
  end

  def test_a_silent_plugin_is_killed
    path = plugin("hang", "exec sleep 30")
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    error = assert_raises(Rubernetes::Client::UnsupportedCredentialError) { run_plugin(config(path), timeout: 0.3) }

    assert_match(/did not answer/, error.message)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 10
  end

  def test_a_plugin_that_closes_stdout_must_still_exit_before_the_deadline
    path = plugin("closed-output", "exec 1>&-\nexec sleep 30")

    error = assert_raises(Client::UnsupportedCredentialError) { run_plugin(config(path), timeout: 0.2) }

    assert_match(/did not answer/, error.message)
  end

  def test_v1_requires_an_interactive_mode
    error = assert_raises(Rubernetes::Client::ConfigurationError) { run_plugin({"apiVersion" => V1, "command" => "true"}) }
    assert_match(/interactiveMode/, error.message)
  end

  def test_fetch_runs_the_plugin_once_until_the_credential_expires
    count = File.join(@dir, "runs")
    path = plugin("count", "echo x >> #{count}\necho '#{credential("token" => "t", "expirationTimestamp" => "2099-01-01T00:00:00Z")}'")

    2.times { Rubernetes::Client::ExecCredential.fetch(config(path), base_directory: @dir) }

    assert_equal 1, File.readlines(count).size
  end

  def test_kubeconfig_resolves_a_context_through_the_plugin
    path = plugin("token", "echo '#{credential("token" => "from-plugin")}'")
    kubeconfig = Rubernetes::Client::Kubeconfig.from_hash(
      "current-context" => "c",
      "contexts" => [{"name" => "c", "context" => {"cluster" => "k", "user" => "u"}}],
      "clusters" => [{"name" => "k", "cluster" => {"server" => "https://127.0.0.1:6443", "insecure-skip-tls-verify" => true}}],
      "users" => [{"name" => "u", "user" => {"exec" => config(path)}}]
    )

    assert_equal "from-plugin", kubeconfig.resolve.bearer_token
  end

  def test_requests_refresh_an_expired_token_on_the_same_client
    first = credential("token" => "expiring", "expirationTimestamp" => "2000-01-01T00:00:00Z")
    path, runs = rotating_plugin(first, credential("token" => "fresh"))
    tokens = []
    transport = lambda do |_, _, headers:, **|
      tokens << headers.fetch("Authorization")
      response(200)
    end
    client = api_client(path, transport: transport)

    refute_path_exists runs
    3.times { client.raw("GET", "/version") }

    assert_equal ["Bearer expiring", "Bearer fresh", "Bearer fresh"], tokens
    assert_equal 2, File.readlines(runs).length
  end

  def test_unauthorized_refreshes_only_once_for_concurrent_requests_and_preserves_the_401
    path, runs = rotating_plugin(credential("token" => "rejected-credential"), credential("token" => "replacement"))
    rejected = Queue.new
    replies = Queue.new
    transport = lambda do |_, _, headers:, **|
      next response(200) if headers.fetch("Authorization") == "Bearer replacement"

      rejected << true
      replies.pop
      response(401, JSON.generate("kind" => "Status", "message" => "rejected-credential is not authorized"))
    end
    client = api_client(path, transport: transport)
    requests = Array.new(2) do
      Thread.new do
        client.raw("GET", "/version")
      rescue Client::APIError => error
        error
      end
    end
    errors = Timeout.timeout(5) do
      2.times { rejected.pop }
      2.times { replies << true }
      requests.map(&:value)
    end

    assert_equal [401, 401], errors.map(&:status)
    errors.each { |error| refute_includes error.message, "rejected-credential" }
    assert_equal 200, client.raw("GET", "/version").status
    assert_equal 2, File.readlines(runs).length
  ensure
    requests&.each { |request| request.kill.join if request.alive? }
  end

  def test_streaming_a_401_refreshes_the_plugin_for_the_next_watch
    path, runs = rotating_plugin(credential("token" => "previous"), credential("token" => "replacement"))
    transport = lambda do |_, _, headers:, **|
      headers.fetch("Authorization") == "Bearer previous" ? response(401) : response(200, "event")
    end
    client = api_client(path, transport: transport).rest_client

    error = assert_raises(Client::APIError) { client.stream("GET", "/watch") { flunk "401 yielded data" } }
    chunks = client.stream("GET", "/watch").to_a

    assert_equal 401, error.status
    assert_equal ["event"], chunks
    assert_equal 2, File.readlines(runs).length
  end

  def test_explicit_authorization_uses_no_exec_plugin
    transport = ->(_, _, headers:, **) { response(headers.values.include?("Bearer override") ? 200 : 401) }
    client = api_client("missing-credential-plugin", transport: transport)

    assert_equal 200, client.raw("GET", "/version", headers: {"authorization" => "Bearer override"}).status
    assert_raises(Client::UnsupportedCredentialError) { client.raw("GET", "/version") }
  end

  def test_static_kubeconfig_authentication_bypasses_the_plugin
    transport = ->(_, _, headers:, **) { response(headers.values.include?("Bearer static") ? 200 : 401) }
    client = api_client("missing-credential-plugin", token: "static", transport: transport)

    assert_equal 200, client.raw("GET", "/version").status
  end

  def test_policy_metrics_record_executed_policy_checks
    path, runs = rotating_plugin(credential("token" => "initial"), credential("token" => "replacement"))
    metric = "rest_client_exec_plugin_policy_call_total"
    registry = Metrics.global
    before = policy_totals(registry.render, metric)
    transport = ->(*) { response(200) }
    denied = api_client(path, exec_policy: {"type" => "DenyAll"}, transport: transport)
    wrong_command = api_client(path, exec_policy: {"type" => "Allowlist", "allowlist" => ["/missing"]}, transport: transport)

    assert_raises(Client::UnsupportedCredentialError) { denied.raw("GET", "/version") }
    assert_raises(Client::UnsupportedCredentialError) { wrong_command.raw("GET", "/version") }
    refute_path_exists runs

    allowed = api_client(path, exec_policy: {"type" => "Allowlist", "allowlist" => [path]}, transport: transport)

    assert_equal 200, allowed.raw("GET", "/version").status
    assert_equal 1, File.readlines(runs).length
    assert_equal([1, 2], policy_totals(registry.render, metric).zip(before).map { |after, initial| after - initial })
  end

  def test_client_certificate_rotation_retires_the_connection_and_updates_live_metrics
    now = Time.now
    ca, ca_key = issue_certificate(1, start: now - 600, expiry: now + 7200)
    old_cert, old_key = issue_certificate(2, start: now - 300, expiry: now + 1600, issuer: ca, signing_key: ca_key)
    new_cert, new_key = issue_certificate(3, start: now - 60, expiry: now + 3600, issuer: ca, signing_key: ca_key)
    path, runs = rotating_plugin(certificate_credential(old_cert, old_key), certificate_credential(new_cert, new_key))
    rotation_count = "rest_client_exec_plugin_certificate_rotation_age_count"
    ttl = "rest_client_exec_plugin_ttl_seconds"
    metrics = Metrics.new(apiserver: false, process: false, component: "kube-scheduler")
    initial = metric_value(metrics.render, rotation_count)

    with_tls_server(ca, ca_key) do |server, handshakes|
      client = api_client(path, server: server, read_timeout: 2, open_timeout: 2)

      assert_equal 401, client.raw("GET", "/version", raise_for_status: false).status
      assert_equal 200, client.raw("GET", "/version").status
      assert_equal [2, 3], handshakes.value
      assert_equal 1, client.rest_client.connection_generation
    ensure
      client&.rest_client&.close
    end

    assert_equal 2, File.readlines(runs).length
    assert_in_delta initial + 1, metric_value(metrics.render, rotation_count)
    assert_in_delta new_cert.not_after - Time.now, metric_value(metrics.render, ttl), 1
  end

  private

  def rotating_plugin(first, second)
    runs = File.join(@dir, "runs")
    command = plugin("rotate", <<~SH)
      if test -e "#{runs}"; then
        printf '%s\\n' '#{second}'
      else
        printf '%s\\n' '#{first}'
      fi
      echo x >> "#{runs}"
    SH
    [command, runs]
  end

  def api_client(command, server: "https://127.0.0.1:6443", token: nil, **)
    path = File.join(@dir, "client.yml")
    user = {"exec" => config(command)}
    user["token"] = token if token
    document = {
      "current-context" => "c",
      "contexts" => [{"name" => "c", "context" => {"cluster" => "k", "user" => "u"}}],
      "clusters" => [{"name" => "k", "cluster" => {"server" => server, "insecure-skip-tls-verify" => true}}],
      "users" => [{"name" => "u", "user" => user}]
    }
    File.write(path, YAML.dump(document))
    File.chmod(0o600, path)
    Client::KubernetesClient.from_kubeconfig(path: path, **)
  end

  def response(status, body = "")
    Client::HTTPClient::Response.new(status: status, headers: {}, body: body)
  end

  def policy_totals(rendered, metric)
    %w[true false].map do |allowed|
      metric_value(rendered, %(#{metric}{allowed="#{allowed}",denied="#{allowed == "false"}"}))
    end
  end

  def metric_value(rendered, series)
    line = rendered.each_line.find { |entry| entry.start_with?("#{series} ") }
    line ? Float(line.split.last) : 0
  end

  def issue_certificate(serial, start:, expiry:, issuer: nil, signing_key: nil)
    key = OpenSSL::PKey::EC.generate("prime256v1")
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = serial
    certificate.subject = OpenSSL::X509::Name.parse("/CN=certificate-#{serial}")
    certificate.issuer = issuer&.subject || certificate.subject
    certificate.public_key = key
    certificate.not_before = start
    certificate.not_after = expiry
    certificate.add_extension(OpenSSL::X509::ExtensionFactory.new.create_extension("basicConstraints", "CA:TRUE", true)) unless issuer
    certificate.sign(signing_key || key, OpenSSL::Digest.new("SHA256"))
    [certificate, key]
  end

  def certificate_credential(cert, key)
    credential("clientCertificateData" => cert.to_pem, "clientKeyData" => key.private_to_pem)
  end

  def with_tls_server(certificate, key)
    server = TCPServer.new("127.0.0.1", 0)
    ssl = OpenSSL::SSL::SSLContext.new
    ssl.cert = certificate
    ssl.key = key
    ssl.cert_store = OpenSSL::X509::Store.new.tap { |store| store.add_cert(certificate) }
    ssl.verify_mode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    listener = OpenSSL::SSL::SSLServer.new(server, ssl)
    handshakes = Thread.new do
      ["401 Unauthorized", "200 OK"].map do |status|
        socket = listener.accept
        socket.each_line { |line| break if line == "\r\n" }
        serial = socket.peer_cert.serial.to_i
        socket.write("HTTP/1.1 #{status}\r\nContent-Length: 0\r\n\r\n")
        socket.read(1) if status.start_with?("401")
        serial
      ensure
        socket&.close
      end
    end
    yield "https://127.0.0.1:#{server.addr[1]}", handshakes
  ensure
    handshakes&.kill&.join if handshakes&.alive?
    server&.close
  end
end
