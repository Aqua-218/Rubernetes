# frozen_string_literal: true

require "test_helper"
require "json"
require "tmpdir"
require "rubernetes/client"

class ClientExecCredentialTest < Minitest::Test
  V1 = "client.authentication.k8s.io/v1"

  def setup
    @dir = Dir.mktmpdir("exec-credential")
    Rubernetes::Client::ExecCredential.reset_cache!
  end

  def teardown
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
end
