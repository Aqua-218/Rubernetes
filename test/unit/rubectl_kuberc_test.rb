# frozen_string_literal: true

require "open3"
require "socket"
require "stringio"
require "tmpdir"
require "yaml"

require_relative "../test_helper"
require "rubernetes/rubectl"

class RubectlKubercTest < Minitest::Test
  CLI = Rubernetes::Rubectl::CLI
  VERSION = "kubectl.config.k8s.io/v1beta1"
  ROOT = File.expand_path("../..", __dir__)

  def setup
    @directory = Dir.mktmpdir("rubernetes-kuberc")
    @env = {"HOME" => @directory}
    FileUtils.mkdir_p(File.join(@directory, ".kube"))
    @plugin = File.join(@directory, "credential-helper")
    @runs = File.join(@directory, "runs")
    File.write(@plugin, <<~SH)
      #!/bin/sh
      echo executed >> "#{@runs}"
      echo '{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"from-plugin"}}'
    SH
    File.chmod(0o755, @plugin)
    @config = File.join(@directory, "config")
    write_kubeconfig("http://127.0.0.1:1")
  end

  def teardown
    FileUtils.remove_entry(@directory)
  end

  def test_default_policy_is_enforced_by_the_rubectl_executable
    save_policy(File.join(@directory, ".kube", "kuberc"), "DenyAll")
    child_env = @env.merge("RUBYLIB" => File.join(ROOT, "lib"), "KUBERC" => nil, "KUBECTL_KUBERC" => "true")
    stdout, stderr, status = Open3.capture3(child_env, File.join(ROOT, "exe", "rubectl"), "--kubeconfig", @config, "raw", "GET", "/version")

    assert_equal CLI::EX_CONFIG, status.exitstatus
    assert_empty stdout
    assert_match(/policy set to DenyAll/, stderr)
    refute_path_exists @runs
  end

  def test_environment_overrides_default_and_flag_overrides_environment
    save_policy(File.join(@directory, ".kube", "kuberc"), "AllowAll")
    @env["KUBERC"] = save_policy(File.join(@directory, "deny"), "DenyAll")
    path = File.join(@directory, "allow")
    save_policy(path, "Allowlist", [{"name" => @plugin, "command" => @plugin}])
    File.write(path, "---\napiVersion: kubectl.config.k8s.io/v9\nkind: Preference\n---\n" + File.read(path))

    status, _, diagnostic = run_cli

    assert_equal CLI::EX_CONFIG, status
    assert_match(/policy set to DenyAll/, diagnostic)
    refute_path_exists @runs

    assert_request_token("from-plugin", "--kuberc=#{path}")
    assert_equal 1, File.readlines(@runs).length
  end

  def test_off_ignores_default_preferences_and_rejects_an_explicit_flag
    path = save_policy(File.join(@directory, ".kube", "kuberc"), "DenyAll")
    @env["KUBERC"] = "off"

    status, _, diagnostic = run_cli("--kuberc", path)

    assert_equal CLI::EX_CONFIG, status
    assert_match(/KUBERC=off cannot be combined with --kuberc/, diagnostic)
    refute_path_exists @runs

    assert_request_token("from-plugin")
  end

  def test_disabled_feature_ignores_preferences_and_removes_the_flag
    @env["KUBECTL_KUBERC"] = "FaLsE"
    path = save_policy(File.join(@directory, "deny"), "DenyAll")
    @env["KUBERC"] = path

    status, _, diagnostic = run_cli("--kuberc", path)

    assert_equal CLI::EX_USAGE, status
    assert_match(/invalid option: --kuberc/, diagnostic)
    assert_request_token("from-plugin")
  end

  def test_deprecated_allowlist_name_in_the_first_supported_document_is_enforced
    path = save_policy(File.join(@directory, "allow-other"), "Allowlist", [{"name" => "/some/other/helper"}])
    File.open(path, "a") { |file| file.write("---\napiVersion: #{VERSION}\nkind: Preference\ncredentialPluginPolicy: AllowAll\n") }

    status, _, diagnostic = run_cli("--kuberc", path)

    assert_equal CLI::EX_CONFIG, status
    assert_match(/credential plugin allowlist/, diagnostic)
    refute_path_exists @runs
  end

  def test_v1alpha1_is_a_supported_document_without_a_credential_policy
    path = File.join(@directory, "first-alpha")
    File.write(path, <<~YAML)
      apiVersion: kubectl.config.k8s.io/v1alpha1
      kind: Preference
      ---
      apiVersion: #{VERSION}
      kind: Preference
      credentialPluginPolicy: DenyAll
    YAML

    assert_request_token("from-plugin", "--kuberc", path)
  end

  def test_a_misconfigured_allowlist_is_rejected_even_with_a_static_token
    path = save_policy(File.join(@directory, "invalid"), "Allowlist", [{"name" => @plugin, "command" => "/other"}])

    status, _, diagnostic = run_cli("--kuberc", path, "--token", "override")

    assert_equal CLI::EX_CONFIG, status
    assert_match(/command and deprecated name are different/, diagnostic)
    refute_path_exists @runs
  end

  def test_a_valid_deny_policy_allows_an_explicit_static_token
    path = save_policy(File.join(@directory, "deny"), "DenyAll")

    assert_request_token("override", "--kuberc", path, "--token", "override")
    refute_path_exists @runs
  end

  def test_missing_explicit_preferences_fail_and_invalid_default_warns
    path = File.join(@directory, "missing")
    status, _, diagnostic = run_cli("--kuberc", path)

    assert_equal CLI::EX_CONFIG, status
    assert_match(/kuberc/, diagnostic)
    refute_path_exists @runs

    File.write(File.join(@directory, ".kube", "kuberc"), "kind: Unknown\napiVersion: #{VERSION}\n")

    assert_request_token("from-plugin", warning: /no supported Preference/)
  end

  private

  def write_kubeconfig(server)
    credential = {"apiVersion" => "client.authentication.k8s.io/v1", "command" => @plugin, "interactiveMode" => "Never"}
    document = {
      "clusters" => [{"name" => "cluster", "cluster" => {"server" => server}}],
      "users" => [{"name" => "user", "user" => {"exec" => credential}}],
      "contexts" => [{"name" => "context", "context" => {"cluster" => "cluster", "user" => "user"}}],
      "current-context" => "context"
    }
    File.write(@config, YAML.dump(document), perm: 0o600)
  end

  def save_policy(path, type, allowlist = nil)
    document = {"apiVersion" => VERSION, "kind" => "Preference", "credentialPluginPolicy" => type}
    document["credentialPluginAllowlist"] = allowlist if allowlist
    File.write(path, YAML.dump(document))
    path
  end

  def run_cli(*options)
    output = StringIO.new
    errors = StringIO.new
    status = CLI.run(["--kubeconfig", @config, *options, "raw", "GET", "/version"], stdout: output, stderr: errors, env: @env)
    [status, output.string, errors.string]
  end

  def assert_request_token(token, *options, warning: nil)
    server = TCPServer.new("127.0.0.1", 0)
    write_kubeconfig("http://127.0.0.1:#{server.addr[1]}")
    request = Thread.new do
      socket = server.accept
      headers = socket.each_line.take_while { |line| line != "\r\n" }
      socket.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
      headers
    ensure
      socket&.close
    end
    status, output, diagnostic = run_cli(*options)

    assert_equal CLI::EX_OK, status, diagnostic
    assert_equal({}, JSON.parse(output))
    assert_includes request.value, "Authorization: Bearer #{token}\r\n"
    warning ? assert_match(warning, diagnostic) : assert_empty(diagnostic)
  ensure
    request&.kill&.join if request&.alive?
    server&.close
  end
end
