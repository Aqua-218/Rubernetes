#!/usr/bin/env ruby
# frozen_string_literal: true

# Isolated Kubernetes v1.36.2 API oracle used only by M1 test evidence.

require "json"
require "net/http"
require "openssl"
require "open3"
require "securerandom"
require "time"
require "tmpdir"
require "uri"

module M1KubernetesOracle
  KUBERNETES_VERSION = "v1.36.2"
  KUBERNETES_SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"
  KUBE_APISERVER_IMAGE = "registry.k8s.io/kube-apiserver@sha256:0535dde1a857029209d7effe681c919a1580d2eb24eda4bd122d24e9a372e1b8"
  ETCD_IMAGE = "registry.k8s.io/etcd@sha256:397189418d1a00e500c0605ad18d1baf3b541a1004d768448c367e48071622e5"
  START_TIMEOUT = 45.0
  # kube-apiserver can answer /version before its built-in API discovery
  # registry has finished publishing every group. The first /apis response
  # is therefore not a stable oracle observation; wait for the pinned default
  # profile's complete built-in group set before handing the client to probes.
  MIN_DISCOVERY_GROUPS = 20

  class Error < StandardError; end

  Response = Struct.new(:status, :headers, :body, keyword_init: true) do
    def content_type
      headers.fetch("content-type", "").split(";", 2).first
    end
  end

  CommandResult = Struct.new(:stdout, :stderr, :status, keyword_init: true) do
    def success?
      status.success?
    end
  end

  class CommandRunner
    def capture(*argv)
      stdout, stderr, status = Open3.capture3(*argv)
      CommandResult.new(stdout: stdout, stderr: stderr, status: status)
    rescue SystemCallError => error
      raise Error, "cannot execute #{argv.first.inspect}: #{error.message}"
    end
  end

  # Identity of every differential request against either server: the static
  # token file entry of the isolated kube-apiserver and the in-process
  # resolver of the Rubernetes API server describe the same user.
  REQUESTER_IDENTITY = {"username" => "m1-oracle", "uid" => "1", "groups" => %w[system:masters system:authenticated]}.freeze
  REVIEW_TOKEN = "m1-review-token-6f1c0d2a"
  REVIEW_USER = "m1-review"
  REVIEW_UID = "2"
  REVIEW_GROUP = "system:reviewers"
  REVIEW_IDENTITY = {"username" => REVIEW_USER, "uid" => REVIEW_UID, "groups" => [REVIEW_GROUP, "system:authenticated"]}.freeze
  API_AUDIENCES = %w[https://kubernetes.default.svc].freeze

  # HTTPS client authenticated by a run-local static token.
  class HTTPClient
    def initialize(port:, token:, ca_file:)
      @port = Integer(port)
      @token = token.to_s
      @ca_file = File.expand_path(ca_file)
      raise Error, "oracle CA certificate is unavailable" unless File.file?(@ca_file)
    end

    def request(method:, path:, body: nil, query: nil, headers: {})
      uri = URI("https://127.0.0.1:#{@port}#{path}")
      uri.query = URI.encode_www_form(query) if query && !query.empty?
      request = request_class(method).new(uri)
      request["Authorization"] = "Bearer #{@token}"
      headers.each { |name, value| request[name.to_s] = value.to_s }
      unless body.nil?
        request.body = body.is_a?(String) ? body : JSON.generate(body)
        request["Content-Type"] ||= "application/json"
      end
      http = Net::HTTP.new(uri.host, uri.port, nil)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.ca_file = @ca_file
      http.verify_hostname = true if http.respond_to?(:verify_hostname=)
      http.open_timeout = 5
      http.read_timeout = 15
      http.write_timeout = 5
      response = http.start { |connection| connection.request(request) }
      Response.new(
        status: Integer(response.code),
        headers: response.each_header.to_h.transform_keys(&:downcase),
        # Discovery for a disabled API group is a valid negative observation.
        # kube-apiserver returns a short plain-text 404 page for that path, so
        # preserve it as a body instead of turning a protocol-level response
        # into an oracle transport failure.  Successful responses remain
        # strict JSON and still fail closed on malformed payloads.
        body: parse_body(response.body, status: Integer(response.code))
      )
    rescue JSON::ParserError => error
      raise Error, "oracle returned invalid JSON for #{method} #{path}: #{error.message}"
    rescue IOError, SystemCallError, Timeout::Error, OpenSSL::SSL::SSLError => error
      raise Error, "oracle request failed for #{method} #{path}: #{error.class}: #{error.message}"
    end

    private

    def request_class(method)
      {
        "DELETE" => Net::HTTP::Delete,
        "GET" => Net::HTTP::Get,
        "PATCH" => Net::HTTP::Patch,
        "POST" => Net::HTTP::Post,
        "PUT" => Net::HTTP::Put
      }.fetch(method.to_s.upcase) { raise Error, "unsupported oracle HTTP method #{method.inspect}" }
    end

    def parse_body(body, status: nil)
      value = body.to_s
      return nil if value.empty?

      JSON.parse(value)
    rescue JSON::ParserError => document_error
      return value if status && status >= 400

      raise document_error unless value.lines.length > 1

      value.lines.filter_map do |line|
        stripped = line.strip
        JSON.parse(stripped) unless stripped.empty?
      end
    end
  end

  # Adapter giving the in-process API server the same request interface as the
  # isolated HTTPS oracle.
  class InProcessClient
    def initialize(server)
      @server = server
    end

    def request(method:, path:, body: nil, query: nil, headers: {})
      response = @server.call(method: method, path: path, body: body, query: query, headers: headers)
      body = if response.body.respond_to?(:events)
               events = response.body.events.map(&:to_h)
               response.body.close
               events
             else
               response.body
             end
      Response.new(status: response.status, headers: response.headers, body: body)
    end
  end

  # Owns one short-lived Docker network, etcd, and kube-apiserver pair.
  class DockerCluster
    def initialize(command_runner: CommandRunner.new, sleeper: ->(seconds) { sleep(seconds) }, extra_api_args: [], token_groups: [])
      suffix = "#{Process.pid}-#{SecureRandom.hex(6)}"
      # Additional kube-apiserver flags (for example a feature-gate profile)
      # and extra groups for the oracle token user (for example
      # system:masters when RBAC authorization is enabled) are used by corpus
      # importers; the M1 differential passes neither.
      @extra_api_args = Array(extra_api_args).map(&:to_s)
      @token_groups = Array(token_groups).map(&:to_s)
      @network_name = "rubernetes-m1-oracle-net-#{suffix}"
      @etcd_name = "rubernetes-m1-oracle-etcd-#{suffix}"
      @api_name = "rubernetes-m1-oracle-api-#{suffix}"
      @command_runner = command_runner
      @sleeper = sleeper
      @created = []
      @command_records = []
    end

    attr_reader :network_name, :etcd_name, :api_name

    def with_client
      verify_image!(KUBE_APISERVER_IMAGE)
      verify_image!(ETCD_IMAGE)
      primary_error = nil
      result = nil
      cleanup_errors = []
      Dir.mktmpdir("rubernetes-m1-oracle-") do |certificate_directory|
        write_certificates(certificate_directory)
        create_network
        start_etcd
        wait_for_etcd
        port = start_api_server(certificate_directory)
        client = HTTPClient.new(
          port: port,
          token: @token,
          ca_file: File.join(certificate_directory, "ca.crt")
        )
        version = wait_for_api(client)
        verify_version!(version)
        result = yield(client, evidence(version: version, port: port))
      rescue StandardError => error
        primary_error = error
      ensure
        cleanup_errors = cleanup
      end
      if primary_error
        detail = cleanup_errors.empty? ? "" : "; cleanup failures: #{cleanup_errors.join("; ")}"
        raise Error, "#{primary_error.class}: #{primary_error.message}#{detail}"
      end
      raise Error, "oracle cleanup failed: #{cleanup_errors.join("; ")}" unless cleanup_errors.empty?

      result
    end

    private

    def verify_image!(reference)
      result = run("docker", "image", "inspect", reference, "--format", "{{json .RepoDigests}}")
      raise Error, "required oracle image is unavailable: #{reference}" unless result.success?

      digests = JSON.parse(result.stdout)
      raise Error, "oracle image digest mismatch for #{reference}" unless Array(digests).include?(reference)
    rescue JSON::ParserError => error
      raise Error, "cannot verify oracle image digest for #{reference}: #{error.message}"
    end

    def create_network
      run!("docker", "network", "create", "--label", "rubernetes.m1.oracle=true", @network_name)
      @created << [:network, @network_name]
    end

    def start_etcd
      run!(
        "docker", "run", "--detach", "--name", @etcd_name,
        "--network", @network_name, "--network-alias", "etcd",
        "--pull", "never", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
        "--tmpfs", "/var/lib/etcd:rw,noexec,nosuid", "--entrypoint", "/usr/local/bin/etcd",
        ETCD_IMAGE,
        "--name", "m1-oracle", "--data-dir", "/var/lib/etcd",
        "--listen-client-urls", "http://0.0.0.0:2379", "--advertise-client-urls", "http://etcd:2379",
        "--listen-peer-urls", "http://0.0.0.0:2380", "--initial-advertise-peer-urls", "http://etcd:2380",
        "--initial-cluster", "m1-oracle=http://etcd:2380"
      )
      @created << [:container, @etcd_name]
    end

    def wait_for_etcd
      wait_until("etcd did not become healthy") do
        result = run(
          "docker", "exec", @etcd_name, "/usr/local/bin/etcdctl",
          "--endpoints=http://127.0.0.1:2379", "endpoint", "health"
        )
        result.success?
      end
    end

    def start_api_server(certificate_directory)
      run!(
        "docker", "run", "--detach", "--name", @api_name,
        "--network", @network_name, "--network-alias", "kube-apiserver",
        "--publish", "127.0.0.1::6443", "--pull", "never",
        "--security-opt", "no-new-privileges=true", "--tmpfs", "/tmp:rw,noexec,nosuid",
        "--volume", "#{certificate_directory}:/oracle-certs:ro",
        "--entrypoint", "/usr/local/bin/kube-apiserver", KUBE_APISERVER_IMAGE,
        "--bind-address=0.0.0.0", "--secure-port=6443",
        "--etcd-servers=http://etcd:2379", "--service-cluster-ip-range=10.96.0.0/12",
        "--authorization-mode=AlwaysAllow", "--anonymous-auth=true",
        "--tls-cert-file=/oracle-certs/tls.crt", "--tls-private-key-file=/oracle-certs/tls.key",
        "--service-account-issuer=https://kubernetes.default.svc",
        "--service-account-signing-key-file=/oracle-certs/tls.key",
        "--service-account-key-file=/oracle-certs/sa.pub",
        "--token-auth-file=/oracle-certs/tokens.csv",
        "--profiling=false",
        *@extra_api_args
      )
      @created << [:container, @api_name]
      port_result = run("docker", "port", @api_name, "6443/tcp")
      unless port_result.success?
        state = run("docker", "inspect", @api_name, "--format", "{{.State.Status}} {{.State.ExitCode}} {{.State.Error}}")
        logs = run("docker", "logs", "--tail", "120", @api_name)
        log_output = "#{logs.stdout}\n#{logs.stderr}"[-6000, 6000].to_s
        raise Error, "kube-apiserver port was not published: #{state.stdout.strip}; #{log_output}"
      end
      mapping = port_result.stdout.strip
      port = mapping.split(":").last
      raise Error, "kube-apiserver published port is missing" unless port&.match?(/\A[0-9]+\z/)

      Integer(port, 10)
    end

    def wait_for_api(client)
      version = nil
      last_error = nil
      wait_until("kube-apiserver did not become ready") do
        response = client.request(method: "GET", path: "/version")
        discovery = client.request(method: "GET", path: "/apis")
        version = response.body
        groups = discovery.body.is_a?(Hash) ? discovery.body["groups"] : nil
        response.status == 200 && version.is_a?(Hash) && discovery.status == 200 &&
          groups.is_a?(Array) && groups.length >= MIN_DISCOVERY_GROUPS &&
          groups.all? { |group| group.is_a?(Hash) && group["name"].is_a?(String) && Array(group["versions"]).any? }
      rescue Error => error
        last_error = error.message
        false
      end
      version
    rescue Error => error
      logs = run("docker", "logs", "--tail", "120", @api_name)
      detail = "#{logs.stdout}\n#{logs.stderr}"[-6000, 6000].to_s
      raise Error, "#{error.message}; last request: #{last_error}; kube-apiserver logs: #{detail}"
    end

    def verify_version!(version)
      return if version["gitVersion"] == KUBERNETES_VERSION && version["gitCommit"] == KUBERNETES_SOURCE_COMMIT

      raise Error, "oracle version identity does not match pinned Kubernetes v1.36.2 source"
    end

    def evidence(version:, port:)
      {
        "executed" => true,
        "kubernetes_version" => version.fetch("gitVersion"),
        "source_commit" => version.fetch("gitCommit"),
        "kube_apiserver_image" => KUBE_APISERVER_IMAGE,
        "etcd_image" => ETCD_IMAGE,
        "network_name" => @network_name,
        "api_container_name" => @api_name,
        "etcd_container_name" => @etcd_name,
        "published_port" => port,
        "tls_verification" => "peer-and-hostname",
        "container_execution" => JSON.parse(JSON.generate(@command_records))
      }
    end

    def wait_until(message)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + START_TIMEOUT
      loop do
        return true if yield
        raise Error, message if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        @sleeper.call(0.25)
      end
    end

    def cleanup
      errors = []
      @created.reverse_each do |kind, name|
        argv = kind == :network ? ["docker", "network", "rm", name] : ["docker", "rm", "--force", name]
        result = run(*argv)
        errors << "#{kind} #{name}: #{result.stderr.strip}" unless result.success?
      end
      @created.clear
      errors
    end

    def write_certificates(directory)
      ca_key = OpenSSL::PKey::RSA.new(2048)
      ca_certificate = OpenSSL::X509::Certificate.new
      ca_certificate.version = 2
      ca_certificate.serial = SecureRandom.random_number(2**63)
      ca_certificate.subject = OpenSSL::X509::Name.parse("/CN=rubernetes-m1-oracle-ca")
      ca_certificate.issuer = ca_certificate.subject
      ca_certificate.public_key = ca_key.public_key
      ca_certificate.not_before = Time.now - 60
      ca_certificate.not_after = Time.now + 3600
      ca_extensions = OpenSSL::X509::ExtensionFactory.new
      ca_extensions.subject_certificate = ca_certificate
      ca_extensions.issuer_certificate = ca_certificate
      ca_certificate.add_extension(ca_extensions.create_extension("basicConstraints", "CA:TRUE", true))
      ca_certificate.add_extension(ca_extensions.create_extension("keyUsage", "keyCertSign,cRLSign", true))
      ca_certificate.add_extension(ca_extensions.create_extension("subjectKeyIdentifier", "hash", false))
      ca_certificate.sign(ca_key, OpenSSL::Digest.new("SHA256"))

      key = OpenSSL::PKey::RSA.new(2048)
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = 2
      certificate.serial = SecureRandom.random_number(2**63)
      certificate.subject = OpenSSL::X509::Name.parse("/CN=kube-apiserver")
      certificate.issuer = ca_certificate.subject
      certificate.public_key = key.public_key
      certificate.not_before = Time.now - 60
      certificate.not_after = Time.now + 3600
      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extension_factory.subject_certificate = certificate
      extension_factory.issuer_certificate = ca_certificate
      certificate.add_extension(extension_factory.create_extension("basicConstraints", "CA:FALSE", true))
      certificate.add_extension(extension_factory.create_extension("keyUsage", "digitalSignature,keyEncipherment", true))
      certificate.add_extension(extension_factory.create_extension("extendedKeyUsage", "serverAuth", false))
      certificate.add_extension(extension_factory.create_extension("subjectAltName", "DNS:kubernetes,DNS:localhost,IP:127.0.0.1", false))
      certificate.sign(ca_key, OpenSSL::Digest.new("SHA256"))
      @token = SecureRandom.hex(32)
      File.write(File.join(directory, "ca.crt"), ca_certificate.to_pem)
      File.write(File.join(directory, "tls.crt"), certificate.to_pem)
      File.write(File.join(directory, "tls.key"), key.to_pem, mode: "w", perm: 0o600)
      File.write(File.join(directory, "sa.pub"), key.public_key.to_pem)
      # The second, deterministic token exists only so the API differential's
      # TokenReview request body is reproducible; it carries no privileged group.
      File.write(File.join(directory, "tokens.csv"),
                 "#{@token},m1-oracle,1,system:masters\n#{REVIEW_TOKEN},#{REVIEW_USER},#{REVIEW_UID},#{REVIEW_GROUP}\n",
                 mode: "w", perm: 0o600)
    end

    def run(*argv)
      result = @command_runner.capture(*argv)
      exit_status = if result.status.respond_to?(:exitstatus) && !result.status.exitstatus.nil?
                      result.status.exitstatus
                    else
                      result.success? ? 0 : 1
                    end
      @command_records << {
        "sequence" => @command_records.length,
        "argv" => argv.map(&:to_s),
        "stdout" => result.stdout.to_s,
        "stderr" => result.stderr.to_s,
        "exit_status" => exit_status
      }
      result
    end

    def run!(*argv)
      result = run(*argv)
      return result if result.success?

      raise Error, "command failed (#{argv.first(4).join(" ")}): #{result.stderr.strip}"
    end
  end

  module_function

  def canonical_resource(value, include_managed_fields: false)
    canonical_value(value, include_managed_fields: include_managed_fields)
  end

  def status_signature(value)
    return value unless value.is_a?(Hash)

    canonical_value(
      value.slice("apiVersion", "kind", "status", "message", "reason", "details", "code"),
      include_managed_fields: false
    )
  end

  def ownership_signature(value)
    entries = value.is_a?(Hash) ? Array(value.dig("metadata", "managedFields")) : []
    entries.map do |entry|
      {
        "manager" => entry["manager"].to_s,
        "operation" => entry["operation"].to_s,
        "apiVersion" => entry["apiVersion"].to_s,
        "subresource" => entry["subresource"].to_s,
        "fieldsType" => entry["fieldsType"].to_s,
        "time" => entry.key?("time") ? canonical_dynamic_value("time", entry["time"]) : nil,
        "fields" => fields_v1_paths(entry["fieldsV1"]).sort
      }
    end.sort_by do |entry|
      [entry.fetch("manager"), entry.fetch("operation"), entry.fetch("subresource"), entry.fetch("fields").join("\0")]
    end
  end

  def watch_signature(value)
    events = if value.is_a?(Hash) && value.key?("type")
               [value]
             else
               Array(value)
             end
    events.map do |event|
      object = event.is_a?(Hash) ? event["object"] : nil
      {
        "type" => event.is_a?(Hash) ? event["type"].to_s : "",
        "object" => canonical_resource(object),
        "ownership" => ownership_signature(object)
      }
    end
  end

  def fields_v1_paths(value, prefix = [])
    return [] unless value.is_a?(Hash)

    value.each_with_object([]) do |(raw_key, child), paths|
      key = raw_key.to_s
      if key == "."
        paths << (prefix.empty? ? "." : prefix.join("."))
        next
      end
      next unless key.start_with?("f:")

      path = prefix + [key.delete_prefix("f:")]
      nested = fields_v1_paths(child, path)
      paths.concat(nested.empty? ? [path.join(".")] : nested)
    end
  end

  def canonical_value(value, include_managed_fields:)
    case value
    when Hash
      value.keys.map(&:to_s).uniq.sort.each_with_object({}) do |key, result|
        next if key == "managedFields" && !include_managed_fields

        child = if value.key?(key)
                  value[key]
                elsif value.key?(key.to_sym)
                  value[key.to_sym]
                end
        result[key] = case key
                      when "uid", "resourceVersion", "creationTimestamp", "deletionTimestamp", "time"
                        canonical_dynamic_value(key, child)
                      else
                        canonical_value(child, include_managed_fields: include_managed_fields)
                      end
      end
    when Array
      value.map { |item| canonical_value(item, include_managed_fields: include_managed_fields) }
    else
      value
    end
  end

  def canonical_dynamic_value(key, value)
    return nil if value.nil?

    case key
    when "uid"
      if value.to_s.match?(/\A[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/i)
        "<uuid>"
      else
        "<invalid-uid>"
      end
    when "resourceVersion"
      value.to_s.match?(/\A[1-9][0-9]*\z/) ? "<positive-integer>" : "<invalid-resourceVersion>"
    else
      begin
        Time.iso8601(value.to_s)
        "<timestamp>"
      rescue ArgumentError
        "<invalid-timestamp>"
      end
    end
  end
  private_class_method :canonical_value
  private_class_method :canonical_dynamic_value
end
