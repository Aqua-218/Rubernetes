# frozen_string_literal: true

# The kubelet's client certificate lifecycle (client-go util/certificate and
# pkg/kubelet/certificate, v1.36.2): TLS bootstrapping with a bootstrap
# credential, rotation at a jittered 70-90% of the certificate's life, the
# kubelet-client-current.pem pair, denied requests, and connection resets.

require_relative "../test_helper"
require "openssl"
require "tmpdir"
require "yaml"
require "rubernetes/node"
require "rubernetes/node/client_certificate_manager"

class KubeletClientCertificateTest < Minitest::Test
  Manager = Rubernetes::Node::ClientCertificateManager

  class Signer
    attr_reader :requests
    attr_accessor :deny, :lifetime

    def initialize(now)
      @now = now
      @ca_key = OpenSSL::PKey::EC.generate("prime256v1")
      @ca = OpenSSL::X509::Certificate.new
      @ca.version = 2
      @ca.serial = 1
      @ca.subject = @ca.issuer = OpenSSL::X509::Name.parse("/CN=ca")
      @ca.public_key = @ca_key
      @ca.not_before = now.call - 60
      @ca.not_after = now.call + (86_400 * 10)
      @ca.sign(@ca_key, OpenSSL::Digest.new("SHA256"))
      @requests = {}
      @lifetime = 1000
      @count = 0
    end

    def create(object, api_version:, path:)
      @count += 1
      name = "csr-#{@count}"
      @requests[name] = object
      {"metadata" => {"name" => name}}
    end

    def get(_resource, name, api_version:)
      object = @requests.fetch(name)
      return {"status" => {"conditions" => [{"type" => "Denied", "status" => "True", "reason" => "Nope"}]}} if deny

      csr = OpenSSL::X509::Request.new(object.dig("spec", "request").unpack1("m"))
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = @count + 100
      cert.subject = csr.subject
      cert.issuer = @ca.subject
      cert.public_key = csr.public_key
      cert.not_before = @now.call
      cert.not_after = @now.call + @lifetime
      cert.sign(@ca_key, OpenSSL::Digest.new("SHA256"))
      {"status" => {"conditions" => [{"type" => "Approved", "status" => "True"}], "certificate" => [cert.to_pem].pack("m0")}}
    end
  end

  def setup
    @time = Time.utc(2026, 9, 25, 12, 0, 0)
    @now = -> { @time }
    @signer = Signer.new(@now)
    @random = Object.new.tap { |random| random.define_singleton_method(:rand) { 0.5 } }
  end

  def manager(directory, **)
    Manager.new(node_name: "worker-0", cert_dir: File.join(directory, "pki"), clock: @now, random: @random,
                sleeper: ->(_) {}, **)
  end

  def test_bootstrap_requests_a_node_certificate_and_writes_the_kubeconfig
    Dir.mktmpdir do |directory|
      subject = manager(directory)
      kubeconfig = File.join(directory, "kubelet.conf")
      subject.bootstrap!(kubeconfig_path: kubeconfig, bootstrap_client: @signer, server: "https://127.0.0.1:6443", ca_file: "/pki/ca.crt")

      request = @signer.requests.values.first

      assert_equal "csr-", request.dig("metadata", "generateName")
      assert_equal "kubernetes.io/kube-apiserver-client-kubelet", request.dig("spec", "signerName")
      assert_equal ["digital signature", "client auth"], request.dig("spec", "usages")
      csr = OpenSSL::X509::Request.new(request.dig("spec", "request").unpack1("m"))

      assert_equal "/O=system:nodes/CN=system:node:worker-0", csr.subject.to_s
      assert_kind_of OpenSSL::PKey::EC, csr.public_key

      assert File.symlink?(subject.current_path)
      assert_equal "kubelet-client-2026-09-25-12-00-00.pem", File.readlink(subject.current_path)
      pem = File.read(subject.current_path)
      certificate = OpenSSL::X509::Certificate.new(pem)

      assert certificate.check_private_key(OpenSSL::PKey.read(pem[/-----BEGIN EC PRIVATE KEY-----.+-----END EC PRIVATE KEY-----/m] ||
                                                             pem[/-----BEGIN PRIVATE KEY-----.+-----END PRIVATE KEY-----/m]))
      assert_equal "0600", format("%04o", File.stat(File.join(directory, "pki", File.readlink(subject.current_path))).mode & 0o777)
      document = YAML.safe_load_file(kubeconfig)

      assert_equal subject.current_path, document.dig("users", 0, "user", "client-certificate")
      assert_equal "https://127.0.0.1:6443", document.dig("clusters", 0, "cluster", "server")

      # A valid kubeconfig is used as it is.
      subject.bootstrap!(kubeconfig_path: kubeconfig, bootstrap_client: @signer, server: "x")

      assert_equal 1, @signer.requests.length
    end
  end

  def test_rotation_deadline_is_a_jittered_70_to_90_percent
    Dir.mktmpdir do |directory|
      subject = manager(directory)

      assert_equal @time, subject.rotation_deadline, "no certificate: rotate now"
      certificate = subject.rotate!(@signer)

      assert_in_delta (certificate.not_before + 800).to_f, subject.rotation_deadline.to_f, 0.001, "0.7 + 0.2 * 0.5 of 1000s"
      low = Object.new.tap { |random| random.define_singleton_method(:rand) { 0.0 } }

      assert_in_delta (certificate.not_before + 700).to_f, manager(directory, random: low).rotation_deadline.to_f, 0.001
    end
  end

  def test_a_foreign_certificate_forces_a_new_request
    Dir.mktmpdir do |directory|
      other = Manager.new(node_name: "worker-1", cert_dir: File.join(directory, "pki"), clock: @now, random: @random, sleeper: ->(_) {})
      other.rotate!(@signer)

      assert_nil manager(directory).current_certificate
      assert_equal @time, manager(directory).rotation_deadline
    end
  end

  def test_a_denied_request_is_an_error
    Dir.mktmpdir do |directory|
      @signer.deny = true
      error = assert_raises(Manager::Error) { manager(directory).rotate!(@signer) }
      assert_match(/is denied: Nope/, error.message)
    end
  end

  def test_the_background_loop_rotates_and_resets_connections
    Dir.mktmpdir do |directory|
      rotated = Queue.new
      subject = manager(directory)
      subject.start(client: @signer, on_rotate: ->(certificate) { rotated << certificate })
      certificate = Timeout.timeout(5) { rotated.pop }

      assert_equal "/O=system:nodes/CN=system:node:worker-0", certificate.subject.to_s
      subject.stop
    end
  end

  def test_the_http_client_starts_new_sessions_after_a_reset
    client = Rubernetes::Client::HTTPClient.new(server: "https://127.0.0.1:1", insecure_skip_tls_verify: true)

    assert_equal 0, client.connection_generation
    assert_equal [], client.reset_connections!
    assert_equal 1, client.connection_generation
  end
end
