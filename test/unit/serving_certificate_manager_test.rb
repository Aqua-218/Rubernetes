# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "rubernetes/node/serving_certificate_manager"
require "rubernetes/node/kubelet_metrics"
require "rubernetes/transport/http_server"

# serverTLSBootstrap: the kubelet-serving CSR, its issued pair, the metrics
# around it, and the streaming server picking a rotated certificate up.
class ServingCertificateManagerTest < Minitest::Test
  Node = Rubernetes::Node

  def ca
    @ca ||= begin
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = OpenSSL::X509::Name.parse("/CN=test-ca")
      cert.issuer = cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 86_400
      factory = OpenSSL::X509::ExtensionFactory.new(cert, cert)
      cert.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
      cert.sign(key, OpenSSL::Digest.new("SHA256"))
      [cert, key]
    end
  end

  # A signer honouring the CSR's key, subject and SANs with server auth.
  def issue(request_pem, lifetime: 3600)
    request = OpenSSL::X509::Request.new(request_pem)
    ca_cert, ca_key = ca
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = rand(1..10_000)
    cert.subject = request.subject
    cert.issuer = ca_cert.subject
    cert.public_key = request.public_key
    cert.not_before = Time.now - 10
    cert.not_after = Time.now + lifetime
    factory = OpenSSL::X509::ExtensionFactory.new(ca_cert, cert)
    cert.add_extension(factory.create_extension("extendedKeyUsage", "serverAuth"))
    ext_req = request.attributes.find { |attribute| attribute.oid == "extReq" }
    if ext_req
      sans = ext_req.value.first.value.map { |sequence| OpenSSL::X509::Extension.new(sequence) }.find { |ext| ext.oid == "subjectAltName" }
      cert.add_extension(sans) if sans
    end
    cert.sign(ca_key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  class FakeClient
    attr_reader :created

    def initialize(issuer)
      @issuer = issuer
      @created = []
    end

    def create(object, **)
      @created << object
      {"metadata" => {"name" => "csr-#{@created.length}"}}
    end

    def get(_resource, name, **)
      request = @created.last.dig("spec", "request").unpack1("m0")
      cert = @issuer.call(request)
      {"metadata" => {"name" => name}, "status" => {"conditions" => [{"type" => "Approved", "status" => "True"}],
                                                    "certificate" => [cert.to_pem].pack("m0")}}
    end
  end

  def test_requests_a_kubelet_serving_certificate_with_sans_and_stores_the_pair
    Dir.mktmpdir do |dir|
      manager = Node::ServingCertificateManager.new(node_name: "worker-0", cert_dir: dir, addresses: lambda {
        ["10.240.0.5", "worker-0.internal"]
      },
                                                    sleeper: ->(_) {})
      client = FakeClient.new(method(:issue))

      assert_nil manager.current_certificate
      certificate = manager.rotate!(client)
      spec = client.created.first["spec"]

      assert_equal "kubernetes.io/kubelet-serving", spec["signerName"]
      assert_equal ["digital signature", "key encipherment", "server auth"], spec["usages"]
      assert_equal "/O=system:nodes/CN=system:node:worker-0", certificate.subject.to_s
      san = certificate.extensions.find { |ext| ext.oid == "subjectAltName" }

      assert_includes san.value, "DNS:worker-0"
      assert_includes san.value, "IP Address:10.240.0.5"
      assert_includes san.value, "DNS:worker-0.internal"
      assert_equal certificate.to_pem, manager.current_certificate.to_pem
      assert_predicate manager.current_private_key, :private?
      assert_predicate manager, :valid?
      assert_path_exists File.join(dir, "kubelet-server-current.pem")
    end
  end

  def test_metrics_follow_the_serving_certificate
    Dir.mktmpdir do |dir|
      manager = Node::ServingCertificateManager.new(node_name: "worker-0", cert_dir: dir, addresses: [], sleeper: ->(_) {})
      metrics = Node::KubeletMetrics.new(node_name: "worker-0")
      metrics.server_certificate_source = -> { manager.current_certificate }
      text = metrics.registry.render

      assert_includes text, "kubelet_certificate_manager_server_ttl_seconds +Inf"
      assert_includes text, "kubelet_server_expiration_renew_errors 0"
      first = manager.rotate!(FakeClient.new(->(pem) { issue(pem, lifetime: 7200) }))
      text = metrics.registry.render
      ttl = text[/kubelet_certificate_manager_server_ttl_seconds ([0-9.e+]+)/, 1].to_f

      assert_in_delta 7200, ttl, 30
      metrics.server_certificate_rotated(first)
      metrics.server_certificate_renew_failed
      text = metrics.registry.render

      assert_match(/kubelet_certificate_manager_server_rotation_seconds_count 1/, text)
      assert_includes text, "kubelet_server_expiration_renew_errors 1"
    end
  end

  def test_http_server_serves_a_reloaded_certificate_to_new_connections
    Dir.mktmpdir do |dir|
      key = OpenSSL::PKey::RSA.new(2048)
      request = OpenSSL::X509::Request.new
      request.version = 0
      request.subject = OpenSSL::X509::Name.parse("/CN=first")
      request.public_key = key
      request.sign(key, OpenSSL::Digest.new("SHA256"))
      first = issue(request.to_pem)
      File.write(File.join(dir, "tls.crt"), first.to_pem)
      File.write(File.join(dir, "tls.key"), key.to_pem)
      server = Rubernetes::Transport::HTTPServer.new(->(_request) { [200, {}, ["ok"]] }, host: "127.0.0.1", port: 0,
                                                                                         cert_file: File.join(dir, "tls.crt"), key_file: File.join(dir,
                                                                                                                                                   "tls.key"))
      server.start(background: true)
      begin
        request.subject = OpenSSL::X509::Name.parse("/CN=second")
        request.sign(key, OpenSSL::Digest.new("SHA256"))
        second = issue(request.to_pem)
        server.reload_tls!(certificate: second, private_key: key)
        socket = TCPSocket.new("127.0.0.1", server.port)
        context = OpenSSL::SSL::SSLContext.new
        context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        tls = OpenSSL::SSL::SSLSocket.new(socket, context)
        tls.connect

        assert_equal "/CN=second", tls.peer_cert.subject.to_s
        tls.close
      ensure
        server.stop
      end
    end
  end
end
