# frozen_string_literal: true

# apiserver_client_certificate_expiration_seconds (x509 request
# authenticator: the remaining lifetime of every presented client
# certificate) and apiserver_tls_handshake_errors_total (net/http's "TLS
# handshake error from" line: a failed handshake on the serving port).

require_relative "../test_helper"
require "openssl"
require "socket"
require "tmpdir"
require "rubernetes/security"
require "rubernetes/transport/http_server"
require "rubernetes/observability/metrics"

class APIServerTLSMetricsTest < Minitest::Test
  def certificate(subject, key, issuer: nil, issuer_key: nil, lifetime: 3600, usage: "clientAuth")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = rand(1 << 30)
    cert.subject = OpenSSL::X509::Name.parse(subject)
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.public_key = key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + lifetime
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer || cert
    cert.add_extension(factory.create_extension("basicConstraints", issuer ? "CA:FALSE" : "CA:TRUE", true))
    cert.add_extension(factory.create_extension("extendedKeyUsage", usage, false)) if issuer
    cert.sign(issuer_key || key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  def test_client_certificate_remaining_lifetime_is_observed
    ca_key = OpenSSL::PKey::EC.generate("prime256v1")
    ca = certificate("/CN=ca", ca_key)
    key = OpenSSL::PKey::EC.generate("prime256v1")
    client = certificate("/CN=alice", key, issuer: ca, issuer_key: ca_key, lifetime: 5000)
    authenticator = Rubernetes::Security::Authentication::X509.new(ca_certificates: [ca])
    registry = Rubernetes::Observability::Metrics.new(apiserver: false)
    authenticator.metrics = registry
    context = Rubernetes::Security::Authentication::RequestContext.new(client_certificate: client)

    assert_equal "alice", authenticator.authenticate(context).user.name
    authenticator.authenticate(context)
    text = registry.render

    assert_includes text, "apiserver_client_certificate_expiration_seconds_count 2"
    assert_includes text, 'apiserver_client_certificate_expiration_seconds_bucket{le="3600"} 0'
    assert_includes text, 'apiserver_client_certificate_expiration_seconds_bucket{le="7200"} 2'
  end

  def test_failed_tls_handshakes_are_reported
    Dir.mktmpdir do |directory|
      key = OpenSSL::PKey::RSA.new(2048)
      cert = certificate("/CN=server", key)
      File.write(File.join(directory, "tls.crt"), cert.to_pem)
      File.write(File.join(directory, "tls.key"), key.to_pem)
      failures = Queue.new
      server = Rubernetes::Transport::HTTPServer.new(->(_request) { [200, {}, ["ok"]] }, host: "127.0.0.1", port: 0,
                                                                                         cert_file: File.join(directory,
                                                                                                              "tls.crt"), key_file: File.join(directory,
                                                                                                                                              "tls.key"))
      server.on_tls_handshake_error = -> { failures << true }
      server.start(background: true)
      begin
        socket = TCPSocket.new("127.0.0.1", server.port)
        socket.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        socket.close

        assert Timeout.timeout(5) { failures.pop }
      ensure
        server.stop
      end
    end
  end
end
