# frozen_string_literal: true

require "net/http"
require "openssl"
require_relative "../test_helper"
require "rubernetes/transport/http_server"

# A listener that asks for client certificates (the API server's, the
# metrics server's) refused every resumed TLS session with an internal_error
# alert: OpenSSL needs a session id context on a peer-verifying context, and
# none was set.  Net::HTTP resumes sessions, so its second connection failed.
class HTTPServerTLSResumptionTest < Minitest::Test
  def certificate(key)
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = 1
    certificate.subject = certificate.issuer = OpenSSL::X509::Name.parse("/CN=localhost")
    certificate.public_key = key
    certificate.not_before = Time.now - 60
    certificate.not_after = Time.now + 3600
    certificate.sign(key, OpenSSL::Digest.new("SHA256"))
    certificate
  end

  def test_a_resumed_session_is_accepted
    key = OpenSSL::PKey::EC.generate("prime256v1")
    server = Rubernetes::Transport::HTTPServer.new(->(_request) { [200, {}, ["ok"]] }, host: "127.0.0.1", port: 0,
                                                   cert: certificate(key), key: key, request_client_certificates: true)
    server.start
    http = Net::HTTP.new("127.0.0.1", server.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    assert_equal %w[200 200 200], Array.new(3) { http.get("/").code }
  ensure
    server&.stop
  end
end
