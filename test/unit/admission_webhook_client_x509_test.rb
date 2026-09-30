# frozen_string_literal: true

require "openssl"
require "socket"
require "json"
require "timeout"
require_relative "../test_helper"
require "rubernetes/security"
require "rubernetes/observability/metrics"

# WebhookClient#call over a real TLS connection: the AdmissionReview round
# trip and the x509 metrics recorded from the peer certificate.  Runs the
# client for real (a fake client hid a NoMethodError on every production
# webhook call).
class AdmissionWebhookClientX509Test < Minitest::Test
  Plugins = Rubernetes::Security::Admission::Plugins

  def certificate(san: nil)
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 2
    # No SAN: hostname verification falls back to the CN (OpenSSL::SSL.verify_certificate_identity).
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse(san ? "/CN=webhook.test" : "/CN=127.0.0.1")
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    if san
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = factory.issuer_certificate = cert
      cert.add_extension(factory.create_extension("subjectAltName", san, false))
    end
    cert.sign(key, "SHA256")
    [cert, key]
  end

  # One-shot HTTPS webhook answering an allowed AdmissionReview.
  def serve(cert, key)
    tcp = TCPServer.new("127.0.0.1", 0)
    context = OpenSSL::SSL::SSLContext.new
    context.cert = cert
    context.key = key
    server = OpenSSL::SSL::SSLServer.new(tcp, context)
    thread = Thread.new do
      loop do
        client = server.accept
        Thread.new(client) do |io|
          io.gets
          length = 0
          loop do
            line = io.gets
            break if line.nil? || line.strip.empty?

            length = line.split(":", 2).last.to_i if line.downcase.start_with?("content-length")
          end
          review = JSON.parse(io.read(length))
          body = JSON.generate({"apiVersion" => "admission.k8s.io/v1", "kind" => "AdmissionReview",
                                "response" => {"uid" => review.dig("request", "uid"), "allowed" => true}})
          io.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: #{body.bytesize}\r\n" \
                   "Connection: close\r\n\r\n#{body}")
          io.close
        rescue StandardError
          begin
            io.close
          rescue StandardError
            nil
          end
        end
      end
    rescue IOError, OpenSSL::SSL::SSLError, Errno::EBADF
      nil
    end
    [server, tcp.addr[1], thread]
  end

  def test_call_round_trips_and_counts_a_certificate_without_san
    cert, key = certificate
    server, port, thread = serve(cert, key)
    metrics = Rubernetes::Observability::Metrics.new
    client = Plugins::WebhookClient.new(metrics: -> { metrics })
    config = {"url" => "https://127.0.0.1:#{port}/validate", "caBundle" => [cert.to_pem].pack("m0")}
    code, body = Timeout.timeout(30) do
      client.call(config, {"apiVersion" => "admission.k8s.io/v1", "kind" => "AdmissionReview", "request" => {"uid" => "u-1"}},
                  timeout_seconds: 5)
    end

    assert_equal 200, code
    assert body.dig("response", "allowed")
    text = metrics.render_own

    assert_match(/apiserver_webhooks_x509_missing_san_total 1/, text)
    refute_match(/apiserver_webhooks_x509_insecure_sha1_total [1-9]/, text)
  ensure
    begin
      server&.close
    rescue StandardError
      nil
    end
    thread&.kill
  end

  def test_a_certificate_with_san_is_not_counted
    cert, key = certificate(san: "IP:127.0.0.1")
    server, port, thread = serve(cert, key)
    metrics = Rubernetes::Observability::Metrics.new
    client = Plugins::WebhookClient.new(metrics: metrics)
    config = {"url" => "https://127.0.0.1:#{port}/validate", "caBundle" => [cert.to_pem].pack("m0")}
    code, = Timeout.timeout(30) { client.call(config, {"request" => {"uid" => "u-2"}}, timeout_seconds: 5) }

    assert_equal 200, code
    refute_match(/apiserver_webhooks_x509_missing_san_total [1-9]/, metrics.render_own)
  ensure
    begin
      server&.close
    rescue StandardError
      nil
    end
    thread&.kill
  end
end
