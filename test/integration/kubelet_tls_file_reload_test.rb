# frozen_string_literal: true

require_relative "../test_helper"
require "net/http"
require "stringio"
require "tmpdir"
require "rubernetes/bootstrap"

class KubeletTLSFileReloadTest < Minitest::Test
  Service = Rubernetes::Bootstrap::AgentService
  Identity = Data.define(:certificate, :key)
  Agent = Struct.new(:api)
  API = Struct.new(:client)

  def setup
    @directory = Dir.mktmpdir("kubelet-tls")
    @files = {"cert_file" => File.join(@directory, "tls.crt"), "key_file" => File.join(@directory, "tls.key"),
              "client_ca_file" => File.join(@directory, "ca.crt")}
    @log = StringIO.new
  end

  def teardown
    @server&.stop(reason: "test")
    FileUtils.remove_entry(@directory)
  end

  def test_rotates_the_serving_pair_and_client_ca_without_breaking_live_tls
    old_ca = identity("old test CA", serial: 1)
    old_serving = identity("localhost", serial: 2, ca: old_ca, usage: "serverAuth")
    old_client = identity("local rotation client", serial: 3, ca: old_ca, usage: "clientAuth")
    new_ca = identity("new test CA", serial: 4)
    new_serving = identity("localhost", serial: 5, ca: new_ca, usage: "serverAuth")
    new_client = identity("local rotation client", serial: 6, ca: new_ca, usage: "clientAuth")
    write("cert_file", old_serving.certificate)
    write("key_file", old_serving.key)
    write("client_ca_file", old_ca.certificate)
    start_server

    assert_equal ["200", 2], request(old_ca, old_client)
    write("cert_file", new_serving.certificate)
    await { @log.string.include?("serving certificate and key do not match") }

    assert_equal ["200", 2], request(old_ca, old_client)

    File.binwrite(@files.fetch("client_ca_file"), "")
    await { @log.string.include?('"material":"client_ca"') }

    assert_equal ["200", 2], request(old_ca, old_client)
    write("key_file", new_serving.key)
    write("client_ca_file", new_ca.certificate)
    result = await do
      value = request(new_ca, new_client)
      value if value == ["200", 5]
    rescue OpenSSL::SSL::SSLError
      false
    end

    assert_equal ["200", 5], result
    assert_equal ["401", 5], request(new_ca, old_client)
  end

  private

  def start_server
    config = {"healthz_port" => 0, "image" => {"staging_root" => @directory},
              "streaming" => {"host" => "127.0.0.1", "port" => 0, "tls" => @files,
                              "authentication" => {"anonymous" => false, "webhook" => false},
                              "authorization" => {"mode" => "AlwaysAllow"}}}
    logger = Rubernetes::Bootstrap::StructuredLogger.new(io: @log, process_name: "agent")
    @server = Service.new(config: config, logger: logger, runtime: Service::NullRuntime.new,
                          sync_loop: Service::NullSyncLoop.new, node_agent: Agent.new(API.new(Object.new)))
    @server.start
    @port = @server.instance_variable_get(:@streaming_server).port
  end

  def request(ca, client)
    http = Net::HTTP.new("127.0.0.1", @port, nil)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.open_timeout = 1
    http.read_timeout = 1
    http.cert_store = OpenSSL::X509::Store.new
    http.cert_store.add_cert(ca.certificate)
    http.cert = client.certificate
    http.key = client.key
    http.start { |connection| [connection.get("/healthz").code, connection.peer_cert.serial.to_i] }
  end

  def write(field, value)
    path = @files.fetch(field)
    File.binwrite(path + ".next", value.to_pem)
    File.rename(path + ".next", path)
  end

  def await
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3
    loop do
      result = yield
      return result if result

      flunk "TLS files were not reconciled in time" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep 0.02
    end
  end

  def identity(name, serial:, ca: nil, usage: nil)
    key = OpenSSL::PKey::EC.generate("prime256v1")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = OpenSSL::X509::Name.new([["CN", name]])
    cert.issuer = ca ? ca.certificate.subject : cert.subject
    cert.public_key = key
    cert.not_before = Time.now - 5
    cert.not_after = Time.now + 300
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = ca ? ca.certificate : cert
    cert.add_extension(factory.create_extension("basicConstraints", ca ? "CA:FALSE" : "CA:TRUE", true))
    cert.add_extension(factory.create_extension("keyUsage", "keyCertSign,cRLSign", true)) unless ca
    cert.add_extension(factory.create_extension("extendedKeyUsage", usage)) if usage
    cert.add_extension(factory.create_extension("subjectAltName", "IP:127.0.0.1")) if usage == "serverAuth"
    cert.sign(ca ? ca.key : key, OpenSSL::Digest.new("SHA256"))
    Identity.new(certificate: cert, key: key)
  end
end
