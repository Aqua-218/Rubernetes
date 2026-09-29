# frozen_string_literal: true

require "openssl"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/bootstrap"

# kube-apiserver --proxy-client-cert-file / --proxy-client-key-file: the
# client certificate the aggregator presents to extension API servers.
class APIServerProxyClientTest < Minitest::Test
  Config = Rubernetes::Bootstrap::Config

  def data(proxy_client)
    {"version" => 1, "logging" => {"level" => "info"},
     "processes" => {"rubernetes-apiserver" => {"bind_address" => "127.0.0.1", "port" => 6443, "max_body_bytes" => 3_145_728, "watch_history_limit" => 1000, "proxy_client" => proxy_client}}}
  end

  def test_proxy_client_is_validated
    Config.new(process_name: "rubernetes-apiserver", data: data({"cert_file" => "/pki/front-proxy-client.crt", "key_file" => "/pki/fp.key"}))
    error = assert_raises(Config::Error) do
      Config.new(process_name: "rubernetes-apiserver", data: data({"cert_file" => "relative.crt", "key_file" => "/pki/fp.key"}))
    end
    assert_match(/rubernetes-apiserver\.proxy_client\.cert_file/, error.message)
    assert_raises(Config::Error) { Config.new(process_name: "rubernetes-apiserver", data: data({"cert" => "/x"})) }
  end

  def test_the_certificate_and_key_are_loaded
    Dir.mktmpdir do |dir|
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=front-proxy-client")
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      cert.sign(key, OpenSSL::Digest::SHA256.new)
      File.write(File.join(dir, "c.crt"), cert.to_pem)
      File.write(File.join(dir, "c.key"), key.to_pem)
      service = Rubernetes::Bootstrap::APIServerService.allocate
      loaded_cert, loaded_key = service.send(:load_proxy_client, {"cert_file" => File.join(dir, "c.crt"), "key_file" => File.join(dir, "c.key")})
      assert_equal "/CN=front-proxy-client", loaded_cert.subject.to_s
      assert_equal key.public_key.to_pem, loaded_key.public_key.to_pem
      assert_equal [nil, nil], service.send(:load_proxy_client, nil)
    end
  end
end
