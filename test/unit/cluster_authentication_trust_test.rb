# frozen_string_literal: true

require "json"
require "openssl"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/bootstrap/cluster_authentication_trust"

# kube-system/extension-apiserver-authentication was never published, so an
# extension API server (metrics-server, sample-apiserver) delegating
# authentication had no front-proxy CA to trust.
class ClusterAuthenticationTrustTest < Minitest::Test
  API = Rubernetes::API
  Trust = Rubernetes::Bootstrap::ClusterAuthenticationTrust

  def certificate(name, not_after: Time.now + 86_400)
    key = OpenSSL::PKey::EC.generate("prime256v1")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = rand(1..1_000_000)
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=#{name}")
    cert.public_key = key
    cert.not_before = Time.now - 60
    cert.not_after = not_after
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  def server
    registry = API::Registry.new(resources: [], defaults: false)
    registry.register(API::Resource.new(group: "", version: "v1", resource: "namespaces", kind: "Namespace", scope: :cluster))
    registry.register(API::Resource.new(group: "", version: "v1", resource: "configmaps", kind: "ConfigMap", scope: :namespaced))
    API::Server.new(registry: registry, store: API::MemoryStore.new, namespace_lifecycle: true)
  end

  def info(client_ca, front_proxy_ca)
    {client_ca: [client_ca],
     request_header: {ca: [front_proxy_ca], allowed_names: ["front-proxy-client"], username_headers: ["X-Remote-User"],
                      uid_headers: ["X-Remote-Uid"], group_headers: ["X-Remote-Group"], extra_header_prefixes: ["X-Remote-Extra-"]}}
  end

  def test_publishes_the_configmap_upstream_keys
    api = server
    client_ca = certificate("client-ca")
    front = certificate("front-proxy-ca")
    Trust.new(api_server: api, authentication_info: info(client_ca, front)).sync_once

    response = api.call(API::Request.new(method: "GET",
                                         path: "/api/v1/namespaces/kube-system/configmaps/extension-apiserver-authentication"))
    data = response.body["data"]

    assert_equal client_ca.to_pem, data["client-ca-file"]
    assert_equal front.to_pem, data["requestheader-client-ca-file"]
    assert_equal '["front-proxy-client"]', data["requestheader-allowed-names"]
    assert_equal '["X-Remote-User"]', data["requestheader-username-headers"]
    assert_equal '["X-Remote-Uid"]', data["requestheader-uid-headers"]
    assert_equal '["X-Remote-Group"]', data["requestheader-group-headers"]
    assert_equal '["X-Remote-Extra-"]', data["requestheader-extra-headers-prefix"]
  end

  def test_a_second_server_merges_rather_than_replaces
    api = server
    first = certificate("front-a")
    second = certificate("front-b")
    Trust.new(api_server: api, authentication_info: info(certificate("client-a"), first)).sync_once
    other = info(certificate("client-b"), second)
    other[:request_header][:allowed_names] = ["aggregator"]
    data = Trust.new(api_server: api, authentication_info: other).sync_once

    assert_equal first.to_pem + second.to_pem, data["requestheader-client-ca-file"]
    assert_equal '["front-proxy-client","aggregator"]', data["requestheader-allowed-names"]
    assert_equal 2, data["client-ca-file"].scan("BEGIN CERTIFICATE").length
  end

  def test_expired_certificates_are_dropped_and_no_front_proxy_means_no_header_keys
    api = server
    expired = certificate("old", not_after: Time.now - 10)
    data = Trust.new(api_server: api, authentication_info: {client_ca: [expired, certificate("fresh")], request_header: nil}).sync_once

    assert_equal 1, data["client-ca-file"].scan("BEGIN CERTIFICATE").length
    assert_equal ["client-ca-file"], data.keys
  end
end
