# frozen_string_literal: true

# The kubelet API's authentication and authorization (pkg/kubelet/server,
# v1.36.2): verified client certificates or TokenReview-checked bearer
# tokens, a SubjectAccessReview for nodes/<subresource> derived from the path
# (KubeletFineGrainedAuthz first, then proxy), cached decisions, and the API
# server dialing the kubelet over TLS with its kubelet client certificate.

require_relative "../test_helper"
require "net/http"
require "openssl"
require "tmpdir"
require "rubernetes/node"
require "rubernetes/api"

class KubeletAPIAuthTest < Minitest::Test
  Auth = Rubernetes::Node::KubeletAuth

  class Reviews
    attr_reader :calls
    attr_accessor :allowed

    def initialize(allowed: [])
      @calls = []
      @allowed = allowed
    end

    def create(object, api_version:, path:)
      @calls << [object["kind"], object["spec"]]
      case object["kind"]
      when "TokenReview"
        good = object.dig("spec", "token") == "good-token"
        {"status" => {"authenticated" => good,
                      "user" => {"username" => "system:serviceaccount:ns:metrics", "uid" => "sa-uid",
                                 "groups" => ["system:serviceaccounts"]}}}
      when "SubjectAccessReview"
        attributes = object.dig("spec", "resourceAttributes")
        {"status" => {"allowed" => @allowed.include?([object.dig("spec", "user"), attributes["subresource"]])}}
      end
    end
  end

  Request = Struct.new(:path, :method, :headers, :client_certificate, :client_chain, keyword_init: true) do
    def header(name) = (headers || {})[name.downcase]
  end

  def pki
    @pki ||= begin
      ca_key = OpenSSL::PKey::EC.generate("prime256v1")
      ca = certificate("/CN=test-ca", ca_key, nil, nil, ca: true)
      other_key = OpenSSL::PKey::EC.generate("prime256v1")
      other_ca = certificate("/CN=other-ca", other_key, nil, nil, ca: true)
      client_key = OpenSSL::PKey::EC.generate("prime256v1")
      client = certificate("/O=system:masters/CN=kube-apiserver-kubelet-client", client_key, ca, ca_key, usage: "clientAuth")
      serving_key = OpenSSL::PKey::EC.generate("prime256v1")
      serving = certificate("/CN=worker-0", serving_key, ca, ca_key, usage: "serverAuth")
      stranger_key = OpenSSL::PKey::EC.generate("prime256v1")
      stranger = certificate("/CN=stranger", stranger_key, other_ca, other_key, usage: "clientAuth")
      server_only = certificate("/CN=server-only", client_key, ca, ca_key, usage: "serverAuth")
      {ca: ca, client: client, client_key: client_key, serving: serving, serving_key: serving_key,
       stranger: stranger, server_only: server_only}
    end
  end

  def certificate(subject, key, issuer, issuer_key, ca: false, usage: nil)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = rand(1 << 32)
    cert.subject = OpenSSL::X509::Name.parse(subject)
    cert.issuer = issuer ? issuer.subject : cert.subject
    cert.public_key = key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer || cert
    cert.add_extension(factory.create_extension("basicConstraints", ca ? "CA:TRUE" : "CA:FALSE", true))
    cert.add_extension(factory.create_extension("extendedKeyUsage", usage, false)) if usage
    cert.add_extension(factory.create_extension("subjectAltName", "IP:127.0.0.1", false)) unless ca
    cert.sign(issuer_key || key, OpenSSL::Digest.new("SHA256"))
    cert
  end

  def auth(reviews, **)
    Auth.new(client: reviews, node_name: "worker-0", client_ca: [pki[:ca]], **)
  end

  def test_request_attributes_follow_the_path
    subject = auth(Reviews.new)
    user = Auth::User.new(name: "u", uid: "", groups: [], extra: {})
    expected = {"/stats/summary" => %w[stats], "/metrics/resource" => %w[metrics], "/metrics" => %w[metrics],
                "/logs/syslog" => %w[log], "/checkpoint/ns/p/c" => %w[checkpoint], "/pods" => %w[pods proxy],
                "/runningpods/" => %w[pods proxy], "/healthz" => %w[healthz proxy], "/configz" => %w[configz proxy],
                "/flagz" => %w[configz], "/statusz" => %w[statusz], "/exec/ns/p/c" => %w[proxy],
                "/containerLogs/ns/p/c" => %w[proxy], "/podsx" => %w[proxy]}
    expected.each do |path, subresources|
      attributes = subject.request_attributes(user, Request.new(path: path, method: "GET"))

      assert_equal subresources, attributes.map { |attribute| attribute[:subresource] }, path
    end
    assert_equal "create", subject.request_attributes(user, Request.new(path: "/exec/a/b/c", method: "POST")).first[:verb]
    coarse = auth(Reviews.new, fine_grained: false)

    assert_equal(%w[proxy], coarse.request_attributes(user, Request.new(path: "/pods", method: "GET")).map { |a| a[:subresource] })
  end

  def test_certificates_must_chain_to_the_client_ca_and_allow_client_auth
    subject = auth(Reviews.new)

    assert_equal "kube-apiserver-kubelet-client",
                 subject.authenticate(Request.new(path: "/", method: "GET", client_certificate: pki[:client])).name
    assert_equal ["system:masters"], subject.authenticate(Request.new(path: "/", method: "GET", client_certificate: pki[:client])).groups
    assert_nil subject.authenticate(Request.new(path: "/", method: "GET", client_certificate: pki[:stranger]))
    assert_nil subject.authenticate(Request.new(path: "/", method: "GET", client_certificate: pki[:server_only]))
    assert_nil Auth.new(client: Reviews.new, node_name: "w").authenticate(Request.new(path: "/", method: "GET", client_certificate: pki[:client])),
               "no client CA: certificates do not authenticate"
  end

  def test_tokens_go_through_token_review_and_are_cached
    reviews = Reviews.new(allowed: [["system:serviceaccount:ns:metrics", "stats"]])
    now = 0.0
    subject = auth(reviews, clock: -> { now })
    request = Request.new(path: "/stats/summary", method: "GET", headers: {"authorization" => "Bearer good-token"})

    assert_nil subject.filter(request)
    assert_nil subject.filter(request)
    assert_equal %w[TokenReview SubjectAccessReview], reviews.calls.map(&:first)
    sar = reviews.calls.last.last

    assert_equal({"verb" => "get", "group" => "", "version" => "v1", "resource" => "nodes", "subresource" => "stats", "name" => "worker-0"},
                 sar["resourceAttributes"])
    assert_equal ["system:serviceaccounts"], sar["groups"]
    now += 301
    subject.filter(request)

    assert_equal 4, reviews.calls.length, "both caches expired (2m / 5m)"

    status, = subject.filter(Request.new(path: "/stats/summary", method: "GET", headers: {"authorization" => "Bearer bad"}))

    assert_equal 401, status
    status, = subject.filter(Request.new(path: "/stats/summary", method: "GET"))

    assert_equal 401, status
  end

  def test_denials_name_every_subresource_tried
    subject = auth(Reviews.new)
    status, _headers, body = subject.filter(Request.new(path: "/pods", method: "GET", client_certificate: pki[:client]))

    assert_equal 403, status
    assert_equal "Forbidden (user=kube-apiserver-kubelet-client, verb=get, resource=nodes, subresource(s)=[pods proxy])\n", body.join
  end

  def test_anonymous_requests_when_enabled
    reviews = Reviews.new(allowed: [["system:anonymous", "healthz"]])

    assert_nil auth(reviews, anonymous: true).filter(Request.new(path: "/healthz", method: "GET"))
    assert_equal 401, auth(reviews).filter(Request.new(path: "/healthz", method: "GET")).first
    assert_nil auth(Reviews.new, anonymous: true, authorization_mode: "AlwaysAllow").filter(Request.new(path: "/pods", method: "GET"))
  end

  class Lifecycle
    def records = {}
  end

  def test_the_api_server_reaches_a_tls_kubelet_with_its_client_certificate
    Dir.mktmpdir do |directory|
      paths = {}
      {ca: pki[:ca], client: pki[:client], serving: pki[:serving]}.each do |name, cert|
        paths[name] = File.join(directory, "#{name}.crt")
        File.write(paths[name], cert.to_pem)
      end
      {client_key: pki[:client_key], serving_key: pki[:serving_key]}.each do |name, key|
        paths[name] = File.join(directory, "#{name}.key")
        File.write(paths[name], key.private_to_pem)
      end
      reviews = Reviews.new(allowed: [%w[kube-apiserver-kubelet-client pods]])
      server = Rubernetes::Node::StreamingServer.new(
        log_service: Object.new, lifecycle: Lifecycle.new, host: "127.0.0.1", port: 0,
        auth: auth(reviews),
        tls: {cert_file: paths[:serving], key_file: paths[:serving_key], request_client_certificates: true,
              client_ca_certificates: [pki[:ca]]}
      )
      server.start(background: true)
      begin
        tls = Rubernetes::API::NodeEndpointResolver::KubeletClientTLS.load(cert_file: paths[:client], key_file: paths[:client_key],
                                                                           ca_file: paths[:ca])
        uri = URI("https://127.0.0.1:#{server.port}/pods")
        http = Net::HTTP.new(uri.host, uri.port)
        Rubernetes::API::NodeEndpointResolver::KubeletClientTLS.configure(http, uri, tls)
        response = http.request(Net::HTTP::Get.new(uri))

        assert_equal "200", response.code, response.body
        assert_equal "PodList", JSON.parse(response.body)["kind"]

        anonymous = Net::HTTP.new(uri.host, uri.port)
        anonymous.use_ssl = true
        anonymous.verify_mode = OpenSSL::SSL::VERIFY_NONE

        assert_equal "401", anonymous.request(Net::HTTP::Get.new(uri)).code

        stats = URI("https://127.0.0.1:#{server.port}/stats/summary")
        denied = Net::HTTP.new(stats.host, stats.port)
        Rubernetes::API::NodeEndpointResolver::KubeletClientTLS.configure(denied, stats, tls)

        assert_equal "403", denied.request(Net::HTTP::Get.new(stats)).code
      ensure
        server.stop
      end
    end
  end
end
