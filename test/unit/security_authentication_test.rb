# frozen_string_literal: true

require "openssl"
require "json"
require_relative "../test_helper"
require "rubernetes/security/authentication"

class SecurityAuthenticationTest < Minitest::Test
  S = Rubernetes::Security
  A = S::Authentication

  def ca_and_client(cn:, org: [], ca_cn: "test-ca", eku: "clientAuth")
    ca_key = OpenSSL::PKey::EC.generate("prime256v1")
    ca = OpenSSL::X509::Certificate.new
    ca.version = 2
    ca.serial = 1
    ca.subject = OpenSSL::X509::Name.new([["CN", ca_cn]])
    ca.issuer = ca.subject
    ca.public_key = ca_key
    ca.not_before = Time.now - 60
    ca.not_after = Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new(ca, ca)
    ca.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
    ca.add_extension(factory.create_extension("keyUsage", "keyCertSign", true))
    ca.sign(ca_key, OpenSSL::Digest.new("SHA256"))
    key = OpenSSL::PKey::EC.generate("prime256v1")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 2
    cert.subject = OpenSSL::X509::Name.new([["CN", cn]] + org.map { |value| ["O", value] })
    cert.issuer = ca.subject
    cert.public_key = key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new(ca, cert)
    cert.add_extension(factory.create_extension("extendedKeyUsage", eku)) if eku
    cert.sign(ca_key, OpenSSL::Digest.new("SHA256"))
    [ca, cert]
  end

  def context(headers: {}, certificate: nil, path: "/api")
    A::RequestContext.new(headers: headers, client_certificate: certificate, path: path)
  end

  def test_x509_maps_cn_and_organizations_and_rejects_foreign_ca
    ca, cert = ca_and_client(cn: "alice", org: %w[dev ops])
    authenticator = A::X509.new(ca_certificates: [ca])
    result = authenticator.authenticate(context(certificate: cert))

    assert_equal "alice", result.user.name
    assert_equal %w[dev ops system:authenticated], result.user.groups
    _other_ca, foreign = ca_and_client(cn: "mallory")
    assert_raises(S::AuthenticationError) { authenticator.authenticate(context(certificate: foreign)) }
    assert_nil authenticator.authenticate(context)
    _ca2, server_only = ca_and_client(cn: "srv", eku: "serverAuth")
    ca2 = server_only.issuer
    assert_raises(S::AuthenticationError) { A::X509.new(ca_certificates: [ca]).authenticate(context(certificate: server_only)) }
    assert ca2
  end

  def test_static_token_file_and_bearer_parsing
    authenticator = A::StaticTokenFile.new(A::StaticTokenFile.parse("tok1,bob,uid-b,\"g1,g2\"\ntok2,carol,uid-c\n"))
    result = authenticator.authenticate(context(headers: {"authorization" => "Bearer tok1"}))

    assert_equal "bob", result.user.name
    assert_equal %w[g1 g2 system:authenticated], result.user.groups
    assert_nil authenticator.authenticate(context(headers: {"authorization" => "Bearer nope"}))
    assert_nil authenticator.authenticate(context(headers: {"authorization" => "Basic abc"}))
    assert_nil authenticator.authenticate(context(headers: {"authorization" => "Bearer   "}))
    assert_raises(S::ConfigurationError) { A::StaticTokenFile.parse("tok1,a,1\ntok1,b,2\n") }
  end

  def test_bootstrap_token_requires_matching_unexpired_secret
    secret = {"type" => "bootstrap.kubernetes.io/token",
              "data" => {"token-id" => ["abcdef"].pack("m0"), "token-secret" => ["0123456789abcdef"].pack("m0"),
                         "usage-bootstrap-authentication" => ["true"].pack("m0"), "auth-extra-groups" => ["system:bootstrappers:workers"].pack("m0"),
                         "expiration" => [(Time.now.utc + 3600).iso8601].pack("m0")}}
    reader = ->(namespace, name) { namespace == "kube-system" && name == "bootstrap-token-abcdef" ? secret : nil }
    authenticator = A::BootstrapToken.new(secret_reader: reader)
    result = authenticator.authenticate_token("abcdef.0123456789abcdef")

    assert_equal "system:bootstrap:abcdef", result.user.name
    assert_includes result.user.groups, "system:bootstrappers:workers"
    assert_nil authenticator.authenticate_token("abcdef.ffffffffffffffff")
    secret["data"]["expiration"] = [(Time.now.utc - 1).iso8601].pack("m0")

    assert_nil authenticator.authenticate_token("abcdef.0123456789abcdef")
  end

  def test_service_account_tokens_round_trip_and_bind_to_live_objects
    key = OpenSSL::PKey::RSA.new(2048)
    accounts = {"default/web" => {"metadata" => {"uid" => "sa-uid"}}}
    pods = {"default/web-1" => {"metadata" => {"uid" => "pod-uid"}, "spec" => {"nodeName" => "node-a"}}}
    lookup = A::ServiceAccount::Lookup.new(service_account: ->(ns, name) { accounts["#{ns}/#{name}"] },
                                           pod: ->(ns, name) { pods["#{ns}/#{name}"] }, secret: ->(*) {}, node: ->(*) {})
    issuer = A::ServiceAccount.new(issuer: "https://kubernetes.default.svc", signing_key: key,
                                   api_audiences: ["https://kubernetes.default.svc"], lookup: lookup)
    token, expires = issuer.issue(namespace: "default", service_account_name: "web", service_account_uid: "sa-uid",
                                  bound_object: {"kind" => "Pod", "name" => "web-1", "uid" => "pod-uid"})

    assert_operator expires, :>, Time.now
    result = issuer.authenticate(context(headers: {"authorization" => "Bearer #{token}"}))

    assert_equal "system:serviceaccount:default:web", result.user.name
    assert_equal %w[system:serviceaccounts system:serviceaccounts:default system:authenticated], result.user.groups
    assert_equal ["web-1"], result.user.extra["authentication.kubernetes.io/pod-name"]
    assert_equal ["node-a"], result.user.extra["authentication.kubernetes.io/node-name"]
    assert_nil result.user.extra["authentication.kubernetes.io/node-uid"]
    node_token, = issuer.issue(namespace: "default", service_account_name: "web", service_account_uid: "sa-uid",
                               bound_object: {"kind" => "Pod", "name" => "web-1", "uid" => "pod-uid",
                                              "node" => {"name" => "node-a", "uid" => "node-uid"}})
    node_result = issuer.authenticate_token(node_token)

    assert_equal ["node-a"], node_result.user.extra["authentication.kubernetes.io/node-name"]
    assert_equal ["node-uid"], node_result.user.extra["authentication.kubernetes.io/node-uid"]
    pods.delete("default/web-1")
    assert_raises(S::AuthenticationError) { issuer.authenticate_token(token) }
    assert_raises(S::AuthenticationError) { issuer.authenticate_token(token, ["other-audience"]) }
    assert_nil issuer.authenticate_token("not.a.jwt")
    assert_equal 1, issuer.jwks["keys"].length
    tampered = token.sub(/\.[^.]+\z/, ".AAAA")
    assert_raises(S::AuthenticationError) { issuer.authenticate_token(tampered) }
  end

  def test_jwt_rejects_none_and_unknown_kid
    key = OpenSSL::PKey::EC.generate("prime256v1")
    token = A::JWT.sign({"sub" => "x"}, key: key, algorithm: "ES256", key_id: "k1")
    header, claims = A::JWT.verify(token, keys: {"k1" => key})

    assert_equal "ES256", header["alg"]
    assert_equal "x", claims["sub"]
    assert_raises(A::JWT::Error) { A::JWT.verify(token, keys: {"k2" => key}) }
    none = "#{A::JWT.encode_segment('{"alg":"none"}')}.#{A::JWT.encode_segment('{"sub":"x"}')}."
    assert_raises(A::JWT::Error) { A::JWT.verify(none, keys: {"k1" => key}) }
    rsa = OpenSSL::PKey::RSA.new(2048)
    rsa_token = A::JWT.sign({"sub" => "y"}, key: rsa, algorithm: "RS256")
    assert_raises(A::JWT::Error) { A::JWT.verify(rsa_token, keys: [rsa], allowed_algorithms: ["ES256"]) }
    round = A::JWT.from_jwk(A::JWT.to_jwk(key))

    assert_equal key.public_to_der, round.public_to_der
  end

  def test_request_header_trusts_only_front_proxy_certificates
    ca, cert = ca_and_client(cn: "front-proxy-client")
    authenticator = A::RequestHeader.new(ca_certificates: [ca], allowed_names: ["front-proxy-client"])
    headers = {"x-remote-user" => "eve", "x-remote-group" => "team", "x-remote-extra-scopes" => "read"}
    result = authenticator.authenticate(context(headers: headers, certificate: cert))

    assert_equal "eve", result.user.name
    assert_equal %w[team system:authenticated], result.user.groups
    assert_equal({"scopes" => ["read"]}, result.user.extra)
    _ca, other = ca_and_client(cn: "someone-else")

    assert_nil A::RequestHeader.new(ca_certificates: [ca],
                                    allowed_names: ["front-proxy-client"]).authenticate(context(
                                      headers: headers, certificate: other
                                    ))
    assert_nil authenticator.authenticate(context(headers: headers))
  end

  def test_webhook_token_review_and_caching
    calls = 0
    transport = lambda do |body|
      calls += 1
      review = JSON.parse(body)
      if review["spec"]["token"] == "good"
        [200,
         {"status" => {"authenticated" => true, "user" => {"username" => "hook-user", "groups" => ["g"]},
                       "audiences" => review["spec"]["audiences"]}}]
      else
        [200, {"status" => {"authenticated" => false}}]
      end
    end
    authenticator = A::WebhookToken.new(transport: transport, api_audiences: ["api"])
    result = authenticator.authenticate_token("good", ["api"])

    assert_equal "hook-user", result.user.name
    authenticator.authenticate_token("good", ["api"])

    assert_equal 1, calls, "authenticated result is cached"
    assert_nil authenticator.authenticate_token("bad", ["api"])
    failing = A::WebhookToken.new(transport: ->(_body) { [500, "boom"] })
    assert_raises(S::AuthenticationError) { failing.authenticate_token("x") }
  end

  def test_oidc_style_jwt_authenticator_with_claim_mappings
    key = OpenSSL::PKey::RSA.new(2048)
    jwks = {"keys" => [A::JWT.to_jwk(key).merge("kid" => "issuer-key")]}
    config = {"issuer" => {"url" => "https://issuer.example", "audiences" => ["client-a"]},
              "claimValidationRules" => [{"claim" => "hd", "requiredValue" => "example.com"}],
              "claimMappings" => {"username" => {"claim" => "email", "prefix" => "oidc:"},
                                  "groups" => {"claim" => "roles", "prefix" => "oidc:"}}}
    authenticator = A::JWTAuthenticator.new(config: config, key_fetcher: ->(_url, _ca) { jwks })
    now = Time.now.to_i
    claims = {"iss" => "https://issuer.example", "aud" => "client-a", "exp" => now + 60, "iat" => now, "email" => "a@example.com", "hd" => "example.com",
              "roles" => %w[admin]}
    token = A::JWT.sign(claims, key: key, algorithm: "RS256", key_id: "issuer-key")
    result = authenticator.authenticate_token(token)

    assert_equal "oidc:a@example.com", result.user.name
    assert_equal %w[oidc:admin system:authenticated], result.user.groups
    wrong_aud = A::JWT.sign(claims.merge("aud" => "other"), key: key, algorithm: "RS256", key_id: "issuer-key")
    assert_raises(S::AuthenticationError) { authenticator.authenticate_token(wrong_aud) }
    wrong_hd = A::JWT.sign(claims.merge("hd" => "evil.com"), key: key, algorithm: "RS256", key_id: "issuer-key")
    assert_raises(S::AuthenticationError) { authenticator.authenticate_token(wrong_hd) }
    expired = A::JWT.sign(claims.merge("exp" => now - 1), key: key, algorithm: "RS256", key_id: "issuer-key")
    assert_raises(S::AuthenticationError) { authenticator.authenticate_token(expired) }
    other_issuer = A::JWT.sign(claims.merge("iss" => "https://other"), key: key, algorithm: "RS256", key_id: "issuer-key")

    assert_nil authenticator.authenticate_token(other_issuer)
    assert_raises(S::ConfigurationError) do
      A::JWTAuthenticator.new(config: {"issuer" => {"url" => "http://plain", "audiences" => ["a"]},
                                       "claimMappings" => {"username" => {"claim" => "sub",
                                                                          "prefix" => ""}}}, key_fetcher: ->(*) { jwks })
    end
  end

  def test_union_rejects_conflicting_identities_and_falls_back_to_anonymous
    first = A::StaticTokenFile.new(A::StaticTokenFile.parse("tok,alice,1\n"))
    second = A::StaticTokenFile.new(A::StaticTokenFile.parse("tok,bob,2\n"))
    conflicting = A::Union.new(authenticators: [first, second])
    assert_raises(S::AuthenticationError) { conflicting.authenticate(context(headers: {"authorization" => "Bearer tok"})) }
    agreeing = A::Union.new(authenticators: [first, A::StaticTokenFile.new(A::StaticTokenFile.parse("tok,alice,1\n"))])

    assert_equal "alice", agreeing.authenticate(context(headers: {"authorization" => "Bearer tok"})).user.name
    anonymous = A::Union.new(authenticators: [first]).authenticate(context)

    assert_predicate anonymous.user, :anonymous?
    restricted = A::Union.new(authenticators: [first],
                              anonymous: A::Union::Anonymous.new(enabled: true,
                                                                 conditions: [{"path" => "/healthz"}]))
    assert_raises(S::AuthenticationError) { restricted.authenticate(context(path: "/api")) }
    assert_predicate restricted.authenticate(context(path: "/healthz")).user, :anonymous?
  end
end
