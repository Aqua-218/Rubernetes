# frozen_string_literal: true

require "openssl"
require_relative "../test_helper"
require "rubernetes/security/authentication"

# Every request on a kept-alive connection re-walked the client certificate
# chain through OpenSSL -- the apiserver's largest non-I/O frame under load --
# although informers and the conformance suite present the same handful of
# certificates for hours.  A verified certificate is remembered briefly, and
# never past its own validity.
class X509VerificationCacheTest < Minitest::Test
  S = Rubernetes::Security
  A = S::Authentication

  def certificates(cn: "alice", org: %w[team], not_after: Time.now + 3600, eku: "clientAuth")
    ca_key = OpenSSL::PKey::EC.generate("prime256v1")
    ca = OpenSSL::X509::Certificate.new
    ca.version = 2
    ca.serial = 1
    ca.subject = OpenSSL::X509::Name.new([%w[CN cache-ca]])
    ca.issuer = ca.subject
    ca.public_key = ca_key
    ca.not_before = Time.now - 60
    ca.not_after = Time.now + 7200
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
    cert.not_after = not_after
    factory = OpenSSL::X509::ExtensionFactory.new(ca, cert)
    cert.add_extension(factory.create_extension("extendedKeyUsage", eku))
    cert.sign(ca_key, OpenSSL::Digest.new("SHA256"))
    [ca, cert]
  end

  def context(certificate)
    A::RequestContext.new(headers: {}, client_certificate: certificate, path: "/api")
  end

  def counting_authenticator(ca, now: -> { Time.now.utc })
    authenticator = A::X509.new(ca_certificates: [ca], clock: now)
    store = authenticator.instance_variable_get(:@store)
    counter = Hash.new(0)
    store.define_singleton_method(:verify) do |*args|
      counter[:verify] += 1
      super(*args)
    end
    [authenticator, counter]
  end

  def test_repeated_requests_verify_once
    ca, cert = certificates
    authenticator, counter = counting_authenticator(ca)
    results = Array.new(5) { authenticator.authenticate(context(cert)) }

    assert_equal 1, counter[:verify]
    assert(results.all? { |r| r.user.name == "alice" })
    assert_includes results.first.user.groups, "team"
  end

  def test_a_different_certificate_is_verified_separately
    ca, alice = certificates(cn: "alice")
    _other_ca, bob = certificates(cn: "bob")
    authenticator, counter = counting_authenticator(ca)

    assert_equal "alice", authenticator.authenticate(context(alice)).user.name
    assert_raises(S::AuthenticationError) { authenticator.authenticate(context(bob)) }
    assert_equal "alice", authenticator.authenticate(context(alice)).user.name
    assert_equal 2, counter[:verify], "the rejected certificate is not cached either"
  end

  def test_the_cache_never_outlives_the_certificate
    now = Time.now.utc
    ca, cert = certificates(not_after: now + 5)
    authenticator, counter = counting_authenticator(ca, now: -> { now })

    assert authenticator.authenticate(context(cert))
    assert_equal 1, counter[:verify]
    now += 10
    assert_raises(S::AuthenticationError) { authenticator.authenticate(context(cert)) }
    assert_equal 2, counter[:verify], "an expired certificate is re-verified, not served from the cache"
  end

  def test_the_cache_expires_after_its_window
    now = Time.now.utc
    ca, cert = certificates
    authenticator, counter = counting_authenticator(ca, now: -> { now })
    authenticator.authenticate(context(cert))
    now += A::X509::CACHE_SECONDS + 1
    authenticator.authenticate(context(cert))

    assert_equal 2, counter[:verify]
  end

  def test_the_cache_is_bounded
    ca, cert = certificates
    authenticator, = counting_authenticator(ca)
    authenticator.authenticate(context(cert))
    cache = authenticator.instance_variable_get(:@cache)
    (A::X509::MAX_CACHED + 10).times { |index| cache["k#{index}"] = {result: nil, expires_at: Time.now + 60} }
    authenticator.send(:remember, "fresh", :result, expires_at: Time.now + 60)

    assert_operator cache.length, :<=, A::X509::MAX_CACHED
  end
end
