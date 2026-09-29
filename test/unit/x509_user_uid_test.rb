# frozen_string_literal: true

require "openssl"
require_relative "../test_helper"
require "rubernetes/security"

# AllowParsingUserUIDFromCertAuth (Beta, on): a client certificate's subject
# may carry the user's UID in the Kubernetes element 1.3.6.1.4.1.57683.2;
# CommonNameUserConversion also records the certificate fingerprint as the
# credential ID (authentication.kubernetes.io/credential-id = X509SHA256=...).
class X509UserUIDTest < Minitest::Test
  A = Rubernetes::Security::Authentication

  def signed(subject)
    ca_key = OpenSSL::PKey::EC.generate("prime256v1")
    ca = OpenSSL::X509::Certificate.new
    ca.version = 2
    ca.serial = 1
    ca.subject = OpenSSL::X509::Name.new([["CN", "uid-ca"]])
    ca.issuer = ca.subject
    ca.public_key = ca_key
    ca.not_before = Time.now - 60
    ca.not_after = Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new(ca, ca)
    ca.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
    ca.add_extension(factory.create_extension("keyUsage", "keyCertSign", true))
    ca.sign(ca_key, OpenSSL::Digest.new("SHA256"))
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 2
    cert.subject = OpenSSL::X509::Name.new(subject)
    cert.issuer = ca.subject
    cert.public_key = OpenSSL::PKey::EC.generate("prime256v1")
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    cert.add_extension(OpenSSL::X509::ExtensionFactory.new(ca, cert).create_extension("extendedKeyUsage", "clientAuth"))
    cert.sign(ca_key, OpenSSL::Digest.new("SHA256"))
    [ca, cert]
  end

  def authenticate(subject)
    ca, cert = signed(subject)
    [A::X509.new(ca_certificates: [ca]).authenticate(A::RequestContext.new(headers: {}, client_certificate: cert, path: "/api")), cert]
  end

  def test_the_uid_element_and_the_credential_id
    result, cert = authenticate([["CN", "alice"], ["O", "dev"], [A::X509::UID_OID, "4f2c-uid"]])
    assert_equal "alice", result.user.name
    assert_equal "4f2c-uid", result.user.uid
    assert_equal ["X509SHA256=#{OpenSSL::Digest::SHA256.hexdigest(cert.to_der)}"], result.user.extra["authentication.kubernetes.io/credential-id"]
    plain, = authenticate([["CN", "bob"]])
    assert_nil plain.user.uid
  end

  def test_several_or_empty_uids_are_refused
    error = assert_raises(Rubernetes::Security::AuthenticationError) { authenticate([["CN", "a"], [A::X509::UID_OID, "1"], [A::X509::UID_OID, "2"]]) }
    assert_equal "expected 1 UID, but found multiple: [1 2]", error.message
  end
end
