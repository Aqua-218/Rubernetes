# frozen_string_literal: true

require "base64"
require "openssl"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/bootstrap"
require "rubernetes/schema"

# pkg/controller/certificates/signer with authority.PermissiveSigningPolicy:
# the CSR signing controller signs approved requests with the configured
# cluster-signing CA (kube-controller-manager --cluster-signing-*-file).
class CSRSigningCATest < Minitest::Test
  Controller = Rubernetes::Controller
  NOW = Time.utc(2026, 9, 24, 12, 0, 0)

  def ca(not_after: NOW + (10 * 365 * 86_400))
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=test-ca")
    cert.public_key = key.public_key
    cert.not_before = NOW - 86_400
    cert.not_after = not_after
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = factory.issuer_certificate = cert
    cert.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
    cert.add_extension(factory.create_extension("subjectKeyIdentifier", "hash", false))
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    [cert, key]
  end

  def csr(signer: "kubernetes.io/kube-apiserver-client", usages: ["digital signature", "key encipherment", "client auth"],
          expiration: nil, approved: true, sans: nil)
    key = OpenSSL::PKey::EC.generate("prime256v1")
    request = OpenSSL::X509::Request.new
    request.version = 0
    request.subject = OpenSSL::X509::Name.parse("/O=e2e/CN=e2e-tester")
    request.public_key = key
    if sans
      extension = OpenSSL::X509::ExtensionFactory.new.create_extension("subjectAltName", sans, false)
      request.add_attribute(OpenSSL::X509::Attribute.new("extReq", OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence([extension])])))
    end
    request.sign(key, OpenSSL::Digest.new("SHA256"))
    spec = {"request" => Base64.strict_encode64(request.to_pem), "signerName" => signer, "usages" => usages}
    spec["expirationSeconds"] = expiration if expiration
    status = approved ? {"conditions" => [{"type" => "Approved", "status" => "True"}]} : {}
    {"apiVersion" => "certificates.k8s.io/v1", "kind" => "CertificateSigningRequest",
     "metadata" => {"name" => "tester-csr", "uid" => "u-1"}, "spec" => spec, "status" => status}
  end

  def sign(object, **)
    result = Controller::CertificateSigningRequestSigningController.new.plan(object, now: NOW, **)
    pem = result.status && result.status["certificate"]
    pem && OpenSSL::X509::Certificate.new(Base64.strict_decode64(pem))
  end

  def extension(cert, oid)
    cert.extensions.find { |item| item.oid == oid }
  end

  def test_signs_a_client_certificate_the_ca_verifies
    ca_cert, ca_key = ca
    cert = sign(csr(expiration: 3600), ca_certificate: ca_cert, ca_key: ca_key)
    store = OpenSSL::X509::Store.new
    store.add_cert(ca_cert)
    store.time = NOW

    assert store.verify(cert), store.error_string
    assert_equal "/O=e2e/CN=e2e-tester", cert.subject.to_s
    assert_equal "Digital Signature, Key Encipherment", extension(cert, "keyUsage").value
    assert_predicate extension(cert, "keyUsage"), :critical?
    assert_equal "TLS Web Client Authentication", extension(cert, "extendedKeyUsage").value
    assert_equal "CA:FALSE", extension(cert, "basicConstraints").value
    refute_nil extension(cert, "authorityKeyIdentifier")
    # Shorter than 8 hours: backdated 5 minutes, full duration kept.
    assert_equal NOW - 300, cert.not_before
    assert_equal NOW + 3600, cert.not_after
    assert_operator cert.serial.num_bits, :<=, 128
  end

  # status.certificate is []byte: the signed object has to survive the
  # protobuf wire (a raw PEM there made every GET of the CSR a 500).
  def test_the_signed_csr_encodes_as_protobuf
    ca_cert, ca_key = ca
    object = csr(expiration: 3600)
    result = Controller::CertificateSigningRequestSigningController.new.plan(object, now: NOW, ca_certificate: ca_cert, ca_key: ca_key)
    signed = object.merge("status" => result.status)
    codec = Rubernetes::Schema::Codec::KubernetesProtobuf.new
    decoded = codec.decode(codec.encode(signed))

    assert_equal result.status["certificate"], decoded.dig("status", "certificate")
    assert_match(/\A-----BEGIN CERTIFICATE-----/, Base64.strict_decode64(decoded.dig("status", "certificate")))
  end

  def test_long_certificates_lose_the_backdate_and_stop_at_the_ca_expiry
    ca_cert, ca_key = ca
    cert = sign(csr, ca_certificate: ca_cert, ca_key: ca_key, cert_ttl_seconds: 86_400)

    assert_equal NOW + 86_400 - 300, cert.not_after
    short_ca, short_key = ca(not_after: NOW + 1800)
    capped = sign(csr, ca_certificate: short_ca, ca_key: short_key)

    assert_equal NOW + 1800, capped.not_after
  end

  def test_subject_alt_names_are_copied_from_the_request
    ca_cert, ca_key = ca
    cert = sign(csr(signer: "kubernetes.io/legacy-unknown", usages: ["digital signature", "server auth"],
                    sans: "DNS:node-1.example.com,IP:10.0.0.7"), ca_certificate: ca_cert, ca_key: ca_key)

    assert_equal "DNS:node-1.example.com, IP Address:10.0.0.7", extension(cert, "subjectAltName").value
    assert_equal "TLS Web Server Authentication", extension(cert, "extendedKeyUsage").value
  end

  def test_no_ca_material_leaves_approved_requests_alone
    result = Controller::CertificateSigningRequestSigningController.new.plan(csr, now: NOW)

    assert_empty result.operations
    ca_cert, ca_key = ca

    assert_nil sign(csr(approved: false), ca_certificate: ca_cert, ca_key: ca_key)
  end

  def test_per_signer_material_wins_and_other_signers_stay_unsigned
    ca_cert, ca_key = ca
    signer_cas = {"kubernetes.io/kube-apiserver-client" => {certificate: ca_cert, key: ca_key}}

    assert_equal "/CN=test-ca", sign(csr, signer_cas: signer_cas).issuer.to_s
    kubelet = csr(signer: "kubernetes.io/legacy-unknown")

    assert_empty Controller::CertificateSigningRequestSigningController.new.plan(kubelet, now: NOW, signer_cas: signer_cas).operations
  end

  def test_unrecognized_usages_are_refused
    ca_cert, ca_key = ca
    error = assert_raises(ArgumentError) do
      sign(csr(signer: "kubernetes.io/legacy-unknown", usages: ["digital signature", "bogus"]), ca_certificate: ca_cert, ca_key: ca_key)
    end
    assert_match(/unrecognized usage values: \["bogus"\]/, error.message)
  end

  def config(section)
    {"version" => 1, "logging" => {"level" => "info"},
     "processes" => {"rubernetes-controller-manager" => {"kubeconfig" => "/k", "cluster_signing" => section}}}
  end

  def validate(section)
    Rubernetes::Bootstrap::Config.new(process_name: "rubernetes-controller-manager", data: config(section))
  end

  def test_config_validates_cluster_signing
    validate({"cert_file" => "/pki/ca.crt", "key_file" => "/pki/ca.key", "duration_seconds" => 3600})
    validate({"signers" => {"kube_apiserver_client" => {"cert_file" => "/a.crt", "key_file" => "/a.key"}}})
    error = Rubernetes::Bootstrap::Config::Error
    assert_raises(error) { validate({"cert_file" => "/pki/ca.crt"}) }
    assert_raises(error) { validate({"cert_file" => "relative.crt", "key_file" => "/k"}) }
    assert_raises(error) { validate({"signers" => {"nope" => {"cert_file" => "/a", "key_file" => "/b"}}}) }
    assert_raises(error) { validate({"duration_seconds" => 0}) }
    assert_raises(error) do
      validate({"cert_file" => "/a", "key_file" => "/b", "signers" => {"kubelet_client" => {"cert_file" => "/c", "key_file" => "/d"}}})
    end
  end
end
