# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# certificates.k8s.io/v1 ExtraValue is `type ExtraValue []string` like the
# authentication/authorization ones; it was missing from EXTRA_VALUES, so a
# CertificateSigningRequest whose requester carried any extra (an x509
# credential id) failed to encode for every protobuf client with HTTP 500.
class ProtobufCertificatesExtraValueTest < Minitest::Test
  def test_a_csr_with_extra_round_trips_through_protobuf
    codec = Rubernetes::API::StoreAdapter.time_codec
    csr = {"apiVersion" => "certificates.k8s.io/v1", "kind" => "CertificateSigningRequest", "metadata" => {"name" => "x"},
           "spec" => {"request" => "YWJj", "signerName" => "kubernetes.io/kube-apiserver-client", "username" => "u",
                      "extra" => {"authentication.kubernetes.io/credential-id" => ["X509SHA256=abc"]}}}

    decoded = codec.decode(codec.encode(csr))

    assert_equal({"authentication.kubernetes.io/credential-id" => ["X509SHA256=abc"]}, decoded.dig("spec", "extra"))
  end
end
