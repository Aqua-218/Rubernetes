# frozen_string_literal: true

# The CSR approving controller (approver/sarapprove.go): kubelet client CSRs
# are approved after a SubjectAccessReview for the requester --
# certificatesigningrequests/selfnodeclient when the requester is the
# certificate's CN, else .../nodeclient -- and left alone when neither is
# allowed.

require_relative "../test_helper"
require "openssl"
require "rubernetes/controller"

class CSRSARApprovalTest < Minitest::Test
  Controller = Rubernetes::Controller

  class Client
    attr_reader :reviews

    def initialize(allowed)
      @allowed = allowed
      @reviews = []
    end

    def create(object, api_version:, path:)
      @reviews << object["spec"]
      {"status" => {"allowed" => @allowed.include?([object.dig("spec", "user"), object.dig("spec", "resourceAttributes", "subresource")])}}
    end
  end

  Store = Struct.new(:client)

  def csr(requester, node: "worker-0")
    key = OpenSSL::PKey::EC.generate("prime256v1")
    request = OpenSSL::X509::Request.new
    request.subject = OpenSSL::X509::Name.new([["O", "system:nodes"], ["CN", "system:node:#{node}"]])
    request.public_key = key
    request.sign(key, OpenSSL::Digest.new("SHA256"))
    {"apiVersion" => "certificates.k8s.io/v1", "kind" => "CertificateSigningRequest",
     "metadata" => {"name" => "csr-1", "uid" => "u"},
     "spec" => {"request" => [request.to_pem].pack("m0"), "signerName" => "kubernetes.io/kube-apiserver-client-kubelet",
                "usages" => ["digital signature", "client auth"], "username" => requester,
                "groups" => ["system:nodes", "system:authenticated"], "uid" => "requester-uid"},
     "status" => {}}
  end

  def controller = Controller::CertificateSigningRequestApprovingController.new(name: "certificatesigningrequest-approving-controller")

  def approval(result)
    Array((result.status || {})["conditions"]).find { |condition| condition["type"] == "Approved" }
  end

  def test_a_node_renewing_its_own_certificate_is_approved_as_selfnodeclient
    client = Client.new([["system:node:worker-0", "selfnodeclient"]])
    result = controller.plan(csr("system:node:worker-0"), store: Store.new(client))

    assert_equal "Auto approving self kubelet client certificate after SubjectAccessReview.", approval(result)["message"]
    review = client.reviews.first

    assert_equal "system:node:worker-0", review["user"]
    assert_equal "requester-uid", review["uid"]
    assert_equal ["system:nodes", "system:authenticated"], review["groups"]
    assert_equal({"group" => "certificates.k8s.io", "version" => "*", "resource" => "certificatesigningrequests",
                  "subresource" => "selfnodeclient", "verb" => "create"}, review["resourceAttributes"])
  end

  def test_a_bootstrap_requester_is_approved_as_nodeclient
    client = Client.new([["system:bootstrap:abcdef", "nodeclient"]])
    result = controller.plan(csr("system:bootstrap:abcdef"), store: Store.new(client))

    assert_equal "Auto approving kubelet client certificate after SubjectAccessReview.", approval(result)["message"]
    assert_equal ["nodeclient"], client.reviews.map { |review| review.dig("resourceAttributes", "subresource") },
                 "selfnodeclient is only tried when the requester is the CN"
  end

  def test_an_unauthorized_request_is_left_alone
    client = Client.new([])

    assert_empty controller.plan(csr("system:node:worker-0"), store: Store.new(client)).operations
    assert_equal(%w[selfnodeclient nodeclient], client.reviews.map { |review| review.dig("resourceAttributes", "subresource") })
    assert_empty controller.plan(csr("system:node:worker-0")).operations, "no API client: no approval"
  end
end
