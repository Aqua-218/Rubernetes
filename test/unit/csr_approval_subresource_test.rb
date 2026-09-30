# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"

# The /approval subresource of a CertificateSigningRequest writes exactly one
# thing: the approval conditions.  registry/certificates/certificates/
# strategy.go approvalStrategy#PrepareForUpdate -- "Updating the approval
# should only update the conditions" -- resets the spec to the stored one and
# keeps the stored status apart from conditions, while the request's own
# metadata applies normally.
#
# Treating it like any other non-status subresource discarded the conditions,
# so a patch to /approval came back with none and "[sig-auth] Certificates API
# should support CSR API operations" reported
# "patched object should have the applied condition".
class CSRApprovalSubresourceTest < Minitest::Test
  API = Rubernetes::API

  CSR_KEY = OpenSSL::PKey::RSA.new(2048)

  def setup
    @store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    @registry = API::Registry.new(resources: [], defaults: false)
    @registry.register(API::Resource.new(
      group: "certificates.k8s.io", version: "v1",
      resource: "certificatesigningrequests", kind: "CertificateSigningRequest",
      scope: :cluster,
      subresources: [{resource: "status", verbs: %w[get patch update]},
                     {resource: "approval", verbs: %w[get patch update]}]
    ))
    @server = API::Server.new(registry: @registry, store: @store)
    create_csr
  end

  def call(method, path, body: nil, content_type: "application/json")
    @server.call(API::Request.new(method: method, path: path,
                                  headers: body ? {"content-type" => content_type} : {},
                                  body: body && JSON.generate(body),
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def csr_request
    request = OpenSSL::X509::Request.new
    request.subject = OpenSSL::X509::Name.parse("/CN=probe")
    request.public_key = CSR_KEY.public_key
    request.sign(CSR_KEY, OpenSSL::Digest.new("SHA256"))
    [request.to_pem].pack("m0")
  end

  def create_csr
    response = call("POST", "/apis/certificates.k8s.io/v1/certificatesigningrequests",
                    body: {"apiVersion" => "certificates.k8s.io/v1", "kind" => "CertificateSigningRequest",
                           "metadata" => {"name" => "probe"},
                           "spec" => {"request" => csr_request, "signerName" => "kubernetes.io/kube-apiserver-client",
                                      "usages" => ["client auth"]}})

    assert_equal(201, response.status, response.body.inspect)
  end

  def approval_patch
    {"metadata" => {"annotations" => {"patchedapproval" => "true"}},
     "status" => {"conditions" => [{"type" => "ApprovalPatch", "status" => "True", "reason" => "e2e"}]}}
  end

  def patch_approval(body = approval_patch)
    response = call("PATCH", "/apis/certificates.k8s.io/v1/certificatesigningrequests/probe/approval",
                    body: body, content_type: "application/merge-patch+json")

    assert_equal(200, response.status, response.body.inspect)
    response.body
  end

  def test_a_patch_to_approval_applies_the_conditions
    patched = patch_approval
    conditions = Array(patched.dig("status", "conditions"))

    assert_equal(1, conditions.length, patched.inspect)
    assert_equal("ApprovalPatch", conditions.first.fetch("type"))
    assert_equal("True", conditions.first.fetch("status"))
  end

  def test_a_patch_to_approval_applies_its_metadata
    assert_equal("true", patch_approval.dig("metadata", "annotations", "patchedapproval"))
  end

  # populateConditionTimestamps: a condition the client sent without timestamps
  # gets them.
  def test_condition_timestamps_are_filled_in
    condition = Array(patch_approval.dig("status", "conditions")).first

    refute_empty(condition["lastUpdateTime"].to_s)
    refute_empty(condition["lastTransitionTime"].to_s)
  end

  # "Updating the approval should only update the conditions": the spec is the
  # stored one whatever the request says.
  def test_the_spec_cannot_be_changed_through_approval
    before = call("GET", "/apis/certificates.k8s.io/v1/certificatesigningrequests/probe").body

    patched = patch_approval(approval_patch.merge("spec" => {"signerName" => "example.com/other"}))

    assert_equal(before.dig("spec", "signerName"), patched.dig("spec", "signerName"))
  end

  def test_an_update_to_approval_applies_the_conditions
    current = JSON.parse(JSON.generate(
      call("GET", "/apis/certificates.k8s.io/v1/certificatesigningrequests/probe/approval").body
    ))
    current["status"] = {"conditions" => [{"type" => "Approved", "status" => "True", "reason" => "e2e"}]}

    response = call("PUT", "/apis/certificates.k8s.io/v1/certificatesigningrequests/probe/approval", body: current)

    assert_equal(200, response.status, response.body.inspect)
    assert_equal(%w[Approved], Array(response.body.dig("status", "conditions")).map { |c| c["type"] })
  end

  # A second patch that repeats a condition unchanged keeps its original
  # transition time.
  def test_an_unchanged_condition_keeps_its_transition_time
    first = Array(patch_approval.dig("status", "conditions")).first
    second = Array(patch_approval.dig("status", "conditions")).first

    assert_equal(first.fetch("lastTransitionTime"), second.fetch("lastTransitionTime"))
  end
end
