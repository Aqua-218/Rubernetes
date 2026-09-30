# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/security"

# pkg/registry/certificates/certificates csrStrategy: a created request names
# the user who created it, never what the client wrote, starts without a
# status, and its spec cannot be changed by an update.
class CSRRequesterIdentityTest < Minitest::Test
  API = Rubernetes::API
  PATH = "/apis/certificates.k8s.io/v1/certificatesigningrequests"

  def setup
    registry = API::Registry.new
    registry.register(API::Resource.new(group: "certificates.k8s.io", version: "v1", resource: "certificatesigningrequests",
                                        kind: "CertificateSigningRequest", scope: :cluster, subresources: %w[status approval]))
    @server = API::Server.new(registry: registry, store: Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil))
    @identity = {"username" => "tester-csr", "uid" => "u-7", "groups" => %w[e2e system:authenticated],
                 "extra" => {"example.com/scope" => ["a"]}}
  end

  def csr(name = "c1")
    {"apiVersion" => "certificates.k8s.io/v1", "kind" => "CertificateSigningRequest", "metadata" => {"name" => name},
     "spec" => {"request" => "cmVx", "signerName" => "kubernetes.io/kube-apiserver-client", "usages" => ["client auth"],
                "username" => "spoofed", "groups" => ["system:masters"]},
     "status" => {"conditions" => [{"type" => "Approved", "status" => "True"}]}}
  end

  def call(method, path, body, identity: @identity, content_type: "application/json")
    @server.call(API::Request.new(method: method, path: path, headers: {"content-type" => content_type},
                                  body: JSON.generate(body), identity: identity))
  end

  def test_create_records_the_requester_and_clears_the_status
    created = call("POST", PATH, csr)

    assert_equal 201, created.status, created.body.inspect
    spec = created.body["spec"]

    assert_equal "tester-csr", spec["username"]
    assert_equal "u-7", spec["uid"]
    assert_equal %w[e2e system:authenticated], spec["groups"]
    assert_equal({"example.com/scope" => ["a"]}, spec["extra"])
    assert_empty Array(created.body.dig("status", "conditions"))
  end

  def test_update_cannot_change_the_spec
    call("POST", PATH, csr)
    current = call("GET", "#{PATH}/c1", {}).body
    changed = JSON.parse(JSON.generate(current))
    changed["spec"]["username"] = "someone-else"
    changed["spec"]["usages"] = ["server auth"]
    changed["metadata"]["labels"] = {"touched" => "yes"}
    updated = call("PUT", "#{PATH}/c1", changed)

    assert_equal 200, updated.status, updated.body.inspect
    assert_equal "tester-csr", updated.body.dig("spec", "username")
    assert_equal ["client auth"], updated.body.dig("spec", "usages")
    assert_equal "yes", updated.body.dig("metadata", "labels", "touched")
  end

  def test_server_side_apply_create_also_records_the_requester
    applied = call("PATCH", "#{PATH}/c2?fieldManager=t", csr("c2"), content_type: "application/apply-patch+yaml")

    assert_equal 201, applied.status, applied.body.inspect
    assert_equal "tester-csr", applied.body.dig("spec", "username")
  end
end
