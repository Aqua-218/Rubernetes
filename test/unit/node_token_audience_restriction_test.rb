# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/security"
require "rubernetes/security/admission/plugins/security"
require_relative "../support/security_admission_fake_context"

# ServiceAccountNodeAudienceRestriction (noderestriction
# validateNodeServiceAccountAudience) and TokenRequestServiceAccountUIDValidation.
class NodeTokenAudienceRestrictionTest < Minitest::Test
  S = Rubernetes::Security
  A = S::Admission
  Fake = SecurityAdmissionFakeContext

  class Authorizer
    def initialize(allowed) = @allowed = allowed

    def authorize(attributes)
      ok = attributes.verb == "request-serviceaccounts-token-audience" && @allowed.include?([attributes.resource, attributes.name])
      ok ? S::Authorization::Decision.allow : S::Authorization::Decision.no_opinion
    end
  end

  def setup
    @context = Fake.new
    @kubelet = S::UserInfo.new(name: "system:node:n1", groups: %w[system:nodes])
    volumes = [{"name" => "kube-api-access", "projected" => {"sources" => [{"serviceAccountToken" => {"path" => "token"}}]}},
               {"name" => "vault", "projected" => {"sources" => [{"serviceAccountToken" => {"path" => "t", "audience" => "vault"}}]}},
               {"name" => "inline", "csi" => {"driver" => "secrets.csi.example"}},
               {"name" => "data", "persistentVolumeClaim" => {"claimName" => "data"}}]
    @context.put("pods", "team", "p", {"metadata" => {"name" => "p", "namespace" => "team", "uid" => "pu"},
                                       "spec" => {"nodeName" => "n1", "serviceAccountName" => "default", "volumes" => volumes}})
    @context.put("csidrivers", nil, "secrets.csi.example", {"spec" => {"tokenRequests" => [{"audience" => "csi-aud"}]}},
                 group: "storage.k8s.io")
    @context.put("csidrivers", nil, "disk.csi.example", {"spec" => {"tokenRequests" => [{"audience" => "disk-aud"}]}},
                 group: "storage.k8s.io")
    @context.put("persistentvolumeclaims", "team", "data", {"spec" => {"volumeName" => "pv-1"}})
    @context.put("persistentvolumes", nil, "pv-1", {"spec" => {"csi" => {"driver" => "disk.csi.example"}}})
    @plugin = A::Registry.factories.fetch("NodeRestriction").call(@context, {})
  end

  def request(audiences)
    object = {"kind" => "TokenRequest",
              "spec" => {"audiences" => audiences,
                         "boundObjectRef" => {"apiVersion" => "v1", "kind" => "Pod", "name" => "p", "uid" => "pu"}}}
    A::Attributes.new(operation: "CREATE", user: @kubelet, group: "", version: "v1", resource: "serviceaccounts", kind: "TokenRequest",
                      namespace: "team", name: "default", object: object, old_object: nil, subresource: "token")
  end

  def test_audiences_the_pod_uses_are_allowed
    [[], ["vault"], ["csi-aud"], ["disk-aud"]].each { |audiences| @plugin.validate(request(audiences)) }
  end

  def test_other_audiences_need_authorization
    error = assert_raises(A::Rejected) { @plugin.validate(request(["attacker.example"])) }
    assert_includes error.message, %(audience "attacker.example" not found in pod spec volume, system:node:n1 is not authorized)
    assert_raises(A::Rejected) { @plugin.validate(request(%w[vault csi-aud])) }
    @context.authorizer = Authorizer.new([["attacker.example", "default"]])
    @plugin.validate(request(["attacker.example"]))
  end

  def test_the_gate_off_skips_the_check
    @context.feature_gates["ServiceAccountNodeAudienceRestriction"] = false
    @plugin.validate(request(["anything"]))
  end

  def test_token_request_uid_must_match_the_service_account
    registry = Rubernetes::API::Registry.new
    registry.register(Rubernetes::API::Resource.new(group: "", version: "v1", resource: "serviceaccounts", kind: "ServiceAccount",
                                                    scope: :namespaced, subresources: %w[token]))
    server = Rubernetes::API::Server.new(registry: registry, store: Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil),
                                         service_account_issuer: S::Authentication::ServiceAccount.new(
                                           issuer: "https://kubernetes.default.svc", signing_key: OpenSSL::PKey::RSA.new(2048),
                                           api_audiences: ["https://kubernetes.default.svc"],
                                           lookup: S::Authentication::ServiceAccount::Lookup.new(service_account: ->(*) {}, pod: ->(*) {},
                                                                                                 secret: ->(*) {}, node: ->(*) {})
                                         ))
    call = ->(method, path,
              body = nil) { server.call(Rubernetes::API::Request.new(method: method, path: path, headers: {"content-type" => "application/json"}, body: body && JSON.generate(body))) }
    call.call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "team"}})
    account = call.call("POST", "/api/v1/namespaces/team/serviceaccounts",
                        {"apiVersion" => "v1", "kind" => "ServiceAccount", "metadata" => {"name" => "robot"}}).body
    path = "/api/v1/namespaces/team/serviceaccounts/robot/token"
    ok = call.call("POST", path,
                   {"kind" => "TokenRequest", "apiVersion" => "authentication.k8s.io/v1", "metadata" => {"uid" => account.dig("metadata", "uid")},
                    "spec" => {}})

    assert_equal 201, ok.status, ok.body.inspect
    stale = call.call("POST", path,
                      {"kind" => "TokenRequest", "apiVersion" => "authentication.k8s.io/v1", "metadata" => {"uid" => "stale"}, "spec" => {}})

    assert_equal 409, stale.status
    assert_equal %(Operation cannot be fulfilled on TokenRequest.authentication.k8s.io "robot": the UID in the token request (stale) ) +
                 %(does not match the UID of the service account (#{account.dig("metadata", "uid")})), stale.body["message"]
  end
end
