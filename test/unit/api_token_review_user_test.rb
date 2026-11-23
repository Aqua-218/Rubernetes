# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/security"

# TokenReview answered `authenticated: true` with an EMPTY user: the
# authenticator returns an AuthenticationResult that WRAPS the UserInfo, and
# the response builder read username/uid/groups off the wrapper.  Upstream
# returns the full UserInfo (pkg/registry/authentication/tokenreview/storage.go),
# which [sig-auth] ServiceAccounts "should mount an API token into pods" checks
# at service_accounts.go:132 and every authenticating webhook client needs.
class APITokenReviewUserTest < Minitest::Test
  Server = Rubernetes::API::Server
  UserInfo = Rubernetes::Security::UserInfo

  def service_account_user
    UserInfo.service_account(namespace: "ns", name: "mysa", uid: "sa-uid",
                             extra: {"authentication.kubernetes.io/credential-id" => ["JTI=abc"]})
  end

  def result_for(user, audiences: ["https://kubernetes.default.svc"])
    Rubernetes::Security::AuthenticationResult.new(
      user: user, authenticator: "serviceaccount", audiences: audiences
    )
  end

  def user_info(identity)
    Server.allocate.send(:user_info, identity)
  end

  def test_an_authentication_result_is_unwrapped_to_its_user
    info = user_info(result_for(service_account_user))

    assert_equal "system:serviceaccount:ns:mysa", info.fetch("username")
    assert_equal "sa-uid", info.fetch("uid")
    assert_includes info.fetch("groups"), "system:authenticated"
    assert_includes info.fetch("groups"), "system:serviceaccounts"
    assert_includes info.fetch("groups"), "system:serviceaccounts:ns"
  end

  def test_the_extra_claims_survive_the_unwrap
    info = user_info(result_for(service_account_user))

    assert_equal ["JTI=abc"], info.fetch("extra").fetch("authentication.kubernetes.io/credential-id")
  end

  def test_a_bare_user_info_still_works
    info = user_info(service_account_user)

    assert_equal "system:serviceaccount:ns:mysa", info.fetch("username")
  end

  def test_a_hash_identity_still_works
    info = user_info({"username" => "alice", "groups" => ["system:authenticated"]})

    assert_equal "alice", info.fetch("username")
    assert_equal ["system:authenticated"], info.fetch("groups")
  end

  def test_an_empty_identity_is_an_empty_user
    assert_empty user_info(nil)
  end

  def test_token_review_authenticates_the_requested_audience_only
    authentication = Rubernetes::Security::Authentication::ServiceAccount
    lookup = authentication::Lookup.new(service_account: ->(_namespace, _name) { {"metadata" => {"uid" => "sa-uid"}} })
    issuer = authentication.new(issuer: "https://kubernetes.example.test", api_audiences: ["api"], lookup: lookup,
                                signing_key: OpenSSL::PKey::EC.generate("prime256v1"))
    registry = Rubernetes::API::Registry.new
    registry.register(group: "authentication.k8s.io", resource: "tokenreviews", kind: "TokenReview", verbs: ["create"])
    server = Server.new(registry: registry, api_audiences: ["api"], security: Rubernetes::Security::Pipeline.new(authenticator: issuer))
    token, = issuer.issue(namespace: "ns", service_account_name: "mysa", service_account_uid: "sa-uid", audiences: ["istio-ca"])

    accepted = review(server, token, %w[other istio-ca])

    assert_equal true, accepted["authenticated"]
    assert_equal ["istio-ca"], accepted["audiences"]
    assert_equal "system:serviceaccount:ns:mysa", accepted.dig("user", "username")
    assert_nil review(server, token, ["other"])["authenticated"]
    assert_nil review(server, token, [])["authenticated"]
    assert_equal 401, server.call(method: "GET", path: "/api", headers: {"authorization" => "Bearer #{token}"}).status
  end

  private

  def review(server, token, audiences)
    body = {"apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenReview", "spec" => {"token" => token, "audiences" => audiences}}
    response = server.call(method: "POST", path: "/apis/authentication.k8s.io/v1/tokenreviews", body: body,
                           identity: {"username" => "reviewer", "groups" => ["system:masters"]})

    assert_equal 201, response.status
    response.body.fetch("status")
  end
end
