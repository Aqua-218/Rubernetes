# frozen_string_literal: true

# Secret-based (legacy) service account tokens (pkg/serviceaccount/legacy.go,
# v1.36.2): the tokens controller signs them with the service account key,
# the authenticator accepts one only while its Secret holds exactly it and
# its ServiceAccount keeps the UID, refuses a Secret labelled
# legacy-token-invalid-since, records the last-used date at most daily, and
# counts legacy / auto / manual uses, as it counts stale and valid projected
# tokens.

require_relative "../test_helper"
require "openssl"
require "rubernetes/security"
require "rubernetes/controller"
require "rubernetes/observability/metrics"

class LegacyServiceAccountTokenTest < Minitest::Test
  A = Rubernetes::Security::Authentication

  def setup
    @key = OpenSSL::PKey::RSA.new(2048)
    @now = Time.utc(2026, 9, 25, 12)
    @objects = {"sa" => {"metadata" => {"name" => "builder", "namespace" => "ns", "uid" => "sa-uid"}, "secrets" => []}}
    @writes = []
    lookup = A::ServiceAccount::Lookup.new(
      service_account: ->(_ns, name) { @objects[name == "builder" ? "sa" : name] },
      secret: ->(_ns, name) { @objects["secret:#{name}"] },
      pod: ->(_ns, _name) {}, node: ->(_ns, _name) {}
    )
    @authenticator = A::ServiceAccount.new(issuer: "https://kubernetes.default.svc", signing_key: @key, api_audiences: ["https://kubernetes.default.svc"],
                                           lookup: lookup, clock: -> { @now },
                                           secret_writer: ->(namespace, name, labels) { @writes << [namespace, name, labels] })
    @metrics = Rubernetes::Observability::Metrics.new(apiserver: false)
    @authenticator.metrics = @metrics
  end

  def legacy_secret(name, token, labels: {})
    @objects["secret:#{name}"] = {"metadata" => {"name" => name, "namespace" => "ns", "labels" => labels},
                                  "type" => "kubernetes.io/service-account-token", "data" => {"token" => [token].pack("m0")}}
  end

  def controller_token(secret_name)
    service_account = @objects["sa"]
    controller = Rubernetes::Controller::ServiceAccountTokenController.new(name: "serviceaccount-token-controller")
    signer = lambda do |account, name|
      @authenticator.issue_legacy(namespace: "ns", service_account_name: account.dig("metadata", "name"),
                                  service_account_uid: account.dig("metadata", "uid"), secret_name: name)
    end
    result = controller.plan(service_account, secrets: [], token_provider: signer, secret_name: secret_name)
    result.operations.first.object.dig("data", "token").unpack1("m")
  end

  def test_a_controller_signed_token_authenticates_while_its_secret_holds_it
    token = controller_token("builder-token")
    header, claims = A::JWT.parse(token).first(2)

    assert_equal "RS256", header["alg"]
    assert_equal "kubernetes/serviceaccount", claims["iss"]
    assert_equal "builder-token", claims["kubernetes.io/serviceaccount/secret.name"]
    legacy_secret("builder-token", token)
    result = @authenticator.authenticate_token(token)

    assert_equal "system:serviceaccount:ns:builder", result.user.name
    assert_equal [["ns", "builder-token", {"kubernetes.io/legacy-token-last-used" => "2026-09-25"}]], @writes
    legacy_secret("builder-token", token, labels: {"kubernetes.io/legacy-token-last-used" => "2026-09-25"})
    @authenticator.authenticate_token(token)

    assert_equal 1, @writes.length, "at most one last-used write a day"

    text = @metrics.render

    assert_includes text, "serviceaccount_legacy_tokens_total 2"
    assert_includes text, "serviceaccount_legacy_manual_token_uses_total 2"
    @objects["sa"]["secrets"] = [{"name" => "builder-token"}]
    @authenticator.authenticate_token(token)

    assert_includes @metrics.render, "serviceaccount_legacy_auto_token_uses_total 1"
  end

  def test_a_legacy_token_is_refused_once_its_secret_or_account_changes
    token = controller_token("builder-token")
    error = assert_raises(Rubernetes::Security::AuthenticationError) { @authenticator.authenticate_token(token) }
    assert_equal "Token has been invalidated", error.message
    legacy_secret("builder-token", "something-else")
    error = assert_raises(Rubernetes::Security::AuthenticationError) { @authenticator.authenticate_token(token) }
    assert_equal "Token does not match server's copy", error.message
    legacy_secret("builder-token", token, labels: {"kubernetes.io/legacy-token-invalid-since" => "2026-09-01"})
    error = assert_raises(Rubernetes::Security::AuthenticationError) { @authenticator.authenticate_token(token) }
    assert_match(/has been marked invalid/, error.message)
    assert_includes @metrics.render, "serviceaccount_invalid_legacy_auto_token_uses_total 1"
    legacy_secret("builder-token", token)
    @objects["sa"]["metadata"]["uid"] = "recreated"
    error = assert_raises(Rubernetes::Security::AuthenticationError) { @authenticator.authenticate_token(token) }
    assert_equal "ServiceAccount UID (recreated) does not match claim (sa-uid)", error.message
    forged = A::JWT.sign(A::JWT.parse(token)[1], key: OpenSSL::PKey::RSA.new(2048), algorithm: "RS256")
    assert_raises(StandardError) { @authenticator.authenticate_token(forged) }
  end

  def test_projected_tokens_count_as_valid_or_stale_by_warnafter
    token, = @authenticator.issue(namespace: "ns", service_account_name: "builder", service_account_uid: "sa-uid", expiration_seconds: 7200)
    @authenticator.authenticate_token(token)

    assert_includes @metrics.render, "serviceaccount_valid_tokens_total 1"
    @now += 3601
    @authenticator.authenticate_token(token)

    assert_includes @metrics.render, "serviceaccount_stale_tokens_total 1"
  end

  def test_the_tokens_controller_keeps_an_existing_token
    controller = Rubernetes::Controller::ServiceAccountTokenController.new(name: "serviceaccount-token-controller")
    existing = {"metadata" => {"name" => "builder-token", "namespace" => "ns",
                               "annotations" => {"kubernetes.io/service-account.name" => "builder"}},
                "type" => "kubernetes.io/service-account-token", "data" => {"token" => ["kept"].pack("m0")}}
    result = controller.plan(@objects["sa"], secrets: [existing], token_provider: ->(_account, _name) { "fresh" })
    update = result.operations.find do |operation|
      operation.object["kind"] == "Secret" || operation.object.dig("metadata", "name") == "builder-token"
    end
    assert_equal "kept", update.object.dig("data", "token").unpack1("m") if update
  end
end
