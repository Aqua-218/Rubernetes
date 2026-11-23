# frozen_string_literal: true

require "tempfile"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/bootstrap/config"
require "rubernetes/bootstrap/security_assembly"
require "rubernetes/security"

class TokenRequestExpirationTest < Minitest::Test
  API = Rubernetes::API
  Authentication = Rubernetes::Security::Authentication
  NAMESPACE = "/api/v1/namespaces/default"
  ISSUER = "https://token-oracle.invalid"
  API_AUDIENCES = [ISSUER, "another-api-audience"].freeze

  def setup
    @now = Time.utc(2026, 11, 19, 17, 0, 0)
    @signing_key = OpenSSL::PKey::EC.generate("prime256v1")
  end

  def test_default_and_capped_unbound_tokens_use_the_effective_response_lifetime
    api, = server
    default = issue(api, {})
    cap = issue(api, "expirationSeconds" => 9000)

    assert_expiration(default, status_seconds: 3600, jwt_seconds: 3600)
    assert_equal API_AUDIENCES, default.body.dig("spec", "audiences")
    assert_nil default.body.fetch("spec").fetch("boundObjectRef")
    assert_expiration(cap, status_seconds: 3607, jwt_seconds: 3607)
    assert_equal '299 - "requested expiration of 9000 seconds shortened to 3607 seconds"', cap.header("warning")
  end

  def test_only_pod_bound_tokens_with_the_migration_lifetime_and_api_audiences_are_extended
    api, bound = server
    projected = issue(api, "expirationSeconds" => 3607, "boundObjectRef" => bound)
    subset = issue(api, "expirationSeconds" => 9000, "boundObjectRef" => bound, "audiences" => [ISSUER])
    custom = issue(api, "expirationSeconds" => 3607, "boundObjectRef" => bound, "audiences" => ["custom"])
    mixed = issue(api, "expirationSeconds" => 3607, "boundObjectRef" => bound, "audiences" => [ISSUER, "custom"])
    ordinary = issue(api, "expirationSeconds" => 3600, "boundObjectRef" => bound)

    assert_expiration(projected, status_seconds: 3607, jwt_seconds: 31_536_000, warn_after: 3607)
    assert_expiration(subset, status_seconds: 3607, jwt_seconds: 31_536_000, warn_after: 3607)
    assert_equal '299 - "requested expiration of 9000 seconds shortened to 3607 seconds"', subset.header("warning")
    assert_expiration(custom, status_seconds: 3607, jwt_seconds: 3607)
    assert_expiration(mixed, status_seconds: 3607, jwt_seconds: 3607)
    assert_expiration(ordinary, status_seconds: 3600, jwt_seconds: 3600)
  end

  def test_extension_can_be_disabled_and_zero_does_not_cap_expiration
    api, bound = server(extend_expiration: false, maximum: 0)

    assert_expiration(issue(api, "expirationSeconds" => 3607, "boundObjectRef" => bound),
                      status_seconds: 3607, jwt_seconds: 3607)
    response = issue(api, "expirationSeconds" => 9000)

    assert_expiration(response, status_seconds: 9000, jwt_seconds: 9000)
    assert_nil response.header("warning")
  end

  def test_bootstrap_honors_the_issuer_expiration_options
    Tempfile.create(["rubernetes-token-request", ".pem"]) do |key|
      key.write(@signing_key.private_to_pem)
      key.flush
      settings = {"issuer" => ISSUER, "signing_key_file" => key.path, "extend_expiration" => false, "max_expiration_seconds" => 3607}
      security = {"authentication" => {"service_account" => settings}}
      config = Rubernetes::Bootstrap::Config.allocate
      config.send(:validate_security!, security)
      assembly = Rubernetes::Bootstrap::SecurityAssembly.new(config: security, store: Rubernetes::Storage::MemoryStore.new,
                                                             key_for: ->(*) { "" }, clock: -> { @now })
      token, expiration = assembly.service_account_issuer.issue(
        namespace: "default", service_account_name: "workload", service_account_uid: "sa-uid", expiration_seconds: 9000,
        bound_object: {"kind" => "Pod", "name" => "workload", "uid" => "pod-uid"}
      )
      claims = Authentication::JWT.parse(token)[1]

      assert_equal 3607, expiration - @now
      assert_equal 3607, claims["exp"] - claims["iat"]
      refute claims.fetch("kubernetes.io").key?("warnafter")

      settings["extend_expiration"] = "false"
      error = assert_raises(Rubernetes::Bootstrap::Config::Error) { config.send(:validate_security!, security) }

      assert_match(/extend_expiration must be a boolean/, error.message)
    end
  end

  private

  def assert_expiration(response, status_seconds:, jwt_seconds:, warn_after: nil)
    assert_equal 201, response.status
    created_at = Time.iso8601(response.body.dig("metadata", "creationTimestamp"))
    expiration = Time.iso8601(response.body.dig("status", "expirationTimestamp"))
    claims = Authentication::JWT.parse(response.body.dig("status", "token"))[1]

    assert_equal status_seconds, response.body.dig("spec", "expirationSeconds")
    assert_equal status_seconds, expiration - created_at
    assert_equal jwt_seconds, claims.fetch("exp") - claims.fetch("iat")
    if warn_after
      assert_equal warn_after, claims.dig("kubernetes.io", "warnafter") - claims.fetch("iat")
    else
      refute claims.fetch("kubernetes.io").key?("warnafter")
    end
  end

  def server(extend_expiration: true, maximum: 3607)
    issuer = Authentication::ServiceAccount.new(issuer: ISSUER, api_audiences: API_AUDIENCES, lookup: Authentication::ServiceAccount::Lookup.new,
                                                signing_key: @signing_key, clock: -> { @now + 1 },
                                                max_expiration_seconds: maximum, extend_expiration: extend_expiration)
    registry = API::Registry.new
    registry.register(API::Resource.new(resource: "serviceaccounts", kind: "ServiceAccount", scope: :namespaced, subresources: %w[token]))
    api = API::Server.new(registry: registry, service_account_issuer: issuer, clock: -> { @now })
    account = post(api, "#{NAMESPACE}/serviceaccounts", "apiVersion" => "v1", "kind" => "ServiceAccount", "metadata" => {"name" => "workload"})
    pod = post(api, "#{NAMESPACE}/pods", "apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "workload"},
                                         "spec" => {"serviceAccountName" => "workload", "containers" => [{"name" => "app", "image" => "busybox"}]})

    assert_equal 201, account.status
    assert_equal 201, pod.status
    [api, {"apiVersion" => "v1", "kind" => "Pod", "name" => "workload", "uid" => pod.body.dig("metadata", "uid")}]
  end

  def issue(api, spec)
    post(api, "#{NAMESPACE}/serviceaccounts/workload/token", "apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenRequest", "spec" => spec)
  end

  def post(api, path, body)
    api.call(API::Request.new(method: "POST", path: path, body: body))
  end
end
