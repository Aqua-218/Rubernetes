# frozen_string_literal: true

require "digest"
require "openssl"
require_relative "../test_helper"
require "rubernetes/security"
require "rubernetes/observability/metrics"

# apiserver_authentication_jwt_authenticator_* (oidc/metrics.go) with
# StructuredAuthenticationConfigurationJWKSMetrics.
class JWTAuthenticatorMetricsTest < Minitest::Test
  A = Rubernetes::Security::Authentication

  def setup
    @metrics = Rubernetes::Observability::Metrics.new
    A::JWTAuthenticator.metrics = @metrics
    A::JWTAuthenticator.api_server_id = "apiserver-abc"
    @key = OpenSSL::PKey::RSA.new(2048)
    @jwks = {"keys" => [A::JWT.to_jwk(@key).merge("kid" => "k1")]}
  end

  def teardown
    A::JWTAuthenticator.metrics = nil
    A::JWTAuthenticator.api_server_id = nil
  end

  def authenticator(fetcher: ->(_url, _ca) { @jwks }, refresh: 300)
    config = {"issuer" => {"url" => "https://issuer.example", "audiences" => ["client"]},
              "claimMappings" => {"username" => {"claim" => "sub", "prefix" => ""}}}
    A::JWTAuthenticator.new(config: config, key_fetcher: fetcher, key_refresh_seconds: refresh)
  end

  def token(**claims)
    now = Time.now.to_i
    A::JWT.sign({"iss" => "https://issuer.example", "aud" => "client", "sub" => "u", "exp" => now + 60, "iat" => now}.merge(claims),
                key: @key, algorithm: "RS256", key_id: "k1")
  end

  def hash(value) = "sha256:#{Digest::SHA256.hexdigest(value)}"

  def test_latency_and_jwks_fetch_metrics
    auth = authenticator
    auth.authenticate_token(token)
    assert_raises(Rubernetes::Security::AuthenticationError) { auth.authenticate_token(token(aud: "other")) }
    text = @metrics.render
    issuer = hash("https://issuer.example")
    server = hash("apiserver-abc")

    assert_match(/apiserver_authentication_jwt_authenticator_latency_seconds_count\{jwt_issuer_hash="#{issuer}",result="success"\} 1/, text)
    assert_match(/apiserver_authentication_jwt_authenticator_latency_seconds_count\{jwt_issuer_hash="#{issuer}",result="failure"\} 1/, text)
    assert_match(
      # rubocop:disable-next Layout/LineLength -- the pattern reads better whole
      /apiserver_authentication_jwt_authenticator_jwks_fetch_last_timestamp_seconds\{apiserver_id_hash="#{server}",jwt_issuer_hash="#{issuer}",result="success"\} \d/, text
    )
    key_set = hash(JSON.generate(@jwks))

    assert_match(
      /apiserver_authentication_jwt_authenticator_jwks_fetch_last_key_set_info\{apiserver_id_hash="#{server}",hash="#{key_set}",jwt_issuer_hash="#{issuer}"\} 1/, text
    )
  end

  def test_a_failed_fetch_is_recorded_and_a_new_key_set_replaces_the_old_hash
    calls = 0
    rotated = {"keys" => [A::JWT.to_jwk(@key).merge("kid" => "k1", "use" => "sig")]}
    fetcher = lambda do |_url, _ca|
      calls += 1
      raise Rubernetes::Security::AuthenticationError, "down" if calls == 1

      calls == 2 ? @jwks : rotated
    end
    auth = authenticator(fetcher: fetcher, refresh: 0)
    assert_raises(Rubernetes::Security::AuthenticationError) { auth.authenticate_token(token) }
    assert_match(/jwks_fetch_last_timestamp_seconds\{[^}]*result="failure"\}/, @metrics.render)
    auth.authenticate_token(token)
    auth.authenticate_token(token)
    lines = @metrics.render.lines.grep(/jwks_fetch_last_key_set_info\{/)

    assert_equal 1, lines.length, lines.inspect
    assert_includes lines.first, hash(JSON.generate(rotated))
  end
end
