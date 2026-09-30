# frozen_string_literal: true

require "tmpdir"
require "base64"
require "json"
require "openssl"
require_relative "../test_helper"
require_relative "../support/grpc_fake_server"
require "rubernetes/security"
require "rubernetes/observability/metrics"

# --service-account-signing-endpoint: tokens signed by an external signer
# over gRPC on a Unix socket, verified with the keys it publishes.
class ExternalJWTSignerTest < Minitest::Test
  A = Rubernetes::Security::Authentication
  GENERATED = File.expand_path("../../lib/rubernetes/security/authentication/generated/externaljwt_services_pb", __dir__)

  SIGNER_BODY = <<~RUBY
    require "openssl"; require "json"; require "base64"
    KEY = OpenSSL::PKey::RSA.new(PARAMS["pem"])
    OTHER = OpenSSL::PKey::RSA.new(2048)
    class Signer < Rubernetes::ExternalJWTProto::ExternalJWTSigner::Service
      def sign(request, _call)
        kid = PARAMS["sign_with_excluded"] ? "hidden" : PARAMS["kid"]
        key = kid == "hidden" ? OTHER : KEY
        header = Base64.urlsafe_encode64(JSON.generate({"alg" => "RS256", "kid" => kid, "typ" => "JWT"}), padding: false)
        signature = key.sign("SHA256", "\#{header}.\#{request.claims}")
        Rubernetes::ExternalJWTProto::SignJWTResponse.new(header: header, signature: Base64.urlsafe_encode64(signature, padding: false))
      end

      def fetch_keys(_request, _call)
        Rubernetes::ExternalJWTProto::FetchKeysResponse.new(
          keys: [Rubernetes::ExternalJWTProto::Key.new(key_id: PARAMS["kid"], key: KEY.public_key.to_der),
                 Rubernetes::ExternalJWTProto::Key.new(key_id: "hidden", key: OTHER.public_key.to_der, exclude_from_oidc_discovery: true)],
          data_timestamp: Google::Protobuf::Timestamp.new(seconds: 1_700_000_000), refresh_hint_seconds: 300)
      end

      def metadata(_request, _call)
        Rubernetes::ExternalJWTProto::MetadataResponse.new(max_token_expiration_seconds: 7200)
      end
    end
    server.handle(Signer)
  RUBY

  def setup
    @metrics = Rubernetes::Observability::Metrics.new
    A::ExternalJWTSigner.metrics = @metrics
  end

  def teardown
    A::ExternalJWTSigner.metrics = nil
  end

  def with_signer(params = {})
    Dir.mktmpdir do |dir|
      socket = File.join(dir, "signer.sock")
      pem = OpenSSL::PKey::RSA.new(2048).to_pem
      pid = GRPCFakeServer.spawn(socket, SIGNER_BODY, params: {"pem" => pem, "kid" => "external-1"}.merge(params), requires: [GENERATED])
      begin
        yield socket, OpenSSL::PKey::RSA.new(pem)
      ensure
        GRPCFakeServer.stop(pid)
      end
    end
  end

  def test_tokens_are_signed_externally_and_verified_with_the_published_keys
    with_signer do |socket, key|
      signer = A::ExternalJWTSigner.new(socket: socket, issuer: "https://issuer.example").start!
      begin
        assert_equal %w[external-1 hidden], signer.keys_by_id.keys
        assert_equal ["external-1"], signer.discovery_keys.map(&:key_id)
        assert_equal 7200, signer.max_token_expiration_seconds
        token = signer.sign({"iss" => "https://issuer.example", "sub" => "x"})
        header, payload, signature = token.split(".")
        assert_equal({"alg" => "RS256", "kid" => "external-1", "typ" => "JWT"}, JSON.parse(Base64.urlsafe_decode64(header)))
        assert key.public_key.verify("SHA256", Base64.urlsafe_decode64(signature), "#{header}.#{payload}")

        lookup = A::ServiceAccount::Lookup.new(service_account: ->(_ns, _name) { {"metadata" => {"name" => "default", "uid" => "sa-1"}} },
                                               pod: ->(*) { nil }, secret: ->(*) { nil }, node: ->(*) { nil })
        issuer = A::ServiceAccount.new(issuer: "https://issuer.example", api_audiences: ["https://issuer.example"], lookup: lookup,
                                       external_signer: signer, max_expiration_seconds: 7200)
        token, expiration = issuer.issue(namespace: "default", service_account_name: "default", service_account_uid: "sa-1")
        assert_operator expiration, :>, Time.now
        result = issuer.authenticate_token(token)
        assert_equal "system:serviceaccount:default:default", result.user.name
        assert_equal ["external-1"], issuer.jwks["keys"].map { |jwk| jwk["kid"] }, "excluded keys stay out of discovery"
        assert_equal "RS256", issuer.algorithm

        text = @metrics.render_own
        assert_match(/apiserver_externaljwt_fetch_keys_request_total\{code="OK"\} 1/, text)
        assert_match(/apiserver_externaljwt_fetch_keys_data_timestamp 1.7e\+09/, text)
        assert_match(/apiserver_externaljwt_fetch_keys_success_timestamp \d/, text)
        assert_match(/apiserver_externaljwt_sign_request_total\{code="OK"\} 2/, text)
        assert_match(/apiserver_externaljwt_request_duration_seconds_count\{code="OK",method="\/v1.ExternalJWTSigner\/Sign"\} 2/, text)
        assert_match(/apiserver_externaljwt_request_duration_seconds_count\{code="OK",method="\/v1.ExternalJWTSigner\/FetchKeys"\} 1/, text)
        assert_match(/apiserver_externaljwt_request_duration_seconds_count\{code="OK",method="\/v1.ExternalJWTSigner\/Metadata"\} 1/, text)
      ensure
        signer.stop
      end
    end
  end

  def test_signing_with_a_key_excluded_from_discovery_is_refused_unless_allowed
    with_signer("sign_with_excluded" => true) do |socket, _key|
      strict = A::ExternalJWTSigner.new(socket: socket, issuer: "https://issuer.example").start!
      error = assert_raises(A::ExternalJWTSigner::Error) { strict.sign({"sub" => "x"}) }
      assert_match(/excluded from OIDC discovery/, error.message)
      strict.stop
      lenient = A::ExternalJWTSigner.new(socket: socket, issuer: "https://issuer.example", allow_signing_with_non_oidc_keys: true).start!
      assert_equal "hidden", JSON.parse(Base64.urlsafe_decode64(lenient.sign({"sub" => "x"}).split(".").first))["kid"]
      lenient.stop
    end
  end

  def test_an_unreachable_signer_is_counted_by_status_code
    Dir.mktmpdir do |dir|
      signer = A::ExternalJWTSigner.new(socket: File.join(dir, "missing.sock"), issuer: "https://issuer.example", key_sync_timeout: 2)
      error = assert_raises(A::ExternalJWTSigner::Error) { signer.sync_keys! }
      assert_match(/while fetching token verification keys/, error.message)
      text = @metrics.render_own
      assert_match(/apiserver_externaljwt_fetch_keys_request_total\{code="(Unavailable|DeadlineExceeded)"\} 1/, text)
      assert_raises(A::ExternalJWTSigner::Error) { signer.sign({"sub" => "x"}) }
      assert_match(/apiserver_externaljwt_sign_request_total\{code="(Unavailable|DeadlineExceeded)"\} 1/, @metrics.render_own)
    end
  end

  def test_process_config_rejects_key_files_with_a_signing_endpoint
    config = Rubernetes::Bootstrap::Config.allocate.tap { |c| c.instance_variable_set(:@process_name, "rubernetes-apiserver") }
    error = assert_raises(Rubernetes::Bootstrap::Config::Error) do
      config.send(:validate_security!, {"authentication" => {"service_account" => {"issuer" => "https://i", "signing_endpoint" => "/run/signer.sock", "signing_key_file" => "/k.pem"}}})
    end
    assert_match(/signing_key_file cannot be combined with signing_endpoint/, error.message)
    config.send(:validate_security!, {"authentication" => {"service_account" => {"issuer" => "https://i", "signing_endpoint" => "/run/signer.sock", "allow_signing_with_non_oidc_keys" => true}}})
  end
end
