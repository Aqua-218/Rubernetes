# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/observability/metrics"
require "rubernetes/security/authentication/token_cache"
require "rubernetes/security/authorization/webhook"

# The kube-apiserver series wired on 2026-09-29: summaries, the token cache,
# the webhook authorizer, and the shared-registry merge they rely on.
class ApiserverRemainingMetricsTest < Minitest::Test
  Metrics = Rubernetes::Observability::Metrics

  def value(text, name, **labels)
    found = text.lines.map(&:chomp).find do |entry|
      entry.start_with?("#{name}{", "#{name} ") && labels.all? { |key, item| entry.include?("#{key}=\"#{item}\"") }
    end
    found && found.split[1]
  end

  def test_summary_type_renders_quantiles_sum_and_count
    registry = Metrics.new(apiserver: false)
    registry.register("test_summary", type: :summary, labels: ["op"])
    (1..100).each { |i| registry.observe("test_summary", i / 100.0, {"op" => "x"}) }
    text = registry.render_own
    assert_includes text, "# TYPE test_summary summary"
    assert_equal "0.5", value(text, "test_summary", op: "x", quantile: "0.5")
    assert_equal "0.9", value(text, "test_summary", op: "x", quantile: "0.9")
    assert_equal "0.99", value(text, "test_summary", op: "x", quantile: "0.99")
    assert_equal "100", value(text, "test_summary_count", op: "x")
    assert_in_delta 50.5, Float(value(text, "test_summary_sum", op: "x")), 0.001
    # The inventory's Summary declaration registers with the component.
    apiserver = Metrics.new
    assert_includes apiserver.registered_names, "apiserver_admission_step_admission_duration_seconds_summary"
    empty = Metrics.new(apiserver: false)
    empty.register("plain_summary", type: :summary, labels: [])
    assert_includes empty.render_own, "plain_summary{quantile=\"0.5\"} NaN"
  end

  def test_plain_shared_series_render_through_a_component_registry
    Metrics.global.register("aggregator_discovery_aggregation_count_total", type: :counter) unless Metrics.global.registered?("aggregator_discovery_aggregation_count_total")
    Metrics.global.increment("aggregator_discovery_aggregation_count_total")
    text = Metrics.new.render
    lines = text.lines.grep(/^aggregator_discovery_aggregation_count_total /)
    assert_equal 1, lines.length, "the shared registry's value shows once, not the component's empty 0 beside it"
    refute_equal "0", lines.first.split.last
  end

  def test_token_cache_records_hits_misses_and_fetches
    inner = Object.new
    calls = 0
    inner.define_singleton_method(:authenticate_token) { |_token, _audiences| calls += 1; {"username" => "alice"} }
    cache = Rubernetes::Security::Authentication::TokenCache.new(inner, success_ttl: 60)
    text_before = Metrics.global.render_own
    before_miss = value(text_before, "authentication_token_cache_request_total", status: "miss").to_i
    before_hit = value(text_before, "authentication_token_cache_request_total", status: "hit").to_i
    before_ok = value(text_before, "authentication_token_cache_fetch_total", status: "ok").to_i
    cache.authenticate_token("t-#{object_id}")
    cache.authenticate_token("t-#{object_id}")
    text = Metrics.global.render_own
    assert_equal 1, calls
    assert_equal before_miss + 1, value(text, "authentication_token_cache_request_total", status: "miss").to_i
    assert_equal before_hit + 1, value(text, "authentication_token_cache_request_total", status: "hit").to_i
    assert_equal before_ok + 1, value(text, "authentication_token_cache_fetch_total", status: "ok").to_i
    assert_equal "0", value(text, "authentication_token_cache_active_fetch_count", status: "in_flight")
    assert_match(/authentication_token_cache_request_duration_seconds_count\{status="miss"\} \d+/, text)
  end

  def test_webhook_authorizer_records_evaluations_and_fail_open
    attributes = Struct.new(:to_h).new({"user" => "u", "resourceAttributes" => {"verb" => "get"}})
    ok = Rubernetes::Security::Authorization::Webhook.new(transport: ->(_body) { [200, {"status" => {"allowed" => true}}] })
    failing = Rubernetes::Security::Authorization::Webhook.new(transport: ->(_body) { raise IOError, "connection reset" })
    text_before = Metrics.global.render_own
    before_success = value(text_before, "apiserver_authorization_webhook_evaluations_total", name: "Webhook", result: "success").to_i
    before_error = value(text_before, "apiserver_authorization_webhook_evaluations_fail_open_total", name: "Webhook", result: "error").to_i
    assert ok.authorize(attributes).allowed?
    refute failing.authorize(attributes).allowed?
    text = Metrics.global.render_own
    assert_equal before_success + 1, value(text, "apiserver_authorization_webhook_evaluations_total", name: "Webhook", result: "success").to_i
    assert_equal before_error + 1, value(text, "apiserver_authorization_webhook_evaluations_fail_open_total", name: "Webhook", result: "error").to_i
    assert_match(/apiserver_authorization_webhook_duration_seconds_count\{name="Webhook",result="error"\} \d+/, text)
  end

  def test_certificate_checks
    key = OpenSSL::PKey::RSA.new(2048)
    plain = OpenSSL::X509::Certificate.new
    plain.version = 2
    plain.serial = 1
    plain.subject = OpenSSL::X509::Name.parse("/CN=hook")
    plain.issuer = plain.subject
    plain.public_key = key.public_key
    plain.not_before = Time.now - 60
    plain.not_after = Time.now + 3600
    plain.sign(key, OpenSSL::Digest.new("SHA1"))
    refute Metrics.certificate_has_san?(plain)
    assert Metrics.certificate_sha1?(plain)
    with_san = plain.dup
    factory = OpenSSL::X509::ExtensionFactory.new
    with_san.add_extension(factory.create_extension("subjectAltName", "DNS:hook.default.svc"))
    with_san.sign(key, OpenSSL::Digest.new("SHA256"))
    assert Metrics.certificate_has_san?(with_san)
    refute Metrics.certificate_sha1?(with_san)
  end
end
