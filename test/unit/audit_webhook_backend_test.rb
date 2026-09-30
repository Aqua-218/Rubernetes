# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/security/audit"
require "rubernetes/security/audit/backend"
require "rubernetes/observability/metrics"

# --audit-webhook-mode: batch flushes in the background, blocking sends
# inline, blocking-strict fails the request when RequestReceived cannot be
# delivered (apiserver_audit_requests_rejected_total via the pipeline).
class AuditWebhookBackendTest < Minitest::Test
  Audit = Rubernetes::Security::Audit

  def event(stage = "RequestReceived")
    {"kind" => "Event", "apiVersion" => "audit.k8s.io/v1", "level" => "Metadata", "stage" => stage, "auditID" => "x"}
  end

  def test_batch_mode_posts_an_event_list
    bodies = []
    backend = Audit::WebhookBackend.new(url: "http://audit.example.test/", mode: "batch", batch_max_size: 2, batch_max_wait: 60,
                                        http: ->(body) { bodies << JSON.parse(body); 200 })
    assert backend.process(event)
    assert backend.process(event("ResponseComplete"))
    backend.flush
    refute_empty bodies
    assert_equal "EventList", bodies.first["kind"]
    assert_equal 2, bodies.flat_map { |list| list["items"] }.length
    backend.close
  end

  def test_blocking_mode_only_logs_a_failure_but_strict_mode_rejects
    metrics = Rubernetes::Observability::Metrics.new
    blocking = Audit::WebhookBackend.new(url: "http://audit.example.test/", mode: "blocking", http: ->(_body) { 503 })
    blocking.metrics = metrics
    assert_equal false, blocking.process(event)
    text = metrics.render_own
    assert_match(/apiserver_audit_error_total\{plugin="webhook"\} 1/, text)

    strict = Audit::WebhookBackend.new(url: "http://audit.example.test/", mode: "blocking-strict", http: ->(_body) { raise IOError, "down" })
    strict.metrics = metrics
    assert strict.strict?
    assert_raises(Audit::RejectedError) { strict.process(event) }
    assert_equal false, strict.process(event("ResponseComplete")), "only RequestReceived fails the request"
  end

  def test_union_backend_propagates_a_strict_rejection_after_feeding_every_backend
    memory = Audit::MemoryBackend.new
    strict = Audit::WebhookBackend.new(url: "http://audit.example.test/", mode: "blocking-strict", http: ->(_body) { 500 })
    union = Audit::UnionBackend.new(memory, strict)
    assert union.strict?
    assert_raises(Audit::RejectedError) { union.process(event) }
    assert_equal 1, memory.events.length
  end
end
