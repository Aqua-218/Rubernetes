# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/client/http_client"
require "rubernetes/observability/metrics"

# client-go rest.Request's retries (with_retry.go, v1.36.2): a 429 or 5xx
# with an integer Retry-After is sent again after that many seconds, a GET
# cut short by a reset connection after one second, at most ten times; and
# the rest_client_* metrics count every attempt and every retry.
class HTTPClientRetryTest < Minitest::Test
  Response = Rubernetes::Client::HTTPClient::Response

  def client(answers, sleeps)
    transport = lambda do |_method, _uri, **_options|
      answer = answers.shift
      raise answer if answer.is_a?(Exception)

      answer
    end
    Rubernetes::Client::HTTPClient.new(server: "http://127.0.0.1:18080", transport: transport,
                                       retry_sleeper: ->(seconds) { sleeps << seconds })
  end

  def answer(status, retry_after = nil)
    headers = retry_after ? {"retry-after" => retry_after} : {}
    Response.new(status: status, headers: headers, body: "{}")
  end

  def retries(code, verb)
    line = Rubernetes::Observability::Metrics.global.render.lines.find do |text|
      text.start_with?(%(rest_client_request_retries_total{code="#{code}",host="127.0.0.1:18080",verb="#{verb}"} ))
    end
    line ? line.split.last.to_i : 0
  end

  def test_retry_after_on_throttling_and_server_errors
    sleeps = []
    before = retries("429", "POST")
    response = client([answer(429, "2"), answer(429, "1"), answer(201)], sleeps).request(:post, "/api/v1/namespaces", body: {})

    assert_equal 201, response.status
    assert_equal [2, 1], sleeps
    assert_equal before + 1, retries("429", "POST"), "the attempt after each Retry-After counts with its own code"

    sleeps.clear

    assert_equal 503, client([answer(503)], sleeps).request(:get, "/healthz").status
    assert_empty sleeps, "no Retry-After, no retry"
    assert_equal 404, client([answer(404, "1")], sleeps).request(:get, "/x").status
    assert_empty sleeps, "only 429 and 5xx wait"
  end

  def test_at_most_ten_retries
    sleeps = []
    answers = Array.new(12) { answer(500, "0") }

    assert_equal 500, client(answers, sleeps).request(:get, "/api").status
    assert_equal 10, sleeps.length
    assert_equal 1, answers.length
  end

  def test_a_reset_get_is_retried_but_not_a_write
    sleeps = []

    assert_equal 200, client([Errno::ECONNRESET.new, answer(200)], sleeps).request(:get, "/api").status
    assert_equal [1], sleeps
    sleeps.clear
    assert_raises(Rubernetes::Client::TransportError) { client([Errno::ECONNRESET.new, answer(200)], sleeps).request(:put, "/api", body: {}) }
    assert_empty sleeps
  end

  # tlsTransportCache.get: one entry per TLS configuration, whatever the
  # server; an injected transport never reaches the cache.
  def test_transport_cache_metrics
    metrics = Rubernetes::Observability::Metrics.global
    value = ->(series) { metrics.render.lines.find { |line| line.start_with?("#{series} ") }&.split&.last.to_i }
    hits = value.call(%(rest_client_transport_create_calls_total{result="hit"}))
    misses = value.call(%(rest_client_transport_create_calls_total{result="miss"}))
    token = "tok-#{rand(1 << 30)}"
    Rubernetes::Client::HTTPClient.new(server: "https://127.0.0.1:1", insecure_skip_tls_verify: true, client_key_data: token)
    Rubernetes::Client::HTTPClient.new(server: "https://127.0.0.2:2", insecure_skip_tls_verify: true, client_key_data: token)
    client([], [])

    assert_equal misses + 1, value.call(%(rest_client_transport_create_calls_total{result="miss"}))
    assert_equal hits + 1, value.call(%(rest_client_transport_create_calls_total{result="hit"}))
  end
end
