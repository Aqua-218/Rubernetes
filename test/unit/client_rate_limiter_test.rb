# frozen_string_literal: true

require "test_helper"
require "rubernetes/client"

class ClientRateLimiterTest < Minitest::Test
  def limiter(qps:, burst:)
    @now = 0.0
    @slept = []
    Rubernetes::Client::RateLimiter.new(qps: qps, burst: burst, clock: -> { @now }, sleeper: lambda { |seconds|
      @slept << seconds
      @now += seconds
    })
  end

  def test_the_burst_passes_without_waiting
    bucket = limiter(qps: 5, burst: 3)

    assert_equal [0.0, 0.0, 0.0], Array.new(3) { bucket.wait }
    assert_empty @slept
  end

  def test_requests_past_the_burst_are_spaced_by_the_rate
    bucket = limiter(qps: 5, burst: 1)
    bucket.wait

    waits = Array.new(2) { bucket.wait }

    waits.each { |seconds| assert_in_delta 0.2, seconds, 1e-9 }
    assert_in_delta 0.4, @now, 1e-9
  end

  def test_idle_time_refills_up_to_the_burst_only
    bucket = limiter(qps: 10, burst: 2)
    2.times { bucket.wait }
    @now += 60

    assert_equal [0.0, 0.0], Array.new(2) { bucket.wait }
    assert_in_delta 0.1, bucket.wait, 1e-9
  end

  def test_a_rate_must_be_positive
    assert_raises(ArgumentError) { Rubernetes::Client::RateLimiter.new(qps: 0, burst: 1) }
    assert_raises(ArgumentError) { Rubernetes::Client::RateLimiter.new(qps: 1, burst: 0) }
  end

  def test_the_http_client_takes_a_token_per_request_and_reports_the_wait
    calls = 0
    transport = lambda do |*|
      calls += 1
      Rubernetes::Client::HTTPClient::Response.new(status: 200, headers: {}, body: "{}")
    end
    client = Rubernetes::Client::HTTPClient.new(server: "https://127.0.0.1:6443", transport: transport, qps: 1000, burst: 1)

    3.times { client.request(:get, "/version") }

    assert_equal 3, calls
    exposition = Rubernetes::Observability::Metrics.global.render

    assert_match(/^rest_client_rate_limiter_duration_seconds_count\{host="127\.0\.0\.1:6443",verb="GET"\} \d+/, exposition)
  end

  def test_no_rate_means_no_limiter
    client = Rubernetes::Client::HTTPClient.new(server: "https://127.0.0.1:6443", transport: lambda { |*|
      Rubernetes::Client::HTTPClient::Response.new(status: 200, headers: {}, body: "{}")
    })

    assert_nil client.instance_variable_get(:@rate_limiter)
  end
end
