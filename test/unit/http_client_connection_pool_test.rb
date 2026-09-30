# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/client"
require "net/http"

# Plain requests share one connection pool per client across threads (perf,
# 2026-09-27): per-thread sessions gave every Pod worker thread its own TLS
# handshake.  Streams keep their own connections and never enter the pool.
class HTTPClientConnectionPoolTest < Minitest::Test
  class FakeNetHTTP < Net::HTTP
    @starts = 0
    @requests = 0
    @fail_next = false
    @lock = Mutex.new
    @live = []
    class << self
      attr_accessor :starts, :requests, :fail_next, :live, :lock
    end

    def start
      self.class.lock.synchronize do
        self.class.starts += 1
        self.class.live << self
      end
      @started = true
      self
    end

    def started? = @started == true

    def finish
      @started = false
      self.class.lock.synchronize { self.class.live.delete(self) }
    end

    def request(_req, _body = nil)
      self.class.lock.synchronize { self.class.requests += 1 }
      if self.class.fail_next
        self.class.fail_next = false
        @started = false
        raise EOFError, "server closed the connection"
      end
      sleep 0.002
      response = Net::HTTPOK.new("1.1", "200", "OK")
      response["content-type"] = "application/json"
      if block_given?
        # Streaming form: the body is delivered through read_body.
        def response.read_body(_dest = nil)
          yield "{\"kind\":\"Status\"}"
        end
        return yield(response)
      end
      response.instance_variable_set(:@read, true)
      response.instance_variable_set(:@body, "{\"kind\":\"Status\"}")
      response
    end
  end

  def setup
    FakeNetHTTP.starts = 0
    FakeNetHTTP.requests = 0
    FakeNetHTTP.fail_next = false
    FakeNetHTTP.live = []
    @client = Rubernetes::Client::HTTPClient.new(context: {server: "http://kube.example.test"}, http_class: FakeNetHTTP)
  end

  def pool_size
    @client.instance_variable_get(:@pool).values.sum(&:length)
  end

  def test_connections_are_shared_across_threads_and_bounded_by_concurrency
    threads = Array.new(4) { Thread.new { 10.times { @client.request("GET", "/api/v1/namespaces") } } }
    threads.each(&:join)
    first_wave = FakeNetHTTP.starts

    assert_operator first_wave, :<=, 4, "no more connections than concurrent threads"
    assert_equal 40, FakeNetHTTP.requests

    # A second wave of new threads reuses the idle connections of the first.
    Array.new(4) { Thread.new { 10.times { @client.request("GET", "/api/v1/namespaces") } } }.each(&:join)

    assert_equal first_wave, FakeNetHTTP.starts
    assert_operator pool_size, :<=, Rubernetes::Client::HTTPClient::POOL_MAX_IDLE_PER_SERVER
  end

  def test_idle_pool_is_bounded
    threads = Array.new(20) { Thread.new { @client.request("GET", "/api/v1/namespaces") } }
    threads.each(&:join)

    assert_operator pool_size, :<=, Rubernetes::Client::HTTPClient::POOL_MAX_IDLE_PER_SERVER
    assert_equal pool_size, FakeNetHTTP.live.length, "connections beyond the bound are finished, not leaked"
  end

  def test_a_connection_the_server_closed_while_idle_is_replaced_and_the_request_retried_once
    @client.request("GET", "/api/v1/namespaces")
    FakeNetHTTP.fail_next = true
    response = @client.request("GET", "/api/v1/namespaces")

    assert_equal 200, response.status
    assert_equal 2, FakeNetHTTP.starts
    assert_equal 3, FakeNetHTTP.requests
    assert_equal 1, pool_size
  end

  def test_certificate_rotation_retires_pooled_connections
    @client.request("GET", "/api/v1/namespaces")
    old = FakeNetHTTP.live.first
    @client.reset_connections!

    refute_predicate old, :started?, "an idle connection of the old generation is finished"
    @client.request("GET", "/api/v1/namespaces")

    assert_equal 2, FakeNetHTTP.starts
    assert_equal 1, pool_size
  end

  def test_a_stream_never_lands_in_the_pool
    chunks = []
    @client.stream("GET", "/api/v1/namespaces") { |chunk| chunks << chunk }

    assert_equal 0, pool_size
    @client.request("GET", "/api/v1/namespaces")

    assert_equal 1, pool_size
    assert_equal ["{\"kind\":\"Status\"}"], chunks
  end

  def test_close_finishes_pooled_connections
    @client.request("GET", "/api/v1/namespaces")
    @client.close

    assert_equal 0, pool_size
    assert_empty FakeNetHTTP.live
  end
end
