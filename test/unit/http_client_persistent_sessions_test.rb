# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/client"
require "net/http"

# Plain requests reuse one started connection per thread and server instead
# of a TLS handshake per call; a connection the server dropped is replaced and
# the request retried once.
class HTTPClientPersistentSessionsTest < Minitest::Test
  class FakeNetHTTP < Net::HTTP
    @starts = 0
    @requests = 0
    @fail_next = false
    class << self
      attr_accessor :starts, :requests, :fail_next
    end

    def start
      self.class.starts += 1
      @started = true
      self
    end

    def started? = @started == true

    def finish
      @started = false
    end

    def request(req, _body = nil)
      self.class.requests += 1
      if self.class.fail_next
        self.class.fail_next = false
        @started = false
        raise EOFError, "server closed the connection"
      end
      response = Net::HTTPOK.new("1.1", "200", "OK")
      response.instance_variable_set(:@read, true)
      response.instance_variable_set(:@body, "{\"kind\":\"Status\"}")
      response["content-type"] = "application/json"
      response
    end
  end

  def setup
    FakeNetHTTP.starts = 0
    FakeNetHTTP.requests = 0
    FakeNetHTTP.fail_next = false
    Thread.current[Rubernetes::Client::HTTPClient::SESSIONS_KEY] = nil
  end

  def client
    Rubernetes::Client::HTTPClient.new(context: {server: "http://kube.example.test"}, http_class: FakeNetHTTP)
  end

  def test_requests_on_one_thread_share_one_started_connection
    c = client
    3.times { c.request("GET", "/api/v1/namespaces") }

    assert_equal 1, FakeNetHTTP.starts
    assert_equal 3, FakeNetHTTP.requests
  end

  def test_a_dropped_connection_is_replaced_and_the_request_retried_once
    c = client
    c.request("GET", "/api/v1/namespaces")
    FakeNetHTTP.fail_next = true

    response = c.request("GET", "/api/v1/namespaces")

    assert_equal 200, response.status
    assert_equal 2, FakeNetHTTP.starts
    assert_equal 3, FakeNetHTTP.requests
  end

  def test_two_clients_do_not_share_a_connection
    client.request("GET", "/api/v1/namespaces")
    client.request("GET", "/api/v1/namespaces")

    assert_equal 2, FakeNetHTTP.starts
  end
end
