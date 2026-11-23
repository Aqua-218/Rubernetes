# frozen_string_literal: true

require "socket"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/platform/linux/native_adapters"

class HTTPProbeRedirectTest < Minitest::Test
  Connector = Rubernetes::Platform::Linux::NativeAdapters::NamespaceConnector

  class DelayedNamespace
    def within_namespaces(_handle, only:, timeout:)
      raise "unexpected helper deadline" unless only == [:network] && timeout == 6.0

      sleep 1.1
      yield
    end
  end

  class NativeRuntime
    Sandbox = Data.define(:namespace)
    Namespace = Data.define(:adapter_handle)

    def http_get(_id, definition, timeout:, **)
      connector = Connector.new(process_adapter: nil, cgroup_adapter: nil, namespace_adapter: DelayedNamespace.new)
      connector.http_get(sandbox: Sandbox.new(Namespace.new("test")), container: nil, definition: definition, timeout: timeout)
    end
  end

  def test_namespace_setup_does_not_consume_the_http_request_deadline
    with_server([["200 OK", nil, "ready"]]) do |port, requests|
      manager = Rubernetes::Node::ProbeManager.new(runtime: NativeRuntime.new)
      result = manager.check("test", {"httpGet" => {"port" => port, "path" => "/ready"}, "timeoutSeconds" => 1})

      assert_predicate result, :success?
      assert_equal ["/ready"], requests
    end
  end

  def test_http_deadline_still_bounds_response_and_tls_handshake
    [false, true].each do |tls|
      with_stalled_connection do |port|
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        assert_raises(Net::ReadTimeout, Rubernetes::Platform::Linux::NativeAdapters::EffectError) do
          Connector.blocking_http_get("127.0.0.1", port, "/ready", {}, 0.2, tls: tls)
        end
        assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 1
      end
    end
  end

  def test_follows_a_same_host_redirect_to_the_failing_endpoint
    responses = [["302 Found", "/broken", "redirect"], ["500 Internal Server Error", nil, "unhealthy"]]
    with_server(responses) do |port, requests|
      result = Connector.blocking_http_get("127.0.0.1", port, "/start", {}, 2.0)

      refute result.fetch("success")
      assert_equal 500, result.fetch("status")
      assert_equal ["/start", "/broken"], requests
    end
  end

  def test_response_bodies_are_bounded_and_failures_report_only_the_status
    large = "ready\n" * 2500
    fetchers = [
      ->(port) { Connector.blocking_http_get("127.0.0.1", port, "/", {}, 2.0) },
      ->(port) { Rubernetes::Node::ProbeConnectors::HTTP.new.get("http://127.0.0.1:#{port}/") }
    ]
    fetchers.each do |fetch_response|
      with_server([["200 OK", nil, large], ["503 Service Unavailable", nil, "maintenance"]]) do |port, _requests|
        ready = fetch_response.call(port)
        unavailable = fetch_response.call(port)

        assert_equal large.byteslice(0, 10_240), ready.fetch("message")
        assert_equal 10_240, ready.fetch("body_bytes")
        refute unavailable.fetch("success")
        assert_equal "HTTP probe failed with statuscode: 503", unavailable.fetch("message")
      end
    end
  end

  def test_preserves_the_success_and_warning_for_a_redirect_to_another_host
    responses = [["302 Found", "http://127.0.0.2:9/", "redirect"]]
    with_server(responses) do |port, requests|
      result = Connector.blocking_http_get("127.0.0.1", port, "/start", {}, 2.0)

      assert result.fetch("success")
      assert result.fetch("warning")
      assert_equal "Probe terminated redirects, Response body: redirect", result.fetch("message")
      assert_equal ["/start"], requests
    end
  end

  def with_server(responses)
    server = TCPServer.new("127.0.0.1", 0)
    requests = []
    worker = Thread.new do
      responses.each do |status, location, body|
        client, request = next_request(server)
        requests << request.split.fetch(1)
        headers = ["HTTP/1.1 #{status}", "Content-Length: #{body.bytesize}", "Connection: close"]
        headers << "Location: #{location}" if location
        client.write("#{headers.join("\r\n")}\r\n\r\n#{body}")
      ensure
        client&.close
      end
    rescue IOError, Errno::EBADF
      nil # The test closed the listening socket during a failed request.
    end
    yield server.addr[1], requests
  ensure
    server&.close
    worker&.join(2)
  end

  def next_request(server)
    loop do
      client = server.accept
      first = client.gets
      if first
        client.each_line { |line| break if line == "\r\n" }
        return [client, first]
      end

      client.close
    end
  end

  def with_stalled_connection
    server = TCPServer.new("127.0.0.1", 0)
    release = Queue.new
    worker = Thread.new do
      client = server.accept
      release.pop
    rescue IOError
      nil # The assertion can stop before opening the connection.
    ensure
      client&.close
    end
    yield server.addr[1]
  ensure
    release&.push(true)
    server&.close
    worker&.join(2)
  end
end
