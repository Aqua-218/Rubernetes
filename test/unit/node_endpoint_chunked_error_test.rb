# frozen_string_literal: true

require_relative "../test_helper"
require "socket"
require "rubernetes/api"

# A node that refuses an exec answers a chunked 500 on a keep-alive
# connection.  The API server used to read that body to EOF, which arrived
# only with the node's 30s idle close, so `kubectl exec -- missing-binary`
# and sonobuoy's retrieve waited half a minute (twice, with the SPDY
# fallback) for an error the node had sent at once.
class NodeEndpointChunkedErrorTest < Minitest::Test
  Endpoint = Rubernetes::API::NodeEndpointResolver::Endpoint

  def serve_once(response, hold_open: 2.0)
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      socket = server.accept
      head = +""
      head << socket.readpartial(4096) until head.include?("\r\n\r\n")
      socket.write(response)
      socket.flush
      sleep(hold_open) # keep-alive: no EOF for the client
      socket.close
    end
    [server, thread]
  end

  def dial(server)
    endpoint = Endpoint.new("http://127.0.0.1:#{server.addr[1]}")
    endpoint.dial_upgrade(method: "POST", path: "/exec/ns/pod/c", query: "command=missing&output=1",
                          headers: {"connection" => ["Upgrade"], "upgrade" => ["websocket"]})
  end

  def test_chunked_error_body_is_returned_at_the_terminating_chunk
    body = "EffectError: exec: \"missing\": executable file not found in $PATH"
    response = "HTTP/1.1 500 Internal Server Error\r\ncontent-type: text/plain\r\n" \
               "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n" \
               "#{body.bytesize.to_s(16)}\r\n#{body}\r\n5\r\n tail\r\n0\r\n\r\n"
    server, thread = serve_once(response)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result = dial(server)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

    refute_predicate result, :upgraded?
    assert_equal 500, result.status
    assert_equal "#{body} tail", result.body
    assert_operator elapsed, :<, 1.0, "the body was read only at the node's idle close (#{elapsed.round(2)}s)"
  ensure
    thread&.kill
    server&.close
  end

  def test_chunked_body_split_across_reads_and_with_extensions
    body = "x" * 10_000
    response = "HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n" \
               "#{body.bytesize.to_s(16)};ext=1\r\n#{body}\r\n0\r\nTrailer: v\r\n\r\n"
    server, thread = serve_once(response, hold_open: 0.5)
    result = dial(server)

    assert_equal 404, result.status
    assert_equal body, result.body
  ensure
    thread&.kill
    server&.close
  end

  def test_truncated_chunked_body_returns_what_arrived
    response = "HTTP/1.1 500 Internal Server Error\r\nTransfer-Encoding: chunked\r\n\r\n4\r\npart\r\n"
    server, thread = serve_once(response, hold_open: 0)
    result = dial(server)

    assert_equal 500, result.status
    assert_equal "part", result.body
  ensure
    thread&.kill
    server&.close
  end
end
