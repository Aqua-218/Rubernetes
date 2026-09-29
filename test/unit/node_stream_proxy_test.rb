# frozen_string_literal: true

require "socket"
require_relative "../test_helper"
require "rubernetes/node/stream_proxy"
require "rubernetes/transport/request"
require "rubernetes/transport/response"

# kubelet proxyStream: the upgrade is relayed to the runtime's streaming
# server with the client's upgrade headers, the runtime's 101 comes back,
# and the connections are spliced; a refusal is returned as it came.
class NodeStreamProxyTest < Minitest::Test
  Proxy = Rubernetes::Node::StreamProxy

  def upstream(status: 101)
    server = TCPServer.new("127.0.0.1", 0)
    seen = Queue.new
    thread = Thread.new do
      socket = server.accept
      head = +""
      head << socket.readpartial(4096) until head.include?("\r\n\r\n")
      seen << head
      if status == 101
        socket.write("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n" \
                     "X-Stream-Protocol-Version: v4.channel.k8s.io\r\n\r\nhello")
        loop { socket.write(socket.readpartial(4096).upcase) }
      else
        socket.write("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\ndenied")
        socket.close
      end
    rescue EOFError, IOError
      socket&.close
    end
    [server, thread, seen]
  end

  def request
    headers = Rubernetes::Transport::Headers.new
    headers.add("Connection", "Upgrade")
    headers.add("Upgrade", "SPDY/3.1")
    headers.add("X-Stream-Protocol-Version", "v4.channel.k8s.io")
    headers.add("X-Stream-Protocol-Version", "v3.channel.k8s.io")
    headers.add("Authorization", "Bearer secret")
    Rubernetes::Transport::Request.new(method: "POST", target: "/exec/ns/pod/c?command=sh", headers: headers)
  end

  def test_the_upgrade_is_relayed_and_spliced
    server, thread, seen = upstream
    response = Proxy.response("http://127.0.0.1:#{server.addr[1]}/exec/TOKEN", request)
    assert_equal 101, response.status
    assert_equal "v4.channel.k8s.io", response.headers["x-stream-protocol-version"]
    head = seen.pop
    assert head.start_with?("POST /exec/TOKEN HTTP/1.1\r\n")
    assert_includes head, "x-stream-protocol-version: v4.channel.k8s.io\r\nx-stream-protocol-version: v3.channel.k8s.io\r\n"
    refute_includes head.downcase, "authorization", "credentials are not forwarded to the runtime"

    client, peer = UNIXSocket.pair
    splicer = Thread.new { response.upgrade.call(peer, nil) }
    assert_equal "hello", client.readpartial(5)
    client.write("ping")
    assert_equal "PING", client.readpartial(4)
    client.close
    splicer.join(5)
    refute splicer.alive?
  ensure
    server&.close
    thread&.kill
  end

  def test_a_refusal_is_returned
    server, thread, = upstream(status: 403)
    status, headers, body = Proxy.response("http://127.0.0.1:#{server.addr[1]}/exec/TOKEN", request)
    assert_equal [403, "text/plain", "denied"], [status, headers["content-type"], body.join]
  ensure
    server&.close
    thread&.kill
  end
end
