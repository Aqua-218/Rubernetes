# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/transport/http_server"
require "rubernetes/transport/response"
require "socket"
require "delegate"

# A response left the server as a head and a body: two writes, two TCP
# segments.  With Nagle's algorithm on, the kernel held the second small
# segment until the client acknowledged the first, and clients delay that
# ACK by 40 ms -- so a 2 ms GET took 45 ms on the wire, every request, on
# every connection.  Accepted sockets now have Nagle disabled, and a small
# response goes out in one write.
class TransportHTTPServerNagleTest < Minitest::Test
  Server = Rubernetes::Transport::HTTPServer
  Response = Rubernetes::Transport::Response

  class RecordingSocket < SimpleDelegator
    attr_reader :writes

    def initialize(io)
      super
      @writes = []
    end

    def write_nonblock(data, *args, **options)
      @writes << data.bytesize
      __getobj__.write_nonblock(data, *args, **options)
    end

    def to_io
      __getobj__
    end
  end

  def server
    Server.new(->(_request) { Response.new(status: 200, body: "{}") }, host: "127.0.0.1", port: 0)
  end

  def response_through(body)
    reader, writer = UNIXSocket.pair
    socket = RecordingSocket.new(writer)
    server.send(:write_response, socket, Response.new(status: 200, headers: {"Content-Type" => "application/json"}, body: body),
                request: nil, keep_alive: true)
    writer.close
    [socket.writes, reader.read]
  ensure
    reader&.close
  end

  def test_a_small_response_is_one_write
    writes, wire = response_through("{\"kind\":\"Namespace\"}")
    assert_equal 1, writes.length, writes.inspect
    assert_match(/\AHTTP\/1.1 200 OK\r\n/, wire)
    assert_match(/Content-Length: 20\r\n/, wire)
    assert wire.end_with?("\r\n\r\n{\"kind\":\"Namespace\"}"), wire[-60..].inspect
  end

  def test_a_large_body_still_follows_the_head_intact
    body = "x" * (Server::COALESCED_BODY_BYTES + 1)
    writes, wire = response_through(body)
    assert_operator writes.length, :>=, 2
    assert wire.end_with?(body)
    assert_match(/Content-Length: #{body.bytesize}\r\n/, wire)
  end

  def test_an_accepted_socket_has_nagle_disabled
    listener = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", listener.addr[1])
    accepted = listener.accept
    assert_equal 0, accepted.getsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY).int, "a fresh socket has Nagle on"
    server.send(:disable_nagle, accepted)
    assert_equal 1, accepted.getsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY).int
  ensure
    [client, accepted, listener].each { |io| io&.close }
  end

  def test_the_server_disables_nagle_on_connections_it_accepts
    seen = Queue.new
    subject = server
    subject.define_singleton_method(:disable_nagle) do |client|
      seen << client.getsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY).int.then { |before| super(client); [before, client.getsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY).int] }
    end
    subject.start
    client = TCPSocket.new("127.0.0.1", subject.port)
    client.write("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    client.read
    assert_equal [0, 1], seen.pop(timeout: 2)
  ensure
    client&.close
    subject&.stop
  end
end
