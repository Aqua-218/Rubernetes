# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "socket"

# A followed container log used to be a bare Enumerator holding a Net::HTTP
# connection to the node inside its generator.  When the API server's client
# went away the consumer stopped pulling, the generator suspended mid-request,
# and the connection to the node was never closed -- so the node saw a peer
# that was still connected, its disconnect monitor never fired, and its
# log-follow thread polled forever.  Measured in the 2026-09-14 K1 run: 603
# threads / 8.9GB in the node agent after two hours with five Pods.
#
# Specification: spec/api/subresources.md (Pod log streaming lifecycle).
class APINodeLogFollowStreamTest < Minitest::Test
  Endpoint = Rubernetes::API::NodeEndpointResolver::Endpoint
  FollowStream = Endpoint::FollowStream

  def setup
    @server = TCPServer.new("127.0.0.1", 0)
    @accepted = Queue.new
    @closed = Queue.new
    @serving = Thread.new do
      loop do
        socket = @server.accept
        @accepted << socket
        Thread.new do
          socket.gets("\r\n\r\n")
          socket.write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" \
                       "Transfer-Encoding: chunked\r\n\r\n")
          socket.write("5\r\nhello\r\n")
          socket.flush
          # Then stay silent, the way an idle container log does.
          begin
            loop do
              break if socket.closed?
              raise EOFError if socket.read_nonblock(1, exception: false).nil?

              sleep 0.02
            end
          rescue IOError, SystemCallError, EOFError
            nil
          ensure
            @closed << true
          end
        end
      end
    rescue IOError, Errno::EBADF
      nil
    end
  end

  def teardown
    @serving&.kill
    @server&.close
  end

  def uri
    URI.parse("http://127.0.0.1:#{@server.addr[1]}/containerLogs/ns/pod/c")
  end

  def test_a_follow_stream_can_be_closed_from_another_thread
    stream = FollowStream.new(uri, open_timeout: 2)
    chunks = Queue.new
    reader = Thread.new { stream.each { |chunk| chunks << chunk } }

    assert_equal "hello", chunks.pop
    # The upstream connection is open and the reader is parked in read_body.
    stream.close

    assert reader.join(5), "closing the stream must end the reader thread"
    assert_predicate stream, :closed?
    assert @closed.pop(timeout: 5), "the node side must observe the disconnect"
  end

  def test_close_before_reading_never_opens_a_connection
    stream = FollowStream.new(uri, open_timeout: 2)
    stream.close

    assert_raises(Endpoint::StreamClosed) { stream.each { |_chunk| flunk("must not stream") } }
    assert_predicate stream, :closed?
  end

  def test_close_is_idempotent
    stream = FollowStream.new(uri, open_timeout: 2)

    assert_same stream, stream.close
    assert_same stream, stream.close
  end

  # Node::Service::Stream#close_endpoint only closes a source that answers
  # #close; a bare Enumerator does not, which is how the leak survived.
  def test_the_stream_presents_the_close_contract_the_transport_relies_on
    stream = FollowStream.new(uri, open_timeout: 2)

    assert_respond_to stream, :close
    assert_respond_to stream, :closed?
    assert_respond_to stream, :each
    assert_respond_to stream, :to_enum
  end
end
