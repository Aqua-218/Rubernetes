# frozen_string_literal: true

require "openssl"
require "net/http"
require_relative "../test_helper"
require "rubernetes/transport/http_server"

# The API server speaks h2 when a client negotiates it (ALPN), like
# kube-apiserver.  client-go then multiplexes its watch and its writes over
# one connection to one apiserver; over HTTP/1.1 they could land on different
# apiservers and the client saw its write before its own watch did.
class HTTP2ServerTest < Minitest::Test
  T = Rubernetes::Transport
  H2 = T::HTTP2

  class ClosableStream
    attr_reader :closed

    def initialize
      @closed = Queue.new
      @wake = Queue.new
    end

    def each
      yield "first\n"
      @wake.pop
    end

    def close
      @closed << true
      @wake << true
    end
  end

  # Just enough of an h2 client to drive the server frame by frame.
  class Client
    attr_reader :socket

    def initialize(port)
      context = OpenSSL::SSL::SSLContext.new
      context.verify_mode = OpenSSL::SSL::VERIFY_NONE
      context.alpn_protocols = %w[h2 http/1.1]
      @socket = OpenSSL::SSL::SSLSocket.new(TCPSocket.new("127.0.0.1", port), context)
      @socket.sync_close = true
      @socket.connect
      @buffer = +"".b
      @socket.write(H2::PREFACE + H2.frame(H2::SETTINGS, 0, 0))
    end

    def get(stream_id, path, end_stream: true)
      block = T::HPACK::Encoder.encode([[":method", "GET"], [":scheme", "https"], [":path", path], [":authority", "localhost"]])
      flags = H2::FLAG_END_HEADERS | (end_stream ? H2::FLAG_END_STREAM : 0)
      @socket.write(H2.frame(H2::HEADERS, flags, stream_id, block))
    end

    def write(frame) = @socket.write(frame)

    def read_frame(timeout: 5)
      fill(9, timeout)
      length = (@buffer.getbyte(0) << 16) | @buffer.unpack1("@1n")
      fill(9 + length, timeout)
      header = @buffer.slice!(0, 9)
      [header.getbyte(3), header.getbyte(4), header.unpack1("@5N"), @buffer.slice!(0, length)]
    end

    # Frames until stream_id has ended: [status, body].
    def response(stream_id, decoder, frames = [])
      status = nil
      body = +"".b
      loop do
        type, flags, id, payload = read_frame
        frames << [type, id]
        next unless id == stream_id

        status = decoder.decode(payload).to_h[":status"] if type == H2::HEADERS
        body << payload if type == H2::DATA
        return [status, body] if flags & H2::FLAG_END_STREAM != 0 && [H2::HEADERS, H2::DATA].include?(type)
      end
    end

    def close = @socket.close

    private

    def fill(count, timeout)
      while @buffer.bytesize < count
        chunk = @socket.read_nonblock(65_536, exception: false)
        if chunk == :wait_readable
          raise "timed out waiting for a frame" unless IO.select([@socket], nil, nil, timeout)
        elsif chunk.nil?
          raise EOFError
        else
          @buffer << chunk
        end
      end
    end
  end

  def setup
    key = OpenSSL::PKey::EC.generate("prime256v1")
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = 1
    certificate.subject = certificate.issuer = OpenSSL::X509::Name.parse("/CN=localhost")
    certificate.public_key = key
    certificate.not_before = Time.now - 60
    certificate.not_after = Time.now + 3600
    certificate.sign(key, OpenSSL::Digest.new("SHA256"))
    @streams = Queue.new
    @events = Queue.new
    @sent = Queue.new
    handler = lambda do |request|
      case request.path
      when "/slow" then sleep 0.5
                        T::Response.new(body: "slow")
      when "/watch" then T::Response.new(stream: true, body: ClosableStream.new.tap { |body| @streams << body }, unbounded: true)
      when "/big" then T::Response.new(body: "z" * 100_000)
      when "/events" then T::Response.new(stream: true, body: Enumerator.new do |out|
        loop do
          out << @events.pop
          @sent << true
        end
      end, unbounded: true)
      # Like API::Server#await_watch_delivery: answered right after the
      # watch has sent the event.
      when "/write" then @events << "event\n"
                         @sent.pop
                         T::Response.new(status: 201, body: "written")
      when "/groups" then T::Response.new(body: request.headers.raw_values("impersonate-group").inspect)
      else T::Response.new(body: "#{request.http_version} #{request.header("host")}")
      end
    end
    @server = T::HTTPServer.new(handler, host: "127.0.0.1", port: 0, cert: certificate, key: key)
    @server.start
    @client = Client.new(@server.port)
  end

  def teardown
    @client&.close
    @server&.stop(timeout: 2)
  end

  def test_alpn_selects_h2_and_requests_carry_the_authority_as_host
    assert_equal "h2", @client.socket.alpn_protocol
    @client.get(1, "/")

    assert_equal ["200", "HTTP/2.0 localhost"], @client.response(1, T::HPACK::Decoder.new)
  end

  def test_streams_are_multiplexed
    decoder = T::HPACK::Decoder.new
    @client.get(1, "/slow")
    @client.get(3, "/")
    frames = []

    assert_equal ["200", "HTTP/2.0 localhost"], @client.response(3, decoder, frames)
    refute_includes frames.map(&:last), 1, "the fast stream is answered while the slow one runs"
    assert_equal %w[200 slow], @client.response(1, decoder)
  end

  def test_a_body_larger_than_the_window_waits_for_window_updates
    decoder = T::HPACK::Decoder.new
    @client.get(1, "/big")
    received = 0
    status = nil
    loop do
      type, flags, _id, payload = @client.read_frame
      status = decoder.decode(payload).to_h[":status"] if type == H2::HEADERS
      next unless type == H2::DATA

      received += payload.bytesize
      # The default 65535-byte windows cover only part of the body.
      if received == 65_535
        assert_raises(RuntimeError) { @client.read_frame(timeout: 0.3) }
        @client.write(H2.frame(H2::WINDOW_UPDATE, 0, 0, [100_000].pack("N")))
        @client.write(H2.frame(H2::WINDOW_UPDATE, 0, 1, [100_000].pack("N")))
      end
      break if flags & H2::FLAG_END_STREAM != 0
    end

    assert_equal "200", status
    assert_equal 100_000, received
  end

  def test_reset_stream_closes_the_response_body
    @client.get(1, "/watch")
    body = @streams.pop(timeout: 5)

    refute_nil body
    @client.write(H2.frame(H2::RST_STREAM, 0, 1, [H2::CANCEL].pack("N")))

    assert_equal true, body.closed.pop(timeout: 5), "the watch body is closed when the client cancels"
  end

  # Impersonate-Group and friends repeat; each value must stay separate, as
  # it does over HTTP/1.1.
  def test_repeated_headers_stay_separate_values
    block = T::HPACK::Encoder.encode([[":method", "GET"], [":scheme", "https"], [":path", "/groups"],
                                      [":authority", "localhost"], ["impersonate-group", "a,b"],
                                      ["impersonate-group", "c"]])
    @client.write(H2.frame(H2::HEADERS, H2::FLAG_END_HEADERS | H2::FLAG_END_STREAM, 1, block))

    assert_equal ["200", ["a,b", "c"].inspect], @client.response(1, T::HPACK::Decoder.new)
  end

  # client-go needs a moment to move a watch event into its informer cache; a
  # write whose event went out on the writer's own watch is answered after it.
  def test_a_write_is_answered_a_moment_after_its_event_on_the_same_connection
    decoder = T::HPACK::Decoder.new
    @client.get(1, "/events")
    block = T::HPACK::Encoder.encode([[":method", "POST"], [":scheme", "https"], [":path", "/write"], [":authority", "localhost"]])
    @client.write(H2.frame(H2::HEADERS, H2::FLAG_END_HEADERS | H2::FLAG_END_STREAM, 3, block))
    event_at = nil
    loop do
      type, _flags, id, payload = @client.read_frame
      now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      status = decoder.decode(payload).to_h[":status"] if type == H2::HEADERS
      event_at = now if type == H2::DATA && id == 1 && payload == "event\n"
      next unless type == H2::HEADERS && id == 3

      assert_equal "201", status
      refute_nil event_at, "the event is sent before the response"
      assert_operator now - event_at, :>=, 0.002
      break
    end
  end

  def test_ping_is_acknowledged
    @client.write(H2.frame(H2::PING, 0, 0, "12345678"))
    frame = nil
    frame = @client.read_frame until frame && frame[0] == H2::PING

    assert_equal [H2::PING, H2::FLAG_ACK, 0, "12345678"], frame
  end

  def test_a_protocol_error_ends_the_connection_with_goaway
    @client.get(2, "/")
    frame = nil
    frame = @client.read_frame until frame && frame[0] == H2::GOAWAY

    assert_equal H2::PROTOCOL_ERROR, frame[3].unpack1("@4N")
  end

  def test_http11_clients_without_alpn_still_work
    http = Net::HTTP.new("127.0.0.1", @server.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    assert_equal "HTTP/1.1 127.0.0.1:#{@server.port}", http.get("/").body
  end
end
