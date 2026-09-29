# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "socket"
require "base64"

# Upstream serves ANY stream over a WebSocket when asked
# (responsewriters.WriteStream -> wsstream.IsWebSocketRequest with
# NewDefaultReaderProtocols).  We rejected the upgrade for Pod logs outright
# ("Pod logs do not support connection upgrades"), so
# "[sig-node] Pods should support retrieving logs from the container over
# websockets" failed with "websocket.Dial ...: bad status".
class PodLogWebSocketTest < Minitest::Test
  Bridge = Rubernetes::API::SubresourceBridge

  def bridge
    Bridge.allocate
  end

  def select(offered, operation)
    bridge.send(:select_websocket_protocol, offered, operation)
  end

  def test_an_absent_subprotocol_is_binary
    assert_equal "", select(nil, "logs")
    assert_equal "", select("", "logs")
  end

  def test_binary_protocol_is_selected
    assert_equal "binary.k8s.io", select("binary.k8s.io", "logs")
  end

  def test_base64_protocol_is_selected
    assert_equal "base64.binary.k8s.io", select("base64.binary.k8s.io", "logs")
  end

  def test_an_unknown_reader_protocol_is_refused
    assert_nil select("v5.channel.k8s.io", "logs")
  end

  def test_duplex_subresources_still_use_the_channel_protocols
    assert_equal "v5.channel.k8s.io", select("v5.channel.k8s.io,v4.channel.k8s.io", "exec")
    assert_nil select("binary.k8s.io", "exec")
  end

  # --- the reader itself ---------------------------------------------------

  class FakeStream
    def initialize(chunks)
      @chunks = chunks.dup
    end

    def read(_length = nil)
      @chunks.shift
    end

    def close = nil
    def closed? = false
  end

  def serve_and_collect(chunks, base64:)
    server, client = UNIXSocket.pair
    reader = Bridge::WebSocketReader.new(FakeStream.new(chunks), base64: base64)
    thread = Thread.new { reader.serve(server) }
    # serve() returns once the stream is exhausted and the close frame is out;
    # only then is the client side drained, so nothing blocks waiting for EOF.
    assert thread.join(10), "the reader must finish once the stream ends"
    server.close unless server.closed?
    data = +"".b
    while IO.select([client], nil, nil, 3)
      chunk = begin
        client.read_nonblock(65_536)
      rescue IO::WaitReadable
        next
      rescue EOFError
        nil
      end
      break if chunk.nil?

      data << chunk
    end
    [data, client]
  ensure
    server.close unless server.closed?
    client.close unless client.closed?
  end

  def frames(data)
    out = []
    i = 0
    while i < data.bytesize
      first = data.getbyte(i)
      length = data.getbyte(i + 1) & 0x7f
      i += 2
      if length == 126
        length = data.byteslice(i, 2).unpack1("n"); i += 2
      elsif length == 127
        length = data.byteslice(i, 8).unpack1("Q>"); i += 8
      end
      out << [first & 0x0f, data.byteslice(i, length)]
      i += length
    end
    out
  end

  def test_binary_frames_carry_the_log_bytes
    data, = serve_and_collect(["hello ", "world", nil], base64: false)
    payloads = frames(data)

    assert_equal [0x2, 0x2, 0x8], payloads.map(&:first)
    assert_equal "hello world", payloads[0][1] + payloads[1][1]
  end

  def test_base64_frames_are_text_and_encoded
    data, = serve_and_collect(["hello", nil], base64: true)
    payloads = frames(data)

    assert_equal 0x1, payloads[0][0], "base64 frames are text frames"
    assert_equal "hello", Base64.decode64(payloads[0][1])
  end

  def test_the_stream_is_closed_with_a_close_frame
    data, = serve_and_collect(["x", nil], base64: false)

    assert_equal 0x8, frames(data).last[0]
  end
end
