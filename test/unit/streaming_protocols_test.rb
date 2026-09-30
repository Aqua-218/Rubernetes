# frozen_string_literal: true

require_relative "../test_helper"
require "socket"
require "json"
require "base64"
require "rubernetes/transport/websocket"
require "rubernetes/transport/spdy"
require "rubernetes/node/streaming_server"
require "rubernetes/node/service"

# The kubelet streaming protocols: WebSocket framing, SPDY/3.1 framing, and
# the node's exec / port-forward sessions driven by a client speaking each.
class StreamingProtocolsTest < Minitest::Test
  WebSocket = Rubernetes::Transport::WebSocket
  SPDY = Rubernetes::Transport::SPDY
  Streaming = Rubernetes::Node::Streaming

  # ---------------------------------------------------------------- websocket

  def test_websocket_frames_round_trip_between_client_and_server
    a, b = UNIXSocket.pair
    server = WebSocket::Connection.new(a)
    client = WebSocket::Connection.new(b, client: true)
    client.write_message("\x01hello".b)
    message = server.read_message

    assert_predicate message, :binary?
    assert_equal "\x01hello".b, message.payload
    big = "x" * 70_000
    server.write_message(big.b)

    assert_equal big.b, client.read_message.payload
    client.write_text("t")

    assert_predicate server.read_message, :text?
    client.close

    assert_nil server.read_message
    assert_nil client.read_message
  ensure
    a&.close
    b&.close
  end

  def test_websocket_handles_fragmented_messages_and_ping
    a, b = UNIXSocket.pair
    server = WebSocket::Connection.new(a)
    mask = "\x01\x02\x03\x04".b
    frame = lambda do |opcode, payload, fin|
      bytes = payload.b
      masked = bytes.bytes.each_with_index.map { |byte, index| byte ^ mask.getbyte(index % 4) }.pack("C*")
      [(fin ? 0x80 : 0) | opcode, 0x80 | bytes.bytesize].pack("CC") + mask + masked
    end
    b.write(frame.call(0x9, "ping", true))
    b.write(frame.call(0x2, "ab", false))
    b.write(frame.call(0x0, "cd", true))
    message = server.read_message

    assert_equal "abcd".b, message.payload
    pong = b.readpartial(64)

    assert_equal 0x8a, pong.getbyte(0)
    assert_equal "ping", pong.byteslice(2, 4)
  ensure
    a&.close
    b&.close
  end

  def test_websocket_handshake_helpers
    request = Rubernetes::Transport::Request.new(
      method: "GET", target: "/exec/ns/pod/c?command=ls",
      headers: Rubernetes::Transport::Headers.new(
        "Connection" => "Upgrade", "Upgrade" => "websocket", "Sec-WebSocket-Version" => "13",
        "Sec-WebSocket-Key" => "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol" => "v5.channel.k8s.io, v4.channel.k8s.io"
      )
    )

    assert WebSocket.upgrade_request?(request)
    assert_equal %w[v5.channel.k8s.io v4.channel.k8s.io], WebSocket.offered_protocols(request)
    headers = WebSocket.handshake_headers(request, protocol: "v5.channel.k8s.io")

    assert_equal "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", headers["sec-websocket-accept"]
    assert_equal "v5.channel.k8s.io", headers["sec-websocket-protocol"]
  end

  # --------------------------------------------------------------------- spdy

  def test_spdy_sessions_exchange_streams_data_and_pings
    a, b = UNIXSocket.pair
    received = Queue.new
    server = SPDY::Session.new(a, server: true, on_stream: lambda { |stream|
      received << stream
      true
    }).start
    client = SPDY::Session.new(b, server: false).start
    stream = client.create_stream({"streamType" => "data", "port" => "80", "requestID" => "7"})
    accepted = received.pop

    assert_equal({"streamtype" => ["data"], "port" => ["80"], "requestid" => ["7"]}, accepted.headers)
    assert_equal "data", accepted.header("streamType")
    stream.write("a" * 100_000)
    total = 0
    total += accepted.read.bytesize while total < 100_000

    assert_equal 100_000, total
    accepted.write("reply")

    assert_equal "reply", stream.read
    assert_kind_of Float, client.ping
    stream.close

    assert_nil accepted.read
    accepted.close

    assert_nil stream.read
    client.close
    server.join(2)

    assert_predicate server, :closed?
  ensure
    a&.close
    b&.close
  end

  def test_spdy_rejects_streams_the_handler_refuses
    a, b = UNIXSocket.pair
    server = SPDY::Session.new(a, server: true, on_stream: ->(_stream) { false }).start
    client = SPDY::Session.new(b, server: false).start
    assert_raises(SPDY::StreamReset) { client.create_stream({"streamType" => "bogus"}) }
  ensure
    client&.close
    server&.close
    a&.close
    b&.close
  end

  # ------------------------------------------------------- exec over websocket

  # A fake exec service: the "process" echoes stdin to stdout, writes a
  # fixed stderr line, and exits with the requested code.
  class FakeExecService
    attr_reader :calls

    def initialize(exit_code: 0)
      @exit_code = exit_code
      @calls = []
    end

    def exec(container, command:, tty: false, stdin: false, stdout: true, stderr: true, **_options)
      @calls << {container: container, command: command, tty: tty, stdin: stdin, stdout: stdout, stderr: stderr}
      in_reader, in_writer = IO.pipe
      out_reader, out_writer = IO.pipe
      err_reader, err_writer = IO.pipe
      status = Queue.new
      code = @exit_code
      echo_stdin = stdin
      Thread.new do
        out_writer.write("hello #{command.join(" ")}\n")
        err_writer.write("warn\n") unless tty
        if echo_stdin
          while (chunk = begin
            in_reader.readpartial(4096)
          rescue StandardError
            nil
          end)
            out_writer.write("echo:#{chunk}")
          end
        end
        out_writer.close
        err_writer.close
        status << FakeStatus.new(code)
      end
      Rubernetes::Node::DuplexStream.new(input: in_writer, output: out_reader, error: tty ? nil : err_reader,
                                         status: status, tty: tty, request_id: "r")
    end
  end

  FakeStatus = Struct.new(:exitstatus) do
    def exited? = true
    def termsig = nil
  end

  def with_streaming_server(exec_service: FakeExecService.new, port_forward_service: nil)
    server = Rubernetes::Node::StreamingServer.new(
      log_service: Object.new, exec_service: exec_service, port_forward_service: port_forward_service,
      host: "127.0.0.1", port: 0
    )
    server.start(background: true)
    yield server
  ensure
    server&.stop
  end

  def websocket_connect(port, path, protocols)
    socket = TCPSocket.new("127.0.0.1", port)
    key = Base64.strict_encode64(Random.bytes(16))
    socket.write([
      "GET #{path} HTTP/1.1", "Host: 127.0.0.1", "Connection: Upgrade", "Upgrade: websocket",
      "Sec-WebSocket-Version: 13", "Sec-WebSocket-Key: #{key}", "Sec-WebSocket-Protocol: #{protocols.join(", ")}", "", ""
    ].join("\r\n"))
    head = +""
    head << socket.readpartial(1024) until head.include?("\r\n\r\n")
    [socket, head]
  end

  def test_exec_over_websocket_v5_streams_output_status_and_stdin
    with_streaming_server do |server|
      socket, head = websocket_connect(server.port, "/exec/default/pod/c?command=sh&command=-c&command=x&stdin=true&stdout=true&stderr=true",
                                       ["v5.channel.k8s.io", "v4.channel.k8s.io"])

      assert_match(/ 101 /, head)
      assert_match(/sec-websocket-protocol: v5\.channel\.k8s\.io/i, head)
      client = WebSocket::Connection.new(socket, client: true)
      client.write_message("\x00stdin-bytes".b)
      client.write_message("\xFF\x00".b) # v5 close signal for stdin
      channels = Hash.new { |hash, key| hash[key] = +"".b }
      Timeout.timeout(10) do
        while (message = client.read_message)
          channels[message.payload.getbyte(0)] << (message.payload.byteslice(1..) || "")
        end
      end

      assert_equal "hello sh -c x\necho:stdin-bytes", channels[1]
      assert_equal "warn\n", channels[2]
      assert_equal({"metadata" => {}, "status" => "Success"}, JSON.parse(channels[3]))
      socket.close
    end
  end

  def test_exec_over_websocket_reports_non_zero_exit_as_status_failure
    with_streaming_server(exec_service: FakeExecService.new(exit_code: 3)) do |server|
      socket, head = websocket_connect(server.port, "/exec/default/pod/c?command=false&stdout=true", ["v4.channel.k8s.io"])

      assert_match(/ 101 /, head)
      client = WebSocket::Connection.new(socket, client: true)
      error_channel = +"".b
      Timeout.timeout(10) do
        while (message = client.read_message)
          error_channel << message.payload.byteslice(1..).to_s if message.payload.getbyte(0) == 3
        end
      end
      status = JSON.parse(error_channel)

      assert_equal "Failure", status["status"]
      assert_equal "NonZeroExitCode", status["reason"]
      assert_equal [{"reason" => "ExitCode", "message" => "3"}], status.dig("details", "causes")
      socket.close
    end
  end

  def test_exec_rejects_unsupported_websocket_protocols_and_missing_streams
    with_streaming_server do |server|
      socket, head = websocket_connect(server.port, "/exec/default/pod/c?command=ls&stdout=true", ["nope.k8s.io"])

      assert_match(/ 400 /, head)
      socket.close
      socket, head = websocket_connect(server.port, "/exec/default/pod/c?command=ls", ["v5.channel.k8s.io"])

      assert_match(/ 400 /, head)
      socket.close
    end
  end

  # ------------------------------------------------------------ exec over SPDY

  def spdy_connect(port, path, protocols, method: "POST")
    socket = TCPSocket.new("127.0.0.1", port)
    lines = ["#{method} #{path} HTTP/1.1", "Host: 127.0.0.1", "Connection: Upgrade", "Upgrade: SPDY/3.1"]
    protocols.each { |protocol| lines << "X-Stream-Protocol-Version: #{protocol}" }
    socket.write(lines.join("\r\n") + "\r\n\r\n")
    head = +""
    head << socket.readpartial(1024) until head.include?("\r\n\r\n")
    [socket, head]
  end

  def test_exec_over_spdy_v4_negotiates_and_streams
    with_streaming_server do |server|
      socket, head = spdy_connect(server.port, "/exec/default/pod/c?command=ls&input=1&output=1&error=1",
                                  ["v4.channel.k8s.io", "v3.channel.k8s.io"])

      assert_match(/ 101 /, head)
      assert_match(/x-stream-protocol-version: v4\.channel\.k8s\.io/i, head)
      assert_match(%r{upgrade: SPDY/3\.1}i, head)
      session = SPDY::Session.new(socket, server: false).start
      error = session.create_stream({"streamType" => "error"})
      stdin = session.create_stream({"streamType" => "stdin"})
      stdout = session.create_stream({"streamType" => "stdout"})
      stderr = session.create_stream({"streamType" => "stderr"})
      stdin.write("in")
      stdin.close
      out = Timeout.timeout(10) { stdout.read_all }
      err = Timeout.timeout(10) { stderr.read_all }
      status = Timeout.timeout(10) { error.read_all }

      assert_equal "hello ls\necho:in", out
      assert_equal "warn\n", err
      assert_equal "Success", JSON.parse(status)["status"]
      session.close
    end
  end

  def test_spdy_handshake_answers_403_without_a_common_protocol
    with_streaming_server do |server|
      socket, head = spdy_connect(server.port, "/exec/default/pod/c?command=ls&output=1", ["v9.channel.k8s.io"])

      assert_match(/ 403 /, head)
      assert_match(/x-accepted-stream-protocol-versions: v4\.channel\.k8s\.io/i, head)
      socket.close
      socket, head = spdy_connect(server.port, "/exec/default/pod/c?command=ls&output=1", [])

      assert_match(/ 400 /, head)
      socket.close
    end
  end

  # ------------------------------------------------------------- port-forward

  # A fake port-forward service whose "connection" answers each request line
  # with an upper-cased copy on channel 0 and reports port 9 as refused.
  class FakePortForwardService
    def port_forward(container, ports, **_options)
      port = ports.first
      in_reader, in_writer = IO.pipe
      out_reader, out_writer = IO.pipe
      status = Queue.new
      Thread.new do
        if port == 9
          out_writer.close
          status << FakeStatus.new(111)
        else
          while (chunk = begin
            in_reader.readpartial(4096)
          rescue StandardError
            nil
          end)
            payload = chunk.byteslice(1..).to_s
            out_writer.write("\x00#{payload.upcase}")
          end
          out_writer.close
          status << FakeStatus.new(0)
        end
      end
      Rubernetes::Node::DuplexStream.new(input: in_writer, output: out_reader, status: [status], request_id: container.to_s)
    end
  end

  def test_port_forward_over_spdy_forwards_data_streams
    with_streaming_server(port_forward_service: FakePortForwardService.new) do |server|
      socket, head = spdy_connect(server.port, "/portForward/default/pod/uid-1", ["portforward.k8s.io"])

      assert_match(/ 101 /, head)
      assert_match(/x-stream-protocol-version: portforward\.k8s\.io/i, head)
      session = SPDY::Session.new(socket, server: false).start
      error = session.create_stream({"streamType" => "error", "port" => "80", "requestID" => "0"})
      data = session.create_stream({"streamType" => "data", "port" => "80", "requestID" => "0"})
      data.write("get /")

      assert_equal "GET /", Timeout.timeout(10) { data.read }
      data.close

      assert_nil Timeout.timeout(10) { data.read }
      assert_equal "", Timeout.timeout(10) { error.read_all }

      refused_error = session.create_stream({"streamType" => "error", "port" => "9", "requestID" => "1"})
      refused_data = session.create_stream({"streamType" => "data", "port" => "9", "requestID" => "1"})
      message = Timeout.timeout(10) { refused_error.read_all }

      assert_match(/error forwarding port 9 to pod pod, uid uid-1/, message)
      refused_data.close
      session.close
    end
  end

  def test_port_forward_over_websocket_tunnel_carries_spdy
    with_streaming_server(port_forward_service: FakePortForwardService.new) do |server|
      socket, head = websocket_connect(server.port, "/portForward/default/pod", ["SPDY/3.1+portforward.k8s.io"])

      assert_match(/ 101 /, head)
      assert_match(%r{sec-websocket-protocol: SPDY/3\.1\+portforward\.k8s\.io}i, head)
      tunnel = WebSocket::TunnelIO.new(WebSocket::Connection.new(socket, client: true))
      session = SPDY::Session.new(tunnel, server: false).start
      session.create_stream({"streamType" => "error", "port" => "80", "requestID" => "0"})
      data = session.create_stream({"streamType" => "data", "port" => "80", "requestID" => "0"})
      data.write("ping")

      assert_equal "PING", Timeout.timeout(10) { data.read }
      session.close
    end
  end

  def test_port_forward_over_websocket_channels
    with_streaming_server(port_forward_service: FakePortForwardService.new) do |server|
      socket, head = websocket_connect(server.port, "/portForward/default/pod?port=80", ["v4.channel.k8s.io"])

      assert_match(/ 101 /, head)
      client = WebSocket::Connection.new(socket, client: true)
      announcements = Array.new(2) { client.read_message.payload }

      assert_equal ["\x00\x50\x00".b, "\x01\x50\x00".b], announcements.sort
      client.write_message("\x00hi".b)
      reply = Timeout.timeout(10) { client.read_message }

      assert_equal "\x00HI".b, reply.payload
      client.close(shutdown: true)
    end
  end
end
