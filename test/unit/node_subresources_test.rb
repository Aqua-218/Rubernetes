# frozen_string_literal: true

require "stringio"
require_relative "../test_helper"
require "rubernetes/node"

class NodeSubresourcesTest < Minitest::Test
  class Runtime
    attr_reader :calls

    def initialize
      @calls = []
    end

    def logs(container_id, follow:, since:, tail:)
      @calls << [:logs, container_id, follow, since, tail]
      "first\nsecond\n\xFF\n".b
    end

    def exec(container_id, command, tty:)
      @calls << [:exec, container_id, command, tty]
      {stdin: StringIO.new, stdout: "out\xFF".b, stderr: "err\xFE".b, status: 0}
    end

    def attach(container_id, tty:)
      @calls << [:attach, container_id, tty]
      {stdin: StringIO.new, stdout: "attached".b}
    end

    def port_forward(container_id, ports, timeout:)
      @calls << [:port_forward, container_id, ports, timeout]
      {stdin: StringIO.new, stdout: "forwarded".b}
    end
  end

  def setup
    @runtime = Runtime.new
    @authorized = []
    @authorizer = lambda do |operation:, container_id:, request_id:, identity:, metadata:|
      @authorized << [operation, container_id, request_id, identity, metadata]
      true
    end
  end

  def test_logs_tail_preserves_arbitrary_bytes_and_passes_follow_since_and_tail
    service = Rubernetes::Node::LogService.new(
      runtime: @runtime,
      authorizer: @authorizer,
      request_id_generator: -> { "request-logs" }
    )

    stream = service.logs("container", follow: true, since: 12, tail: 2, identity: "node")

    assert_equal("request-logs", stream.request_id)
    assert_equal("second\n\xFF\n".b, stream.read)
    assert_equal([:logs, "container", true, 12, 2], @runtime.calls.fetch(0))
    assert_equal(["logs", "container", "request-logs", "node", {}], @authorized.fetch(0))
  end

  # PodLogOptions.limitBytes ("kubectl logs --limit-bytes=1" must print one
  # byte) cuts the stream, mid-line if need be.
  def test_logs_limit_bytes_truncates_the_stream
    service = Rubernetes::Node::LogService.new(runtime: @runtime, authorizer: @authorizer)

    assert_equal("f".b, service.logs("container", limit_bytes: "1", identity: "node").read)
    assert_equal("second\n\xFF".b, service.logs("container", tail: 2, limit_bytes: 8, identity: "node").read)
    assert_raises(Rubernetes::Node::InvalidRequest) { service.logs("container", limit_bytes: 0) }
  end

  def test_logs_reject_negative_tail_and_since
    service = Rubernetes::Node::LogService.new(runtime: @runtime)

    assert_raises(Rubernetes::Node::InvalidRequest) { service.logs("container", tail: -2) }
    assert_raises(Rubernetes::Node::InvalidRequest) { service.logs("container", since: -1) }
  end

  def test_missing_authorizer_fails_closed_before_runtime_invocation
    service = Rubernetes::Node::LogService.new(
      runtime: @runtime,
      request_id_generator: -> { "missing-policy" }
    )

    error = assert_raises(Rubernetes::Node::AuthorizationError) do
      service.logs("container", identity: "authenticated")
    end
    assert_equal("missing-policy", error.request_id)
    assert_empty(@runtime.calls)
  end

  def test_authorization_is_fail_closed_and_carries_request_id
    service = Rubernetes::Node::LogService.new(
      runtime: @runtime,
      authorizer: ->(**_context) { false },
      request_id_generator: -> { "denied-request" }
    )

    error = assert_raises(Rubernetes::Node::AuthorizationError) { service.logs("container") }
    assert_equal("denied-request", error.request_id)
    assert_empty(@runtime.calls)
  end

  def test_exec_returns_bidirectional_stream_and_tty_merges_stderr
    service = Rubernetes::Node::ExecService.new(
      runtime: @runtime,
      authorizer: @authorizer,
      request_id_generator: -> { "request-exec" }
    )

    stream = service.exec("container", ["/bin/sh", "-c", "printf x"], tty: true, stdin: true, stdout: true, stderr: true)

    assert_instance_of(Rubernetes::Node::DuplexStream, stream)
    assert_equal("request-exec", stream.request_id)
    assert_predicate(stream, :tty?)
    assert_nil(stream.stderr)
    assert_equal("out\xFF".b, stream.read)
    assert_equal(5, stream.write("input"))
    stream.close_write

    assert_predicate(stream, :half_closed?)
    assert_equal([:exec, "container", ["/bin/sh", "-c", "printf x"], true], @runtime.calls.fetch(0))
  end

  def test_minimal_runtime_adapter_receives_only_contract_keywords
    service = Rubernetes::Node::AttachService.new(
      runtime: @runtime,
      trusted: true,
      request_id_generator: -> { "request-attach" }
    )

    stream = service.attach(container_id: "container", tty: false)

    assert_equal("attached".b, stream.read)
    assert_equal([:attach, "container", false], @runtime.calls.fetch(0))
  end

  def test_port_forward_validates_ports_and_supports_half_close
    service = Rubernetes::Node::PortForwardService.new(
      runtime: @runtime,
      authorizer: @authorizer,
      request_id_generator: -> { "request-forward" }
    )

    stream = service.port_forward("container", ["127.0.0.1:8080", 8443], timeout: 2)

    assert_equal("request-forward", stream.request_id)
    assert_equal([8080, 8443], @runtime.calls.fetch(0).fetch(2))
    assert_in_delta(2.0, @runtime.calls.fetch(0).fetch(3))
    assert_equal("forwarded".b, stream.read)
    stream.close_write

    assert_predicate(stream, :half_closed?)

    assert_raises(Rubernetes::Node::InvalidRequest) { service.port_forward("container", [0]) }
  end

  def test_bounded_stream_raises_backpressure_without_transcoding
    stream, = Rubernetes::Node::Stream.memory(capacity: 2)

    assert_equal(2, stream.write("\xFF\xFE".b))
    error = assert_raises(Rubernetes::Node::BackpressureError) { stream.write("x", timeout: 0.01) }
    assert_match(/capacity/, error.message)
    assert_equal("\xFF".b, stream.read(1))
  end

  def test_stream_enumeration_yields_live_io_before_eof
    reader, writer = IO.pipe
    stream = Rubernetes::Node::Stream.new(source: reader)
    observed = Queue.new
    consumer = Thread.new { stream.each { |chunk| observed << chunk } }

    writer.write("live")
    writer.flush

    assert_equal("live", Timeout.timeout(1) { observed.pop })
    assert_predicate(consumer, :alive?)

    writer.close
    consumer.join(1)

    refute_predicate(consumer, :alive?)
  ensure
    writer&.close unless writer&.closed?
    reader&.close unless reader&.closed?
    consumer&.kill if consumer&.alive?
  end

  def test_closed_stream_errors_keep_request_id
    stream = Rubernetes::Node::Stream.new(source: "data".b, request_id: "closed-request")
    stream.close

    read_error = assert_raises(Rubernetes::Node::StreamClosed) { stream.read }
    write_error = assert_raises(Rubernetes::Node::StreamClosed) { stream.write("input") }
    assert_equal("closed-request", read_error.request_id)
    assert_equal("closed-request", write_error.request_id)
  end
end
