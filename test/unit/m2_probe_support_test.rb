# frozen_string_literal: true

require "socket"
require "timeout"

require_relative "../test_helper"
require_relative "../../tools/milestones/m2_probe_support"
require "rubernetes/api"
require "rubernetes/client"
require "rubernetes/node"

class M2ProbeSupportTest < Minitest::Test
  Server = Data.define(:port)

  class WatchStream
    attr_reader :close_calls

    def initialize(lines: [], blocked: false, close_error: nil, close_signal: nil)
      @lines = lines
      @blocked = blocked
      @close_error = close_error
      @close_signal = close_signal
      @close_calls = 0
      @closed = false
      @started = false
      @mutex = Mutex.new
      @condition = ConditionVariable.new
    end

    def each_json_line(timeout: nil, &)
      if @blocked
        @mutex.synchronize do
          @started = true
          @condition.broadcast
          @condition.wait(@mutex) until @closed
        end
      else
        @lines.each(&)
      end
      self
    end

    def close
      @mutex.synchronize do
        @close_calls += 1
        @closed = true
        @condition.broadcast
      end
      @close_signal << true if @close_signal
      raise @close_error if @close_error

      self
    end

    def started?
      @mutex.synchronize { @started }
    end
  end

  def test_chunked_decoder_excludes_http_terminating_chunk
    payload = "9\r\n" + [0].pack("C") + "port-ok\n\r\n0\r\n\r\n"
    decoded, complete = M2ProbeSupport.decode_chunked_payload(payload.b)

    assert_equal [0].pack("C") + "port-ok\n", decoded
    assert_equal true, complete
    refute_includes decoded, "0\r\n\r\n"
  end

  def test_stream_probe_returns_decoded_empty_body_when_only_terminating_chunk_arrives
    listener = TCPServer.new("127.0.0.1", 0)
    port = listener.addr.fetch(1)
    response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n".b
    server_thread = Thread.new do
      socket = listener.accept
      begin
        Timeout.timeout(2) do
          loop do
            break if socket.readpartial(4096).include?("\r\n\r\n")
          end
        end
      rescue EOFError, IO::WaitReadable, Timeout::Error
        nil
      ensure
        socket.write(response) unless socket.closed?
        socket.close unless socket.closed?
      end
    end

    status, body = M2ProbeSupport.probe_http_stream_until(
      Server.new(port), "/stream", request_id: "probe", marker: "port-ok\n", timeout: 2
    )

    assert_equal "200", status
    assert_equal "".b, body
  ensure
    listener&.close unless listener&.closed?
    server_thread&.join(2)
    server_thread&.kill if server_thread&.alive?
  end

  def test_native_watch_body_closes_and_unregisters_on_eof
    stream = WatchStream.new(lines: [watch_line])
    transport = native_transport(stream)
    body = transport.request("GET", "/watch").body

    assert_equal [watch_line], body.to_a
    assert_equal 0, transport.active_watch_count
    assert_equal 1, stream.close_calls
  end

  def test_native_watch_body_closes_and_unregisters_on_parser_error
    stream = WatchStream.new(lines: ["not-json\n"])
    transport = native_transport(stream)
    body = transport.request("GET", "/watch").body

    assert_raises(JSON::ParserError) { body.to_a }
    assert_equal 0, transport.active_watch_count
    assert_equal 1, stream.close_calls
  end

  def test_native_watch_body_closes_and_unregisters_on_consumer_error
    stream = WatchStream.new(lines: [watch_line])
    transport = native_transport(stream)
    body = transport.request("GET", "/watch").body

    assert_raises(RuntimeError) { body.each { raise "consumer failed" } } # rubocop:disable Lint/UnreachableLoop -- the consumer fails on purpose
    assert_equal 0, transport.active_watch_count
    assert_equal 1, stream.close_calls
  end

  def test_native_watch_body_closes_and_unregisters_on_consumer_break
    stream = WatchStream.new(lines: [watch_line])
    transport = native_transport(stream)
    body = transport.request("GET", "/watch").body

    body.each { break } # rubocop:disable Lint/UnreachableLoop -- reads one chunk on purpose

    assert_equal 0, transport.active_watch_count
    assert_equal 1, stream.close_calls
  end

  def test_native_watch_body_suppresses_yield_after_concurrent_close
    observer_started = Queue.new
    release_observer = Queue.new
    delivered = []
    stream = WatchStream.new(lines: [watch_line])
    transport = native_transport(stream)
    observer = lambda do |_event|
      observer_started << true
      release_observer.pop
    end
    body = M2ProbeSupport::NativeAPITransport::WatchBody.new(
      stream,
      observer: observer,
      on_close: ->(watch_body) { transport.send(:unregister_watch_body, watch_body) }
    )
    transport.instance_variable_get(:@watch_bodies) << body
    consumer = Thread.new { body.each { |line| delivered << line } }
    observer_started.pop
    closer = Thread.new { body.close }
    release_observer << true

    closer.join(2)
    consumer.join(2)

    refute_predicate closer, :alive?, "concurrent close must complete"
    refute_predicate consumer, :alive?, "watch consumer must terminate after close"
    assert_empty delivered
    assert_equal 0, transport.active_watch_count
    assert_equal 1, stream.close_calls
  ensure
    closer&.kill if closer&.alive?
    consumer&.kill if consumer&.alive?
  end

  def test_native_watch_body_close_waits_for_reserved_delivery_and_preserves_gap
    observer_started = Queue.new
    release_observer = Queue.new
    close_started = Queue.new
    close_finished = Queue.new
    delivered = []
    stream = WatchStream.new(lines: [watch_line], close_signal: close_started)
    transport = native_transport(stream)
    observer = lambda do |_event|
      observer_started << true
      release_observer.pop
    end
    body = M2ProbeSupport::NativeAPITransport::WatchBody.new(
      stream,
      observer: observer,
      on_close: ->(watch_body) { transport.send(:unregister_watch_body, watch_body) }
    )
    transport.instance_variable_get(:@watch_bodies) << body
    consumer = Thread.new { body.each { |line| delivered << line } }
    observer_started.pop
    closer = Thread.new do
      body.close
      close_finished << true
    end

    Timeout.timeout(1) { close_started.pop }

    assert_empty close_finished, "close must wait for the reserved observer delivery"
    release_observer << true
    Timeout.timeout(1) { close_finished.pop }
    consumer.join(1)

    refute_predicate consumer, :alive?
    assert_empty delivered, "close linearized before consumer reservation"
    assert_equal 0, transport.active_watch_count
  ensure
    release_observer << true if release_observer && observer_started && !observer_started.empty?
    closer&.kill if closer&.alive?
    consumer&.kill if consumer&.alive?
  end

  def test_native_watch_body_preserves_parser_error_when_close_fails
    close_error = RuntimeError.new("stream close failed")
    stream = WatchStream.new(lines: ["not-json\n"], close_error: close_error)
    transport = native_transport(stream)
    body = transport.request("GET", "/watch").body

    parser_error = assert_raises(JSON::ParserError) { body.to_a }
    assert_same close_error, parser_error.cleanup_errors.fetch(0)
    assert_equal 1, transport.active_watch_count
    stream.instance_variable_set(:@close_error, nil)
    body.close

    assert_equal 0, transport.active_watch_count
  end

  # Requirement: a failed body close suppresses future deliveries but keeps
  # transport registration until a later close attempt succeeds.
  def test_native_watch_body_retries_close_before_unregistering
    stream = WatchStream.new(close_error: RuntimeError.new("transient body close failure"))
    transport = native_transport(stream)
    body = transport.request("GET", "/watch").body

    error = assert_raises(RuntimeError) { body.close }
    assert_match(/transient body close failure/, error.message)
    assert_equal 1, transport.active_watch_count

    stream.instance_variable_set(:@close_error, nil)

    assert_same body, body.close
    assert_equal 0, transport.active_watch_count
  end

  def test_native_transport_close_retains_all_body_cleanup_errors
    first_error = RuntimeError.new("first close failed")
    second_error = RuntimeError.new("second close failed")
    first = WatchStream.new(close_error: first_error)
    second = WatchStream.new(close_error: second_error)
    server = Object.new
    streams = [first, second]
    server.define_singleton_method(:call) do |**_options|
      Rubernetes::API::Response.new(status: 200, headers: {}, body: streams.shift)
    end
    transport = M2ProbeSupport::NativeAPITransport.new(server)
    2.times { |index| transport.request("GET", "/watch/#{index}") }

    cleanup_error = assert_raises(Rubernetes::CleanupError) { transport.close }
    assert_equal [first_error, second_error], cleanup_error.cleanup_errors
    assert_equal 2, transport.active_watch_count
    first.instance_variable_set(:@close_error, nil)
    second.instance_variable_set(:@close_error, nil)
    transport.close

    assert_equal 0, transport.active_watch_count
  end

  def test_sync_loop_stop_closes_transport_owned_watch_and_joins
    stream = WatchStream.new(blocked: true)
    transport = native_transport(stream) do |query:|
      if query && query["watch"] == "true"
        stream
      else
        {"items" => [], "metadata" => {"resourceVersion" => "1"}}
      end
    end
    client = Rubernetes::Client::KubernetesClient.new(rest_client: transport)
    source = Rubernetes::Node::APIClientAdapter.new(client: client, node_name: "node-a")
    sync_loop = Rubernetes::Node::SyncLoop.new(
      source: source,
      node_name: "node-a",
      reconcile: ->(_pod, **_options) {},
      resync_period: 60,
      sleeper: ->(_seconds) {}
    )
    sync_loop.start
    Timeout.timeout(2) do
      sleep 0.001 until stream.started?
    end

    Timeout.timeout(2) { sync_loop.stop }

    refute_predicate sync_loop, :thread_alive?
    assert_equal 0, transport.active_watch_count
    assert_equal 1, stream.close_calls
  ensure
    sync_loop&.stop if sync_loop&.running?
  end

  # Requirement: SyncLoop stop cleanup remains retryable after a transient
  # source close failure.
  def test_sync_loop_retries_source_close_after_failure
    source = Class.new do
      attr_reader :close_calls

      def initialize
        @close_calls = 0
      end

      def list(**_options)
        {"items" => [], "metadata" => {"resourceVersion" => "1"}}
      end

      def watch(**_options)
        []
      end

      def close
        @close_calls += 1
        raise IOError, "transient source close failure" if @close_calls == 1

        self
      end
    end.new
    sync_loop = Rubernetes::Node::SyncLoop.new(
      source: source,
      reconcile: ->(_pod, **_options) {},
      resync_period: 60,
      sleeper: ->(_seconds) {}
    )
    sync_loop.start
    Timeout.timeout(1) { sleep 0.001 until sync_loop.thread_alive? }

    assert_raises(Rubernetes::CleanupError) { sync_loop.stop }
    assert_equal 1, source.close_calls
    assert_same sync_loop, sync_loop.stop
    assert_equal 2, source.close_calls
  ensure
    sync_loop&.stop if sync_loop&.running?
  end

  def test_record_resource_reuse_counts_only_identities_seen_in_prior_cycles
    # M2 resource-ledger cycles must expose the same measured reuse count that
    # feeds the aggregate ledger count; duplicate raw observations are not
    # allowed to disappear during that calculation.
    seen_identities = {}
    first_cycle = [
      {"identity" => "mount:one"},
      {"identity" => "process:one"}
    ]
    second_cycle = [
      {"identity" => "mount:one"},
      {"identity" => "process:two"}
    ]

    assert_equal 0, M2ProbeSupport.record_resource_reuse(first_cycle, seen_identities)
    assert_equal 1, M2ProbeSupport.record_resource_reuse(second_cycle, seen_identities)
    assert_equal %w[mount:one process:one process:two], seen_identities.keys.sort

    assert_raises(RuntimeError) do
      M2ProbeSupport.record_resource_reuse(
        [{"identity" => "process:two"}, {"identity" => "process:two"}],
        seen_identities
      )
    end
  end

  private

  def watch_line
    JSON.generate("type" => "BOOKMARK", "object" => {"metadata" => {"resourceVersion" => "1"}}) << "\n"
  end

  def native_transport(stream, &response_body)
    server = Object.new
    server.define_singleton_method(:call) do |**options|
      query = options[:query].to_h
      value = if response_body
                yield(query: query)
              elsif query["watch"] == "true" || options[:path] == "/watch"
                stream
              else
                {"items" => [], "metadata" => {"resourceVersion" => "1"}}
              end
      Rubernetes::API::Response.new(status: 200, headers: {}, body: value)
    end
    M2ProbeSupport::NativeAPITransport.new(server)
  end
end
