# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/event_sink"

# Events were written synchronously: every "Scheduled" or "Started" record
# cost its caller an API write round trip (20-40 ms) that nothing waits for.
# client-go's recorder hands events to a background broadcaster; the sink now
# queues them for a writer thread, bounded so a slow API server cannot hold
# events in memory without limit.
class NodeEventSinkAsyncTest < Minitest::Test
  Sink = Rubernetes::Node::EventSink

  class Client
    attr_reader :created

    def initialize(gate: nil)
      @created = Queue.new
      @gate = gate
    end

    def create(event, **_options)
      @gate&.pop
      @created << event.dig("metadata", "name")
      event
    end

    def patch(*) = nil
  end

  def event(name)
    {"apiVersion" => "v1", "kind" => "Event", "metadata" => {"name" => name, "namespace" => "ns"}, "reason" => "Scheduled"}
  end

  def test_record_returns_before_the_write_and_the_write_still_happens
    gate = Queue.new
    client = Client.new(gate: gate)
    sink = Sink.new(client: client)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    sink.record_event(event("a"))
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.05, "record must not wait for the write"
    assert_equal 1, sink.pending
    gate << :go
    assert sink.flush(timeout: 2.0)
    assert_equal "a", client.created.pop(timeout: 1)
    assert_equal 0, sink.pending
  end

  def test_events_are_written_in_order
    client = Client.new
    sink = Sink.new(client: client)
    10.times { |index| sink.record_event(event("e#{index}")) }
    assert sink.flush(timeout: 2.0)
    assert_equal (0...10).map { |index| "e#{index}" }, Array.new(10) { client.created.pop(timeout: 1) }
  end

  def test_the_queue_is_bounded_and_drops_the_oldest
    gate = Queue.new
    client = Client.new(gate: gate)
    sink = Sink.new(client: client)
    (Sink::MAX_PENDING + 3).times { |index| sink.record_event(event("e#{index}")) }
    assert_operator sink.dropped, :>=, 2
    assert_operator sink.pending, :<=, Sink::MAX_PENDING + 1
    (Sink::MAX_PENDING + 3).times { gate << :go }
    assert sink.flush(timeout: 5.0)
  end

  def test_synchronous_mode_writes_inline
    client = Client.new
    sink = Sink.new(client: client, async: false)
    sink.record_event(event("s"))
    assert_equal "s", client.created.pop(true)
  end
end

# The writer thread was started only when Thread#alive? said the previous one
# had died.  A thread that had timed out and was on its way to returning is
# still alive, so a record arriving in that window started no thread and its
# event sat in the queue until some later record happened to find the thread
# dead.  Specs that wait for an Event -- kubectl describe, the DaemonSet retry
# spec -- then waited tens of seconds for a record that was already queued.
class NodeEventSinkHandoffTest < Minitest::Test
  Sink = Rubernetes::Node::EventSink

  class Client
    attr_reader :created

    def initialize = @created = Queue.new
    def create(event, **_options) = @created << event.dig("metadata", "name")
    def patch(*) = nil
  end

  def event(name)
    {"apiVersion" => "v1", "kind" => "Event", "metadata" => {"name" => name, "namespace" => "ns"}}
  end

  def test_a_record_arriving_as_the_writer_retires_is_written_promptly
    client = Client.new
    sink = Sink.new(client: client)
    sink.instance_variable_set(:@idle_timeout, 0.01)
    # Retire the writer, then record again: a new writer must start.
    sink.record_event(event("a"))
    assert sink.flush(timeout: 2.0)
    assert_equal "a", client.created.pop(timeout: 1)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2.0
    sleep 0.01 while sink.instance_variable_get(:@draining) && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

    30.times do |index|
      sink.record_event(event("b#{index}"))
      assert_equal "b#{index}", client.created.pop(timeout: 2), "record #{index} was not written promptly"
    end
  end

  def test_a_writer_that_raises_is_replaced_and_the_queue_drains
    client = Client.new
    boom = true
    client.define_singleton_method(:create) do |ev, **_o|
      raise IOError, "broken pipe" if boom && ev.dig("metadata", "name") == "poison"

      created << ev.dig("metadata", "name")
    end
    sink = Sink.new(client: client)
    sink.record_event(event("poison"))
    sink.record_event(event("after"))
    assert_equal "after", client.created.pop(timeout: 2), "the queue keeps draining after a writer error"
    assert sink.flush(timeout: 2.0)
    assert_equal 0, sink.pending
  end
end
