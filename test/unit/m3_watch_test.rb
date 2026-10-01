# frozen_string_literal: true

require_relative "../test_helper"
require "timeout"
require "rubernetes/watch"

class M3WatchTest < Minitest::Test
  Watch = Rubernetes::Watch

  class FakeClock
    attr_reader :now

    def initialize(value = 0.0)
      @now = value
      @mutex = Mutex.new
    end

    def call
      @mutex.synchronize { @now }
    end

    def advance(seconds)
      @mutex.synchronize { @now += seconds }
    end
  end

  class Stream
    def initialize(events, error: nil)
      @events = events
      @error = error
      @closed = false
    end

    attr_reader :closed

    def each
      @events.each { |event| yield event unless @closed }
      raise @error if @error && !@closed
    end

    def close
      @closed = true
    end
  end

  class ListWatchClient
    attr_reader :list_calls, :watch_versions

    def initialize(lists:, streams:)
      @lists = lists
      @streams = streams
      @list_calls = []
      @watch_versions = []
    end

    def list(**options)
      @list_calls << options
      @lists.fetch([@list_calls.length - 1, @lists.length - 1].min)
    end

    def watch(**options)
      @watch_versions << options.fetch(:resource_version)
      @streams.fetch([@watch_versions.length - 1, @streams.length - 1].min)
    end
  end

  def object(name, version: nil, namespace: nil, labels: nil)
    metadata = {"name" => name}
    metadata["resourceVersion"] = version.to_s if version
    metadata["namespace"] = namespace if namespace
    metadata["labels"] = labels if labels
    {"metadata" => metadata, "spec" => {"value" => name}}
  end

  def test_indexer_returns_detached_frozen_objects_and_keeps_indexes_atomic
    indexer = Watch::Indexer.new(
      key_func: ->(value) { value.dig("metadata", "name") },
      indices: {"namespace" => ->(value) { value.dig("metadata", "namespace") }}
    )
    source = object("pod", namespace: "dev")
    indexer.add(source)

    source["metadata"]["name"] = "changed"
    returned = indexer.get("pod")

    assert_equal("pod", returned.dig("metadata", "name"))
    assert_predicate(returned, :frozen?)
    assert_predicate(returned.fetch("metadata"), :frozen?)
    assert_equal(["pod"], indexer.by_index("namespace", "dev").map { |value| value.dig("metadata", "name") })
    assert_raises(FrozenError) { returned.fetch("metadata")["name"] = "mutated" }

    indexer.update(object("pod", namespace: "prod"))

    assert_empty(indexer.by_index("namespace", "dev"))
    assert_equal(["pod"], indexer.by_index("namespace", "prod").map { |value| value.dig("metadata", "name") })
  end

  def test_indexer_replace_all_is_atomic_on_duplicate_keys
    indexer = Watch::Indexer.new
    indexer.add(object("existing"))
    assert_raises(ArgumentError) { indexer.replace_all([object("a"), object("a")]) }
    assert_equal(["existing"], indexer.list.map { |value| value.dig("metadata", "name") })
  end

  def test_indexer_rejects_mutable_read_configuration_and_deletes_false_values
    assert_raises(ArgumentError) { Watch::Indexer.new(freeze_objects: false) }

    indexer = Watch::Indexer.new(key_func: ->(value) { value ? "true" : "false" })
    indexer.add(false)

    assert_equal(false, indexer.delete("false"))
    refute_includes(indexer, "false")
  end

  def test_indexer_does_not_call_custom_key_functions_while_holding_its_mutex
    indexer = nil
    indexer = Watch::Indexer.new(key_func: lambda { |value|
      indexer.size
      value.dig("metadata", "name")
    })
    indexer.add(object("pod"))

    assert_equal(["pod"], indexer.list.map { |value| value.dig("metadata", "name") })
  end

  def test_delta_fifo_requeues_processing_key_without_losing_arrival_order
    fifo = Watch::DeltaFIFO.new
    first = object("a", version: 1)
    second = object("a", version: 2)
    fifo.add(first)
    key, popped = fifo.pop(timeout: 0)
    fifo.update(second)
    fifo.requeue(key, popped)

    _, deltas = fifo.pop(timeout: 0)

    assert_equal(%i[add update], deltas.map(&:type))
    fifo.done(key)

    assert_nil(fifo.pop(timeout: 0))
  end

  def test_delta_fifo_replace_emits_sync_and_missing_delete
    fifo = Watch::DeltaFIFO.new
    fifo.add(object("stale"))
    fifo.replace([object("current")], resource_version: "8")

    first_key, first_deltas = fifo.pop(timeout: 0)
    second_key, second_deltas = fifo.pop(timeout: 0)

    assert_equal("stale", first_key)
    assert_equal(:add, first_deltas.first.type)
    fifo.done(first_key)

    assert_equal("current", second_key)
    assert_equal(:sync, second_deltas.first.type)
    assert_equal("8", second_deltas.first.resource_version)
    assert_predicate fifo, :synced?
  end

  def test_work_queue_deduplicates_dirty_key_and_requeues_once_after_done
    queue = Watch::WorkQueue.new(bucket_capacity: 10, bucket_rate: 10)
    queue.add("key")
    queue.add("key")
    key, shutdown = queue.get(timeout: 0)

    refute(shutdown)
    assert_equal("key", key)
    queue.add("key")
    queue.add("key")

    assert queue.dirty?("key")
    queue.done("key")
    key, shutdown = queue.get(timeout: 0)

    refute(shutdown)
    assert_equal("key", key)
    queue.done("key")

    assert_equal([nil, false], queue.get(timeout: 0))
  end

  def test_work_queue_exponential_backoff_is_bounded_and_token_limited
    clock = FakeClock.new
    queue = Watch::WorkQueue.new(clock: clock, base_delay: 0.005, max_delay: 1_000,
                                 bucket_capacity: 1, bucket_rate: 1)
    first = queue.add_rate_limited("a")
    second = queue.add_rate_limited("a")
    third = queue.add_rate_limited("a")

    assert_in_delta(0.005, first, 0.000001)
    assert_operator(second, :>=, 1.01)
    assert_operator(third, :>=, 2.02)
    assert_equal(3, queue.num_requeues("a"))
  end

  def test_work_queue_token_reservations_honor_future_retries
    clock = FakeClock.new
    queue = Watch::WorkQueue.new(clock: clock, base_delay: 0.005, max_delay: 1_000,
                                 bucket_capacity: 1, bucket_rate: 1)
    queue.add("a")
    queue.get(timeout: 0)

    assert_in_delta(0.005, queue.add_rate_limited("a"), 0.000001)
    assert_operator(queue.add_rate_limited("a"), :>=, 1.01)

    clock.advance(1.5)

    assert_operator(queue.add_rate_limited("a"), :>=, 0.519999)
  end

  def test_work_queue_does_not_bypass_retry_delay_when_a_new_event_arrives
    clock = FakeClock.new
    queue = Watch::WorkQueue.new(clock: clock, base_delay: 0.005, max_delay: 1_000,
                                 bucket_capacity: 1, bucket_rate: 1)
    queue.add("a")
    key, _shutdown = queue.get(timeout: 0)
    queue.add_rate_limited(key)
    queue.add(key)
    queue.done(key)

    assert_equal([nil, false], queue.get(timeout: 0))
    clock.advance(0.005)

    assert_equal(["a", false], queue.get(timeout: 0))
  end

  def test_work_queue_shutdown_discards_dirty_requeues
    queue = Watch::WorkQueue.new
    queue.add("a")
    key, shutdown = queue.get(timeout: 0)

    refute(shutdown)
    queue.add("a")
    queue.shutdown
    queue.done(key)

    assert_empty(queue.keys)
    assert_equal(0, queue.num_requeues("a"))
    assert_equal([nil, true], queue.get(timeout: 0))
    assert_raises(IOError) { queue.add_rate_limited("a") }
  end

  def test_delta_fifo_shutdown_discards_events_waiting_for_processing
    fifo = Watch::DeltaFIFO.new
    fifo.add(object("a", version: 1))
    key, _deltas = fifo.pop(timeout: 0)
    fifo.update(object("a", version: 2))
    fifo.shutdown
    fifo.done(key)

    assert_empty(fifo.keys)
    assert_nil(fifo.pop(timeout: 0))
  end

  def test_delta_fifo_rejects_non_finite_timeouts_and_unknown_delta_types
    fifo = Watch::DeltaFIFO.new
    assert_raises(ArgumentError) { fifo.pop(timeout: Float::NAN) }
    assert_raises(ArgumentError) { fifo.pop(timeout: Float::INFINITY) }
    assert_raises(ArgumentError) { Watch::DeltaFIFO::Delta.new(type: :unknown, key: "a") }
  end

  def test_reflector_starts_watch_at_list_rv_and_relists_after_410
    clock = FakeClock.new
    fifo = Watch::DeltaFIFO.new(clock: clock.method(:call))
    client = ListWatchClient.new(
      lists: [
        {"items" => [object("a", version: 1)], "metadata" => {"resourceVersion" => "1"}},
        {"items" => [object("a", version: 2), object("b", version: 2)], "metadata" => {"resourceVersion" => "2"}}
      ],
      streams: [
        Stream.new([{"type" => "ADDED", "object" => object("b", version: 2)}], error: Watch::Reflector::Gone.new),
        Stream.new([])
      ]
    )
    reflector = Watch::Reflector.new(client: client, fifo: fifo, resource: "pods", clock: clock.method(:call),
                                     sleeper: ->(_seconds) {})
    reflector.list!

    refute(reflector.watch_once)
    assert_equal(["1"], client.watch_versions)
    assert_equal("2", reflector.resource_version)
    assert_equal(2, client.list_calls.length)
  end

  def test_reflector_applies_exponential_reconnect_backoff
    clock = FakeClock.new
    fifo = Watch::DeltaFIFO.new(clock: clock.method(:call))
    client = Object.new
    list = ->(**_options) { {"items" => [], "metadata" => {"resourceVersion" => "1"}} }
    calls = 0
    client.define_singleton_method(:list, &list)
    client.define_singleton_method(:watch) do |**_options|
      calls += 1
      raise IOError, "temporary disconnect"
    end
    sleeps = []
    reflector = Watch::Reflector.new(client: client, fifo: fifo, resource: "pods", clock: clock.method(:call),
                                     sleeper: ->(seconds) { sleeps << seconds }, max_backoff: 1)
    reflector.run(iterations: 3)

    assert_equal([0.005, 0.01, 0.02], sleeps)
    assert_equal(3, calls)
  end

  # A watch that stayed healthy resets the reconnect delay: routine server
  # side watch expiry must never accumulate into the maximum backoff.
  def test_reflector_resets_backoff_after_a_healthy_watch
    clock = FakeClock.new
    fifo = Watch::DeltaFIFO.new(clock: clock.method(:call))
    client = Object.new
    client.define_singleton_method(:list) { |**_options| {"items" => [], "metadata" => {"resourceVersion" => "1"}} }
    calls = 0
    client.define_singleton_method(:watch) do |**_options|
      calls += 1
      raise IOError, "temporary disconnect" if calls <= 3

      clock.advance(Watch::Reflector::HEALTHY_WATCH_SECONDS + 1) if clock.respond_to?(:advance)
      []
    end
    sleeps = []
    reflector = Watch::Reflector.new(client: client, fifo: fifo, resource: "pods", clock: clock.method(:call),
                                     sleeper: ->(seconds) { sleeps << seconds }, max_backoff: 1)
    reflector.run(iterations: 5)

    assert_equal([0.005, 0.01, 0.02], sleeps.first(3))
    assert_in_delta(0.005, sleeps[3], 0.001, "healthy watch must reset the delay to the minimum: #{sleeps.inspect}")
  end

  # I2 shutdown contract: stopping a reflector during a reconnect backoff
  # must wake the blocked sleeper promptly without changing the running retry sequence.
  def test_reflector_stop_interrupts_reconnect_backoff
    clock = FakeClock.new
    fifo = Watch::DeltaFIFO.new(clock: clock.method(:call))
    watch_started = Queue.new
    client = Object.new
    client.define_singleton_method(:list) do |**_options|
      {"items" => [], "metadata" => {"resourceVersion" => "1"}}
    end
    client.define_singleton_method(:watch) do |**_options|
      watch_started << true
      raise IOError, "temporary disconnect"
    end
    sleeps = []
    backoff_started = Queue.new
    reflector = Watch::Reflector.new(
      client: client, fifo: fifo, resource: "pods", clock: clock.method(:call),
      min_backoff: 30, max_backoff: 30,
      sleeper: lambda { |seconds|
        sleeps << seconds
        backoff_started << true
        sleep(seconds)
      }
    )

    reflector.start(thread: true)
    Timeout.timeout(1) { watch_started.pop }
    Timeout.timeout(1) { backoff_started.pop }
    started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    reflector.stop

    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at

    assert_operator elapsed, :<, 0.5
    assert_equal [30.0], sleeps
    refute_predicate reflector, :running?
  ensure
    reflector&.stop
  end

  def test_reflector_watch_once_performs_initial_list_before_watch
    clock = FakeClock.new
    fifo = Watch::DeltaFIFO.new(clock: clock.method(:call))
    client = ListWatchClient.new(
      lists: [{"items" => [], "metadata" => {"resourceVersion" => "1"}}],
      streams: [Stream.new([])]
    )
    reflector = Watch::Reflector.new(client: client, fifo: fifo, resource: "pods", clock: clock.method(:call),
                                     sleeper: ->(_seconds) {})

    assert(reflector.watch_once)
    assert_equal(1, client.list_calls.length)
    assert_equal(["1"], client.watch_versions)
  end

  def test_informer_delivers_events_updates_cache_and_enqueues_key
    client = ListWatchClient.new(
      lists: [{"items" => [object("a", version: 1)], "metadata" => {"resourceVersion" => "1"}}],
      streams: [Stream.new([
                             {"type" => "MODIFIED", "object" => object("a", version: 2)},
                             {"type" => "DELETED", "object" => object("a", version: 3)}
                           ])]
    )
    informer = Watch::Informer.new(client: client, resource: "pods", resync_period: 0)
    events = []
    informer.on(:sync) { |value| events << [:sync, value.dig("metadata", "name")] }
    informer.on(:add) { |value| events << [:add, value.dig("metadata", "name")] }
    informer.on(:update) do |value, old|
      events << [:update, old.dig("metadata", "resourceVersion"), value.dig("metadata", "resourceVersion")]
    end
    informer.on(:delete) { |value| events << [:delete, value.dig("metadata", "resourceVersion")] }
    informer.run_once

    assert_equal([[:sync, "a"], [:update, "1", "2"], [:delete, "2"]], events)
    assert_empty(informer.indexer.list)
    key, shutdown = informer.queue.get(timeout: 0)

    refute(shutdown)
    assert_equal("a", key)
  end

  def test_informer_resync_emits_sync_and_updates_resync_timestamp
    clock = FakeClock.new
    client = ListWatchClient.new(
      lists: [{"items" => [object("a", version: 1)], "metadata" => {"resourceVersion" => "1"}}],
      streams: [Stream.new([])]
    )
    informer = Watch::Informer.new(client: client, resource: "pods", resync_period: 10,
                                   clock: clock.method(:call), sleeper: ->(_seconds) {})
    syncs = 0
    informer.on(:sync) { |_value| syncs += 1 }
    informer.run_once
    clock.advance(10)
    informer.resync!

    assert_equal(2, syncs)
  end
end
