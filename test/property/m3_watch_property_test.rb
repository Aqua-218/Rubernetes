# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/watch"

class M3WatchPropertyTest < Minitest::Test
  Watch = Rubernetes::Watch

  def object(name, version)
    {"metadata" => {"name" => name, "resourceVersion" => version.to_s}, "spec" => {"generation" => version}}
  end

  def test_fixed_seed_delta_sequences_never_drop_a_key_or_duplicate_work
    random = Random.new(20_260_823)
    fifo = Watch::DeltaFIFO.new
    queue = Watch::WorkQueue.new(bucket_capacity: 1_000, bucket_rate: 1_000)
    names = %w[a b c d e]
    expected = {}
    500.times do |step|
      name = names.fetch(random.rand(names.length))
      version = step + 1
      value = object(name, version)
      case random.rand(4)
      when 0
        fifo.add(value)
        expected[name] = value
      when 1
        fifo.update(value)
        expected[name] = value
      when 2
        fifo.delete(value)
        expected.delete(name)
      else
        fifo.sync(value)
        expected[name] = value
      end
      queue.add(name)
    end

    seen_keys = []
    loop do
      item = fifo.pop(timeout: 0)
      break unless item

      key, deltas = item
      refute_empty(deltas)
      seen_keys << key
      fifo.done(key)
    end
    assert_equal(seen_keys.uniq.sort, seen_keys.sort)
    assert_equal(names.sort, seen_keys.sort)

    work_keys = []
    loop do
      key, shutdown = queue.get(timeout: 0)
      break if key.nil?

      refute(shutdown)
      work_keys << key
      queue.done(key)
    end
    assert_equal(names.sort, work_keys.sort)
  end

  def test_concurrent_indexer_updates_preserve_a_consistent_snapshot
    indexer = Watch::Indexer.new(indices: {"generation" => ->(value) { value.dig("spec", "generation") }})
    threads = 8.times.map do |worker|
      Thread.new do
        50.times do |offset|
          name = "pod-#{worker}-#{offset}"
          indexer.upsert(object(name, offset + 1))
        end
      end
    end
    threads.each(&:join)

    assert_equal(400, indexer.size)
    snapshot = indexer.snapshot
    assert_predicate(snapshot, :frozen?)
    assert_equal(400, snapshot.size)
    assert_equal(8, indexer.by_index("generation", "1").size)
  end

  def test_processing_key_is_requeued_once_after_concurrent_dirty_writes
    fifo = Watch::DeltaFIFO.new
    fifo.add(object("pod", 1))
    key, _first = fifo.pop(timeout: 0)
    writers = 10.times.map do |index|
      Thread.new { fifo.update(object("pod", index + 2)) }
    end
    writers.each(&:join)
    fifo.done(key)
    second_key, second = fifo.pop(timeout: 0)
    assert_equal("pod", second_key)
    assert_equal(10, second.length)
    assert_equal((2..11).to_a, second.map { |delta| delta.object.dig("metadata", "resourceVersion").to_i })
    fifo.done(second_key)
    assert_nil(fifo.pop(timeout: 0))
  end

  def test_out_of_order_and_duplicate_updates_leave_the_newest_resource_version
    client = Object.new
    client.define_singleton_method(:list) do |**_options|
      {"items" => [], "metadata" => {"resourceVersion" => "1"}}
    end
    client.define_singleton_method(:watch) do |**_options|
      value = ->(version) { {"metadata" => {"name" => "pod", "resourceVersion" => version}, "spec" => {"value" => version}} }
      [
        {"type" => "MODIFIED", "object" => value.call("3")},
        {"type" => "MODIFIED", "object" => value.call("2")},
        {"type" => "MODIFIED", "object" => value.call("3")}
      ]
    end
    informer = Watch::Informer.new(client: client, resource: "pods", resync_period: 0)
    updates = []
    informer.on(:update) { |value, _old| updates << value.dig("metadata", "resourceVersion") }
    informer.run_once

    assert_equal(["3"], updates)
    assert_equal("3", informer.indexer.get("pod").dig("metadata", "resourceVersion"))
  end
end
