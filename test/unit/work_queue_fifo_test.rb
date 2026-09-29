# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/watch/work_queue"

# client-go's workqueue pops q.queue[0] -- the oldest item -- and nothing else
# (util/workqueue/queue.go Type.Get).  Ordering by the key STRING instead is
# invisible on an idle queue and unfair under load: with keys arriving faster
# than they drain, a key late in the alphabet is overtaken by every new key
# that sorts before it.  A new namespace called "lat1-24438" waited 38 seconds
# for its default ServiceAccount while "conformance/..." and
# "endpointslice-..." keys went first.
class WorkQueueFIFOTest < Minitest::Test
  WorkQueue = Rubernetes::Watch::WorkQueue

  def drain(queue, count)
    Array.new(count) do
      key, = queue.get(timeout: 0)
      queue.done(key) if key
      key
    end
  end

  def test_keys_come_back_in_the_order_they_were_added
    queue = WorkQueue.new
    %w[zulu alpha mike].each { |key| queue.add(key) }

    assert_equal(%w[zulu alpha mike], drain(queue, 3))
  end

  # The starvation case: a key late in the alphabet must not be overtaken by
  # keys added after it.
  def test_a_late_alphabet_key_is_not_starved_by_newer_keys
    queue = WorkQueue.new
    queue.add("zzz-namespace")
    20.times { |index| queue.add("aaa-#{index}") }

    key, = queue.get(timeout: 0)

    assert_equal("zzz-namespace", key)
  end

  # A delayed key waits for its time and then takes its place; keys that are
  # ready are served first whatever they are called.
  def test_a_delayed_key_does_not_block_a_ready_one
    now = 0.0
    queue = WorkQueue.new(clock: -> { now })
    queue.add_after("aaa-delayed", 5.0)
    queue.add("zzz-ready")

    assert_equal("zzz-ready", queue.get(timeout: 0).first)
    assert_nil(queue.get(timeout: 0).first)

    now += 6.0

    assert_equal("aaa-delayed", queue.get(timeout: 0).first)
  end

  # Re-adding a key that is already waiting keeps its original place rather
  # than moving it to the back: the queue deduplicates, it does not reorder.
  def test_a_duplicate_add_keeps_the_original_position
    queue = WorkQueue.new
    %w[first second].each { |key| queue.add(key) }
    queue.add("first")

    assert_equal(%w[first second], drain(queue, 2))
  end

  def test_a_key_marked_dirty_while_processing_is_requeued_once
    queue = WorkQueue.new
    queue.add("busy")
    key, = queue.get(timeout: 0)
    queue.add("busy")
    queue.add("busy")
    queue.done(key)

    assert_equal("busy", queue.get(timeout: 0).first)
    assert_nil(queue.get(timeout: 0).first)
  end
end
