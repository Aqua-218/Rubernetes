# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

# Emptying a namespace is one delete per object, and the conformance suite
# builds namespaces with hundreds of them.  Only creates ran together, so
# deleting the namespace "[sig-network] Service endpoints latency" leaves
# behind -- 500 Services plus an EndpointSlice and an Endpoints each -- took a
# single reconcile 177.92 s, and the whole control plane queued behind it:
# 440 keys waiting, nothing else reconciled for eleven minutes.
class ApplyBatchParallelDeleteTest < Minitest::Test
  Adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter

  Operation = Struct.new(:action, :name, keyword_init: true)

  # Each apply blocks until CREATE_PARALLELISM of the same action are in
  # flight, so the batch can only finish if they really do overlap.
  class LatchingAdapter < Adapter
    attr_reader :order

    def initialize(width)
      @width = width
      @mutex = Mutex.new
      @condition = ConditionVariable.new
      @in_flight = Hash.new(0)
      @order = []
    end

    def apply(operation, fence: nil)
      @mutex.synchronize do
        @order << operation.action
        @in_flight[operation.action] += 1
        @condition.broadcast if @in_flight[operation.action] >= @width
        @condition.wait(@mutex, 5) while @in_flight[operation.action] < @width
      end
      operation.name
    end
  end

  def batch(action, count)
    Array.new(count) { |i| Operation.new(action: action, name: "#{action}-#{i}") }
  end

  def test_deletes_in_one_batch_go_out_together
    width = Adapter::CREATE_PARALLELISM
    adapter = LatchingAdapter.new(width)

    results = Timeout.timeout(20) { adapter.apply_batch(batch(:delete, width)) }

    assert_equal width, results.length
    assert_equal [:delete] * width, adapter.order
  end

  def test_creates_still_go_out_together
    width = Adapter::CREATE_PARALLELISM
    adapter = LatchingAdapter.new(width)

    Timeout.timeout(20) { adapter.apply_batch(batch(:create, width)) }

    assert_equal [:create] * width, adapter.order
  end

  # A batch that both creates and deletes must not interleave the two: the
  # creates went first when only they ran together, and they still do.
  def test_creates_are_finished_before_deletes_begin
    width = Adapter::CREATE_PARALLELISM
    adapter = LatchingAdapter.new(width)
    operations = batch(:create, width) + batch(:delete, width)

    Timeout.timeout(30) { adapter.apply_batch(operations) }

    assert_equal ([:create] * width) + ([:delete] * width), adapter.order
  end

  def test_the_returned_results_keep_the_order_of_the_batch
    adapter = LatchingAdapter.new(1)
    operations = batch(:delete, 3)

    results = Timeout.timeout(20) { adapter.apply_batch(operations) }

    assert_equal %w[delete-0 delete-1 delete-2], results
  end

  def test_updates_finish_before_following_deletes
    adapter = LatchingAdapter.new(1)
    operations = batch(:update, 2) + batch(:delete, 2)

    results = adapter.apply_batch(operations)

    assert_equal %i[update update delete delete], adapter.order
    assert_equal %w[update-0 update-1 delete-0 delete-1], results
  end

  def test_updates_between_deletes_keep_their_position
    adapter = LatchingAdapter.new(1)
    operations = batch(:delete, 1) + batch(:update, 1) + batch(:delete, 1)

    adapter.apply_batch(operations)

    assert_equal %i[delete update delete], adapter.order
  end

  def test_parallel_failure_waits_for_started_writes_and_stops_the_batch
    width = Adapter::CREATE_PARALLELISM
    operations = batch(:delete, width + 1) + batch(:update, 1)
    started = Queue.new
    first_worker = Queue.new
    second_started = Queue.new
    release_second = Queue.new
    failure = RuntimeError.new("first delete failed")
    adapter = Adapter.allocate
    adapter.define_singleton_method(:apply) do |operation, fence: nil|
      started << operation.name
      case operation.name
      when "delete-0"
        Thread.current.report_on_exception = false
        first_worker << Thread.current
        raise failure
      when "delete-1"
        Thread.current.report_on_exception = false
        second_started << true
        release_second.pop
        raise "second delete failed"
      end
    end

    applying = Thread.new do
      adapter.apply_batch(operations)
    rescue StandardError => error
      error
    end

    Timeout.timeout(5) do
      second_started.pop
      failed = first_worker.pop

      assert_same failure, assert_raises(RuntimeError) { failed.join }
      assert_nil applying.join(0.2), "the batch returned while another write was still in flight"

      release_second << true

      assert_same failure, applying.value
      assert_equal operations.first(width).map(&:name).sort, Array.new(started.size) { started.pop }.sort
    end
  ensure
    release_second << true
    applying&.join(5)
  end
end
