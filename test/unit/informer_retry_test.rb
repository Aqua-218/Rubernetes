# frozen_string_literal: true

require_relative "../test_helper"
require "timeout"
require "rubernetes/watch/informer"

class InformerRetryTest < Minitest::Test
  Watch = Rubernetes::Watch

  class Clock
    def initialize
      @mutex = Mutex.new
      @now = 0.0
    end

    def call = @mutex.synchronize { @now }
    def advance(seconds) = @mutex.synchronize { @now += seconds }
  end

  class IdleWatch
    def initialize = @closed = Queue.new
    def each = @closed.pop
    def close = @closed.close
  end

  class Client
    def initialize(background: false) = @background = background
    def list(**) = {"items" => [], "metadata" => {"resourceVersion" => "1"}}
    def watch(**) = @background ? IdleWatch.new : []
  end

  class FailingQueue < Watch::WorkQueue
    def add(key)
      unless @failed
        @failed = true
        raise IOError, "temporary queue error"
      end

      super
    end
  end

  def test_run_once_retries_the_unfinished_batch_without_repeating_handlers
    informer = Watch::Informer.new(client: Client.new, resource: "pods", resync_period: 0)
    events = []
    failed = false
    informer.on(:sync) { |pod| events << [:sync, version(pod)] }
    informer.on(:update) { |pod, old| events << [:first, version(old), version(pod)] }
    informer.on(:update) do |pod, old|
      events << [:second, version(old), version(pod)]
      unless failed
        failed = true
        raise "temporary handler error"
      end
    end
    informer.on(:delete) { |pod| events << [:delete, version(pod)] }
    informer.reflector.list!
    informer.fifo.sync(object("pod", 1))
    informer.fifo.update(object("pod", 2))
    informer.fifo.delete(object("pod", 3))

    error = assert_raises(RuntimeError) { informer.run_once }
    assert_equal "temporary handler error", error.message
    assert_equal [[:sync, "1"], [:first, "1", "2"], [:second, "1", "2"]], events
    assert_same informer, informer.run_once
    assert_equal [[:sync, "1"], [:first, "1", "2"], [:second, "1", "2"], [:second, "1", "2"], [:delete, "2"]], events
    assert_empty informer.indexer.list
    assert_equal ["pod", false], informer.queue.get(timeout: 0)
  ensure
    informer&.stop
  end

  def test_queue_failure_does_not_repeat_notification_or_discard_the_key
    queue = FailingQueue.new
    informer = Watch::Informer.new(client: Client.new, resource: "pods", resync_period: 0, queue: queue)
    observed = []
    informer.on(:add) { |pod| observed << version(pod) }
    informer.reflector.list!
    informer.fifo.add(object("pod", 2))

    assert_raises(IOError) { informer.run_once }
    assert_same informer, informer.run_once
    assert_equal ["2"], observed
    assert_equal ["pod", false], queue.get(timeout: 0)
  ensure
    informer&.stop
  end

  def test_background_retry_preserves_hot_key_order_and_healthy_delivery
    clock = Clock.new
    deliveries = Queue.new
    errors = Queue.new
    poison = Mutex.new
    failing = true
    informer = Watch::Informer.new(client: Client.new(background: true), resource: "pods", resync_period: 0,
                                   clock: clock, error_handler: ->(error) { errors << error })
    informer.on(:sync) do |pod|
      raise "broken key" if poison.synchronize { failing }

      deliveries << [:sync, version(pod)]
    end
    informer.on(:add) { |pod| deliveries << [:add, pod.dig("metadata", "name")] }
    informer.on(:update) { |pod, old| deliveries << [:update, version(old), version(pod)] }
    informer.on(:delete) { |pod| deliveries << [:delete, version(pod)] }
    informer.reflector.list!
    informer.fifo.sync(object("bad", 1))
    informer.start

    assert_equal "broken key", errors.pop(timeout: 2)&.message
    informer.fifo.update(object("bad", 2))
    informer.fifo.delete(object("bad", 3))
    informer.fifo.add(object("healthy", 4))

    assert_equal [:add, "healthy"], deliveries.pop(timeout: 2)
    assert_empty errors
    assert informer.fifo.pending?("bad")
    assert_equal ["bad"], informer.fifo.keys

    clock.advance(Watch::Informer::INITIAL_RETRY_DELAY)

    assert_equal "broken key", errors.pop(timeout: 2)&.message
    clock.advance(Watch::Informer::INITIAL_RETRY_DELAY)
    informer.fifo.add(object("still-healthy", 5))

    assert_equal [:add, "still-healthy"], deliveries.pop(timeout: 2)
    assert_empty errors
    poison.synchronize { failing = false }
    clock.advance(Watch::Informer::INITIAL_RETRY_DELAY)

    assert_equal [:sync, "1"], deliveries.pop(timeout: 2)
    assert_equal [:update, "1", "2"], deliveries.pop(timeout: 2)
    assert_equal [:delete, "2"], deliveries.pop(timeout: 2)
    assert_nil informer.indexer.get("bad")
  ensure
    informer&.stop
  end

  def test_stop_interrupts_a_wait_on_a_delayed_key
    clock = Clock.new
    errors = Queue.new
    informer = Watch::Informer.new(client: Client.new(background: true), resource: "pods", resync_period: 0,
                                   clock: clock, error_handler: ->(error) { errors << error })
    informer.on(:sync) { raise "broken key" }
    informer.reflector.list!
    informer.fifo.sync(object("bad", 1))
    informer.start

    assert_equal "broken key", errors.pop(timeout: 2)&.message
    Timeout.timeout(1) { informer.stop }

    refute_predicate informer, :running?
    assert_empty informer.fifo.keys
    assert_empty errors
  ensure
    informer&.stop
  end

  def test_relist_appends_its_delete_behind_a_delayed_key
    clock = Clock.new
    fifo = Watch::DeltaFIFO.new(clock: clock)
    fifo.add(object("old", 1))
    key, deltas = fifo.pop(timeout: 0)
    fifo.requeue(key, deltas, delay: 1)
    fifo.replace([object("new", 2)], resource_version: "2")
    next_key, next_deltas = fifo.pop(timeout: 0)

    assert_equal "new", next_key
    assert_equal [:sync], next_deltas.map(&:type)
    assert_nil fifo.pop(timeout: 0)
    clock.advance(1)
    retry_key, retry_deltas = fifo.pop(timeout: 0)

    assert_equal "old", retry_key
    assert_equal %i[add delete], retry_deltas.map(&:type)
    assert_equal %w[1 2], retry_deltas.map(&:resource_version)
  end

  private

  def object(name, resource_version)
    {"metadata" => {"name" => name, "resourceVersion" => resource_version.to_s}}
  end

  def version(pod) = pod.dig("metadata", "resourceVersion")
end
