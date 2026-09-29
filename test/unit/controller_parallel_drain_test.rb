# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# kube-controller-manager runs each controller with several workers
# (--concurrent-*-syncs).  Ours drained one key at a time and a reconcile is
# dominated by API round trips, not CPU, so the loop idled while the queue
# grew: under a parallel conformance run a freshly created namespace waited
# over two minutes for its default ServiceAccount.  The WorkQueue hands a key
# to exactly one worker, so the drain can be shared safely.
class ControllerParallelDrainTest < Minitest::Test
  WorkQueue = Rubernetes::Watch::WorkQueue

  def test_the_queue_hands_each_key_to_exactly_one_worker
    queue = WorkQueue.new
    100.times { |index| queue.add("key-#{index}") }
    seen = Queue.new

    workers = Array.new(4) do
      Thread.new do
        loop do
          key, shutdown = queue.get(timeout: 0)
          break if shutdown || key.nil?

          seen << key
          queue.done(key)
        end
      end
    end
    workers.each(&:join)

    drained = []
    drained << seen.pop until seen.empty?
    assert_equal(100, drained.length)
    assert_equal(100, drained.uniq.length, "a key must not be processed twice")
  end

  # A key re-added while it is being processed is handed out again afterwards,
  # never concurrently -- which is what makes a shared drain safe.
  def test_a_key_re_added_while_processing_is_not_handed_out_twice
    queue = WorkQueue.new
    queue.add("a")
    first, = queue.get(timeout: 0)
    queue.add("a")

    assert_nil(queue.get(timeout: 0).first, "the key is still being processed")
    queue.done(first)
    assert_equal("a", queue.get(timeout: 0).first)
  end

  def test_the_manager_defaults_to_several_workers
    assert_operator(Rubernetes::Controller::Manager::DEFAULT_WORKER_COUNT, :>, 1)
  end
end
