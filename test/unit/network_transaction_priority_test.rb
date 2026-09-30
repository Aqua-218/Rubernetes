# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"

# A Pod start queued behind the teardown of the previous spec's Pods waited
# 5-6 s for its network.  Transactions still run one at a time, but a waiting
# attach goes ahead of waiting detaches.
class NetworkTransactionPriorityTest < Minitest::Test
  Lock = Rubernetes::Network::TransactionLock

  def test_a_waiting_attach_overtakes_waiting_detaches
    lock = Lock.new
    order = Queue.new
    release_first = Queue.new
    first = Thread.new do
      lock.synchronize(:delete) do
        order << :delete0
        release_first.pop
      end
    end
    sleep 0.05
    deletes = Array.new(3) { |index| Thread.new { lock.synchronize(:delete) { order << :"delete#{index + 1}" } } }
    sleep 0.05
    add = Thread.new { lock.synchronize(:add) { order << :add } }
    sleep 0.05
    release_first << true
    [first, add, *deletes].each(&:join)
    sequence = Array.new(order.size) { order.pop }

    assert_equal :delete0, sequence.first
    assert_equal :add, sequence[1], "the attach runs before the queued detaches"
    assert_equal 5, sequence.length
  end

  def test_transactions_never_overlap
    lock = Lock.new
    active = 0
    peak = 0
    guard = Mutex.new
    threads = Array.new(12) do |index|
      Thread.new do
        lock.synchronize(index.even? ? :add : :delete) do
          guard.synchronize do
            active += 1
            peak = [peak, active].max
          end
          sleep 0.005
          guard.synchronize { active -= 1 }
        end
      end
    end
    threads.each(&:join)

    assert_equal 1, peak
  end

  def test_a_recursive_transaction_is_refused
    lock = Lock.new

    assert_raises(ThreadError) { lock.synchronize(:add) { lock.synchronize(:delete) { nil } } }
  end
end
