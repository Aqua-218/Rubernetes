# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/consensus"

# Every linearizable read waits for the state machine to reach its read index.
# That wait used to poll -- `@mutex.synchronize { @node.last_applied >= index }`
# every millisecond -- on the same monitor the apply loop and every proposal
# need.  Under a conformance run's read load the barrier therefore starved the
# apply loop it was waiting for, each slow apply added more spinning waiters,
# and reads blocked 10 s a try for three tries until the apiserver answered its
# own informers with "503 read index timed out".  The barrier now sleeps on a
# condition variable the apply hook signals.
class ConsensusReadBarrierContentionTest < Minitest::Test
  Server = Rubernetes::Consensus::Server

  # A stand-in node whose last_applied only advances when the test says so,
  # with a monitor that counts how often the barrier takes it.
  class CountingMonitor < Monitor
    attr_reader :entries

    def initialize
      super
      @entries = 0
    end

    def synchronize(&)
      @entries += 1
      super
    end
  end

  def server_with(monitor, node)
    subject = Server.allocate
    subject.instance_variable_set(:@mutex, monitor)
    # The applied index has a lock of its own: the state machine runs on the
    # apply thread, outside the raft monitor, and notifying the barriers it
    # releases must never need that monitor.
    subject.instance_variable_set(:@applied_mutex, Mutex.new)
    subject.instance_variable_set(:@applied_condition, ConditionVariable.new)
    subject.instance_variable_set(:@node, node)
    subject
  end

  def node_at(applied)
    node = Object.new
    node.define_singleton_method(:last_applied) { applied }
    node
  end

  def test_a_barrier_that_waits_does_not_spin_on_the_shared_monitor
    monitor = CountingMonitor.new
    subject = server_with(monitor, node_at(0))

    assert_raises(Rubernetes::Consensus::Timeout) { subject.send(:wait_applied, 5, 0.5) }

    # Polling took the monitor ~500 times for this wait; now the barrier
    # never touches it at all.
    assert_equal 0, monitor.entries,
                 "a barrier must not touch the raft monitor, which the apply loop needs to make progress"
  end

  def test_an_already_applied_index_returns_without_waiting
    monitor = CountingMonitor.new
    subject = server_with(monitor, node_at(9))

    subject.send(:wait_applied, 5, 5.0)

    assert_equal 0, monitor.entries
  end

  def test_the_barrier_is_woken_by_the_apply_hook
    monitor = CountingMonitor.new
    applied = 0
    node = Object.new
    node.define_singleton_method(:last_applied) { applied }
    subject = server_with(monitor, node)
    subject.instance_variable_set(:@pending, {})
    subject.instance_variable_set(:@applied_listeners, [])

    waiter = Thread.new do
      subject.send(:wait_applied, 3, 10.0)
      :released
    end
    sleep 0.05
    applied = 3
    subject.send(:applied_hook, Struct.new(:index, :term, :result).new(3, 1, nil))

    assert_equal :released, waiter.value
    assert_equal 0, monitor.entries, "the apply hook notifies waiters without the raft monitor"
  end

  # The apply thread holds the node's apply lock while it runs the state
  # machine and notifies waiters; a thread holding the raft monitor may be
  # waiting for that same apply lock (a snapshot capture).  If notifying
  # needed the monitor the two would deadlock, so the notification path must
  # take nothing but its own lock.
  def test_the_apply_notification_never_reaches_for_the_raft_monitor
    monitor = CountingMonitor.new
    subject = server_with(monitor, node_at(0))
    subject.instance_variable_set(:@pending, {})
    subject.instance_variable_set(:@applied_listeners, [])
    held = Queue.new
    release = Queue.new
    holder = Thread.new do
      monitor.synchronize do
        held << :held
        release.pop
      end
    end
    held.pop
    done = Queue.new
    notified = Thread.new do
      subject.send(:applied_hook, Struct.new(:index, :term, :result).new(1, 1, nil))
      done << :done
    end

    assert_equal :done, done.pop(timeout: 2), "the notification blocked on the raft monitor"
    notified.join
    release << :go
    holder.join
  end

  def test_the_barrier_reports_a_timeout_rather_than_hanging
    monitor = CountingMonitor.new
    subject = server_with(monitor, node_at(0))

    error = assert_raises(Rubernetes::Consensus::Timeout) { subject.send(:wait_applied, 7, 0.1) }

    assert_match(/read index 7 was not applied in time/, error.message)
  end
end
