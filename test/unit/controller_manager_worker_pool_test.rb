# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/watch/work_queue"

# Two properties of Manager#step that a conformance run depends on:
#   * a slow reconcile does not leave the other workers gone, so keys that
#     arrive meanwhile are served at once (the pool used to collapse to one
#     worker -- reconcile time pinned at 1 worker-second per second while the
#     queue grew past a hundred keys);
#   * controllers sharing a key are independent: one failing does not stop
#     the rest (the root CA publisher's refused ConfigMap kept the
#     ServiceAccount controller from ever creating "default").
class ControllerManagerWorkerPoolTest < Minitest::Test
  Manager = Rubernetes::Controller::Manager

  Elector = Struct.new(:leader) do
    def step = :renewed
    def leader? = leader
  end

  Recorder = Struct.new(:name, :calls, :behaviour) do
    def reconcile(resource, **)
      calls << [name, resource, Process.clock_gettime(Process::CLOCK_MONOTONIC)]
      behaviour&.call(resource)
      Rubernetes::Controller::ReconcileResult.new(operations: [], status: {}, controller: name, key: resource)
    end
  end

  def eventually(timeout = 5)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    sleep 0.01 until yield || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
  end

  def teardown
    @managers&.each(&:stop)
  end

  def manager(routes, workers:)
    manager = Manager.allocate
    {queue: Rubernetes::Watch::WorkQueue.new, elector: Elector.new(true), elector_mutex: Mutex.new,
     worker_count: workers, reconciled_total: 0, reconciled_mutex: Mutex.new, key_time: Hash.new(0.0),
     key_count: 0, queue_routes: {}, route_mutex: Mutex.new}.each { |name, value| manager.instance_variable_set(:"@#{name}", value) }
    manager.define_singleton_method(:orphan_controllers_for_key) { |_key| [] }
    manager.define_singleton_method(:controllers_for_key) { |key| routes.fetch(key).map { |controller| [controller, key] } }
    manager.define_singleton_method(:clear_route_if_idle) { |_key| nil }
    (@managers ||= []) << manager
    manager
  end

  def test_keys_arriving_during_a_slow_reconcile_are_served_immediately
    log = []
    slow = Recorder.new("slow", log, ->(_) { sleep 0.6 })
    fast = Recorder.new("fast", log, nil)
    subject = manager({"slow" => [slow], "a" => [fast], "b" => [fast]}, workers: 4)
    queue = subject.instance_variable_get(:@queue)
    queue.add("slow")
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    feeder = Thread.new do
      sleep 0.15
      queue.add("a")
      queue.add("b")
    end
    subject.step(wait: 0.05)
    feeder.join
    eventually { log.map { |entry| entry[1] }.include?("b") }
    finished = log.to_h { |_name, key, at| [key, at - started] }

    assert_operator finished.fetch("a"), :<, 0.45, "a key queued behind a slow one must not wait for it"
    assert_operator finished.fetch("b"), :<, 0.45
  end

  # Keys arriving together at the start of a pass are reconciled in parallel,
  # not one after another by the only worker that stayed.
  def test_a_burst_of_slow_keys_is_reconciled_concurrently
    log = []
    slow = Recorder.new("slow", log, ->(_) { sleep 0.3 })
    keys = %w[k1 k2 k3 k4]
    subject = manager(keys.to_h { |key| [key, [slow]] }, workers: 4)
    queue = subject.instance_variable_get(:@queue)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    feeder = Thread.new do
      sleep 0.05
      keys.each { |key| queue.add(key) }
    end
    subject.step(wait: 0.01)
    feeder.join
    eventually { log.length == 4 }
    elapsed = log.map(&:last).max + 0.3 - started

    assert_equal 4, log.length
    assert_operator elapsed, :<, 0.8, "four 0.3 s reconciles on four workers must not run serially (took #{elapsed.round(2)} s)"
  end

  def test_one_failing_controller_does_not_starve_the_others_on_the_same_key
    log = []
    failing = Recorder.new("root-ca", log, ->(_) { raise "admission webhook denied the request" })
    accounts = Recorder.new("serviceaccount", log, nil)
    subject = manager({"ns" => [failing, accounts]}, workers: 2)
    subject.instance_variable_get(:@queue).add("ns")
    subject.step(wait: 0.05)
    eventually { log.length >= 2 }

    assert_equal %w[root-ca serviceaccount], log.map(&:first).first(2)
    assert_equal "admission webhook denied the request", subject.instance_variable_get(:@last_error).message
  end
end
