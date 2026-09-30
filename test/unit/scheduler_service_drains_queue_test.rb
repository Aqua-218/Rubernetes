# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap/control_plane_services"

# The scheduler loop slept its sync interval after every pass, whether or not
# it had just bound a Pod, so scheduling ran at one Pod per interval: with the
# cluster tool's 0.5 s, a 30-replica Deployment took 25 s to place while every
# node sat idle.  kube-scheduler drains its queue as fast as it can bind; the
# interval is only how long an idle loop waits before looking again.
class SchedulerServiceDrainsQueueTest < Minitest::Test
  Service = Rubernetes::Bootstrap::SchedulerService

  Result = Struct.new(:status, :pod, :error) do
    def failed? = false
    def unschedulable? = false
    def dropped? = false
  end

  class Elector
    def step = :leader
    def leader? = true
  end

  # Three Pods to place, then an empty queue.  The empty pass is where the
  # loop may sleep; the test stops the service from the sleeper.
  def build_service(results:, sleeps:)
    service = Service.allocate
    remaining = results.dup
    framework = Object.new
    framework.define_singleton_method(:schedule_next) { |**| remaining.shift }
    service.instance_variable_set(:@framework, framework)
    service.instance_variable_set(:@elector, Elector.new)
    service.instance_variable_set(:@mutex, Mutex.new)
    service.instance_variable_set(:@nodes, {})
    service.instance_variable_set(:@pods, {})
    service.instance_variable_set(:@running, true)
    service.instance_variable_set(:@interval, 0.5)
    service.instance_variable_set(:@clock, -> { Time.now.utc })
    service.instance_variable_set(:@logger, nil)
    service.instance_variable_set(:@sleeper, lambda { |seconds|
      sleeps << seconds
      service.instance_variable_set(:@running, false)
    })
    service
  end

  def test_the_loop_only_sleeps_when_the_queue_is_empty
    sleeps = []
    results = 3.times.map { |_index| Result.new(:scheduled, nil, nil) }
    service = build_service(results: results, sleeps: sleeps)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    service.send(:run_loop)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

    assert_equal [Service::IDLE_POLL_SECONDS], sleeps, "one short sleep, on the empty pass"
    assert_operator elapsed, :<, 0.4, "three Pods were placed without pacing"
  end

  # Pods arrive one at a time, so a queue that is momentarily empty is the
  # normal state between two arrivals of the same burst.  Waiting the
  # configured sync interval there put half a second between consecutive
  # Pods.
  def test_an_idle_pass_waits_far_less_than_the_sync_interval
    sleeps = []
    service = build_service(results: [], sleeps: sleeps)
    service.instance_variable_set(:@interval, 0.5)
    service.send(:run_loop)

    assert_equal [0.02], sleeps
    assert_operator sleeps.first, :<, 0.5
  end

  def test_a_shorter_configured_interval_still_wins
    sleeps = []
    service = build_service(results: [], sleeps: sleeps)
    service.instance_variable_set(:@interval, 0.005)
    service.send(:run_loop)

    assert_equal [0.005], sleeps
  end
end
