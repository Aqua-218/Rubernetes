# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# While an owner deleted with propagationPolicy=Foreground waits for its
# dependents, the collector sweeps every second instead of every ten; the
# foreground protocol takes three passes.
class GCExpeditedSweepTest < Minitest::Test
  Controller = Rubernetes::Controller::GarbageCollectorController

  def controller
    Controller.allocate.tap { |subject| subject.instance_variable_set(:@sweep_mutex, Mutex.new) }
  end

  def test_the_normal_interval_applies_without_a_foreground_owner
    subject = controller

    assert subject.send(:sweep_due?)
    subject.instance_variable_set(:@last_sweep_at, Process.clock_gettime(Process::CLOCK_MONOTONIC) - 2.0)

    refute subject.send(:sweep_due?), "two seconds after a sweep is too early normally"
  end

  def test_a_foreground_owner_shortens_the_interval
    subject = controller
    subject.send(:expedite_sweeps!)
    subject.instance_variable_set(:@last_sweep_at, Process.clock_gettime(Process::CLOCK_MONOTONIC) - 1.5)

    assert subject.send(:sweep_due?)
  end

  def test_a_changed_foreground_owner_expedites
    subject = controller
    owner = {"apiVersion" => "v1", "kind" => "ReplicationController",
             "metadata" => {"name" => "rc", "namespace" => "ns", "uid" => "u",
                            "deletionTimestamp" => "2026-09-23T00:00:00Z", "finalizers" => ["foregroundDeletion"]}}

    assert subject.send(:foreground_owner?, owner)
    subject.send(:expedite_sweeps!) if subject.send(:foreground_owner?, owner)

    refute_nil subject.instance_variable_get(:@expedite_until)
  end
end
