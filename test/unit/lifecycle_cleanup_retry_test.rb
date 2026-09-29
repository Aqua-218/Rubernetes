# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A Pod whose release failed sits in CleanupPending owning mounts and ledger
# entries.  Nothing re-synced it once its API object was gone, so the entries
# stayed for the life of the node.  The relist thread now retries the cleanup
# with a backoff until it succeeds.
class LifecycleCleanupRetryTest < Minitest::Test
  Node = Rubernetes::Node

  class Runtime
    def remove_container(*) = true
    def remove_sandbox(*) = true
  end

  class Volume
    attr_reader :calls

    def initialize(failures:)
      @failures = failures
      @calls = 0
    end

    def release(_handle)
      @calls += 1
      raise Rubernetes::Volume::Error, "umount2 reported success but mount 4800 remains mounted" if @calls <= @failures

      true
    end
  end

  def pending_lifecycle(volume)
    lifecycle = Node::Lifecycle.new(runtime: Runtime.new, volume: volume)
    pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "pod-uid"}, "spec" => {"containers" => []}}
    record = lifecycle.send(:new_record, pod)
    record[:state] = "CleanupPending"
    record[:phase] = "Unknown"
    record[:volume] = {"mounts" => {}}
    record[:cleanup_completed] = {}
    record[:cleanup_errors] = ["volume: volume cleanup failed: ambiguous"]
    lifecycle.instance_variable_get(:@records)["pod-uid"] = record
    [lifecycle, record]
  end

  def test_a_pending_cleanup_is_retried_with_backoff_until_it_succeeds
    volume = Volume.new(failures: 1)
    lifecycle, record = pending_lifecycle(volume)

    assert_equal ["pod-uid"], lifecycle.retry_pending_cleanups(now: 0.0)
    assert_equal 1, volume.calls
    assert_equal "CleanupPending", record[:state], "the first retry still fails"

    assert_empty lifecycle.retry_pending_cleanups(now: 1.0), "inside the backoff nothing is retried"

    assert_equal ["pod-uid"], lifecycle.retry_pending_cleanups(now: 6.0)
    assert_equal 2, volume.calls
    assert_equal "Removed", record[:state]
    assert_empty record[:cleanup_errors]
    assert_empty lifecycle.retry_pending_cleanups(now: 100.0)
  end

  def test_records_that_are_not_pending_are_left_alone
    volume = Volume.new(failures: 0)
    lifecycle, record = pending_lifecycle(volume)
    record[:state] = "Running"

    assert_empty lifecycle.retry_pending_cleanups(now: 0.0)
    assert_equal 0, volume.calls
  end
end
