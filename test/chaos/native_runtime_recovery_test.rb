# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"

class NativeRuntimeRecoveryTest < Minitest::Test
  Native = Rubernetes::Runtime::Native

  def test_restart_cleans_dead_resources_in_reverse_dependency_order_and_releases_ledger
    Dir.mktmpdir("native-recovery") do |directory|
      journal = Native::RollbackJournal.new(File.join(directory, "ledger.jsonl"), fsync: false)
      first = Native.new(journal: journal)
      sandbox_id = first.run_sandbox({"request_id" => "restart"})
      operation = first.ledger.operation(sandbox_id)
      first.ledger.transition(operation_id: sandbox_id, to: "RollingBack")
      observed = first.resource_inventory.map { |entry| entry.merge("metadata" => entry.fetch("metadata").merge("live" => false)) }

      restarted = Native.new(journal: Native::RollbackJournal.new(File.join(directory, "ledger.jsonl"), fsync: false))
      cleaned = []
      report = restarted.recover(observer: -> { observed }, cleaner: lambda { |resource|
        cleaned << resource.fetch("kind")
        true
      })

      assert_equal %w[cgroup namespace workspace], cleaned
      assert_equal ["cgroup:#{sandbox_id}", "namespace:#{sandbox_id}", "workspace:#{sandbox_id}"].sort,
                   report.to_h.fetch("released").sort
      assert_empty restarted.ledger.resources
      assert_equal "Stopped", restarted.ledger.operation(operation.id).state
    end
  end

  def test_identity_mismatch_and_live_unknown_are_never_deleted
    runtime = Native.new
    sandbox_id = runtime.run_sandbox({"request_id" => "identity"})
    inventory = runtime.resource_inventory
    mismatch = inventory.fetch(0).merge("identity" => "reused", "metadata" => {"managed_by" => "rubernetes-native", "live" => false})
    live_unknown = {
      "kind" => "namespace", "id" => "unknown", "identity" => "namespace:unknown", "owner" => "sandbox:unknown",
      "metadata" => {"managed_by" => "rubernetes-native", "live" => true}
    }
    dead_unknown = {
      "kind" => "workspace", "id" => "untracked", "identity" => "workspace:untracked", "owner" => "sandbox:unknown",
      "metadata" => {"managed_by" => "rubernetes-native", "live" => false}
    }
    cleaned = []
    report = runtime.recover(observer: -> { [mismatch, live_unknown, dead_unknown] }, cleaner: lambda { |resource|
      cleaned << resource
      true
    })

    assert_equal(["workspace:#{sandbox_id}"], report.to_h.fetch("identity_mismatch").map { |entry| entry.fetch("resource") })
    assert_empty report.to_h.fetch("cleaned_orphans")
    assert_includes report.to_h.fetch("kernel_only"), "workspace:untracked"
    assert_empty cleaned
    assert_equal "WorkloadStopped", runtime.ledger.operation(sandbox_id).state
  end

  def test_cleanup_failure_leaves_cleanup_pending
    Dir.mktmpdir("native-recovery") do |directory|
      path = File.join(directory, "ledger.jsonl")
      journal = Native::RollbackJournal.new(path, fsync: false)
      runtime = Native.new(journal: journal)
      sandbox_id = runtime.run_sandbox({"request_id" => "failure"})
      runtime.ledger.transition(operation_id: sandbox_id, to: "RollingBack")
      observed = runtime.resource_inventory.map { |entry| entry.merge("metadata" => entry.fetch("metadata").merge("live" => false)) }

      report = runtime.recover(observer: -> { observed }, cleaner: lambda { |_resource|
        raise Rubernetes::Runtime::RecoveryRequired, "effect point"
      })

      refute_empty report.to_h.fetch("errors")
      assert_equal "CleanupPending", runtime.ledger.operation(sandbox_id).state
    end
  end
end
