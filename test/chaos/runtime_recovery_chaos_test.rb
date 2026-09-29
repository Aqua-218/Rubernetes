# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/runtime"
require "tmpdir"

class RuntimeRecoveryChaosTest < Minitest::Test
  def test_startup_reconciliation_distinguishes_orphan_and_identity_reuse
    directory = Dir.mktmpdir("runtime-chaos")
    runtime = Rubernetes::Runtime::Runtime.new(data_dir: directory)
    sandbox = runtime.run_sandbox({}, request_id: "recover-sandbox")
    resources = runtime.ledger.resources
    first = resources.first
    observer = lambda do
      [
        {"kind" => first.kind, "id" => first.id, "identity" => "reused", "owner" => first.owner},
        {"kind" => "namespace", "id" => "orphan", "identity" => "namespace:orphan", "owner" => "runtime-orphan"}
      ]
    end
    cleaned = []
    report = Rubernetes::Runtime::StartupReconciler.new(
      ledger: runtime.ledger,
      observer: observer,
      cleaner: ->(resource) { cleaned << resource }
    ).reconcile

    assert_equal ["namespace:orphan"], report.to_h.fetch("orphans").map { |resource| "#{resource.fetch("kind")}:#{resource.fetch("id")}" }
    assert_equal ["#{first.kind}:#{first.id}"], report.to_h.fetch("identity_mismatch").map { |entry| entry.fetch("resource") }
    assert_equal ["namespace:orphan"], cleaned.map { |resource| "#{resource.fetch("kind")}:#{resource.fetch("id")}" }
    refute_includes report.to_h.fetch("released"), "#{first.kind}:#{first.id}"
    assert_equal sandbox, runtime.ledger.operation_for_request("recover-sandbox").result.fetch("sandbox_id")
  end

  def test_state_unknown_is_not_reused_during_recovery
    adapter = Object.new
    adapter.define_singleton_method(:hold_workload) { raise Rubernetes::Runtime::AmbiguousResult, "lost" }
    directory = Dir.mktmpdir("runtime-chaos")
    runtime = Rubernetes::Runtime::Runtime.new(data_dir: directory, adapter: adapter)

    assert_raises(Rubernetes::Runtime::OperationFailure) { runtime.run_sandbox({}, request_id: "ambiguous") }
    assert_equal "StateUnknown", runtime.ledger.operation_for_request("ambiguous").state
    assert_raises(Rubernetes::Runtime::StateUnknownError) do
      runtime.run_sandbox({}, request_id: "ambiguous")
    end
  end
end
