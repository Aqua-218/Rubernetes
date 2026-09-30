# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/runtime"
require "tmpdir"

class RuntimeResourceLedgerPropertyTest < Minitest::Test
  # M2 exit criterion: 1,000 create/start/stop/delete cycles leave no active
  # ownership.  The fake adapter has no kernel side effects; the property
  # targets the durable ownership and reverse cleanup contract at L0/L1.
  def test_one_thousand_fake_resource_cycles_leave_no_live_owned_resource
    directory = Dir.mktmpdir("runtime-property")
    # The unit/chaos suites exercise the façade, fsync failures, and replay.
    # This property drives the ledger directly so all 1,000 cycles remain a
    # focused ownership/state exploration while still writing every event.
    wal = Rubernetes::Runtime::DurableWAL.new(File.join(directory, "ledger.wal"), fsync: false)
    ledger = Rubernetes::Runtime::ResourceLedger.new(wal: wal)

    1_000.times do |index|
      operation = ledger.begin_operation(request_id: "cycle-#{index}", operation_id: "cycle-#{index}",
                                         action: "cycle", target_id: "sandbox-#{index}", owner: "owner-#{index}",
                                         config_digest: Rubernetes::Runtime::Canonical.digest(index: index))
      ledger.transition(operation_id: operation.id, to: "Validated")
      ledger.transition(operation_id: operation.id, to: "ImagePinned")
      ledger.transition(operation_id: operation.id, to: "WorkspaceAllocated")
      ledger.claim(operation_id: operation.id, kind: "workspace", id: "workspace-#{index}",
                   identity: "workspace:#{index}")
      ledger.transition(operation_id: operation.id, to: "IsolationCreated")
      ledger.claim(operation_id: operation.id, kind: "namespace", id: "namespace-#{index}",
                   identity: "namespace:#{index}")
      ledger.transition(operation_id: operation.id, to: "ResourcesAttached")
      ledger.claim(operation_id: operation.id, kind: "process", id: "process-#{index}",
                   identity: "pidfd:#{index}")
      ledger.transition(operation_id: operation.id, to: "WorkloadStopped")
      ledger.transition(operation_id: operation.id, to: "Running")
      ledger.transition(operation_id: operation.id, to: "Stopping")
      ledger.transition(operation_id: operation.id, to: "Stopped")
      ledger.resources(operation_id: operation.id).sort_by(&:sequence).reverse_each do |resource|
        ledger.release(operation_id: operation.id, kind: resource.kind, id: resource.id, identity: resource.identity)
      end
      ledger.transition(operation_id: operation.id, to: "Removed")

      assert_empty ledger.resources(owner: "owner-#{index}")
    end

    assert_empty ledger.resources
  end
end
