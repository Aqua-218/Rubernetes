# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/runtime"
require "tmpdir"

class RuntimeCommonTest < Minitest::Test
  def test_validation_rejects_without_touching_the_backend
    calls = []
    adapter = Object.new
    adapter.define_singleton_method(:allocate_workspace) { |*| calls << :workspace }
    runtime = Rubernetes::Runtime::Runtime.new(data_dir: Dir.mktmpdir("runtime-unit"), adapter: adapter)

    assert_raises(Rubernetes::Runtime::ValidationError) do
      runtime.run_sandbox({"image_digest" => "sha256:not-a-digest"}, request_id: "invalid")
    end
    assert_empty calls
  end

  def test_workload_gate_is_closed_until_explicit_start
    adapter = GateAdapter.new
    runtime = Rubernetes::Runtime::Runtime.new(data_dir: Dir.mktmpdir("runtime-unit"), adapter: adapter)
    sandbox = runtime.run_sandbox({}, request_id: "sandbox")
    container = runtime.create_container(sandbox, {}, request_id: "container")

    assert_equal [], adapter.workload_calls
    assert_raises(Rubernetes::Runtime::InvalidTransition) { runtime.exec(container, ["true"], tty: false) }
    runtime.start_container(container, request_id: "start")

    assert_equal [%i[start closed], [:open, container]], adapter.workload_calls
  end

  def test_request_id_replay_does_not_repeat_effects
    adapter = GateAdapter.new
    directory = Dir.mktmpdir("runtime-unit")
    first = Rubernetes::Runtime::Runtime.new(data_dir: directory, adapter: adapter)
    sandbox = first.run_sandbox({}, request_id: "same-request")
    second = Rubernetes::Runtime::Runtime.new(data_dir: directory, adapter: adapter)

    assert_equal sandbox, second.run_sandbox({}, request_id: "same-request")
    assert_equal 1, adapter.calls.fetch(:workspace)
    assert_equal 1, adapter.calls.fetch(:isolation)
  end

  def test_wal_and_snapshot_are_durable_and_checksum_checked
    directory = Dir.mktmpdir("runtime-unit")
    wal_path = File.join(directory, "runtime.wal")
    wal = Rubernetes::Runtime::DurableWAL.new(wal_path)
    wal.append(operation_id: "op", event: "state_transition", payload: {"to" => "Validated"})
    reopened = Rubernetes::Runtime::DurableWAL.new(wal_path)

    assert_equal "state_transition", reopened.records.fetch(0).to_h.fetch("event")
    reopened.append(operation_id: "op", event: "state_transition", payload: {"to" => "ImagePinned"})

    assert_equal [1, 2], reopened.records.map(&:sequence)

    snapshots = Rubernetes::Runtime::AtomicSnapshotStore.new(File.join(directory, "snapshots"))
    snapshots.write(snapshot_id: "base", state: "WorkloadStopped", identity: "base-id", payload: {"digest" => "sha256:x"})

    assert_equal "base-id", snapshots.read("base").fetch("identity")
  end

  def test_rollback_preserves_primary_and_all_cleanup_errors
    adapter = GateAdapter.new(failing_cleanup: true)
    runtime = Rubernetes::Runtime::Runtime.new(data_dir: Dir.mktmpdir("runtime-unit"), adapter: adapter)
    error = assert_raises(Rubernetes::Runtime::OperationFailure) do
      runtime.run_sandbox({"fail_effect" => true}, request_id: "rollback")
    end

    assert_match(/injected effect failure/, error.cause_error.message)
    refute_empty error.cleanup_errors
    operation = runtime.ledger.operation_for_request("rollback")

    assert_equal "CleanupPending", operation.state
    assert_equal error.cause_error.message, operation.error.fetch("message")
  end

  def test_state_unknown_allows_observe_but_forbids_start
    adapter = GateAdapter.new(ambiguous_start: true)
    runtime = Rubernetes::Runtime::Runtime.new(data_dir: Dir.mktmpdir("runtime-unit"), adapter: adapter)
    sandbox = runtime.run_sandbox({}, request_id: "unknown-sandbox")
    container = runtime.create_container(sandbox, {}, request_id: "unknown-container")

    assert_raises(Rubernetes::Runtime::OperationFailure) { runtime.start_container(container, request_id: "unknown-start") }
    assert_equal "StateUnknown", runtime.ledger.operation_for_request("unknown-container").state
    assert_equal "StateUnknown", runtime.container_status(container).fetch("state")
    assert_raises(Rubernetes::Runtime::StateUnknownError) { runtime.start_container(container, request_id: "unknown-start-2") }
  end

  class GateAdapter
    attr_reader :workload_calls, :calls

    def initialize(failing_cleanup: false, ambiguous_start: false)
      @workload_calls = []
      @calls = Hash.new(0)
      @failing_cleanup = failing_cleanup
      @ambiguous_start = ambiguous_start
    end

    def allocate_workspace(config: {}, **)
      @calls[:workspace] += 1
    end

    def create_isolation(config: {}, **)
      raise "injected effect failure" if config["fail_effect"]

      @calls[:isolation] += 1
    end

    def attach_resources(**)
      @calls[:attached] += 1
    end

    def hold_workload(**)
      @calls[:stopped] += 1
    end

    def create_container(**)
      @calls[:container] += 1
    end

    def start_container(id:, gate:)
      raise Rubernetes::Runtime::AmbiguousResult, "start response lost" if @ambiguous_start

      @workload_calls << [:start, gate]
    end

    def release_workload_gate(id:, sandbox_id:)
      @workload_calls << [:open, id]
    end

    def cleanup_resource(resource)
      raise "cleanup failed for #{resource.kind}" if @failing_cleanup
    end
  end
end
