# frozen_string_literal: true

require_relative "../test_helper"
require "digest"
require "fileutils"
require "json"
require "tmpdir"
require_relative "../../tools/verification/m2_formal_verify"
require_relative "../../tools/verification/m2_runtime_trace_verifier"

# Fixed-seed implementation-trace properties for the M2 lifecycle invariants.
# These tests intentionally use the dependency-free verifier so they run on a
# host without TLC, Lean, or any external proof profile.
class M2RuntimeTracePropertyTest < Minitest::Test
  Verifier = Rubernetes::Verification::M2RuntimeTraceVerifier
  FormalVerifier = Rubernetes::Verification::M2FormalVerifier
  PROPERTY_SEEDS = [0x2A, 0x5EED, 0xC0FFEE].freeze

  def test_seeded_complete_lifecycle_traces_preserve_all_runtime_invariants
    PROPERTY_SEEDS.each do |seed|
      trace = complete_trace(seed)
      report = Verifier.new(trace, source: "seed-#{seed}").verify

      assert_equal true, report.fetch("success"), report
      assert_equal trace.fetch("events").length, report.fetch("event_count")
      assert_operator report.fetch("transition_count"), :>=, 10
      assert_empty report.fetch("violations")
    end
  end

  def test_sequential_operations_reset_the_state_machine_at_operation_boundaries
    first = complete_trace(0x11)
    second = complete_trace(0x22)
    events = first.fetch("events").map { |event| event.merge("operation_id" => "op-1") }
    events.concat(second.fetch("events").map { |event| event.merge("operation_id" => "op-2") })

    report = Verifier.new({"schema" => Verifier::TRACE_SCHEMA, "events" => events}).verify

    assert_equal true, report.fetch("success"), report
    assert_equal 2, report.fetch("event_count") / first.fetch("events").length
    assert_empty report.fetch("violations")
  end

  def test_digest_mismatch_is_fail_closed_even_when_an_event_claims_work
    trace = base_trace
    trace.fetch("events") << snapshot_event(
      "digest_mismatch",
      state: "Validated",
      digest_mismatch: true,
      no_workload_effect: false,
      workload_effect: true
    )

    report = Verifier.new(trace).verify

    assert_equal false, report.fetch("success")
    assert_includes report.fetch("violations").map { |item| item.fetch("code") },
                    "digest_mismatch_workload_effect"
    assert_includes report.fetch("violations").map { |item| item.fetch("code") },
                    "digest_mismatch_event_effect"
  end

  def test_workload_stopped_to_running_rejects_digest_mismatch_and_missing_effect
    trace = base_trace
    trace.fetch("events") << transition_event(
      "New", "Validated"
    )
    trace.fetch("events") << transition_event(
      "Validated", "ImagePinned"
    )
    trace.fetch("events") << transition_event(
      "ImagePinned", "WorkspaceAllocated", owned_resources: ["temp"], live_owner: ["temp"]
    )
    trace.fetch("events") << transition_event(
      "WorkspaceAllocated", "IsolationCreated", owned_resources: %w[temp mount ns],
                                                live_owner: %w[temp mount ns]
    )
    trace.fetch("events") << transition_event(
      "IsolationCreated", "ResourcesAttached",
      owned_resources: %w[temp mount ns cgroup pidfd],
      live_owner: %w[temp mount ns cgroup pidfd]
    )
    trace.fetch("events") << transition_event(
      "ResourcesAttached", "WorkloadStopped",
      owned_resources: %w[temp mount ns cgroup pidfd],
      live_owner: %w[temp mount ns cgroup pidfd],
      sandbox_ready: true
    )
    trace.fetch("events") << transition_event(
      "WorkloadStopped", "Running",
      owned_resources: %w[temp mount ns cgroup pidfd],
      live_owner: %w[temp mount ns cgroup pidfd],
      sandbox_ready: true, digest_mismatch: true, no_workload_effect: true, live_process: false
    )

    report = Verifier.new(trace).verify

    assert_equal false, report.fetch("success")
    codes = report.fetch("violations").map { |item| item.fetch("code") }

    assert_includes codes, "running_after_digest_mismatch"
    assert_includes codes, "running_without_workload_effect"
    assert_includes codes, "running_without_live_process"
  end

  def test_resource_identity_reuse_and_non_reverse_cleanup_are_rejected
    trace = {
      "schema" => Verifier::TRACE_SCHEMA,
      "events" => [
        snapshot_event("operation_started", state: "New"),
        transition_event("New", "Validated"),
        transition_event("Validated", "ImagePinned"),
        transition_event("ImagePinned", "WorkspaceAllocated", live_owner: ["temp"], owned_resources: ["temp"]),
        transition_event("WorkspaceAllocated", "IsolationCreated", live_owner: %w[temp mount], owned_resources: %w[temp mount]),
        transition_event("IsolationCreated", "ResourcesAttached", live_owner: %w[temp mount ns],
                                                                  owned_resources: %w[temp mount ns]),
        transition_event("ResourcesAttached", "WorkloadStopped", live_owner: %w[temp mount ns],
                                                                 owned_resources: %w[temp mount ns], sandbox_ready: true),
        transition_event("WorkloadStopped", "RollingBack", live_owner: %w[temp mount ns], owned_resources: %w[temp mount ns],
                                                           next_action: "CleanupOrObserve"),
        snapshot_event("resource_released", state: "RollingBack", live_owner: %w[temp mount],
                                            released: ["ns"], owned_resources: %w[temp mount], live_process: false),
        snapshot_event("resource_released", state: "RollingBack", live_owner: ["mount"],
                                            released: %w[ns temp], owned_resources: ["mount"], live_process: false),
        snapshot_event("resource_released", state: "RollingBack", live_owner: %w[temp ns],
                                            released: %w[ns mount], owned_resources: %w[temp ns], live_process: false)
      ]
    }

    report = Verifier.new(trace).verify

    assert_equal false, report.fetch("success")
    codes = report.fetch("violations").map { |item| item.fetch("code") }

    assert_includes codes, "cleanup_order_violation"
    assert_includes codes, "resource_identity_reused"
  end

  def test_unknown_trace_reconciles_before_stop_and_remove
    owner = ["temp"]
    owned = ["temp"]
    trace = {
      "schema" => Verifier::TRACE_SCHEMA,
      "events" => [
        snapshot_event("operation_started", state: "New"),
        transition_event("New", "Validated"),
        transition_event("Validated", "ImagePinned"),
        transition_event("ImagePinned", "WorkspaceAllocated", live_owner: owner, owned_resources: owned),
        transition_event(
          "WorkspaceAllocated", "StateUnknown", live_owner: owner, owned_resources: owned,
                                                next_action: "CleanupOrObserve"
        ),
        snapshot_event(
          "observation", state: "StateUnknown", live_owner: owner, owned_resources: owned,
                         next_action: "CleanupOrObserve"
        ),
        transition_event(
          "StateUnknown", "Stopping", live_owner: owner, owned_resources: owned,
                                      next_action: "CleanupOrObserve"
        ),
        transition_event("Stopping", "Stopped", live_owner: owner, owned_resources: owned),
        snapshot_event(
          "resource_released", state: "Stopped", released: owner, owned_resources: [],
                               live_process: false
        ),
        transition_event("Stopped", "Removed", released: owner, owned_resources: [])
      ]
    }

    report = Verifier.new(trace).verify

    assert_equal true, report.fetch("success"), report
    assert_empty report.fetch("violations")
  end

  def test_unknown_stop_requires_observation_and_a_dead_process
    trace = base_trace
    trace.fetch("events") << transition_event("New", "Validated")
    trace.fetch("events") << transition_event("Validated", "StateUnknown", next_action: "CleanupOrObserve")
    trace.fetch("events") << transition_event(
      "StateUnknown", "Stopping", next_action: "CleanupOrObserve", live_process: false
    )
    report = Verifier.new(trace).verify

    assert_equal false, report.fetch("success")
    assert_includes report.fetch("violations").map { |item| item.fetch("code") },
                    "unknown_stopping_without_observation"

    observed_live = base_trace
    observed_live.fetch("events") << transition_event("New", "Validated")
    observed_live.fetch("events") << transition_event("Validated", "StateUnknown", next_action: "CleanupOrObserve")
    observed_live.fetch("events") << snapshot_event(
      "observation", state: "StateUnknown", next_action: "CleanupOrObserve", live_process: true
    )
    observed_live.fetch("events") << transition_event(
      "StateUnknown", "Stopping", next_action: "CleanupOrObserve", live_process: false
    )
    live_report = Verifier.new(observed_live).verify

    assert_equal false, live_report.fetch("success")
    assert_includes live_report.fetch("violations").map { |item| item.fetch("code") },
                    "unknown_observation_with_live_process"
  end

  def test_running_stop_and_failure_rollback_require_action_results
    stopping = base_trace
    stopping.fetch("events") << transition_event("New", "Validated")
    stopping.fetch("events") << transition_event(
      "Validated", "Running", sandbox_ready: true, no_workload_effect: false,
                              live_process: true, owned_resources: Verifier::RESOURCE_KINDS,
                              live_owner: Verifier::RESOURCE_KINDS
    )
    stopping.fetch("events") << transition_event("Running", "Stopping", live_process: false, result: true)
    stopping_report = Verifier.new(stopping).verify

    assert_equal false, stopping_report.fetch("success")
    assert_includes stopping_report.fetch("violations").map { |item| item.fetch("code") }, "stopping_result_true"

    rollback = base_trace
    rollback.fetch("events") << transition_event("New", "Validated")
    rollback.fetch("events") << transition_event(
      "Validated", "ImagePinned"
    )
    rollback.fetch("events") << transition_event(
      "ImagePinned", "WorkspaceAllocated", live_owner: ["temp"], owned_resources: ["temp"]
    )
    rollback.fetch("events") << transition_event(
      "WorkspaceAllocated", "RollingBack", next_action: "NoAction", live_process: true,
                                           no_workload_effect: false, live_owner: ["temp"], owned_resources: ["temp"]
    )
    rollback_report = Verifier.new(rollback).verify

    assert_equal false, rollback_report.fetch("success")
    codes = rollback_report.fetch("violations").map { |item| item.fetch("code") }

    assert_includes codes, "rollback_missing_action"
    assert_includes codes, "rollback_with_workload_effect"
    assert_includes codes, "rollback_with_live_process"
  end

  def test_rollback_retry_trace_cleans_in_reverse_without_releasing_a_live_owner
    trace = {
      "schema" => Verifier::TRACE_SCHEMA,
      "events" => [
        snapshot_event("operation_started", state: "New"),
        transition_event("New", "Validated"),
        transition_event("Validated", "ImagePinned"),
        transition_event("ImagePinned", "WorkspaceAllocated", live_owner: ["temp"], owned_resources: ["temp"]),
        transition_event(
          "WorkspaceAllocated", "RollingBack", live_owner: ["temp"], owned_resources: ["temp"],
                                               next_action: "CleanupOrObserve"
        ),
        transition_event(
          "RollingBack", "CleanupPending", live_owner: ["temp"], owned_resources: ["temp"],
                                           next_action: "CleanupOrObserve"
        ),
        transition_event(
          "CleanupPending", "RollingBack", live_owner: ["temp"], owned_resources: ["temp"],
                                           next_action: "CleanupOrObserve"
        ),
        snapshot_event(
          "resource_released", state: "RollingBack", released: ["temp"], owned_resources: [],
                               live_owner: [], next_action: "CleanupOrObserve"
        ),
        transition_event(
          "RollingBack", "Stopped", released: ["temp"], owned_resources: [],
                                    live_owner: [], live_process: false
        ),
        transition_event("Stopped", "Removed", released: ["temp"], owned_resources: [], live_owner: [])
      ]
    }

    report = Verifier.new(trace).verify

    assert_equal true, report.fetch("success"), report
    assert_empty report.fetch("violations")
  end

  def test_each_state_safety_invariant_rejects_its_minimal_counterexample
    cases = {
      "live_owner_released" => snapshot_event(
        "observation", state: "Validated", live_owner: ["temp"], released: ["temp"]
      ),
      "running_without_sandbox_ready" => snapshot_event(
        "observation", state: "Running", sandbox_ready: false
      ),
      "unknown_action" => snapshot_event(
        "observation", state: "StateUnknown", next_action: "Start"
      ),
      "stopped_with_live_process" => snapshot_event(
        "observation", state: "Stopped", live_process: true
      ),
      "removed_with_resources" => snapshot_event(
        "observation", state: "Removed", owned_resources: ["temp"]
      )
    }

    cases.each do |code, event|
      report = Verifier.new(base_trace.merge("events" => [base_trace.fetch("events").first, event])).verify

      assert_equal false, report.fetch("success"), "counterexample=#{code}"
      assert_includes report.fetch("violations").map { |item| item.fetch("code") }, code,
                      "counterexample=#{code}: #{report.inspect}"
    end
  end

  def test_invalid_state_edges_and_missing_observations_fail_closed
    invalid_transition = base_trace.merge(
      "events" => [
        base_trace.fetch("events").first,
        snapshot_event("state_transition", from: "New", to: "Running", state: "Running")
      ]
    )
    report = Verifier.new(invalid_transition).verify

    assert_equal false, report.fetch("success")
    assert_includes report.fetch("violations").map { |item| item.fetch("code") }, "invalid_transition"

    missing = {"schema" => Verifier::TRACE_SCHEMA, "events" => [{"event" => "state_transition", "from" => "New", "to" => "Validated"}]}
    missing_report = Verifier.new(missing).verify

    assert_equal false, missing_report.fetch("success")
    assert_includes missing_report.fetch("violations").map { |item| item.fetch("code") }, "missing_live_owner"
  end

  def test_json_lines_and_external_profile_absence_do_not_become_false_success
    directory = Dir.mktmpdir("m2-runtime-trace-")
    trace_path = File.join(directory, "trace.jsonl")
    File.write(trace_path, complete_trace(0x1234).fetch("events").map { |event| JSON.generate(event) }.join("\n") << "\n")

    report = Verifier.verify_file(trace_path)

    assert_equal true, report.fetch("success")

    formal = FormalVerifier.new(trace_path: trace_path, proof_profile: File.join(directory, "missing.profile"), ruby_only: true).verify

    assert_equal false, formal.fetch("success")
    assert_equal "missing", formal.dig("external_proof_profile", "status")
    assert_equal true, formal.dig("tla", "isolated_workdir") if formal.dig("tla", "available")
    assert_equal true, formal.dig("lean", "isolated_workdir") if formal.dig("lean", "available")
  ensure
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end

  def test_external_proof_profile_requires_content_schema_digests_and_non_empty_tool_output
    directory = Dir.mktmpdir("m2-external-profile-")
    trace_path = File.join(directory, "trace.jsonl")
    File.write(trace_path, complete_trace(0xBEEF).fetch("events").map { |event| JSON.generate(event) }.join("\n") << "\n")

    # A profile that only repeats claimed output/hash values is not evidence;
    # all three pinned tools must be executed by the verifier.
    tool_output = "apalache: verified\n"
    tool = {
      "name" => "apalache",
      "command" => ["apalache-mc", "check", "--inv", "AllInvariants"],
      "exit_status" => 0,
      "output" => tool_output,
      "output_sha256" => Digest::SHA256.hexdigest(tool_output),
      "status" => "PASS"
    }
    profile = {
      "schema_version" => 1,
      "kind" => "m2_external_proof_profile",
      "claim" => "RuntimeLifecycle",
      "source_files" => expected_formal_source_files,
      "source_sha256" => M2Gate.canonical_document_digest(expected_formal_source_files),
      "tools" => [tool]
    }
    profile["tool_output_sha256"] =
      M2Gate.canonical_document_digest([{"name" => tool["name"], "exit_status" => 0, "output_sha256" => tool["output_sha256"]}])
    profile["profile_sha256"] = M2Gate.canonical_document_digest(profile, excluded_keys: ["profile_sha256"])
    valid_path = File.join(directory, "valid.profile.json")
    File.write(valid_path, JSON.generate(profile) << "\n")
    valid_report = FormalVerifier.new(trace_path: trace_path, proof_profile: valid_path, ruby_only: true).verify

    assert_equal false, valid_report.fetch("external_proof_profile").fetch("success")
    assert_equal "invalid_schema", valid_report.fetch("external_proof_profile").fetch("status")
    assert_includes valid_report.fetch("external_proof_profile").fetch("message"), "tools must contain exactly"
  ensure
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end

  private

  def base_trace
    {"schema" => Verifier::TRACE_SCHEMA, "events" => [snapshot_event("operation_started", state: "New")]}
  end

  def expected_formal_source_files
    [
      ["tla_source", FormalVerifier::TLA_SOURCE],
      ["tla_config", FormalVerifier::TLA_CONFIG],
      ["lean_source", FormalVerifier::LEAN_SOURCE],
      ["ruby_trace_verifier", FormalVerifier::RUBY_TRACE_SOURCE],
      ["ruby_formal_verifier", FormalVerifier::RUBY_FORMAL_SOURCE]
    ].map do |label, path|
      {
        "label" => label,
        "path" => path.delete_prefix("#{FormalVerifier::ROOT}/"),
        "sha256" => Digest::SHA256.file(path).hexdigest
      }
    end
  end

  def snapshot_event(event, state:, live_owner: [], released: [], owned_resources: [],
                     sandbox_ready: false, digest_mismatch: false, no_workload_effect: true,
                     next_action: "NoAction", live_process: false, result: false, **extra)
    {
      "event" => event,
      "state" => state,
      "live_owner" => live_owner,
      "released" => released,
      "owned_resources" => owned_resources,
      "sandbox_ready" => sandbox_ready,
      "digest_mismatch" => digest_mismatch,
      "no_workload_effect" => no_workload_effect,
      "next_action" => next_action,
      "live_process" => live_process,
      "result" => result
    }.merge(extra)
  end

  def transition_event(from, to, **fields)
    snapshot_event("state_transition", state: to, **fields).merge("from" => from, "to" => to)
  end

  def complete_trace(seed)
    random = Random.new(seed)
    owner = []
    released = []
    owned = []
    events = [snapshot_event("operation_started", state: "New")]

    events << transition_event("New", "Validated")
    events << transition_event("Validated", "ImagePinned")

    owner << "temp"
    owned << "temp"
    events << transition_event("ImagePinned", "WorkspaceAllocated", live_owner: owner.dup, owned_resources: owned.dup)

    owner.push("mount", "ns")
    owned.push("mount", "ns")
    events << transition_event("WorkspaceAllocated", "IsolationCreated", live_owner: owner.dup, owned_resources: owned.dup)

    owner.push("cgroup", "pidfd")
    owned.push("cgroup", "pidfd")
    events << transition_event("IsolationCreated", "ResourcesAttached", live_owner: owner.dup, owned_resources: owned.dup)
    events << transition_event(
      "ResourcesAttached", "WorkloadStopped", live_owner: owner.dup,
                                              owned_resources: owned.dup, sandbox_ready: true
    )

    owner << "process"
    owned << "process"
    events << transition_event(
      "WorkloadStopped", "Running", live_owner: owner.dup, owned_resources: owned.dup,
                                    sandbox_ready: true, no_workload_effect: false, live_process: true
    )
    events << transition_event(
      "Running", "Stopping", live_owner: owner.dup, owned_resources: owned.dup,
                             sandbox_ready: true, live_process: false
    )
    events << transition_event(
      "Stopping", "Stopped", live_owner: owner.dup, owned_resources: owned.dup,
                             sandbox_ready: true, live_process: false
    )

    # Cleanup observations are deliberately shuffled by a deterministic seed
    # only in their metadata; the resource release order remains reverse claim
    # order as required by the lifecycle specification.
    %w[process pidfd cgroup ns mount temp].each_with_index do |resource, index|
      owner.delete(resource)
      owned.delete(resource)
      released << resource
      events << snapshot_event(
        "resource_released", state: "Stopped", live_owner: owner.dup,
                             released: released.dup, owned_resources: owned.dup,
                             sandbox_ready: true, live_process: false, cleanup_attempt: random.rand(10_000) + index
      )
    end
    events << transition_event(
      "Stopped", "Removed", live_owner: owner.dup, released: released.dup,
                            owned_resources: owned.dup, sandbox_ready: true, live_process: false
    )

    {"schema" => Verifier::TRACE_SCHEMA, "seed" => seed, "events" => events}
  end
end
