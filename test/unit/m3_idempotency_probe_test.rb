# frozen_string_literal: true

# M3 controller contract: spec/control-plane/controllers.md §5.5.1 (C1).
# This integration test covers the production idempotency evidence adapter,
# including watched-object fixtures and deterministic logical-clock handling.
# It intentionally executes the probe as a subprocess because the evidence
# runner exits with its fail-closed status after emitting the JSON report.

require_relative "../test_helper"
require "json"
require "open3"
require "rbconfig"
require_relative "../../tools/milestones/m3_gate"

class M3IdempotencyProbeTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__).freeze
  PROBE = File.join(ROOT, "tools/milestones/m3_idempotency_probe.rb").freeze

  # Requirement: every pinned v1.36.2 built-in controller must converge to
  # the same final state on a replay, with no second-run API mutation.
  # Mutation target: removing a watched-object fixture or the fixed clock must
  # fail this exact assertion through the probe's non-zero exit status or
  # failure counts.
  def test_all_builtin_controller_reconciles_are_idempotent
    stdout, stderr, process = Open3.capture3(RbConfig.ruby, "-Ilib", PROBE, chdir: ROOT)
    report = JSON.parse(stdout, create_additions: false)

    assert process.success?, "idempotency probe failed: #{stderr}\n#{report.fetch("errors", []).join("; ")}"
    assert_equal "PASS", report.fetch("status")
    assert_equal true, report.fetch("passed")
    assert_equal 52, report.fetch("cases").length
    assert_equal 0, report.fetch("failure_count")
    assert_equal 0, report.fetch("difference_count")
    assert_equal 0, report.fetch("non_idempotent_count")
    assert report.fetch("cases").all? { |entry| entry.fetch("passed") == true }
    assert(
      report.fetch("cases").all? do |entry|
        first = entry.fetch("first_effect_observable")
        second = entry.fetch("second_effect_observable")
        first_step = first.fetch("step")
        second_step = second.fetch("step")
        first.fetch("store") == second.fetch("store") &&
          first_step.fetch("leader_execution") == true && first_step.fetch("reconciled") == 1 &&
          first_step.fetch("reconcile_success") == true && first_step.fetch("pending_retry") == false &&
          second_step.fetch("leader_execution") == true && second_step.fetch("reconciled") == 1 &&
          second_step.fetch("reconcile_success") == true && second_step.fetch("pending_retry") == false &&
          first.fetch("provider_effect_applicability").fetch("applicable") == false &&
          second.fetch("provider_effect_applicability") == first.fetch("provider_effect_applicability") &&
          second.fetch("events").empty? && second.fetch("provider_calls").empty? &&
          entry.fetch("first_run_raw_snapshot").fetch("raw_entries").length == entry.fetch("first_run_raw_snapshot").fetch("raw_entry_count") &&
          entry.fetch("second_run_raw_snapshot").fetch("raw_entries").length == entry.fetch("second_run_raw_snapshot").fetch("raw_entry_count") &&
          entry.fetch("second_run_raw_snapshot").fetch("api_mutation_count") == 0 &&
          entry.fetch("second_run_raw_snapshot").fetch("event_count") == 0 &&
          entry.fetch("second_run_raw_snapshot").fetch("provider_call_count") == 0
      end
    )
  end

  # Requirement: duplicate controller events must remain visible in raw
  # evidence and fail the independent gate recomputation.  Mutation target:
  # restoring Array#uniq or trusting the supplied inventory would make this
  # injected duplicate pass.
  def test_gate_rejects_an_injected_duplicate_controller_event
    event = controller_event
    first = observable_for("first", [event, Marshal.load(Marshal.dump(event))])
    second = observable_for("second", [])

    errors = []
    M3Gate.send(:validate_idempotency_effect_inventory, first, second, errors, 0)

    assert errors.any? { |error| error.include?("duplicate controller event") }
  end

  # Requirement: provider calls are first-class durable effects and duplicate
  # calls cannot be hidden by set-like projection.  Mutation target: removing
  # provider signature counts would make this injected replay pass.
  def test_gate_rejects_injected_duplicate_provider_call
    provider = {
      "schema_version" => 1, "kind" => "provider_event", "component" => "controller-manager",
      "identity" => "m3-test", "generation" => "m3-test", "effect_key" => "controller-manager|m3|provider:record",
      "reconcile_key" => "default/m3", "provider" => "M3TestProvider", "operation" => "record",
      "observed_at" => "2026-01-01T00:00:00.000000Z"
    }
    first = observable_for("first", [provider, Marshal.load(Marshal.dump(provider))])
    second = observable_for("second", [])

    errors = []
    M3Gate.send(:validate_idempotency_effect_inventory, first, second, errors, 0)

    assert errors.any? { |error| error.include?("duplicate provider call") }
  end

  private

  def controller_event
    {
      "schema_version" => 1, "kind" => "controller_event", "component" => "controller-manager",
      "identity" => "m3-test", "generation" => "m3-test", "effect_key" => "controller-manager|default/m3|reconcile",
      "reconcile_key" => "default/m3", "event_sha256" => "a" * 64,
      "observed_at" => "2026-01-01T00:00:00.000000Z"
    }
  end

  def observable_for(run, raw_entries)
    snapshot = {"raw_entries" => raw_entries}
    refresh_snapshot(snapshot)
    inventory = snapshot.fetch("inventory")
    {"store" => [], "api_mutations" => inventory.fetch("api_mutations"),
     "events" => inventory.fetch("events"), "provider_calls" => inventory.fetch("provider_calls"),
     "durable_journal" => {"run" => run, "before" => {}, "after" => inventory, "raw_snapshot" => snapshot}}
  end

  def refresh_snapshot(snapshot)
    raw_entries = snapshot.fetch("raw_entries")
    inventory = M3Gate.send(:recompute_idempotency_inventory, raw_entries)
    snapshot["raw_entry_count"] = raw_entries.length
    snapshot["raw_sha256"] = M3Gate.canonical_document_digest(raw_entries)
    %w[effect_ids effect_id_counts effect_signature_counts api_effect_key_counts api_mutation_count event_count provider_call_count
        event_effect_key_counts provider_effect_key_counts event_signatures event_signature_counts
        provider_call_signatures provider_call_signature_counts].each do |key|
      snapshot[key] = inventory.fetch(key)
    end
    snapshot["inventory"] = inventory
  end

end
