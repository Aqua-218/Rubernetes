# frozen_string_literal: true

require "json"
require "time"
require_relative "../test_helper"
require_relative "../../tools/milestones/m9_gate"

class M9GateTest < Minitest::Test
  def report(kind, cases)
    now = Time.now.utc.iso8601
    {"schema_version" => 1, "milestone" => "M9", "kind" => kind, "available" => true, "status" => "COMPLETE",
     "passed" => true, "cases" => cases, "case_count" => cases.length, "passed_count" => cases.length,
     "failed_count" => 0, "input_sha256" => "0" * 64, "input_file_count" => 1,
     "started_at" => now, "finished_at" => now}
  end

  def test_missing_manifest_fails_closed
    result = M9Gate.evaluate(File.join(Dir.tmpdir, "rubernetes-m9-missing-#{Process.pid}.json"))

    refute result.fetch("passed")
  end

  # A soak shorter than 72 hours is the single most tempting thing to wave
  # through; the gate must refuse it on the number, not on a summary flag.
  def test_short_soak_is_rejected_even_when_it_found_nothing
    errors = []
    cases = [
      {"id" => "benchmark_against_oracle", "passed" => true},
      {"id" => "soak_ran_for_the_required_duration", "passed" => true, "elapsed_hours" => 3.5},
      {"id" => "soak_found_no_defect", "passed" => true,
       "findings" => {"unexpected_process_exits" => 0, "resource_leaks" => 0, "stuck_queues" => 0,
                      "lost_watches" => 0, "lost_commits" => 0}},
      {"id" => "clean_host_reproduction", "passed" => true}
    ]
    M9Gate.send(:validate_operations, report("m9_operations", cases), cases, errors)

    assert errors.any? { |error| error.include?("the criterion is 72 h") }, errors.inspect
  end

  def test_soak_findings_are_reported_individually
    errors = []
    cases = [
      {"id" => "benchmark_against_oracle", "passed" => true},
      {"id" => "soak_ran_for_the_required_duration", "passed" => true, "elapsed_hours" => 72.5},
      {"id" => "soak_found_no_defect", "passed" => false,
       "findings" => {"unexpected_process_exits" => 2, "resource_leaks" => 1, "stuck_queues" => 0,
                      "lost_watches" => 0, "lost_commits" => 3}},
      {"id" => "clean_host_reproduction", "passed" => true}
    ]
    M9Gate.send(:validate_operations, report("m9_operations", cases), cases, errors)

    assert errors.any? { |error| error.include?("2 unexpected_process_exits") }, errors.inspect
    assert errors.any? { |error| error.include?("3 lost_commits") }, errors.inspect
  end

  def test_release_requires_pinned_sbom_identical_rebuild_and_ruby_ratio
    errors = []
    cases = [
      {"id" => "release_manifest_present", "passed" => true},
      {"id" => "release_manifest_binds_source", "passed" => false},
      {"id" => "sbom_present", "passed" => true},
      {"id" => "sbom_pins_every_component", "passed" => false, "unpinned" => %w[mystery-lib]},
      {"id" => "rebuild_is_byte_identical", "passed" => false},
      {"id" => "clean_host_rebuild_attached", "passed" => false},
      {"id" => "ruby_ratio_at_least_85_percent", "passed" => false, "ruby_ratio" => 0.71}
    ]
    M9Gate.send(:validate_release, report("m9_release_artifacts", cases), cases, errors)

    assert errors.any? { |error| error.include?("bind a source input digest") }, errors.inspect
    assert errors.any? { |error| error.include?("SBOM components must all be pinned") }, errors.inspect
    assert errors.any? { |error| error.include?("byte-identical") }, errors.inspect
    assert errors.any? { |error| error.include?("clean-host rebuild") }, errors.inspect
    assert errors.any? { |error| error.include?("below the required 0.85") }, errors.inspect
  end

  def test_lean_escape_hatch_is_rejected
    errors = []
    cases = [
      {"id" => "lean_sources_present", "passed" => true},
      {"id" => "lean_has_no_escape_hatch", "passed" => false,
       "occurrences" => [{"file" => "verification/lean/RaftLog.lean", "line" => 12}]},
      {"id" => "lean_proofs_compile", "passed" => true},
      {"id" => "model_checked_claims_have_a_run", "passed" => true},
      {"id" => "every_claim_states_its_level", "passed" => true}
    ]
    M9Gate.send(:validate_formal, report("m9_formal_verification", cases), cases, errors)

    assert errors.any? { |error| error.include?("no sorry/admit/native_decide") }, errors.inspect
  end

  def test_supply_chain_rejects_critical_findings
    errors = []
    cases = [
      {"id" => "security_report_present", "passed" => true},
      {"id" => "security-dependency_audit", "passed" => false, "detail" => "2 advisories"},
      {"id" => "no_critical_or_high_findings", "passed" => false, "critical_or_high" => 2}
    ]
    M9Gate.send(:validate_supply_chain, report("m9_supply_chain", cases), cases, errors)

    assert errors.any? { |error| error.include?("zero critical or high") }, errors.inspect
    assert errors.any? { |error| error.include?("security-dependency_audit did not pass") }, errors.inspect
  end

  def test_clean_release_bundle_produces_no_errors
    errors = []
    cases = [
      {"id" => "benchmark_against_oracle", "passed" => true},
      {"id" => "soak_ran_for_the_required_duration", "passed" => true, "elapsed_hours" => 72.1},
      {"id" => "soak_found_no_defect", "passed" => true,
       "findings" => {"unexpected_process_exits" => 0, "resource_leaks" => 0, "stuck_queues" => 0,
                      "lost_watches" => 0, "lost_commits" => 0}},
      {"id" => "clean_host_reproduction", "passed" => true}
    ]
    M9Gate.send(:validate_operations, report("m9_operations", cases), cases, errors)

    assert_empty errors, errors.inspect
  end
end
