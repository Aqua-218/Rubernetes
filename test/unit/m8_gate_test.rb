# frozen_string_literal: true

require "json"
require "fileutils"
require "tmpdir"
require "time"
require "digest"
require_relative "../test_helper"
require_relative "../../tools/milestones/m8_gate"

class M8GateTest < Minitest::Test
  def report(kind, cases, extra = {})
    now = Time.now.utc.iso8601
    {"schema_version" => 1, "milestone" => "M8", "kind" => kind, "available" => true, "status" => "COMPLETE",
     "passed" => true, "cases" => cases, "case_count" => cases.length,
     "passed_count" => cases.length, "failed_count" => 0,
     "input_sha256" => "0" * 64, "input_file_count" => 1,
     "started_at" => now, "finished_at" => now}.merge(extra)
  end

  def test_missing_manifest_fails_closed
    result = M8Gate.evaluate(File.join(Dir.tmpdir, "rubernetes-m8-missing-#{Process.pid}.json"))

    refute result.fetch("passed")
    assert_operator result.fetch("error_count"), :>, 0
  end

  # A K1 run that selected fewer than the full conformance set, or that let a
  # test skip, must never be accepted.
  def test_conformance_totals_must_be_the_full_446_with_nothing_skipped
    errors = []
    cases = [
      {"id" => "k1_runs_recorded", "passed" => true, "runs" => 1},
      {"id" => "k1_totals-run1", "passed" => true,
       "summary" => {"selected" => 446, "passed" => 440, "failed" => 0, "skipped" => 6, "flaked" => 0}},
      {"id" => "k1_codename_join-run1", "passed" => true, "codenames" => {}},
      {"id" => "k1_consecutive_clean-a", "passed" => true, "profile" => "a", "clean_streak" => 3},
      {"id" => "k1_consecutive_clean-b", "passed" => true, "profile" => "b", "clean_streak" => 3},
      {"id" => "k1_consecutive_clean-c", "passed" => true, "profile" => "c", "clean_streak" => 3},
      {"id" => "k2_certified_conformance", "passed" => true}
    ]
    M8Gate.send(:validate_conformance, report("m8_conformance", cases), cases, errors)

    assert errors.any? { |error| error.include?("must pass 446") }, errors.inspect
    assert errors.any? { |error| error.include?("skipped 0") }, errors.inspect
  end

  def test_conformance_requires_three_consecutive_clean_runs_per_profile
    errors = []
    cases = [
      {"id" => "k1_runs_recorded", "passed" => true},
      {"id" => "k1_totals-run1", "passed" => true,
       "summary" => {"selected" => 446, "passed" => 446, "failed" => 0, "skipped" => 0, "flaked" => 0}},
      {"id" => "k1_codename_join-run1", "passed" => true},
      {"id" => "k1_consecutive_clean-a", "passed" => false, "profile" => "a", "clean_streak" => 2},
      {"id" => "k1_consecutive_clean-b", "passed" => true, "profile" => "b", "clean_streak" => 3},
      {"id" => "k1_consecutive_clean-c", "passed" => true, "profile" => "c", "clean_streak" => 3},
      {"id" => "k2_certified_conformance", "passed" => true}
    ]
    M8Gate.send(:validate_conformance, report("m8_conformance", cases), cases, errors)

    assert errors.any? { |error| error.include?("3 consecutive clean K1 runs") }, errors.inspect
  end

  def test_selection_ledger_must_classify_every_spec_and_link_replacements
    errors = []
    cases = [
      {"id" => "ledger_present", "passed" => true},
      {"id" => "every_spec_classified_once", "passed" => false, "unclassified" => 4, "duplicate_ids" => 1},
      {"id" => "no_forbidden_exclusion_reason", "passed" => true},
      {"id" => "external_contracts_have_replacements", "passed" => false, "unlinked" => 2},
      {"id" => "required_tests_present", "passed" => true},
      {"id" => "k4_node_conformance", "passed" => true}
    ]
    M8Gate.send(:validate_selection, report("m8_selection", cases, "counts" => {"required" => 10}), cases, errors)

    assert errors.any? { |error| error.include?("classify every spec") }, errors.inspect
    assert errors.any? { |error| error.include?("reuse a test id") }, errors.inspect
    assert errors.any? { |error| error.include?("needs a replacement test") }, errors.inspect
  end

  def test_corpus_minimums_and_pinning_are_enforced
    errors = []
    cases = [
      {"id" => "client_matrix_pinned", "passed" => true,
       "clients" => [{"version" => "v1.36.2", "present" => true, "checksum_matches" => false}]},
      {"id" => "client_matrix_covers_supported_skew", "passed" => true},
      {"id" => "corpus_minimums", "passed" => false, "total" => 12,
       "categories" => {"helm-chart" => 12, "operator" => 2, "crd-webhook" => 1, "statefulset-pvc" => 1}},
      {"id" => "corpus_domain_coverage", "passed" => false, "missing" => %w[gitops]},
      {"id" => "corpus_fully_pinned", "passed" => false, "unpinned" => %w[redis]},
      {"id" => "corpus_has_no_rubernetes_patch", "passed" => true},
      {"id" => "k6_executed", "passed" => true}
    ]
    M8Gate.send(:validate_corpus, report("m8_corpus", cases), cases, errors)

    assert errors.any? { |error| error.include?("at least 30 projects") }, errors.inspect
    assert errors.any? { |error| error.include?("10 operator") }, errors.inspect
    assert errors.any? { |error| error.include?("every required domain") }, errors.inspect
    assert errors.any? { |error| error.include?("pin its chart and image digests") }, errors.inspect
    assert errors.any? { |error| error.include?("checksum must match") }, errors.inspect
  end

  # The milestone forbids silencing a failure by narrowing focus or adding a
  # skip; the gate must reject a run whose argv shows it.
  def test_integrity_rejects_focus_narrowing_and_open_failures
    errors = []
    cases = [
      {"id" => "k0_input_integrity", "passed" => true},
      {"id" => "no_focus_narrowing_or_added_skip", "passed" => false,
       "violations" => [{"lane" => "K1", "flags" => ["--ginkgo.skip"]}]},
      {"id" => "k5_api_wire_differential", "passed" => true},
      {"id" => "k7_upgrade_and_recovery", "passed" => true},
      {"id" => "failure_ledger_has_no_open_items", "passed" => false, "open" => 3}
    ]
    M8Gate.send(:validate_integrity, report("m8_integrity", cases), cases, errors)

    assert errors.any? { |error| error.include?("must not narrow focus") }, errors.inspect
    assert errors.any? { |error| error.include?("no open item") }, errors.inspect
  end

  def test_clean_bundles_produce_no_lane_errors
    errors = []
    conformance = [
      {"id" => "k1_runs_recorded", "passed" => true},
      {"id" => "k1_totals-run1", "passed" => true,
       "summary" => {"selected" => 446, "passed" => 446, "failed" => 0, "skipped" => 0, "flaked" => 0}},
      {"id" => "k1_codename_join-run1", "passed" => true},
      {"id" => "k1_consecutive_clean-a", "passed" => true, "profile" => "a", "clean_streak" => 3},
      {"id" => "k1_consecutive_clean-b", "passed" => true, "profile" => "b", "clean_streak" => 3},
      {"id" => "k1_consecutive_clean-c", "passed" => true, "profile" => "c", "clean_streak" => 3},
      {"id" => "k2_certified_conformance", "passed" => true}
    ]
    M8Gate.send(:validate_conformance, report("m8_conformance", conformance), conformance, errors)

    assert_empty errors, errors.inspect
  end
end
