#!/usr/bin/env ruby
# frozen_string_literal: true

# M8 selection probe: the K3/K4 evidence.  The selection ledger must classify
# every upstream spec exactly once, must not use a forbidden exclusion reason,
# and every excluded item that still has an external contract must name the
# replacement test that covers it.

require_relative "m8_probe_support"

module M8SelectionProbe
  S = M8ProbeSupport
  LEDGER = File.join(S::ROOT, "test/compatibility/api/selection-ledger.json")
  CLASSIFICATIONS = %w[required platform-inapplicable provider-private implementation-internal].freeze
  # Tags the spec explicitly refuses as exclusion grounds.
  FORBIDDEN_REASONS = ["LinuxOnly", "Disruptive", "Slow", "Serial", "Flaky", "Feature:",
                       "unimplemented", "not implemented", "fails", "timeout", "hard to set up"].freeze

  module_function

  def run
    started_at = S.now
    cases = []
    unless File.file?(LEDGER)
      cases << {"id" => "ledger_present", "passed" => false, "detail" => "#{LEDGER} is missing"}
      S.emit(S.report(kind: "m8_selection", measurement_level: "integration_tested", started_at: started_at, cases: cases))
      return 1
    end

    ledger = JSON.parse(File.read(LEDGER))
    tests = ledger.fetch("tests")
    cases << {"id" => "ledger_present", "passed" => true, "spec_count" => tests.length,
              "sha256" => S.digest_file(LEDGER)}
    cases << {"id" => "every_spec_classified_once",
              "passed" => tests.all? { |entry| CLASSIFICATIONS.include?(entry["classification"]) } &&
                          tests.map { |entry| entry.fetch("id") }.uniq.length == tests.length,
              "unclassified" => tests.count { |entry| !CLASSIFICATIONS.include?(entry["classification"]) },
              "duplicate_ids" => tests.length - tests.map { |entry| entry.fetch("id") }.uniq.length}
    excluded = tests.reject { |entry| entry.fetch("classification") == "required" }
    cases << {"id" => "no_forbidden_exclusion_reason",
              "passed" => excluded.none? { |entry| FORBIDDEN_REASONS.any? { |bad| entry.fetch("reason").to_s.include?(bad) } },
              "excluded" => excluded.length}
    unlinked = excluded.select { |entry| entry["external_contract"] == true && entry["replacement_test"].to_s.empty? }
    cases << {"id" => "external_contracts_have_replacements", "passed" => unlinked.empty?,
              "unlinked" => unlinked.length}
    cases << {"id" => "required_tests_present",
              "passed" => tests.count { |entry| entry["classification"] == "required" }.positive?,
              "required" => tests.count { |entry| entry["classification"] == "required" }}

    manifests = S.run_manifests
    k4 = manifests.flat_map { |manifest| S.lane_results(manifest, "K4") }
    cases << {"id" => "k4_node_conformance",
              "passed" => k4.any? { |lane| lane["status"] == "COMPLETE" && lane["passed"] == true },
              "runs" => k4.length,
              "detail" => k4.empty? ? "no Node Conformance run is recorded" : nil}

    S.emit(S.report(kind: "m8_selection", measurement_level: "integration_tested",
                    started_at: started_at, cases: cases,
                    extra: {"counts" => ledger["counts"]}))
    cases.all? { |entry| entry.fetch("passed") } ? 0 : 1
  end
end

exit(M8SelectionProbe.run) if $PROGRAM_NAME == __FILE__
