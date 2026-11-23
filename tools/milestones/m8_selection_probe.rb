#!/usr/bin/env ruby
# frozen_string_literal: true

# M8 selection probe: the K3/K4 evidence.  The selection ledger must classify
# every upstream spec exactly once, must not use a forbidden exclusion reason,
# and every excluded item that still has an external contract must name the
# replacement test that covers it.

require_relative "m8_probe_support"
require_relative "m8_k3_evidence"
require_relative "m8_k4_evidence"

module M8SelectionProbe
  S = M8ProbeSupport
  LEDGER = File.join(S::ROOT, "test/compatibility/api/selection-ledger.json")
  CLASSIFICATIONS = M8K3Evidence::CLASSIFICATIONS
  FORBIDDEN_REASONS = M8K3Evidence::FORBIDDEN_REASONS

  module_function

  def run
    started_at = S.now
    cases = []
    unless File.file?(LEDGER)
      cases << {"id" => "ledger_present", "passed" => false, "detail" => "#{LEDGER} is missing"}
      S.emit(S.report(kind: "m8_selection", measurement_level: "integration_tested", started_at: started_at, cases: cases))
      return 1
    end

    ledger_bytes = File.binread(LEDGER)
    ledger = JSON.parse(ledger_bytes)
    tests = ledger.fetch("tests")
    cases << {"id" => "ledger_present", "passed" => true, "spec_count" => tests.length,
              "sha256" => Digest::SHA256.hexdigest(ledger_bytes)}
    cases << {"id" => "every_spec_classified_once",
              "passed" => tests.all? { |entry| CLASSIFICATIONS.include?(entry["classification"]) } &&
                          tests.map { |entry| entry.fetch("id") }.uniq.length == tests.length,
              "unclassified" => tests.count { |entry| !CLASSIFICATIONS.include?(entry["classification"]) },
              "duplicate_ids" => tests.length - tests.map { |entry| entry.fetch("id") }.uniq.length}
    excluded = tests.reject { |entry| entry.fetch("classification") == "required" }
    cases << {"id" => "no_forbidden_exclusion_reason",
              "passed" => excluded.none? { |entry| FORBIDDEN_REASONS.any? { |bad| entry.fetch("reason").to_s.include?(bad) } },
              "excluded" => excluded.length}
    unlinked = excluded.select { |entry| entry["external_contract"] == true && !M8K3Evidence::K3.linked_replacement?(entry) }
    cases << {"id" => "external_contracts_have_replacements", "passed" => unlinked.empty?,
              "unlinked" => unlinked.length}
    cases << {"id" => "required_tests_present",
              "passed" => tests.any? { |entry| entry["classification"] == "required" },
              "required" => tests.count { |entry| entry["classification"] == "required" }}

    manifests = S.run_manifests
    cases << k3_campaign(manifests, ledger_bytes)
    cases << k4_case(manifests)

    S.emit(S.report(kind: "m8_selection", measurement_level: "integration_tested",
                    started_at: started_at, cases: cases,
                    extra: {"counts" => ledger["counts"]}))
    cases.all? { |entry| entry.fetch("passed") } ? 0 : 1
  end

  def k3_campaign(manifests, ledger_bytes)
    attempts = manifests.reject { |manifest| S.lane_results(manifest, "K3").empty? }
    verdicts = attempts.map do |manifest|
      original = M8K3Evidence.reference(manifest.fetch("_path"))
      M8K3Evidence.verify(original, ledger_bytes: ledger_bytes).merge("original" => original)
    rescue M8K3Evidence::Invalid, SystemCallError => error
      {"passed" => false, "detail" => error.message}
    end
    result = verdicts.find { |verdict| verdict["passed"] } || verdicts.first ||
             {"passed" => false, "detail" => "no K3 campaign is recorded"}
    result.merge("id" => M8K3Evidence::CASE, "runs" => attempts.length)
  end

  def k4_case(manifests)
    runs = manifests.flat_map do |manifest|
      lanes = S.lane_results(manifest, "K4")
      lanes.map do |lane|
        verdict = if lanes.one?
                    M8K4Evidence.verify(manifest, lane)
                  else
                    M8K4Evidence.failure("invalid_evidence", "the manifest has more than one K4 result")
                  end
        verdict.merge("manifest" => manifest.fetch("_path"), "recorded_status" => lane["status"])
      end
    end
    proof = runs.find { |run| M8K4Evidence.proof?(run) }
    {"id" => "k4_node_conformance", "passed" => !proof.nil?, "runs" => runs.length, "proof" => proof,
     "attempts" => runs.map { |run| run.slice("manifest", "recorded_status", "status", "detail") }}
  end
end

exit(M8SelectionProbe.run) if $PROGRAM_NAME == __FILE__
