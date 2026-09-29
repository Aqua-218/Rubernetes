#!/usr/bin/env ruby
# frozen_string_literal: true

# M8 conformance probe: the K1/K2 evidence.  Reads the recorded conformance
# runs and checks the exit criteria the milestone states — 446 selected, 446
# passed, 0 failed/skipped/flaked, and three consecutive clean runs for each of
# the three release profiles.  A missing run is reported as missing; it is
# never treated as a pass.

require_relative "m8_probe_support"

module M8ConformanceProbe
  S = M8ProbeSupport

  module_function

  def run
    started_at = S.now
    manifests = S.run_manifests
    cases = []
    expected = S.profiles.fetch("conformance").fetch("expected_tests")

    k1 = manifests.flat_map { |manifest| S.lane_results(manifest, "K1").map { |lane| [manifest, lane] } }
    cases << {
      "id" => "k1_runs_recorded",
      "passed" => !k1.empty?,
      "runs" => k1.length,
      "detail" => k1.empty? ? "no K1 lane result exists under #{S::RUN_ROOT.sub("#{S::ROOT}/", "")}" : nil
    }
    k1.each do |manifest, lane|
      summary = lane["summary"] || {}
      cases << {
        "id" => "k1_totals-#{manifest["runId"]}",
        "passed" => summary["selected"] == expected && summary["passed"] == expected &&
                    summary["failed"].to_i.zero? && summary["skipped"].to_i.zero? && summary["flaked"].to_i.zero?,
        "profile" => manifest["profile"], "summary" => summary
      }
      codenames = lane["codenames"] || {}
      cases << {
        "id" => "k1_codename_join-#{manifest["runId"]}",
        "passed" => codenames["definition_available"] == true &&
                    Array(codenames["unmatched_codenames"]).empty? &&
                    Array(codenames["duplicate_codenames"]).empty?,
        "codenames" => codenames.slice("definition_count", "executed_count")
      }
    end

    S.consecutive_clean_runs("K1").each do |profile|
      cases << profile.merge("id" => "k1_consecutive_clean-#{profile.fetch("profile")}")
    end

    k2 = manifests.flat_map { |manifest| S.lane_results(manifest, "K2") }
    cases << {
      "id" => "k2_certified_conformance",
      "passed" => !k2.empty? && k2.any? { |lane| lane["status"] == "COMPLETE" && lane["passed"] == true },
      "runs" => k2.length,
      "detail" => k2.empty? ? "no Sonobuoy certified-conformance archive is recorded" : nil
    }

    S.emit(S.report(kind: "m8_conformance", measurement_level: "integration_tested",
                    started_at: started_at, cases: cases,
                    extra: {"expected_tests" => expected, "run_root" => S::RUN_ROOT.sub("#{S::ROOT}/", "")}))
    cases.all? { |entry| entry.fetch("passed") } ? 0 : 1
  end
end

exit(M8ConformanceProbe.run) if $PROGRAM_NAME == __FILE__
