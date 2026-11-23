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
    S.emit(evaluate)
  end

  def evaluate(manifests: S.run_manifests, configuration: S.profiles)
    started_at = S.now
    expected = configuration.fetch("conformance").fetch("expected_tests")
    profiles = S.consecutive_clean_runs("K1", manifests: manifests, configuration: configuration)
    runs = profiles.sum { |profile| profile.fetch("runs") }

    cases = [{
      "id" => "k1_runs_recorded",
      "passed" => runs.positive?,
      "runs" => runs,
      "detail" => runs.zero? ? "no release-profile K1 lane result exists under #{S::RUN_ROOT.sub("#{S::ROOT}/", "")}" : nil
    }]
    profiles.each do |profile|
      name = profile.fetch("profile")
      profile.fetch("latest_runs").each do |attempt|
        run_id = attempt["run_id"]
        key = if run_id.is_a?(String) && !run_id.strip.empty?
                "#{name}-#{run_id}"
              else
                "#{name}-unidentified-#{Digest::SHA256.hexdigest(attempt.fetch("manifest"))}"
              end
        status = attempt.slice("passed", "status", "detail", "manifest").merge("profile" => name, "run_id" => run_id)
        cases << status.merge("id" => "k1_totals-#{key}", "summary" => attempt["summary"])
        cases << status.merge("id" => "k1_codename_join-#{key}", "codenames" => attempt["codenames"])
      end
      cases << profile.except("earlier_runs", "latest_runs").merge("id" => "k1_consecutive_clean-#{name}")
    end

    k2 = manifests.flat_map { |manifest| S.lane_results(manifest, "K2") }
    cases << {
      "id" => "k2_certified_conformance",
      "passed" => !k2.empty? && k2.any? { |lane| lane["status"] == "COMPLETE" && lane["passed"] == true },
      "runs" => k2.length,
      "detail" => k2.empty? ? "no Sonobuoy certified-conformance archive is recorded" : nil
    }

    history = profiles.to_h { |profile| [profile.fetch("profile"), profile.fetch("earlier_runs")] }
    S.report(kind: "m8_conformance", measurement_level: "integration_tested",
             started_at: started_at, cases: cases,
             extra: {"expected_tests" => expected, "run_root" => S::RUN_ROOT.sub("#{S::ROOT}/", ""),
                     "k1_earlier_runs" => history})
  end
end

exit(M8ConformanceProbe.run) if $PROGRAM_NAME == __FILE__
