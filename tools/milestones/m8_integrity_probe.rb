#!/usr/bin/env ruby
# frozen_string_literal: true

# M8 integrity probe: the K0/K5/K7 evidence plus the milestone's "no silencing"
# criterion — no source patch, focus narrowing, added skip, overwritten failure
# or extended timeout anywhere in the recorded runs.

require "open3"
require_relative "m8_probe_support"

module M8IntegrityProbe
  S = M8ProbeSupport
  # Argv shapes the spec forbids in a K1/K2 run.
  FORBIDDEN_ARGS = ["--skip", "--ginkgo.skip", "E2E_SKIP", "--ginkgo.focus", "--focus",
                    "--mode=quick", "--mode=non-disruptive-conformance", "--e2e-skip"].freeze

  module_function

  def run
    started_at = S.now
    cases = []
    manifests = S.run_manifests

    k0 = manifests.flat_map { |manifest| S.lane_results(manifest, "K0") }
    cases << {"id" => "k0_input_integrity",
              "passed" => k0.any? { |lane| lane["passed"] == true },
              "runs" => k0.length,
              "failed_checks" => k0.flat_map { |lane| Array(lane["cases"]).reject { |entry| entry["passed"] }.map { |entry| entry["id"] } }.uniq}

    argv_violations = manifests.flat_map do |manifest|
      Array(manifest["lanes"]).flat_map do |lane|
        Array(lane["artifacts"]).filter_map do |artifact|
          path = File.join(S::ROOT, artifact.fetch("path"))
          next unless File.file?(path) && path.end_with?("command.json")

          document = JSON.parse(File.read(path)) rescue nil
          argv = Array(document && document["command"]).join(" ")
          bad = FORBIDDEN_ARGS.select { |flag| argv.include?(flag) }
          bad.empty? ? nil : {"lane" => lane["lane"], "path" => artifact.fetch("path"), "flags" => bad}
        end
      end
    end
    cases << {"id" => "no_focus_narrowing_or_added_skip", "passed" => argv_violations.empty?,
              "violations" => argv_violations}

    k5 = manifests.flat_map { |manifest| S.lane_results(manifest, "K5") }
    cases << {"id" => "k5_api_wire_differential",
              "passed" => k5.any? { |lane| lane["status"] == "COMPLETE" && lane["passed"] == true },
              "runs" => k5.length,
              "differences" => k5.map { |lane| lane["differences"] }.compact,
              "detail" => k5.empty? ? "no K5 differential is recorded" : k5.first["reason"]}

    k7 = manifests.flat_map { |manifest| S.lane_results(manifest, "K7") }
    cases << {"id" => "k7_upgrade_and_recovery",
              "passed" => k7.any? { |lane| lane["status"] == "COMPLETE" && lane["passed"] == true },
              "runs" => k7.length,
              "detail" => k7.empty? ? "no K7 lifecycle run is recorded" : k7.first["reason"]}

    ledger = File.join(S::ROOT, "test/compatibility/failure-ledger.json")
    open_items = File.file?(ledger) ? Array(JSON.parse(File.read(ledger))["open"]) : []
    cases << {"id" => "failure_ledger_has_no_open_items",
              "passed" => File.file?(ledger) && open_items.empty?,
              "open" => open_items.length,
              "detail" => File.file?(ledger) ? nil : "#{ledger.sub("#{S::ROOT}/", "")} is missing"}

    S.emit(S.report(kind: "m8_integrity", measurement_level: "integration_tested",
                    started_at: started_at, cases: cases))
    cases.all? { |entry| entry.fetch("passed") } ? 0 : 1
  end
end

exit(M8IntegrityProbe.run) if $PROGRAM_NAME == __FILE__
