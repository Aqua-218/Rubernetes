#!/usr/bin/env ruby
# frozen_string_literal: true

# M8 integrity probe: the K0/K5/K7 evidence plus the milestone's "no silencing"
# criterion — no source patch, focus narrowing, added skip, overwritten failure
# or extended timeout anywhere in the recorded runs.

require "open3"
require_relative "../conformance/k7_evidence"
require_relative "m8_probe_support"
require_relative "m8_k5_evidence"

module M8IntegrityProbe
  S = M8ProbeSupport
  FULL_SUITE_COMMANDS = {"K1" => "k1/hydrophone-command.json", "K2" => "k2/sonobuoy-command.json"}.freeze
  SELECTION_FLAG = /(?:\A|[=\s,])(-{1,2}(?:ginkgo\.)?(?:focus|skip)(?:-file)?|--e2e-(?:skip|focus)|--(?:ginkgo\.)?(?:label-filter|sem-ver-filter))(?=[=\s,]|\z)/

  module_function

  def run
    started_at = S.now
    cases = []
    manifests = S.run_manifests

    k0 = manifests.flat_map { |manifest| S.lane_results(manifest, "K0") }
    cases << {"id" => "k0_input_integrity",
              "passed" => k0.any? { |lane| lane["passed"] == true },
              "runs" => k0.length,
              "failed_checks" => k0.flat_map do |lane|
                Array(lane["cases"]).reject do |entry|
                  entry["passed"]
                end.map { |entry| entry["id"] }
              end.uniq}

    argv_violations = command_violations(manifests)
    cases << {"id" => "no_focus_narrowing_or_added_skip", "passed" => argv_violations.empty?,
              "violations" => argv_violations}

    cases << k5_outcome(manifests)

    cases << k7_outcome(manifests)

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

  def command_violations(manifests)
    manifests.flat_map do |manifest|
      Array(manifest["lanes"]).grep(Hash).filter_map do |lane|
        name = FULL_SUITE_COMMANDS[lane["lane"]]
        next unless name
        next if lane["status"] != "COMPLETE" && Conformance::ArchivedArtifact.recorded_digests(lane, name).empty?

        begin
          dir = File.realpath(File.dirname(File.expand_path(manifest.fetch("_path"), S::ROOT)))
          path = Conformance::ArchivedArtifact.verify!(manifest, lane, dir, name)
          row = JSON.parse(File.binread(path))
          args = row["command"] if row.is_a?(Hash)
          raise ArgumentError, "missing suite command" unless args.is_a?(Array) && !args.empty? && args.all?(String)

          flags = selection_flags(args)
          {"lane" => lane["lane"], "path" => name, "flags" => flags} unless flags.empty?
        rescue Conformance::ArchivedArtifact::Invalid, SystemCallError, JSON::ParserError, ArgumentError, KeyError => error
          {"lane" => lane["lane"], "path" => name, "detail" => error.message}
        end
      end
    end
  end

  def selection_flags(argv)
    argv.each_with_index.flat_map do |arg, index|
      flags = arg.scan(SELECTION_FLAG).flatten
      flags << "E2E_SKIP" if arg.match?(/(?:\A|[.=:,\s])E2E_SKIP(?:=|\z)/)
      key, value = arg.split("=", 2)
      flags << "--mode" if key == "--mode" && (value || argv[index + 1]) != "certified-conformance"
      flags
    end.uniq
  end

  def k5_outcome(manifests)
    runs = manifests.flat_map do |manifest|
      S.lane_results(manifest, "K5").map do |lane|
        M8K5Evidence.verify(manifest, lane, root: S::ROOT).merge("run_id" => manifest["runId"])
      end
    end
    verified = runs.find { |run| run.fetch("passed") }
    {"id" => "k5_api_wire_differential", "passed" => !verified.nil?, "runs" => runs.length,
     "verified_run" => verified&.fetch("run_id"), "matching" => verified&.fetch("matching"),
     "detail" => runs.empty? ? "no K5 differential is recorded" : (runs.first["detail"] unless verified)}
  end

  def k7_outcome(manifests)
    evidence = Conformance::K7Evidence
    runs = manifests.flat_map do |manifest|
      S.lane_results(manifest, "K7").map do |lane|
        evidence.archived(manifest, lane, root: S::ROOT).merge("run_id" => manifest["runId"])
      end
    end
    verified = runs.find { |run| run.fetch("passed") }
    {"id" => "k7_upgrade_and_recovery", "passed" => !verified.nil?, "runs" => runs.length,
     "verified_run" => verified&.fetch("run_id"), "expected_stages" => Conformance::K7Contract::STAGE_IDS.length,
     "completed_stages" => (verified || runs.first)&.fetch("completed_stages"),
     "detail" => runs.empty? ? "no K7 lifecycle run is recorded" : (runs.first["detail"] unless verified)}
  end
end

exit(M8IntegrityProbe.run) if $PROGRAM_NAME == __FILE__
