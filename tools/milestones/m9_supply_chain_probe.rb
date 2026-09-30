#!/usr/bin/env ruby
# frozen_string_literal: true

# M9 supply-chain probe (exit criterion 6 and the release-gate list): zero
# critical/high findings, zero unreviewed dependencies, zero unpinned inputs,
# and no undated work note or security claim without an assurance level.

require_relative "m9_probe_support"

module M9SupplyChainProbe
  S = M9ProbeSupport

  module_function

  def run
    started_at = S.now
    security = S.load("security-report.json")
    cases = []

    cases << {"id" => "security_report_present", "passed" => security["available"] == true,
              "detail" => security["available"] ? nil : "security-report.json is missing"}
    Array(security["cases"]).each do |entry|
      cases << {"id" => "security-#{entry.fetch("id")}", "passed" => entry.fetch("passed"),
                "detail" => entry["detail"], "findings" => entry["findings"] || entry["marker_count"]}
    end
    cases << {"id" => "no_critical_or_high_findings",
              "passed" => security["available"] == true && security["critical_or_high"].to_i.zero?,
              "critical_or_high" => security["critical_or_high"]}

    S.emit(S.report(kind: "m9_supply_chain", measurement_level: "integration_tested",
                    started_at: started_at, cases: cases))
    cases.all? { |entry| entry.fetch("passed") } ? 0 : 1
  end
end

exit(M9SupplyChainProbe.run) if $PROGRAM_NAME == __FILE__
