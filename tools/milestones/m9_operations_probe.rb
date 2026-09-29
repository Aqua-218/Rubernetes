#!/usr/bin/env ruby
# frozen_string_literal: true

# M9 operations probe (exit criteria 4, 5 and 8): performance against the
# oracle, the 72-hour soak, and the clean-host reproduction that installs only
# the release artifact and runs every M8 gate.

require_relative "m9_probe_support"

module M9OperationsProbe
  S = M9ProbeSupport
  REQUIRED_SOAK_HOURS = 72

  module_function

  def run
    started_at = S.now
    benchmark = S.load("benchmark.json")
    soak = S.load("soak-report.json")
    reproduction = S.load("clean-host-reproduction.json")
    cases = []

    cases << {"id" => "benchmark_against_oracle",
              "passed" => benchmark["available"] == true && benchmark["status"] == "COMPLETE" && benchmark["passed"] == true,
              "status" => benchmark["status"],
              "scenarios" => Array(benchmark["scenarios"]).map { |entry| entry.slice("id", "p95_ratio", "passed") },
              "detail" => benchmark["reason"]}

    cases << {"id" => "soak_ran_for_the_required_duration",
              "passed" => soak["available"] == true && soak["duration_satisfied"] == true,
              "elapsed_hours" => soak["elapsed_hours"], "required_hours" => REQUIRED_SOAK_HOURS,
              "detail" => soak["available"] ? nil : "soak-report.json is missing"}
    cases << {"id" => "soak_found_no_defect",
              "passed" => soak["available"] == true &&
                          %w[unexpected_process_exits resource_leaks stuck_queues lost_watches lost_commits]
                            .all? { |key| Array(soak[key]).empty? },
              "findings" => %w[unexpected_process_exits resource_leaks stuck_queues lost_watches lost_commits]
                              .to_h { |key| [key, Array(soak[key]).length] }}

    cases << {"id" => "clean_host_reproduction",
              "passed" => reproduction["available"] == true && reproduction["passed"] == true,
              "detail" => reproduction["available"] ? nil :
                          "clean-host-reproduction.json is missing: exit criterion 8 needs a clean x86_64 host that " \
                          "installs only the release artifact, creates a cluster and runs every M8 gate"}

    S.emit(S.report(kind: "m9_operations", measurement_level: "integration_tested",
                    started_at: started_at, cases: cases))
    cases.all? { |entry| entry.fetch("passed") } ? 0 : 1
  end
end

exit(M9OperationsProbe.run) if $PROGRAM_NAME == __FILE__
