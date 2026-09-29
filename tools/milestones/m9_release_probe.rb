#!/usr/bin/env ruby
# frozen_string_literal: true

# M9 release probe: the artifact identity evidence — release manifest, SBOM,
# reproducible rebuild and Ruby ratio (spec/delivery/milestones.md#milestone-m9
# exit criteria 2 and 7, and the required evidence list).

require_relative "m9_probe_support"

module M9ReleaseProbe
  S = M9ProbeSupport

  module_function

  def run
    started_at = S.now
    manifest = S.load("release-manifest.json")
    sbom = S.load("sbom.cdx.json")
    repro = S.load("reproducibility.json")
    loc = S.load("ruby-loc-report.json")
    cases = []

    cases << {"id" => "release_manifest_present", "passed" => manifest["available"] == true,
              "input_sha256" => manifest.dig("source", "input_sha256"),
              "input_file_count" => manifest.dig("source", "input_file_count")}
    cases << {"id" => "release_manifest_binds_source",
              "passed" => manifest["available"] == true &&
                          manifest.dig("source", "input_sha256").to_s.match?(/\A[0-9a-f]{64}\z/) &&
                          manifest.dig("source", "input_file_count").to_i.positive?}
    cases << {"id" => "sbom_present", "passed" => sbom["available"] == true,
              "components" => Array(sbom["components"]).length,
              "format" => sbom["bomFormat"], "spec_version" => sbom["specVersion"]}
    cases << {"id" => "sbom_pins_every_component",
              "passed" => sbom["available"] == true &&
                          Array(sbom["components"]).all? { |component| component["purl"] || Array(component["hashes"]).any? },
              "unpinned" => Array(sbom["components"]).reject { |component| component["purl"] || Array(component["hashes"]).any? }
                                                     .map { |component| component["name"] }.first(5)}
    cases << {"id" => "rebuild_is_byte_identical",
              "passed" => repro["available"] == true && repro["same_host_identical"] == true,
              "rounds" => Array(repro["rounds"]).length,
              "detail" => repro["available"] ? nil : "reproducibility.json is missing"}
    # Exit criterion 2 needs a second, clean host; this probe records whether
    # that independent run has been attached rather than implying it passed.
    cases << {"id" => "clean_host_rebuild_attached",
              "passed" => repro["available"] == true && repro["clean_host_digests"].is_a?(Array) &&
                          !Array(repro["clean_host_digests"]).empty?,
              "detail" => repro["clean_host"]}
    cases << {"id" => "ruby_ratio_at_least_85_percent",
              "passed" => loc["available"] == true && loc["passed"] == true,
              "ruby_ratio" => loc["ruby_ratio"], "required" => loc["required_ratio"],
              "by_language" => loc["by_language"]}

    S.emit(S.report(kind: "m9_release_artifacts", measurement_level: "integration_tested",
                    started_at: started_at, cases: cases))
    cases.all? { |entry| entry.fetch("passed") } ? 0 : 1
  end
end

exit(M9ReleaseProbe.run) if $PROGRAM_NAME == __FILE__
