#!/usr/bin/env ruby
# frozen_string_literal: true

# M8 corpus probe: the K6 evidence.  Checks the client version-skew matrix and
# the project corpus as pinned contracts (shape, licences, digests) and then
# the recorded K6 run results.  A corpus that is well formed but never executed
# is reported as exactly that.

require_relative "m8_probe_support"

module M8CorpusProbe
  S = M8ProbeSupport
  CORPUS = File.join(S::ROOT, "test/compatibility/projects/corpus.yml")
  MATRIX = File.join(S::ROOT, "test/compatibility/clients/matrix.yml")
  REQUIRED_DOMAINS = %w[ingress certificate observability database message-queue
                        autoscaling gitops storage security].freeze

  module_function

  def run
    started_at = S.now
    cases = []

    if File.file?(MATRIX)
      matrix = YAML.safe_load_file(MATRIX)
      entries = Array(matrix["kubectl"])
      verified = entries.map do |entry|
        path = File.join(S::ROOT, entry.fetch("path"))
        {"version" => entry.fetch("version"),
         "present" => File.executable?(path),
         "checksum_matches" => File.file?(path) && S.digest_file(path) == entry.fetch("sha256")}
      end
      cases << {"id" => "client_matrix_pinned",
                "passed" => entries.length >= 2 && verified.all? { |entry| entry.fetch("present") && entry.fetch("checksum_matches") },
                "clients" => verified}
      # The spec adds the next minor to the required set as soon as it ships.
      cases << {"id" => "client_matrix_covers_supported_skew",
                "passed" => entries.map { |entry| entry["skew"] }.sort == %w[+1 -1 0],
                "skews" => entries.map { |entry| entry["skew"] }}
    else
      cases << {"id" => "client_matrix_pinned", "passed" => false, "detail" => "#{MATRIX} is missing"}
    end

    if File.file?(CORPUS)
      corpus = YAML.safe_load_file(CORPUS)
      projects = Array(corpus["projects"])
      categories = projects.flat_map { |project| Array(project["categories"]) }.tally
      domains = projects.flat_map { |project| Array(project["domains"]) }.uniq
      unpinned = projects.reject do |project|
        !project["chart_sha256"].to_s.empty? && !project["license"].to_s.empty? &&
          !Array(project["images"]).empty? &&
          Array(project["images"]).all? { |image| image.to_s.include?("@sha256:") }
      end
      cases << {"id" => "corpus_minimums",
                "passed" => projects.length >= 30 &&
                            categories.fetch("helm-chart", 0) >= 10 &&
                            categories.fetch("operator", 0) >= 10 &&
                            categories.fetch("crd-webhook", 0) >= 5 &&
                            categories.fetch("statefulset-pvc", 0) >= 5,
                "total" => projects.length, "categories" => categories}
      cases << {"id" => "corpus_domain_coverage",
                "passed" => (REQUIRED_DOMAINS - domains).empty?,
                "missing" => REQUIRED_DOMAINS - domains}
      cases << {"id" => "corpus_fully_pinned",
                "passed" => unpinned.empty?,
                "unpinned" => unpinned.map { |project| project["name"] }}
      cases << {"id" => "corpus_has_no_rubernetes_patch",
                "passed" => projects.none? { |project| project.values.grep(String).any? { |value| value.downcase.include?("rubernetes") } },
                "detail" => "install procedures are the projects' own"}
    else
      cases << {"id" => "corpus_minimums", "passed" => false, "detail" => "#{CORPUS} is missing"}
    end

    k6 = S.run_manifests.flat_map { |manifest| S.lane_results(manifest, "K6") }
    cases << {"id" => "k6_executed",
              "passed" => k6.any? { |lane| lane["status"] == "COMPLETE" && lane["passed"] == true },
              "runs" => k6.length,
              "detail" => k6.empty? ? "no K6 run is recorded" : k6.first["reason"]}

    S.emit(S.report(kind: "m8_corpus", measurement_level: "integration_tested",
                    started_at: started_at, cases: cases))
    cases.all? { |entry| entry.fetch("passed") } ? 0 : 1
  end
end

exit(M8CorpusProbe.run) if $PROGRAM_NAME == __FILE__
