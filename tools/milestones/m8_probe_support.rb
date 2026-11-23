# frozen_string_literal: true

# Shared helpers for the M8 Kubernetes-compatibility probes.  Each probe reads
# the artefacts the conformance runner produced (or the pinned corpus/ledger
# when the lane is a static contract) and never re-derives a lane result from
# anything but the recorded run.

require "digest"
require "json"
require "time"
require "yaml"

require_relative "m5_probe_support"
require_relative "m8_k1_evidence"

module M8ProbeSupport
  ROOT = M5ProbeSupport::ROOT
  RUN_ROOT = ENV.fetch("RUBERNETES_M8_RUN_ROOT", File.join(ROOT, "artifacts/conformance"))
  REPORT_SOURCES = {
    "m8_conformance" => %w[
      tools/milestones/m8_k1_evidence.rb tools/conformance/k1_evidence.rb tools/conformance/k1_ginkgo_report.rb
      test/conformance/kubernetes/profiles.yml third_party/locks/kubernetes-v1.36.2.json
    ],
    "m8_selection" => %w[
      tools/milestones/m8_k4_evidence.rb tools/conformance/k4_node_conformance.rb tools/conformance/k4_junit.rb
      tools/conformance/k4_rro.rb tools/conformance/k4_evidence.rb
      test/compatibility/api/selection-ledger.json third_party/locks/kubernetes-v1.36.2.json
    ],
    "m8_corpus" => %w[tools/conformance/k6_evidence.rb test/compatibility/clients/matrix.yml test/compatibility/projects/corpus.yml],
    "m8_integrity" => %w[
      tools/milestones/m8_k5_evidence.rb tools/conformance/k5_evidence.rb tools/conformance/k7_evidence.rb
      test/compatibility/failure-ledger.json third_party/locks/kubernetes-v1.36.2.json
    ]
  }.freeze

  module_function

  def now = M5ProbeSupport.now

  def report(kind:, measurement_level:, started_at:, cases:, extra: {})
    document = M5ProbeSupport.report(kind: kind, measurement_level: measurement_level,
                                     started_at: started_at, cases: cases, extra: extra)
    document.merge("milestone" => "M8",
                   "input_sha256" => ENV.fetch("RUBERNETES_M8_INPUT_SHA256", document["input_sha256"]),
                   "input_file_count" => ENV["RUBERNETES_M8_INPUT_FILE_COUNT"] ? Integer(ENV["RUBERNETES_M8_INPUT_FILE_COUNT"]) : document["input_file_count"],
                   "sources" => report_sources(kind))
  end

  def report_sources(kind)
    implementation = %W[tools/milestones/#{kind}_probe.rb tools/milestones/m8_probe_support.rb
                        tools/milestones/m5_probe_support.rb tools/conformance/archived_artifact.rb]
    # A missing ledger or configuration is reported by its own failed case.
    inputs = REPORT_SOURCES.fetch(kind).select { |path| File.file?(File.join(ROOT, path)) }
    M5ProbeSupport.source_files(implementation + inputs)
  end

  def emit(document) = M5ProbeSupport.emit(document)

  # Every conformance run manifest under the run root, newest first.
  def run_manifests
    Dir.glob(File.join(RUN_ROOT, "*", "manifest.json")).reverse.filter_map do |path|
      document = JSON.parse(File.read(path))
      document.merge("_path" => path.delete_prefix("#{ROOT}/")) if document.is_a?(Hash)
    rescue JSON::ParserError, SystemCallError
      nil
    end
  end

  def lane_results(manifest, lane)
    Array(manifest["lanes"]).select { |entry| entry.is_a?(Hash) && entry["lane"] == lane }
  end

  def profiles
    YAML.safe_load_file(File.join(ROOT, "test/conformance/kubernetes/profiles.yml"))
  end

  # A copy is another copy of the same attempt, and a failed or missing
  # attempt terminates the streak at its position in the recorded history.
  def consecutive_clean_runs(lane, manifests: run_manifests, configuration: profiles)
    required = configuration.fetch("consecutive_clean_runs")
    release_profiles = configuration.fetch("profiles")
    profile_names = release_profiles.map { |profile| profile.fetch("name") }
    manifests = manifests.select do |manifest|
      profile_names.include?(manifest["profile"]) && !lane_results(manifest, lane).empty?
    end.sort_by { |manifest| run_order(manifest) }.reverse
    cohort = manifests.first&.fetch("rubernetesCommit", nil)

    by_id = manifests.group_by { |manifest| run_identity(manifest) }
    by_profile = manifests.group_by { |manifest| manifest.fetch("profile") }
    replayed_ids = replayed_k1_run_ids(by_id) if lane == "K1"
    release_profiles.map do |profile|
      name = profile.fetch("name")
      groups = by_profile.fetch(name, []).group_by { |manifest| run_identity(manifest) }.values
      latest = groups.take(required).map do |copies|
        manifest = copies.first
        result = lane_results(manifest, lane).first
        verdict = if lane == "K1"
                    verify_k1_copies(by_id.fetch(run_identity(manifest)), profile, configuration, cohort, replayed_ids)
                  else
                    clean = lane_results(manifest, lane).all? { |entry| entry["status"] == "COMPLETE" && entry["passed"] == true }
                    {"passed" => clean}
                  end
        k1_history_entry(manifest, lane).merge(verdict).merge("summary" => result["summary"], "codenames" => result["codenames"])
      end
      streak = latest.take_while { |run| run.fetch("passed") }.length
      {
        "profile" => name, "runs" => groups.length, "clean_streak" => streak, "required" => required,
        "passed" => streak >= required, "run_ids" => latest.reverse.map { |run| run.fetch("run_id") },
        "release_cohort" => cohort, "latest_runs" => latest,
        "earlier_runs" => groups.drop(required).map { |copies| k1_history_entry(copies.first, lane) }
      }
    end
  end

  def verify_k1_copies(copies, profile, configuration, cohort, replayed_ids)
    manifest = copies.first
    run_id = manifest["runId"]
    return M8K1Evidence.failure("invalid_run", "K1 attempt has no run ID") unless run_id.is_a?(String) && !run_id.strip.empty?
    unless copies.map { |copy| copy.except("_path") }.uniq.one? && lane_results(manifest, "K1").one?
      return M8K1Evidence.failure("conflicting_run_id", "K1 run ID has conflicting manifests or multiple K1 results")
    end
    return M8K1Evidence.failure("duplicate_evidence", "a K1 original report is claimed by more than one run ID") if replayed_ids.key?(run_id)
    if !M8K1Evidence::RELEASE_REVISION.match?(cohort.to_s) || manifest["rubernetesCommit"] != cohort
      return M8K1Evidence.failure("different_cohort", "K1 attempt is outside the latest Rubernetes release cohort")
    end

    expected = configuration.fetch("conformance").fetch("expected_tests")
    result = lane_results(manifest, "K1").first
    verdicts = copies.map do |copy|
      M8K1Evidence.verify(copy, result, profile: profile, expected: expected).merge("manifest" => copy.fetch("_path"))
    end
    verdicts.find { |verdict| verdict["status"] == "invalid_evidence" } ||
      verdicts.find { |verdict| verdict["passed"] } || verdicts.first
  end

  def run_identity(manifest)
    id = manifest["runId"]
    id.is_a?(String) && !id.strip.empty? ? [:run, id] : [:manifest, manifest["_path"]]
  end

  def run_order(manifest)
    # Prefer the immutable timestamp. When it is absent, the timestamp in
    # the runner's standard directory name still locates the failed attempt.
    path = manifest.fetch("_path")
    time = parse_run_start(manifest["startedAt"]) ||
           parse_run_start(File.basename(File.dirname(path))[/\A\d{8}T\d{6}\.\d{6}Z/], "%Y%m%dT%H%M%S.%NZ")
    [time.nil? ? 1 : 0, time || Time.at(0), path]
  end

  def parse_run_start(value, format = nil)
    return unless value.is_a?(String)

    format ? Time.strptime(value, format) : Time.iso8601(value)
  rescue ArgumentError
    nil
  end

  def replayed_k1_run_ids(by_id)
    by_report = Hash.new { |hash, key| hash[key] = [] }
    by_id.each do |(kind, id), copies|
      next unless kind == :run

      copies.flat_map { |manifest| lane_results(manifest, "K1") }.each do |lane|
        next unless lane["status"] == "COMPLETE" && lane["passed"] == true

        M8K1Evidence.fingerprints(lane).each { |fingerprint| by_report[fingerprint] << id }
      end
    end
    by_report.values.map(&:uniq).select { |ids| ids.length > 1 }.flatten.to_h { |id| [id, true] }
  end

  def k1_history_entry(manifest, lane)
    {
      "run_id" => manifest["runId"], "manifest" => manifest.fetch("_path"), "started_at" => manifest["startedAt"],
      "rubernetes_commit" => manifest["rubernetesCommit"], "recorded_status" => lane_results(manifest, lane).first["status"]
    }
  end

  def digest_file(path) = Digest::SHA256.file(path).hexdigest
end
