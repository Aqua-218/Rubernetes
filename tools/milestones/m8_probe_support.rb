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

module M8ProbeSupport
  ROOT = M5ProbeSupport::ROOT
  RUN_ROOT = ENV.fetch("RUBERNETES_M8_RUN_ROOT", File.join(ROOT, "artifacts/conformance"))

  module_function

  def now = M5ProbeSupport.now

  def report(kind:, measurement_level:, started_at:, cases:, extra: {})
    document = M5ProbeSupport.report(kind: kind, measurement_level: measurement_level,
                                     started_at: started_at, cases: cases, extra: extra)
    document.merge("milestone" => "M8",
                   "input_sha256" => ENV.fetch("RUBERNETES_M8_INPUT_SHA256", document["input_sha256"]),
                   "input_file_count" => ENV["RUBERNETES_M8_INPUT_FILE_COUNT"] ? Integer(ENV["RUBERNETES_M8_INPUT_FILE_COUNT"]) : document["input_file_count"])
  end

  def emit(document) = M5ProbeSupport.emit(document)

  # Every conformance run manifest under the run root, newest first.
  def run_manifests
    Dir.glob(File.join(RUN_ROOT, "*", "manifest.json")).sort.reverse.filter_map do |path|
      document = begin
        JSON.parse(File.read(path))
      rescue StandardError
        nil
      end
      document && document.merge("_path" => path.delete_prefix("#{ROOT}/"))
    end
  end

  def lane_results(manifest, lane)
    Array(manifest["lanes"]).select { |entry| entry["lane"] == lane }
  end

  def profiles
    YAML.safe_load_file(File.join(ROOT, "test/conformance/kubernetes/profiles.yml"))
  end

  # The spec requires N consecutive clean runs per profile; a failed or
  # incomplete run in between resets the streak, and a later single-test rerun
  # can never repair an earlier run.
  def consecutive_clean_runs(lane)
    required = profiles.fetch("consecutive_clean_runs")
    by_profile = Hash.new { |hash, key| hash[key] = [] }
    run_manifests.reverse_each do |manifest|
      profile = manifest["profile"]
      next if profile.nil?

      results = lane_results(manifest, lane)
      next if results.empty?

      clean = results.all? { |entry| entry["status"] == "COMPLETE" && entry["passed"] == true }
      by_profile[profile] << {"run_id" => manifest["runId"], "clean" => clean, "manifest" => manifest["_path"]}
    end
    profiles.fetch("profiles").map do |profile|
      name = profile.fetch("name")
      runs = by_profile[name]
      streak = runs.reverse.take_while { |run| run.fetch("clean") }.length
      {
        "profile" => name,
        "runs" => runs.length,
        "clean_streak" => streak,
        "required" => required,
        "passed" => streak >= required,
        "run_ids" => runs.last(required).map { |run| run["run_id"] }
      }
    end
  end

  def digest_file(path) = Digest::SHA256.file(path).hexdigest
end
