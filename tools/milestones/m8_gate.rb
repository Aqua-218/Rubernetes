#!/usr/bin/env ruby
# frozen_string_literal: true

# Validate the content-addressed M8 Kubernetes-compatibility evidence bundle.
# M8 inherits the complete M0 -> M7 chain and requires the conformance result
# (K1/K2), the upstream selection ledger (K3/K4), the client and project corpus
# (K6) and the compatibility integrity report (K0/K5/K7).  A lane that was never
# executed, a run whose focus was narrowed or whose skips were extended, a
# profile without three consecutive clean runs, an unclassified upstream spec,
# a corpus entry on a mutable tag, or an open failure-ledger item is rejected.
require "digest"
require "json"
require "time"
require_relative "m7_gate"
require_relative "m3_evidence_support"

module M8Gate
  MANIFEST_SCHEMA_VERSION = 3
  REPORT_SCHEMA_VERSION = 1
  SOURCE_EXCLUDED_ROOTS = M4Gate::SOURCE_EXCLUDED_ROOTS
  SOURCE_EXCLUDED_PATTERNS = M4Gate::SOURCE_EXCLUDED_PATTERNS
  PROJECT_ROOT = File.expand_path("../..", __dir__).freeze
  PRIOR_GATES = M7Gate::PRIOR_GATES.merge("M8" => File.join(__dir__, "m7_gate.rb")).freeze
  ARTIFACT_LOCK = "third_party/locks/conformance-runners.json"
  
  REPORTS = {
    "conformance" => {kind: "m8_conformance", names: %w[conformance-result.json]},
    "selection" => {kind: "m8_selection", names: %w[selection-ledger-result.json]},
    "corpus" => {kind: "m8_corpus", names: %w[client-project-corpus.json]},
    "integrity" => {kind: "m8_integrity", names: %w[compatibility-integrity.json]}
  }.freeze
  REQUIRED_REPORTS = REPORTS

  # Exit criteria that the gate re-derives from the reports rather than
  # trusting a summary field (spec/delivery/milestones.md#milestone-m8).
  CONFORMANCE_REQUIRED_PREFIXES = %w[k1_runs_recorded k1_totals- k1_codename_join- k1_consecutive_clean- k2_certified_conformance].freeze
  SELECTION_REQUIRED = %w[ledger_present every_spec_classified_once no_forbidden_exclusion_reason
                          external_contracts_have_replacements required_tests_present k4_node_conformance].freeze
  CORPUS_REQUIRED = %w[client_matrix_pinned client_matrix_covers_supported_skew corpus_minimums
                       corpus_domain_coverage corpus_fully_pinned corpus_has_no_rubernetes_patch k6_executed].freeze
  INTEGRITY_REQUIRED = %w[k0_input_integrity no_focus_narrowing_or_added_skip k5_api_wire_differential
                          k7_upgrade_and_recovery failure_ledger_has_no_open_items].freeze
  EXPECTED_CONFORMANCE_TESTS = 446
  REQUIRED_PROFILES = 3
  REQUIRED_CLEAN_RUNS = 3

  INVENTORY_NAMES = M4Gate::INVENTORY_NAMES

  class << self
    def evaluate(manifest_path)
      manifest_path = File.expand_path(manifest_path)
      directory = File.dirname(manifest_path)
      errors = []
      manifest = M4Gate.send(:parse_json, manifest_path, errors, "manifest")
      return result(errors) unless manifest.is_a?(Hash)

      validate_manifest_shape(manifest, errors)
      artifacts = M4Gate.send(:validate_entries, manifest.fetch("artifacts", []), directory, errors, "artifact")
      subjects = M4Gate.send(:validate_entries, manifest.fetch("subjects", []), directory, errors, "subject")
      artifact_index = M4Gate.send(:index_artifacts, artifacts, errors)
      validate_inventory(manifest, directory, artifact_index, errors)
      validate_prior_milestones(manifest, directory, artifacts, errors)
      REPORTS.each do |name, specification|
        document = report_document(name, specification, directory, artifact_index, errors)
        validate_report(name, document, specification.fetch(:kind), manifest, errors) if document
      end
      validate_result_counts(manifest, artifacts, subjects, errors)
      errors << "manifest status must be COMPLETE" unless manifest["status"] == "COMPLETE"
      result(errors)
    rescue Errno::ENOENT => error
      result(["evidence file is missing: #{error.message}"])
    rescue JSON::ParserError => error
      result(["invalid JSON in evidence bundle: #{error.message}"])
    rescue StandardError => error
      result(["gate could not validate evidence bundle: #{error.class}: #{error.message}"])
    end

    def canonical_inventory_digest(entries)
      M4Gate.canonical_inventory_digest(entries)
    end

    private

    def result(errors)
      {"schema_version" => 1, "milestone" => "M8", "passed" => errors.empty?, "error_count" => errors.length, "errors" => errors}
    end

    def validate_manifest_shape(manifest, errors)
      errors << "schema_version must be #{MANIFEST_SCHEMA_VERSION}" unless manifest["schema_version"] == MANIFEST_SCHEMA_VERSION
      errors << "milestone must be M8" unless manifest["milestone"] == "M8"
      errors << "input_sha256 must be a SHA-256 digest" unless valid_digest?(manifest["input_sha256"])
      errors << "input_file_count must be positive" unless manifest["input_file_count"].is_a?(Integer) && manifest["input_file_count"].positive?
      errors << "source input must remain stable during evidence capture" unless manifest["input_stable"] == true
      host = manifest["host"]
      errors << "host architecture, kernel, and Ruby description are required" unless host.is_a?(Hash) && %w[architecture kernel ruby].all? { |key| non_empty_string?(host[key]) }
      errors << "M8 evidence must be captured on x86_64" unless host.is_a?(Hash) && host["architecture"] == "x86_64"
      %w[started_at finished_at].each { |key| errors << "#{key} must be an ISO-8601 timestamp" unless iso8601?(manifest[key]) }
      M4Gate.send(:validate_input_capture, manifest, errors)
      M4Gate.send(:validate_git_metadata_capture, manifest, errors)
      M4Gate.send(:validate_commands, manifest["commands"], errors)
      errors << "artifacts must be an array" unless manifest["artifacts"].is_a?(Array)
      errors << "subjects must be an array" unless manifest["subjects"].is_a?(Array)
      errors << "result_counts must be an object" unless manifest["result_counts"].is_a?(Hash)
    end

    def validate_inventory(manifest, directory, artifact_index, errors)
      artifact = M4Gate.send(:find_named_artifact, INVENTORY_NAMES, artifact_index, errors, "source inventory")
      return unless artifact

      document = M4Gate.send(:parse_json, M4Gate.send(:evidence_path, directory, artifact["path"]), errors, "source inventory")
      return unless document.is_a?(Hash)

      errors << "source inventory kind must be m8_source_inventory" unless document["kind"] == "m8_source_inventory"
      errors << "source inventory input_sha256 must match manifest" unless document["input_sha256"] == manifest["input_sha256"]
      errors << "source inventory input_file_count must match manifest" unless document["input_file_count"] == manifest["input_file_count"]
      entries = document["entries"]
      unless entries.is_a?(Array) && !entries.empty?
        errors << "source inventory entries must be a non-empty array"
        return
      end
      paths = entries.map { |entry| entry.is_a?(Hash) ? entry["path"] : nil }
      errors << "source inventory paths must be sorted and unique" unless paths.compact.sort == paths && paths.uniq.length == paths.length
      excluded = paths.compact.select do |path|
        SOURCE_EXCLUDED_ROOTS.include?(path.split("/", 2).first) || SOURCE_EXCLUDED_PATTERNS.any? { |pattern| pattern.match?(path) }
      end
      errors << "source inventory includes excluded paths: #{excluded.first(3).join(", ")}" unless excluded.empty?
      valid = entries.select { |entry| entry.is_a?(Hash) && non_empty_string?(entry["path"]) && valid_digest?(entry["sha256"]) }
      errors << "source inventory digest does not match manifest input" unless canonical_inventory_digest(valid) == manifest["input_sha256"]
      errors << "source inventory file count does not match manifest input" unless valid.length == manifest["input_file_count"]
      valid.each do |entry|
        path = File.expand_path(entry.fetch("path"), PROJECT_ROOT)
        errors << "source inventory entry #{entry.fetch("path")} is missing" unless File.file?(path)
        errors << "source inventory digest mismatch #{entry.fetch("path")}" if File.file?(path) && Digest::SHA256.file(path).hexdigest != entry["sha256"]
      end
      errors << "source inventory must include #{ARTIFACT_LOCK}" unless paths.include?(ARTIFACT_LOCK)
    end

    def validate_prior_milestones(manifest, directory, artifacts, errors)
      prior = manifest["prior_milestones"]
      unless prior.is_a?(Hash)
        errors << "COMPLETE M0 through M6 evidence is required for cumulative M8 completion"
        return
      end
      PRIOR_GATES.each do |name, gate_path|
        M4Gate.send(:validate_prior_milestone, name, prior[name], manifest, directory, artifacts, errors, gate_path)
      end
    end

    def report_document(name, specification, directory, artifact_index, errors)
      artifact = M4Gate.send(:find_named_artifact, specification.fetch(:names), artifact_index, errors, "#{name} report")
      return nil unless artifact

      path = M4Gate.send(:evidence_path, directory, artifact["path"])
      M4Gate.send(:parse_json, path, errors, "#{name} report")
    end

    def validate_report(name, document, kind, manifest, errors)
      unless document.is_a?(Hash)
        errors << "#{name} report must be an object"
        return
      end
      errors << "#{name} report schema_version must be #{REPORT_SCHEMA_VERSION}" unless document["schema_version"] == REPORT_SCHEMA_VERSION
      errors << "#{name} report milestone must be M8" unless document["milestone"] == "M8"
      errors << "#{name} report kind must be #{kind}" unless document["kind"] == kind
      errors << "#{name} report input_sha256 must match manifest" unless document["input_sha256"] == manifest["input_sha256"]
      errors << "#{name} report input_file_count must match manifest" unless document["input_file_count"] == manifest["input_file_count"]
      errors << "#{name} report must be available" unless document["available"] == true
      errors << "#{name} report status must be COMPLETE" unless document["status"] == "COMPLETE"
      errors << "#{name} report passed must be true" unless document["passed"] == true
      cases = document["cases"]
      unless cases.is_a?(Array) && !cases.empty?
        errors << "#{name} report cases must be a non-empty array"
        return
      end
      errors << "#{name} report case_count must equal the number of cases" unless document["case_count"] == cases.length
      errors << "#{name} report failed_count must be 0" unless document["failed_count"] == 0
      errors << "#{name} report passed_count must equal case_count" unless document["passed_count"] == cases.length
      cases.each_with_index do |entry, index|
        errors << "#{name} case #{index} must be an object with an id" unless entry.is_a?(Hash) && non_empty_string?(entry["id"])
        errors << "#{name} case #{entry.is_a?(Hash) ? entry["id"] : index} did not pass" unless entry.is_a?(Hash) && entry["passed"] == true
      end
      ids = cases.filter_map { |entry| entry.is_a?(Hash) ? entry["id"] : nil }
      errors << "#{name} case ids must be unique" unless ids.uniq.length == ids.length
      validate_sources(name, document, errors)
      validate_host(name, document, errors)
      send(:"validate_#{name}", document, cases, errors)
    end

    def validate_sources(name, document, errors)
      sources = document["sources"]
      unless sources.is_a?(Array) && !sources.empty?
        errors << "#{name} report must bind its source files"
        return
      end
      sources.each do |entry|
        unless entry.is_a?(Hash) && non_empty_string?(entry["path"]) && valid_digest?(entry["sha256"])
          errors << "#{name} report source entry is malformed"
          next
        end
        path = File.join(PROJECT_ROOT, entry["path"])
        errors << "#{name} source #{entry["path"]} is missing" unless File.file?(path)
        errors << "#{name} source #{entry["path"]} digest does not match the source tree" if File.file?(path) && Digest::SHA256.file(path).hexdigest != entry["sha256"]
      end
    end

    # Every M8 report is bound to a real KVM host and the pinned artifacts.
    def validate_host(name, document, errors)
      host = document["host"]
      unless host.is_a?(Hash)
        errors << "#{name} report must record the host facts"
        return
      end
      errors << "#{name} report must be measured on a KVM host" unless host["kvm"] == true && host["vhost_vsock"] == true
      errors << "#{name} report must record CPU virtualization support" unless %w[vmx svm].include?(host["cpu_virtualization"])
      artifacts = host["artifacts"]
      errors << "#{name} report must bind Firecracker #{FIRECRACKER_VERSION}" unless artifacts.is_a?(Hash) && artifacts["firecracker_version"] == FIRECRACKER_VERSION
      errors << "#{name} report must bind the artifact digest" unless artifacts.is_a?(Hash) && valid_digest?(artifacts["digest"]) && valid_digest?(artifacts["verity_root_hash"])
      lock = File.join(PROJECT_ROOT, ARTIFACT_LOCK)
      if File.file?(lock) && artifacts.is_a?(Hash)
        document = JSON.parse(File.read(lock))
        errors << "#{name} report verity root hash does not match the artifact lock" unless document.dig("verity", "root_hash") == artifacts["verity_root_hash"]
      end
    end

    # K1/K2: 446 selected, 446 passed, nothing failed, skipped or flaked, the
    # codename join is complete, and each of the three release profiles has the
    # required number of consecutive clean runs.
    def validate_conformance(document, cases, errors)
      by_id = cases.to_h { |entry| [entry["id"], entry] }
      CONFORMANCE_REQUIRED_PREFIXES.each do |prefix|
        errors << "conformance report must contain a #{prefix} case" unless cases.any? { |entry| entry["id"].to_s.start_with?(prefix) }
      end
      cases.select { |entry| entry["id"].to_s.start_with?("k1_totals-") }.each do |entry|
        summary = entry["summary"] || {}
        errors << "K1 run #{entry["id"]} must select #{EXPECTED_CONFORMANCE_TESTS} tests" unless summary["selected"] == EXPECTED_CONFORMANCE_TESTS
        errors << "K1 run #{entry["id"]} must pass #{EXPECTED_CONFORMANCE_TESTS} tests" unless summary["passed"] == EXPECTED_CONFORMANCE_TESTS
        %w[failed skipped flaked].each do |key|
          errors << "K1 run #{entry["id"]} must record #{key} 0" unless summary[key].to_i.zero?
        end
      end
      streaks = cases.select { |entry| entry["id"].to_s.start_with?("k1_consecutive_clean-") }
      errors << "K1 must record a clean-run streak for each of the #{REQUIRED_PROFILES} release profiles" unless streaks.length == REQUIRED_PROFILES
      streaks.each do |entry|
        errors << "profile #{entry["profile"]} needs #{REQUIRED_CLEAN_RUNS} consecutive clean K1 runs, has #{entry["clean_streak"]}" unless entry["clean_streak"].to_i >= REQUIRED_CLEAN_RUNS
      end
      errors << "K2 certified-conformance evidence is required" unless by_id.dig("k2_certified_conformance", "passed") == true
    end

    # K3/K4: every upstream spec classified exactly once, no forbidden
    # exclusion reason, every external contract linked to its replacement.
    def validate_selection(document, cases, errors)
      by_id = cases.to_h { |entry| [entry["id"], entry] }
      SELECTION_REQUIRED.each do |id|
        errors << "selection report must contain the #{id} case" unless by_id.key?(id)
      end
      errors << "selection ledger must classify every spec" unless by_id.dig("every_spec_classified_once", "unclassified").to_i.zero?
      errors << "selection ledger must not reuse a test id" unless by_id.dig("every_spec_classified_once", "duplicate_ids").to_i.zero?
      errors << "selection ledger must not exclude on a forbidden ground" unless by_id.dig("no_forbidden_exclusion_reason", "passed") == true
      errors << "every excluded external contract needs a replacement test" unless by_id.dig("external_contracts_have_replacements", "unlinked").to_i.zero?
      counts = document["counts"]
      errors << "selection report must carry the classification counts" unless counts.is_a?(Hash) && counts["required"].to_i.positive?
    end

    # K6: the client matrix covers the supported skew with checksum-pinned
    # binaries, and the project corpus meets every minimum with nothing on a
    # mutable tag.
    def validate_corpus(document, cases, errors)
      by_id = cases.to_h { |entry| [entry["id"], entry] }
      CORPUS_REQUIRED.each do |id|
        errors << "corpus report must contain the #{id} case" unless by_id.key?(id)
      end
      clients = Array(by_id.dig("client_matrix_pinned", "clients"))
      errors << "client matrix must pin at least the supported skew set" unless clients.length >= 3
      clients.each do |client|
        errors << "kubectl #{client["version"]} must be present" unless client["present"] == true
        errors << "kubectl #{client["version"]} checksum must match its published value" unless client["checksum_matches"] == true
      end
      errors << "corpus must contain at least 30 projects" unless by_id.dig("corpus_minimums", "total").to_i >= 30
      categories = by_id.dig("corpus_minimums", "categories") || {}
      {"helm-chart" => 10, "operator" => 10, "crd-webhook" => 5, "statefulset-pvc" => 5}.each do |category, minimum|
        errors << "corpus needs at least #{minimum} #{category} projects" unless categories[category].to_i >= minimum
      end
      errors << "corpus must cover every required domain" unless Array(by_id.dig("corpus_domain_coverage", "missing")).empty?
      errors << "every corpus project must pin its chart and image digests" unless Array(by_id.dig("corpus_fully_pinned", "unpinned")).empty?
      errors << "corpus projects must carry no Rubernetes-specific patch" unless by_id.dig("corpus_has_no_rubernetes_patch", "passed") == true
      errors << "the corpus must actually have been executed against a cluster" unless by_id.dig("k6_executed", "passed") == true
    end

    # K0/K5/K7 plus the milestone's "nothing was silenced" criterion.
    def validate_integrity(document, cases, errors)
      by_id = cases.to_h { |entry| [entry["id"], entry] }
      INTEGRITY_REQUIRED.each do |id|
        errors << "integrity report must contain the #{id} case" unless by_id.key?(id)
      end
      errors << "K0 input integrity must pass before any cluster is touched" unless by_id.dig("k0_input_integrity", "passed") == true
      violations = Array(by_id.dig("no_focus_narrowing_or_added_skip", "violations"))
      errors << "runs must not narrow focus, add skips or change mode: #{violations.first(3).inspect}" unless violations.empty?
      errors << "K5 differential must report zero differences" unless by_id.dig("k5_api_wire_differential", "passed") == true
      errors << "K7 upgrade and recovery must pass with no data loss or stuck operation" unless by_id.dig("k7_upgrade_and_recovery", "passed") == true
      errors << "the compatibility failure ledger must have no open item" unless by_id.dig("failure_ledger_has_no_open_items", "open").to_i.zero?
    end


    def validate_result_counts(manifest, artifacts, subjects, errors)
      counts = manifest["result_counts"]
      return unless counts.is_a?(Hash)

      errors << "result_counts.artifacts must match the artifact list" unless counts["artifacts"] == artifacts.length
      errors << "result_counts.subjects must match the subject list" unless counts["subjects"] == subjects.length
      errors << "result_counts.reports must be #{REPORTS.length}" unless counts["reports"] == REPORTS.length
      errors << "result_counts.command_failures must be 0" unless counts["command_failures"] == 0
      errors << "result_counts.commands must match the command list" unless counts["commands"] == Array(manifest["commands"]).length
      errors << "result_counts.source_files must match input_file_count" unless counts["source_files"] == manifest["input_file_count"]
    end

    def valid_digest?(value)
      value.is_a?(String) && value.match?(/\A[0-9a-f]{64}\z/)
    end

    def non_empty_string?(value)
      value.is_a?(String) && !value.empty?
    end

    def iso8601?(value)
      return false unless value.is_a?(String)

      Time.iso8601(value)
      true
    rescue ArgumentError
      false
    end
  end
end

if $PROGRAM_NAME == __FILE__
  manifest = ARGV.fetch(0) { abort("usage: m7_gate.rb <manifest.json>") }
  result = M8Gate.evaluate(manifest)
  puts JSON.pretty_generate(result)
  exit(result.fetch("passed") ? 0 : 1)
end
