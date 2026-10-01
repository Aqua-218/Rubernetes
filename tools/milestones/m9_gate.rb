#!/usr/bin/env ruby
# frozen_string_literal: true

# Validate the content-addressed M9 release evidence bundle.  M9 inherits the
# complete M0 -> M8 chain and requires the release-artifact report, the formal
# verification report, the operations report (performance, 72-hour soak,
# clean-host reproduction) and the supply-chain report.  A soak shorter than
# 72 hours, a rebuild that is not byte-identical, a Lean escape hatch, a
# benchmark with no oracle to compare against, an unpinned input or a Ruby
# ratio below 85% is rejected; none of these may be waived by a summary field.
require "digest"
require "json"
require "time"
require_relative "m8_gate"
require_relative "m3_evidence_support"

module M9Gate
  MANIFEST_SCHEMA_VERSION = 3
  REPORT_SCHEMA_VERSION = 1
  SOURCE_EXCLUDED_ROOTS = M4Gate::SOURCE_EXCLUDED_ROOTS
  SOURCE_EXCLUDED_PATTERNS = M4Gate::SOURCE_EXCLUDED_PATTERNS
  PROJECT_ROOT = File.expand_path("../..", __dir__).freeze
  PRIOR_GATES = M7Gate::PRIOR_GATES.merge("M9" => File.join(__dir__, "m7_gate.rb")).freeze
  ARTIFACT_LOCK = "third_party/locks/kubernetes-v1.36.2.json"

  REPORTS = {
    "release" => {kind: "m9_release_artifacts", names: %w[release-artifacts.json]},
    "formal" => {kind: "m9_formal_verification", names: %w[formal-verification.json]},
    "operations" => {kind: "m9_operations", names: %w[operations-report.json]},
    "supply_chain" => {kind: "m9_supply_chain", names: %w[supply-chain-report.json]}
  }.freeze
  REQUIRED_REPORTS = REPORTS

  RELEASE_REQUIRED = %w[release_manifest_present release_manifest_binds_source sbom_present
                        sbom_pins_every_component rebuild_is_byte_identical clean_host_rebuild_attached
                        ruby_ratio_at_least_85_percent].freeze
  FORMAL_REQUIRED = %w[lean_sources_present lean_has_no_escape_hatch lean_proofs_compile
                       model_checked_claims_have_a_run every_claim_states_its_level].freeze
  OPERATIONS_REQUIRED = %w[benchmark_against_oracle soak_ran_for_the_required_duration
                           soak_found_no_defect clean_host_reproduction].freeze
  SUPPLY_CHAIN_REQUIRED = %w[security_report_present no_critical_or_high_findings].freeze
  REQUIRED_SOAK_HOURS = 72
  REQUIRED_RUBY_RATIO = 0.85

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
      {"schema_version" => 1, "milestone" => "M9", "passed" => errors.empty?, "error_count" => errors.length, "errors" => errors}
    end

    def validate_manifest_shape(manifest, errors)
      errors << "schema_version must be #{MANIFEST_SCHEMA_VERSION}" unless manifest["schema_version"] == MANIFEST_SCHEMA_VERSION
      errors << "milestone must be M9" unless manifest["milestone"] == "M9"
      errors << "input_sha256 must be a SHA-256 digest" unless valid_digest?(manifest["input_sha256"])
      errors << "input_file_count must be positive" unless manifest["input_file_count"].is_a?(Integer) && manifest["input_file_count"].positive?
      errors << "source input must remain stable during evidence capture" unless manifest["input_stable"] == true
      host = manifest["host"]
      errors << "host architecture, kernel, and Ruby description are required" unless host.is_a?(Hash) && %w[architecture kernel
                                                                                                             ruby].all? do |key|
        non_empty_string?(host[key])
      end
      errors << "M9 evidence must be captured on x86_64" unless host.is_a?(Hash) && host["architecture"] == "x86_64"
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

      errors << "source inventory kind must be m9_source_inventory" unless document["kind"] == "m9_source_inventory"
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
        if File.file?(path) && Digest::SHA256.file(path).hexdigest != entry["sha256"]
          errors << "source inventory digest mismatch #{entry.fetch("path")}"
        end
      end
      errors << "source inventory must include #{ARTIFACT_LOCK}" unless paths.include?(ARTIFACT_LOCK)
    end

    def validate_prior_milestones(manifest, directory, artifacts, errors)
      prior = manifest["prior_milestones"]
      unless prior.is_a?(Hash)
        errors << "COMPLETE M0 through M8 evidence is required for cumulative M9 completion"
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
      errors << "#{name} report milestone must be M9" unless document["milestone"] == "M9"
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
        if File.file?(path) && Digest::SHA256.file(path).hexdigest != entry["sha256"]
          errors << "#{name} source #{entry["path"]} digest does not match the source tree"
        end
      end
    end

    # Every M9 report is bound to the host that produced it and the pinned inputs.
    def validate_host(name, document, errors)
      host = document["host"]
      unless host.is_a?(Hash)
        errors << "#{name} report must record the host facts"
        return
      end
      errors << "#{name} report must be measured on a KVM host" unless host["kvm"] == true && host["vhost_vsock"] == true
      errors << "#{name} report must record CPU virtualization support" unless %w[vmx svm].include?(host["cpu_virtualization"])
      artifacts = host["artifacts"]
      unless artifacts.is_a?(Hash) && artifacts["firecracker_version"] == FIRECRACKER_VERSION
        errors << "#{name} report must bind Firecracker #{FIRECRACKER_VERSION}"
      end
      unless artifacts.is_a?(Hash) && valid_digest?(artifacts["digest"]) && valid_digest?(artifacts["verity_root_hash"])
        errors << "#{name} report must bind the artifact digest"
      end
      lock = File.join(PROJECT_ROOT, ARTIFACT_LOCK)
      return unless File.file?(lock) && artifacts.is_a?(Hash)

      document = JSON.parse(File.read(lock))
      errors << "#{name} report verity root hash does not match the artifact lock" unless document.dig("verity",
                                                                                                       "root_hash") == artifacts["verity_root_hash"]
    end

    # Release artifacts: the manifest binds the source, the SBOM pins every
    # component, the rebuild is byte-identical, and the Ruby ratio holds.
    def validate_release(_document, cases, errors)
      by_id = cases.to_h { |entry| [entry["id"], entry] }
      RELEASE_REQUIRED.each { |id| errors << "release report must contain the #{id} case" unless by_id.key?(id) }
      errors << "release manifest must bind a source input digest" unless by_id.dig("release_manifest_binds_source", "passed") == true
      unpinned = Array(by_id.dig("sbom_pins_every_component", "unpinned"))
      errors << "SBOM components must all be pinned: #{unpinned.first(3).inspect}" unless unpinned.empty?
      errors << "the rebuild must be byte-identical" unless by_id.dig("rebuild_is_byte_identical", "passed") == true
      errors << "an independent clean-host rebuild must be attached" unless by_id.dig("clean_host_rebuild_attached", "passed") == true
      ratio = by_id.dig("ruby_ratio_at_least_85_percent", "ruby_ratio").to_f
      errors << "Ruby ratio #{ratio} is below the required #{REQUIRED_RUBY_RATIO}" unless ratio >= REQUIRED_RUBY_RATIO
    end

    # Formal verification: no Lean escape hatch, every proof compiles, and no
    # claim asserts a level it cannot support.
    def validate_formal(_document, cases, errors)
      by_id = cases.to_h { |entry| [entry["id"], entry] }
      FORMAL_REQUIRED.each { |id| errors << "formal report must contain the #{id} case" unless by_id.key?(id) }
      occurrences = Array(by_id.dig("lean_has_no_escape_hatch", "occurrences"))
      errors << "Lean sources must contain no sorry/admit/native_decide: #{occurrences.first(3).inspect}" unless occurrences.empty?
      errors << "every Lean proof must compile" unless by_id.dig("lean_proofs_compile", "passed") == true
      errors << "every model_checked claim must name its run and report no counterexample" unless by_id.dig(
        "model_checked_claims_have_a_run", "passed"
      ) == true
      errors << "every claim must state its assurance level" unless by_id.dig("every_claim_states_its_level", "passed") == true
    end

    # Operations: the benchmark is a comparison, the soak actually ran for 72
    # hours, and the clean-host reproduction happened.
    def validate_operations(_document, cases, errors)
      by_id = cases.to_h { |entry| [entry["id"], entry] }
      OPERATIONS_REQUIRED.each { |id| errors << "operations report must contain the #{id} case" unless by_id.key?(id) }
      errors << "the benchmark must compare against a Kubernetes v1.36.2 oracle" unless by_id.dig("benchmark_against_oracle",
                                                                                                  "passed") == true
      elapsed = by_id.dig("soak_ran_for_the_required_duration", "elapsed_hours").to_f
      errors << "soak ran #{elapsed} h, the criterion is #{REQUIRED_SOAK_HOURS} h" unless elapsed >= REQUIRED_SOAK_HOURS
      findings = by_id.dig("soak_found_no_defect", "findings") || {}
      findings.each do |kind, count|
        errors << "soak recorded #{count} #{kind}" unless count.to_i.zero?
      end
      errors << "a clean-host reproduction of the release is required" unless by_id.dig("clean_host_reproduction", "passed") == true
    end

    # Supply chain: no critical/high finding, nothing unpinned, no claim
    # without a level, no undated work note.
    def validate_supply_chain(_document, cases, errors)
      by_id = cases.to_h { |entry| [entry["id"], entry] }
      SUPPLY_CHAIN_REQUIRED.each { |id| errors << "supply chain report must contain the #{id} case" unless by_id.key?(id) }
      errors << "release must have zero critical or high security findings" unless by_id.dig("no_critical_or_high_findings",
                                                                                             "critical_or_high").to_i.zero?
      cases.select { |entry| entry["id"].to_s.start_with?("security-") }.each do |entry|
        errors << "#{entry.fetch("id")} did not pass: #{entry["detail"]}" unless entry.fetch("passed") == true
      end
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
  result = M9Gate.evaluate(manifest)
  puts JSON.pretty_generate(result)
  exit(result.fetch("passed") ? 0 : 1)
end
