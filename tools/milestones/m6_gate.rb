#!/usr/bin/env ruby
# frozen_string_literal: true

# Validate the content-addressed M6 complete-API-surface evidence bundle.
# M6 inherits the complete M0 -> M5 chain and requires the API coverage
# ledger, feature-gate matrix, CRD/aggregation differential, webhook
# differential, security pipeline trace and fuzz summary.  Every report must
# be a real measurement against the pinned kube-apiserver oracle or the
# production pipeline: a differential without the oracle's execution record,
# a coverage ledger with missing operations, a profile with API differences,
# a pipeline trace whose stage order deviates, or a fuzz corpus with any
# panic, hang or policy bypass is rejected.

require "digest"
require "json"
require "time"
require_relative "m5_gate"
require_relative "m3_evidence_support"

module M6Gate
  MANIFEST_SCHEMA_VERSION = 3
  REPORT_SCHEMA_VERSION = 1
  SOURCE_EXCLUDED_ROOTS = M4Gate::SOURCE_EXCLUDED_ROOTS
  SOURCE_EXCLUDED_PATTERNS = M4Gate::SOURCE_EXCLUDED_PATTERNS
  PROJECT_ROOT = File.expand_path("../..", __dir__).freeze
  PRIOR_GATES = M5Gate::PRIOR_GATES.merge("M5" => File.join(__dir__, "m5_gate.rb")).freeze

  REPORTS = {
    "api_coverage" => {kind: "m6_api_coverage_ledger", names: %w[api-coverage-ledger.json]},
    "feature_gate" => {kind: "m6_feature_gate_matrix", names: %w[feature-gate-matrix.json]},
    "crd" => {kind: "m6_crd_aggregation_differential", names: %w[crd-aggregation-differential.json]},
    "webhook" => {kind: "m6_webhook_differential", names: %w[webhook-differential.json]},
    "security" => {kind: "m6_security_pipeline_trace", names: %w[security-pipeline-trace.json]},
    "fuzz" => {kind: "m6_fuzz_summary", names: %w[fuzz-summary.json]}
  }.freeze
  REQUIRED_REPORTS = REPORTS

  API_COVERAGE_REQUIRED = %w[discovery_missing_resources discovery_missing_verbs_or_fields discovery_extra_resources
                             openapi_operations openapi_v3_index_served protobuf_descriptors].freeze
  MIN_DISCOVERY_DOCUMENTS = 40
  MIN_UPSTREAM_OPENAPI_PATHS = 500
  FEATURE_PROFILES = %w[profile-default profile-all-beta profile-alpha-apis].freeze
  MIN_FEATURE_GATES = 200
  CRD_REQUIRED = %w[create_crd wait_established get_crd_conditions discovery_group discovery_v1 openapi_v3 create_invalid_min
                    create_missing_required create_bad_enum create_cel_violation create_duplicate_set_item create_ok get_ok get_via_v2
                    list status_update get_after_status patch_merge create_apiservice wait_apiservice discovery_with_apiservice
                    aggregated_unavailable delete_apiservice delete_crd wait_gone get_after_delete].freeze
  WEBHOOK_REQUIRED = %w[validating_allow validating_deny timeout_fail_policy timeout_ignore_policy mutating_patch_and_warning
                        reinvocation_if_needed reinvocation_never match_policy_exact_misses_other_version match_conditions_skip
                        unsupported_review_version dry_run_side_effects_unknown object_selector_excludes].freeze
  SECURITY_REQUIRED = %w[stage_order_create invalid_credentials_stop_at_authentication unauthorized_user_stops_before_admission_and_store
                         forbidden_before_not_found validating_admission_rejects_after_mutation_before_store
                         malformed_body_is_400_without_internal_detail audit_records_every_outcome_without_credentials].freeze
  SECURITY_STAGE_ORDER = %w[authentication audit.RequestReceived authorization flow_control admission.mutating admission.validating
                            store.create audit.ResponseComplete].freeze
  MIN_FUZZ_CASES = 100
  ORACLE_FIELDS = %w[executed kubernetes_version source_commit kube_apiserver_image etcd_image container_execution].freeze
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
      {"schema_version" => 1, "milestone" => "M6", "passed" => errors.empty?, "error_count" => errors.length, "errors" => errors}
    end

    def validate_manifest_shape(manifest, errors)
      errors << "schema_version must be #{MANIFEST_SCHEMA_VERSION}" unless manifest["schema_version"] == MANIFEST_SCHEMA_VERSION
      errors << "milestone must be M6" unless manifest["milestone"] == "M6"
      errors << "input_sha256 must be a SHA-256 digest" unless valid_digest?(manifest["input_sha256"])
      errors << "input_file_count must be positive" unless manifest["input_file_count"].is_a?(Integer) && manifest["input_file_count"].positive?
      errors << "source input must remain stable during evidence capture" unless manifest["input_stable"] == true
      host = manifest["host"]
      errors << "host architecture, kernel, and Ruby description are required" unless host.is_a?(Hash) && %w[architecture kernel
                                                                                                             ruby].all? do |key|
        non_empty_string?(host[key])
      end
      errors << "M6 evidence must be captured on x86_64" unless host.is_a?(Hash) && host["architecture"] == "x86_64"
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

      errors << "source inventory kind must be m6_source_inventory" unless document["kind"] == "m6_source_inventory"
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
    end

    def validate_prior_milestones(manifest, directory, artifacts, errors)
      prior = manifest["prior_milestones"]
      unless prior.is_a?(Hash)
        errors << "COMPLETE M0, M1, M2, M3, M4, and M5 evidence is required for cumulative M6 completion"
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
      errors << "#{name} report milestone must be M6" unless document["milestone"] == "M6"
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
      send(:"validate_#{name}", document, cases, errors)
    end

    # Every report binds the implementation files it measured; the digests
    # must match the source tree the manifest describes.
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

    def validate_oracle(name, document, errors)
      oracle = document["oracle"]
      unless oracle.is_a?(Hash)
        errors << "#{name} differential must record the kube-apiserver oracle execution"
        return
      end
      ORACLE_FIELDS.each { |field| errors << "#{name} oracle record is missing #{field}" if oracle[field].nil? }
      errors << "#{name} oracle must have executed" unless oracle["executed"] == true
      errors << "#{name} oracle must be the pinned v1.36.2 kube-apiserver" unless oracle["kubernetes_version"].to_s.start_with?("v1.36.2")
      errors << "#{name} oracle must pin images by digest" unless %w[kube_apiserver_image etcd_image].all? do |key|
        oracle[key].to_s.include?("@sha256:")
      end
      return if oracle["container_execution"].is_a?(Array) && !oracle["container_execution"].empty?

      errors << "#{name} oracle must record container execution"
    end

    def validate_differential_cases(name, cases, required, errors)
      ids = cases.map { |entry| entry["id"] }
      required.each { |id| errors << "#{name} differential is missing case #{id}" unless ids.include?(id) }
      cases.each do |entry|
        errors << "#{name} case #{entry["id"]} must record the oracle observation" if entry["oracle"].nil?
        errors << "#{name} case #{entry["id"]} must record the rubernetes observation" if entry["rubernetes"].nil?
        errors << "#{name} case #{entry["id"]} observations differ" unless entry["oracle"] == entry["rubernetes"]
      end
    end

    def validate_api_coverage(document, cases, errors)
      errors << "API coverage ledger must be differentially tested" unless document["measurement_level"] == "differentially_tested"
      ids = cases.map { |entry| entry["id"] }
      API_COVERAGE_REQUIRED.each { |id| errors << "API coverage ledger is missing case #{id}" unless ids.include?(id) }
      discovery = cases.count { |entry| entry["id"].to_s.start_with?("discovery:") }
      errors << "API coverage ledger must compare at least #{MIN_DISCOVERY_DOCUMENTS} discovery documents" unless discovery >= MIN_DISCOVERY_DOCUMENTS
      %w[discovery_missing_resources discovery_missing_verbs_or_fields].each do |id|
        entry = cases.find { |candidate| candidate["id"] == id }
        errors << "#{id} must list zero missing items" unless entry && Array(entry["missing"]).empty?
      end
      extra = cases.find { |entry| entry["id"] == "discovery_extra_resources" }
      errors << "discovery_extra_resources must list zero extra resources" unless extra && Array(extra["extra"]).empty?
      openapi = cases.find { |entry| entry["id"] == "openapi_operations" }
      unless openapi && openapi["upstream_paths"].to_i >= MIN_UPSTREAM_OPENAPI_PATHS
        errors << "openapi_operations must cover at least #{MIN_UPSTREAM_OPENAPI_PATHS} upstream paths"
      end
      errors << "openapi_operations must report zero missing operations" unless openapi && openapi["missing_count"] == 0 && Array(openapi["missing"]).empty?
      protobuf = cases.find { |entry| entry["id"] == "protobuf_descriptors" }
      errors << "protobuf_descriptors must count the corpus messages" unless protobuf && protobuf["descriptor_messages"].to_i.positive?
      return if document["upstream_group_versions"].to_i >= MIN_DISCOVERY_DOCUMENTS

      errors << "API coverage ledger must record the upstream group/version count"
    end

    def validate_feature_gate(document, cases, errors)
      errors << "feature-gate matrix must be differentially tested" unless document["measurement_level"] == "differentially_tested"
      FEATURE_PROFILES.each do |id|
        entry = cases.find { |candidate| candidate["id"] == id }
        errors << "feature-gate matrix is missing #{id}" unless entry
        next unless entry

        errors << "#{id} must report zero API differences" unless entry["difference_count"] == 0 && Array(entry["differences"]).empty?
        errors << "#{id} must compare discovery documents" unless entry["documents_compared"].to_i >= MIN_DISCOVERY_DOCUMENTS
      end
      corpus = cases.find { |entry| entry["id"] == "gate_corpus" }
      errors << "feature-gate matrix must record at least #{MIN_FEATURE_GATES} corpus gates" unless corpus && corpus["gate_count"].to_i >= MIN_FEATURE_GATES
      profiles = document["profiles"]
      errors << "feature-gate matrix must describe the default, all-beta and alpha-apis profiles" unless profiles.is_a?(Hash) && %w[default
                                                                                                                                    all-beta alpha-apis].all? do |key|
        profiles.key?(key)
      end
    end

    def validate_crd(document, cases, errors)
      errors << "CRD/aggregation differential must be differentially tested" unless document["measurement_level"] == "differentially_tested"
      validate_oracle("CRD/aggregation", document, errors)
      validate_differential_cases("CRD/aggregation", cases, CRD_REQUIRED, errors)
      established = cases.find { |entry| entry["id"] == "get_crd_conditions" }
      conditions = established && established.dig("rubernetes", "conditions")
      errors << "CRD differential must observe an Established CRD" unless conditions.is_a?(Array) && conditions.any? do |condition|
        condition["type"] == "Established" && condition["status"] == "True"
      end
      unavailable = cases.find { |entry| entry["id"] == "aggregated_unavailable" }
      errors << "aggregated_unavailable must observe 503 from both servers" unless unavailable && unavailable.dig("rubernetes",
                                                                                                                  "status") == 503 && unavailable.dig(
                                                                                                                    "oracle", "status"
                                                                                                                  ) == 503
    end

    def validate_webhook(document, cases, errors)
      errors << "webhook differential must be differentially tested" unless document["measurement_level"] == "differentially_tested"
      validate_oracle("webhook", document, errors)
      validate_differential_cases("webhook", cases, WEBHOOK_REQUIRED, errors)
      unless non_empty_string?(document["docker_gateway"])
        errors << "webhook differential must record the docker gateway used by the oracle"
      end
      timeout = cases.find { |entry| entry["id"] == "timeout_fail_policy" }
      errors << "timeout_fail_policy must observe a 500 InternalError on both servers" unless timeout && timeout.dig("rubernetes",
                                                                                                                     "status") == 500 && timeout.dig(
                                                                                                                       "rubernetes", "reason"
                                                                                                                     ) == "InternalError"
      ignore = cases.find { |entry| entry["id"] == "timeout_ignore_policy" }
      errors << "timeout_ignore_policy must observe a successful create" unless ignore && ignore.dig("rubernetes", "status") == 201
      reinvoke = cases.find { |entry| entry["id"] == "reinvocation_if_needed" }
      errors << "reinvocation_if_needed must observe two invocations" unless reinvoke && reinvoke.dig("rubernetes", "calls", "/count") == 2
    end

    def validate_security(document, cases, errors)
      errors << "security pipeline trace must be integration tested" unless document["measurement_level"] == "integration_tested"
      ids = cases.map { |entry| entry["id"] }
      SECURITY_REQUIRED.each { |id| errors << "security pipeline trace is missing case #{id}" unless ids.include?(id) }
      order = cases.find { |entry| entry["id"] == "stage_order_create" }
      unless order && order["observed"] == SECURITY_STAGE_ORDER && order["expected"] == SECURITY_STAGE_ORDER
        errors << "stage_order_create must observe the specified stage order"
      end
      unauthorized = cases.find { |entry| entry["id"] == "invalid_credentials_stop_at_authentication" }
      unless unauthorized && unauthorized["status"] == 401 && unauthorized["www_authenticate"] == "Bearer"
        errors << "invalid credentials must yield 401 with WWW-Authenticate"
      end
      forbidden = cases.find { |entry| entry["id"] == "unauthorized_user_stops_before_admission_and_store" }
      errors << "unauthorized principals must yield 403 before admission" unless forbidden && forbidden["status"] == 403
      hidden = cases.find { |entry| entry["id"] == "forbidden_before_not_found" }
      errors << "forbidden must be reported before not found" unless hidden && hidden["status"] == 403
      audit = cases.find { |entry| entry["id"] == "audit_records_every_outcome_without_credentials" }
      errors << "audit trace must record every outcome" unless audit && audit["events"].to_i >= 6
      errors << "security pipeline trace must list the specified order" unless Array(document["specified_order"]).length >= 10
    end

    def validate_fuzz(document, cases, errors)
      errors << "fuzz summary must be integration tested" unless document["measurement_level"] == "integration_tested"
      errors << "fuzz summary must record its seed" unless document["seed"].is_a?(Integer)
      errors << "fuzz summary must exercise at least #{MIN_FUZZ_CASES} cases" unless cases.length >= MIN_FUZZ_CASES
      errors << "fuzz summary must observe zero panics" unless document["panics"] == 0
      errors << "fuzz summary must observe zero hangs" unless document["hangs"] == 0
      errors << "fuzz summary must observe zero policy bypasses" unless document["policy_bypasses"] == 0
      errors << "fuzz crash corpus must be empty" unless document["crash_corpus"].is_a?(Array) && document["crash_corpus"].empty?
      cases.each do |entry|
        errors << "fuzz case #{entry["id"]} panicked" if entry["panic"] == true
        errors << "fuzz case #{entry["id"]} hung" if entry["hang"] == true
        errors << "fuzz case #{entry["id"]} leaked internal detail" if entry["internal_leak"] == true
      end
      bypass = cases.select { |entry| entry["id"].to_s.start_with?("bypass-") }
      errors << "fuzz summary must replay malformed input as an unauthorized principal" unless bypass.length >= 6
      %w[body-invalid_utf8-post body-oversized-post body-duplicate_keys-post body-deep_nesting-post negotiation-0 path-1].each do |id|
        errors << "fuzz summary is missing case #{id}" unless cases.any? { |entry| entry["id"] == id }
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
  manifest = ARGV.fetch(0) { abort("usage: m6_gate.rb <manifest.json>") }
  result = M6Gate.evaluate(manifest)
  puts JSON.pretty_generate(result)
  exit(result.fetch("passed") ? 0 : 1)
end
