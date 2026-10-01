#!/usr/bin/env ruby
# frozen_string_literal: true

# Validate the content-addressed M5 durable-high-availability evidence bundle.
# M5 inherits the complete M0 -> M4 chain and requires the
# linearizability histories, fault matrix, WAL/snapshot corruption corpus,
# RTO/RPO report and resource ownership ledger.  Every report must be a
# real measurement: scope below the specification minimum, a history that
# exercised no faults, a fault case without real-process SIGKILL provenance,
# or a corruption case that did not fail closed is rejected.

require "digest"
require "json"
require "time"
require_relative "m4_gate"
require_relative "m3_evidence_support"

module M5Gate
  MANIFEST_SCHEMA_VERSION = 3
  REPORT_SCHEMA_VERSION = 1
  MAX_JSON_BYTES = 64 * 1024 * 1024
  SOURCE_EXCLUDED_ROOTS = M4Gate::SOURCE_EXCLUDED_ROOTS
  SOURCE_EXCLUDED_PATTERNS = M4Gate::SOURCE_EXCLUDED_PATTERNS
  PROJECT_ROOT = File.expand_path("../..", __dir__).freeze
  PRIOR_GATES = {
    "M0" => File.join(__dir__, "m0_gate.rb"),
    "M1" => File.join(__dir__, "m1_gate.rb"),
    "M2" => File.join(__dir__, "m2_gate.rb"),
    "M3" => File.join(__dir__, "m3_gate.rb"),
    "M4" => File.join(__dir__, "m4_gate.rb")
  }.freeze

  REPORTS = {
    "linearizability" => {kind: "m5_linearizability_histories", names: %w[linearizability-histories.json]},
    "fault_matrix" => {kind: "m5_fault_matrix", names: %w[fault-matrix.json]},
    "corruption" => {kind: "m5_corruption_corpus", names: %w[wal-snapshot-corruption-corpus.json]},
    "rto_rpo" => {kind: "m5_rto_rpo_report", names: %w[rto-rpo-report.json]},
    "ownership" => {kind: "m5_resource_ownership_ledger", names: %w[resource-ownership-ledger.json]}
  }.freeze
  REQUIRED_REPORTS = REPORTS

  # The TLA+ model stays in the source inventory even though no model-checking
  # report is required; see verification/claims.yml for what backs the Raft claims.
  TLA_SOURCES = %w[verification/tla/Raft.tla verification/tla/Raft.cfg].freeze
  LINEARIZABILITY_FAULTS = %w[partition asymmetric_partition reorder duplicate loss crash_restart clock_jump].freeze
  FAULT_MATRIX_REQUIRED = %w[3_nodes_1_failures 5_nodes_2_failures membership_change_leader_loss snapshot_install_leader_loss].freeze
  CORRUPTION_REQUIRED = %w[wal_bit_flip_middle wal_torn_tail wal_length_overflow snapshot_truncated snapshot_state_bit_flip
                           short_write fail_fsync wal_disk_full_tmpfs backup_restore_round_trip].freeze
  OWNERSHIP_REQUIRED_COMPONENTS = %w[raft_store native_runtime controller volume network].freeze
  OWNERSHIP_REQUIRED_RAFT_EFFECTS = %w[create update delete].freeze
  RTO_LIMIT_SECONDS = 60
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
      {"schema_version" => 1, "milestone" => "M5", "passed" => errors.empty?, "error_count" => errors.length, "errors" => errors}
    end

    def validate_manifest_shape(manifest, errors)
      errors << "schema_version must be #{MANIFEST_SCHEMA_VERSION}" unless manifest["schema_version"] == MANIFEST_SCHEMA_VERSION
      errors << "milestone must be M5" unless manifest["milestone"] == "M5"
      errors << "input_sha256 must be a SHA-256 digest" unless valid_digest?(manifest["input_sha256"])
      errors << "input_file_count must be positive" unless manifest["input_file_count"].is_a?(Integer) && manifest["input_file_count"].positive?
      errors << "source input must remain stable during evidence capture" unless manifest["input_stable"] == true
      host = manifest["host"]
      errors << "host architecture, kernel, and Ruby description are required" unless host.is_a?(Hash) && %w[architecture kernel
                                                                                                             ruby].all? do |key|
        non_empty_string?(host[key])
      end
      errors << "M5 evidence must be captured on x86_64" unless host.is_a?(Hash) && host["architecture"] == "x86_64"
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

      errors << "source inventory kind must be m5_source_inventory" unless document["kind"] == "m5_source_inventory"
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
      # The formal sources are part of the input and must be exactly the
      # files the model-checking sources are pinned against.
      TLA_SOURCES.each { |source| errors << "source inventory must include #{source}" unless paths.include?(source) }
    end

    def validate_prior_milestones(manifest, directory, artifacts, errors)
      prior = manifest["prior_milestones"]
      unless prior.is_a?(Hash)
        errors << "COMPLETE M0, M1, M2, M3, and M4 evidence is required for cumulative M5 completion"
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
      errors << "#{name} report milestone must be M5" unless document["milestone"] == "M5"
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
      send(:"validate_#{name}", document, cases, errors)
    end

    def validate_linearizability(_document, cases, errors)
      histories = cases.select { |entry| entry["id"].to_s.start_with?("history-") }
      errors << "linearizability report needs at least 10 histories" unless histories.length >= 10
      oracle = cases.find { |entry| entry["id"] == "lean_sequential_oracle" }
      errors << "linearizability report must include the Lean sequential oracle differential" unless oracle
      unless oracle && oracle["compared_operations"].to_i >= 100 && oracle["mismatches"] == 0
        errors << "Lean oracle differential must compare at least 100 operations with 0 mismatches"
      end
      coverage = cases.find { |entry| entry["id"] == "fault_coverage" }
      errors << "linearizability report must record fault coverage" unless coverage
      if coverage
        faults = coverage["faults"] || {}
        LINEARIZABILITY_FAULTS.each do |fault|
          errors << "linearizability histories never exercised #{fault}" unless faults[fault].to_i.positive?
        end
      end
      histories.each do |entry|
        errors << "history #{entry["id"]} is not linearizable" unless entry["linearizable"] == true
        events = entry["events"] || {}
        errors << "history #{entry["id"]} has too few completed operations" unless events["ok"].to_i >= 10
        errors << "history #{entry["id"]} must include its raw events" unless entry["history"].is_a?(Array) && entry["history"].length == events.values.sum
        if entry["history"].is_a?(Array) && M34EvidenceSupport.canonical_document_digest(entry["history"]) != entry["history_sha256"]
          errors << "history #{entry["id"]} digest mismatch"
        end
      end
    end

    def validate_fault_matrix(_document, cases, errors)
      ids = cases.map { |entry| entry["id"] }
      FAULT_MATRIX_REQUIRED.each { |id| errors << "fault matrix is missing case #{id}" unless ids.include?(id) }
      cases.each do |entry|
        errors << "fault case #{entry["id"]} must come from real processes under SIGKILL" unless entry["measurement_source"] == "real_processes_sigkill"
        next unless entry["id"].to_s.end_with?("_failures")

        errors << "fault case #{entry["id"]} must acknowledge writes before the fault" unless entry["acknowledged_writes"].to_i >= 100
        errors << "fault case #{entry["id"]} lost acknowledged writes" unless entry["lost_acknowledged_writes"] == 0
        unless entry["rto_seconds"].is_a?(Numeric) && entry["rto_seconds"] < RTO_LIMIT_SECONDS
          errors << "fault case #{entry["id"]} exceeded the #{RTO_LIMIT_SECONDS}s recovery bound"
        end
        errors << "fault case #{entry["id"]} replicas diverged" unless entry["replica_state_identical"] == true
      end
      membership = cases.find { |entry| entry["id"] == "membership_change_leader_loss" }
      errors << "membership case must observe zero split brain" unless membership && membership["split_brain"] == false
      snapshot = cases.find { |entry| entry["id"] == "snapshot_install_leader_loss" }
      return if snapshot && snapshot["snapshot_installs_on_new_node"].to_i.positive?

      errors << "snapshot case must observe a real snapshot install"
    end

    def validate_corruption(_document, cases, errors)
      ids = cases.map { |entry| entry["id"] }
      CORRUPTION_REQUIRED.each { |id| errors << "corruption corpus is missing case #{id}" unless ids.include?(id) }
      cases.each do |entry|
        next unless entry.key?("fail_closed")

        errors << "corruption case #{entry["id"]} did not fail closed" unless entry["fail_closed"] == true
        errors << "corruption case #{entry["id"]} must name its error class" unless non_empty_string?(entry["error"])
      end
      disk_full = cases.find { |entry| entry["id"] == "wal_disk_full_tmpfs" }
      unless disk_full && disk_full["measurement_level"] == "L2" && disk_full["tmpfs_size"]
        errors << "disk-full case must be measured on a real size-limited tmpfs (L2)"
      end
      return if disk_full && disk_full["durable_entries_after_reopen"] == disk_full["acknowledged_entries"]

      errors << "disk-full case lost acknowledged entries"
    end

    def validate_rto_rpo(_document, cases, errors)
      main = cases.find { |entry| entry["id"] == "quorum_loss_two_of_three_apiservers" }
      unless main
        errors << "RTO/RPO report must contain quorum_loss_two_of_three_apiservers"
        return
      end
      unless main["measurement_source"] == "real_apiserver_and_controller_manager_processes"
        errors << "RTO/RPO case must run real apiserver and controller-manager processes"
      end
      errors << "RPO must be 0 objects" unless main["rpo_objects"] == 0 && main["lost_acknowledged_writes"] == 0
      %w[read_resumed_seconds write_resumed_seconds control_loop_resumed_seconds].each do |key|
        errors << "#{key} must be below #{RTO_LIMIT_SECONDS}s" unless main[key].is_a?(Numeric) && main[key] < RTO_LIMIT_SECONDS
      end
      errors << "writes must not be acknowledged during quorum loss" unless main.dig("write_during_outage", "acknowledged") == false
      errors << "readyz must fail during quorum loss" unless main["readyz_during_outage"] == false
      errors << "control loop must have reconciled before the fault" unless main["control_loop_reconciled_before_fault"] == true
      errors << "at least 20 writes must be acknowledged before the fault" unless main["acknowledged_before_fault"].to_i >= 20
      counts = main["replica_object_counts"]
      return if counts.is_a?(Array) && counts.length == 3 && counts.uniq.length == 1

      errors << "replicas must hold the same object count after recovery"
    end

    def validate_ownership(document, cases, errors)
      components = cases.map { |entry| entry["component"] }.uniq
      OWNERSHIP_REQUIRED_COMPONENTS.each do |component|
        errors << "ownership ledger is missing component #{component}" unless components.include?(component)
      end
      raft_effects = cases.select { |entry| entry["component"] == "raft_store" }.map { |entry| entry["effect"] }
      OWNERSHIP_REQUIRED_RAFT_EFFECTS.each do |effect|
        errors << "ownership ledger is missing raft_store #{effect}" unless raft_effects.include?(effect)
      end
      cases.select { |entry| entry["component"] == "raft_store" }.each do |entry|
        errors << "raft_store #{entry["effect"]} must classify request loss" unless entry["request_loss_classification"] == "request_loss"
        unless entry["response_loss_classification"] == "response_loss"
          errors << "raft_store #{entry["effect"]} must classify response loss"
        end
        unless entry["request_loss_effect_count"] == 1 && entry["response_loss_retry_effect_count"] == 0
          errors << "raft_store #{entry["effect"]} re-execution must apply exactly once"
        end
        unless entry["measurement_source"] == "real_raft_cluster_tls"
          errors << "raft_store #{entry["effect"]} must be measured on a real TLS cluster"
        end
      end
      points = document["effect_points"]
      errors << "ownership ledger must enumerate its effect points" unless points.is_a?(Array) && points.length >= 7
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
  manifest = ARGV.fetch(0) { abort("usage: m5_gate.rb <manifest.json>") }
  result = M5Gate.evaluate(manifest)
  puts JSON.pretty_generate(result)
  exit(result.fetch("passed") ? 0 : 1)
end
