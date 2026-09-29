#!/usr/bin/env ruby
# frozen_string_literal: true

# Validate the content-addressed M7 MicroVM-isolation evidence bundle.  M7
# inherits the complete M0 -> M6 chain and requires the x86_64 KVM L4/L5
# report, the guest/host attack matrix, the identity ledger, the snapshot
# corruption corpus and the startup latency samples.  Every report must
# come from the real Firecracker/jailer/KVM stack on the pinned artifacts:
# a lifecycle without kernel-verified confinement, a fault case that did
# not fail closed or left residue, an identity value issued twice, a
# corrupt snapshot that started a VMM, or a p95 above 1.5 s is rejected.

require "digest"
require "json"
require "time"
require_relative "m6_gate"
require_relative "m3_evidence_support"

module M7Gate
  MANIFEST_SCHEMA_VERSION = 3
  REPORT_SCHEMA_VERSION = 1
  SOURCE_EXCLUDED_ROOTS = M4Gate::SOURCE_EXCLUDED_ROOTS
  SOURCE_EXCLUDED_PATTERNS = M4Gate::SOURCE_EXCLUDED_PATTERNS
  PROJECT_ROOT = File.expand_path("../..", __dir__).freeze
  PRIOR_GATES = M6Gate::PRIOR_GATES.merge("M6" => File.join(__dir__, "m6_gate.rb")).freeze
  ARTIFACT_LOCK = "third_party/locks/m7-microvm-artifacts.json"
  FIRECRACKER_VERSION = "1.16.1"

  REPORTS = {
    "kvm" => {kind: "m7_kvm_l4_l5_report", names: %w[kvm-l4-l5-report.json]},
    "attacks" => {kind: "m7_guest_host_attack_matrix", names: %w[guest-host-attack-matrix.json]},
    "identity" => {kind: "m7_identity_ledger", names: %w[identity-ledger.json]},
    "snapshots" => {kind: "m7_snapshot_corruption_corpus", names: %w[snapshot-corruption-corpus.json]},
    "latency" => {kind: "m7_startup_latency_samples", names: %w[startup-latency-samples.json]}
  }.freeze
  REQUIRED_REPORTS = REPORTS

  KVM_REQUIRED = %w[artifact_verification cold_boot_lifecycle base_snapshot restored_lifecycle node_lifecycle_contract fault_jailer_kill fault_vmm_hang
                    fault_uds_disconnect fault_vsock_disconnect fault_pause_ack_loss identity_reuse_after_faults host_inventory_after_cleanup].freeze
  ATTACK_REQUIRED = %w[guest_attack_matrix host_confinement identity_ack_forgery broker_fail_closed restricted_no_network_device cleanup].freeze
  ATTACK_DENIED = %w[rootfs_write raw_block_write jailer_root other_vm_vsock host_vsock_unlisted_port other_tenant_network host_filesystem shared_host_mounts].freeze
  IDENTITY_REQUIRED = %w[clone_identities ledger_history_reuse stale_ack_and_revocation].freeze
  IDENTITY_FIELDS = %w[vm_id subject_id capability_id request_id vsock_session_key vsock_nonce entropy hostname machine_id mac_address workspace_id
                       credential_id policy_digest policy_generation jail_uid guest_cid ip].freeze
  MIN_CLONES = 8
  SNAPSHOT_REQUIRED = %w[pristine_restore mem_bit_flip_middle vmstate_bit_flip vmstate_truncated mem_truncated vmstate_garbage_resigned
                         manifest_artifact_mismatch mem_missing restore_after_corpus].freeze
  LATENCY_BOUND_SECONDS = 1.5
  MIN_LATENCY_SAMPLES = 20
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
      {"schema_version" => 1, "milestone" => "M7", "passed" => errors.empty?, "error_count" => errors.length, "errors" => errors}
    end

    def validate_manifest_shape(manifest, errors)
      errors << "schema_version must be #{MANIFEST_SCHEMA_VERSION}" unless manifest["schema_version"] == MANIFEST_SCHEMA_VERSION
      errors << "milestone must be M7" unless manifest["milestone"] == "M7"
      errors << "input_sha256 must be a SHA-256 digest" unless valid_digest?(manifest["input_sha256"])
      errors << "input_file_count must be positive" unless manifest["input_file_count"].is_a?(Integer) && manifest["input_file_count"].positive?
      errors << "source input must remain stable during evidence capture" unless manifest["input_stable"] == true
      host = manifest["host"]
      errors << "host architecture, kernel, and Ruby description are required" unless host.is_a?(Hash) && %w[architecture kernel ruby].all? { |key| non_empty_string?(host[key]) }
      errors << "M7 evidence must be captured on x86_64" unless host.is_a?(Hash) && host["architecture"] == "x86_64"
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

      errors << "source inventory kind must be m7_source_inventory" unless document["kind"] == "m7_source_inventory"
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
        errors << "COMPLETE M0 through M6 evidence is required for cumulative M7 completion"
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
      errors << "#{name} report milestone must be M7" unless document["milestone"] == "M7"
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

    # Every M7 report is bound to a real KVM host and the pinned artifacts.
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

    def validate_kvm(document, cases, errors)
      errors << "KVM report must be at measurement level L5" unless document["measurement_level"] == "L5"
      errors << "KVM report must come from the real Firecracker/jailer/KVM stack" unless document["measurement_source"] == "real_firecracker_jailer_kvm"
      ids = cases.map { |entry| entry["id"] }
      KVM_REQUIRED.each { |id| errors << "KVM report is missing case #{id}" unless ids.include?(id) }
      %w[cold_boot_lifecycle restored_lifecycle].each do |id|
        entry = cases.find { |candidate| candidate["id"] == id }
        next if entry.nil?

        confinement = entry["confinement"] || {}
        errors << "#{id} must verify seccomp filter mode" unless confinement["seccomp"] == "2"
        errors << "#{id} must verify no_new_privs" unless confinement["no_new_privs"] == "1"
        errors << "#{id} must verify an empty capability set" unless confinement["cap_eff"].to_s.to_i(16).zero?
        errors << "#{id} must verify the chroot" unless confinement["root_inode"] == confinement["chroot_inode"]
        errors << "#{id} must verify the private PID namespace" unless Array(confinement["nspid"]).last == "1"
        errors << "#{id} must reach the L3 isolation profile inside the guest" unless entry.dig("guest", "isolation_profile") == "l3"
        errors << "#{id} must reach the Pod IP from the host" unless entry["pod_ip_reachable_from_host"] == true
        errors << "#{id} must leave no residue" unless entry["residue"].is_a?(Hash) && entry["residue"].reject { |key, _| key == "resources_listed" }.values.none? && Array(entry["residue"]["resources_listed"]).empty?
        errors << "#{id} must end in Removed" unless entry["sandbox_state"] == "Removed" && entry["container_final_state"] == "Removed"
      end
      restored = cases.find { |entry| entry["id"] == "restored_lifecycle" }
      errors << "restored_lifecycle must restore from the base snapshot" unless restored && restored["restored_from_base"] == true
      %w[fault_jailer_kill fault_vmm_hang fault_uds_disconnect fault_vsock_disconnect fault_pause_ack_loss].each do |id|
        entry = cases.find { |candidate| candidate["id"] == id }
        next if entry.nil?

        residue = entry["residue"]
        errors << "#{id} must leave no residue" unless residue.is_a?(Hash) && residue.reject { |key, _| key == "resources_listed" }.values.none? && Array(residue["resources_listed"]).empty?
      end
      hang = cases.find { |entry| entry["id"] == "fault_vmm_hang" }
      errors << "fault_vmm_hang must refuse start while the VM state is unresolved" unless hang && hang["start_refused_while_unknown"] == true
      errors << "fault_vmm_hang must leave the container in a non-running unresolved state" unless hang && %w[StateUnknown Stopping Stopped].include?(hang["container_state_after_hang"])
      pause = cases.find { |entry| entry["id"] == "fault_pause_ack_loss" }
      errors << "fault_pause_ack_loss must classify the VM SnapshotPauseUnknown" unless pause && pause["outcome"].to_s.start_with?("SnapshotPauseUnknown") && pause["phase"] == "pause_unknown"
      reuse = cases.find { |entry| entry["id"] == "identity_reuse_after_faults" }
      errors << "identity reuse after faults must be zero" unless reuse && reuse["report"].is_a?(Hash) && reuse["report"].values.sum { |entry| entry["reused"].to_i }.zero?
      inventory = cases.find { |entry| entry["id"] == "host_inventory_after_cleanup" }
      errors << "host inventory must be empty after cleanup" unless inventory && Array(inventory["resources"]).empty?
      node = cases.find { |entry| entry["id"] == "node_lifecycle_contract" }
      errors << "node lifecycle contract must reach Running and Removed through Node::Lifecycle" unless node && node["start_phase"] == "Running" && node["finish_state"] == "Removed" && node["lifecycle_class"] == "Rubernetes::Node::Lifecycle"
    end

    def validate_attacks(document, cases, errors)
      errors << "attack matrix must be at measurement level L5" unless document["measurement_level"] == "L5"
      ids = cases.map { |entry| entry["id"] }
      ATTACK_REQUIRED.each { |id| errors << "attack matrix is missing case #{id}" unless ids.include?(id) }
      matrix = cases.find { |entry| entry["id"] == "guest_attack_matrix" }
      if matrix
        ATTACK_DENIED.each do |key|
          errors << "attack #{key} must be denied" unless matrix.dig("matrix", key, "outcome") == "denied"
        end
      end
      confinement = cases.find { |entry| entry["id"] == "host_confinement" }
      errors << "host confinement must verify uid, capabilities, seccomp, no_new_privs, chroot and namespaces" unless confinement && confinement["passed"] == true && Array(confinement["forbidden_in_jail"]).empty?
      forgery = cases.find { |entry| entry["id"] == "identity_ack_forgery" }
      errors << "every forged or stale ACK must be rejected" unless forgery && forgery["rejections"].is_a?(Hash) && forgery["rejections"].length >= 4 && forgery["rejections"].values.all? { |value| value.to_s.start_with?("rejected") }
      restricted = cases.find { |entry| entry["id"] == "restricted_no_network_device" }
      errors << "the restricted class must expose only the loopback interface" unless restricted && restricted["interfaces"] == ["lo"]
    end

    def validate_identity(document, cases, errors)
      ids = cases.map { |entry| entry["id"] }
      IDENTITY_REQUIRED.each { |id| errors << "identity ledger is missing case #{id}" unless ids.include?(id) }
      clones = cases.find { |entry| entry["id"] == "clone_identities" }
      if clones
        errors << "identity ledger must restore at least #{MIN_CLONES} clones" unless clones["clones"].to_i >= MIN_CLONES && Array(clones["records"]).length >= MIN_CLONES
        errors << "every clone must restore from the base snapshot" unless clones["all_restored_from_base"] == true
        reused = clones["reused_values"] || {}
        IDENTITY_FIELDS.each do |field|
          errors << "identity field #{field} must be reported" unless reused.key?(field)
          errors << "identity field #{field} was reused across clones" unless Array(reused[field]).empty?
        end
        records = Array(clones["records"])
        IDENTITY_FIELDS.each do |field|
          values = records.map { |record| record.dig("fields", field) }.compact
          errors << "identity field #{field} values must be unique in the records" unless values.uniq.length == values.length
        end
      end
      history = cases.find { |entry| entry["id"] == "ledger_history_reuse" }
      errors << "ledger history must show zero reuse" unless history && history["report"].is_a?(Hash) && history["report"].values.sum { |entry| entry["reused"].to_i }.zero?
      stale = cases.find { |entry| entry["id"] == "stale_ack_and_revocation" }
      errors << "stale ACKs must be rejected and revocation must take effect" unless stale && stale["stale_ack_rejected"] == true && stale["after_revoke"].to_s.start_with?("denied")
    end

    def validate_snapshots(document, cases, errors)
      ids = cases.map { |entry| entry["id"] }
      SNAPSHOT_REQUIRED.each { |id| errors << "snapshot corpus is missing case #{id}" unless ids.include?(id) }
      cases.each do |entry|
        next if %w[pristine_restore restore_after_corpus].include?(entry["id"])

        errors << "corrupt snapshot #{entry["id"]} started a VM" if entry["outcome"] == "started"
        errors << "corrupt snapshot #{entry["id"]} left a VMM process" unless entry["vmm_processes_after"] == 0
        errors << "corrupt snapshot #{entry["id"]} left a live identity" unless entry["live_identities_after"] == 0
        errors << "corrupt snapshot #{entry["id"]} left host resources" unless Array(entry["resources_after"]).empty?
      end
      pristine = cases.find { |entry| entry["id"] == "pristine_restore" }
      errors << "the pristine base must restore" unless pristine && pristine["outcome"] == "started"
    end

    def validate_latency(document, cases, errors)
      entry = cases.find { |candidate| candidate["id"] == "pod_start_from_base_snapshot" }
      unless entry
        errors << "latency report must contain pod_start_from_base_snapshot"
        return
      end
      samples = Array(entry["raw_samples"])
      errors << "latency report needs at least #{MIN_LATENCY_SAMPLES} raw samples" unless samples.length >= MIN_LATENCY_SAMPLES && entry["samples"] == samples.length
      totals = samples.map { |sample| sample["total"] }
      errors << "latency samples must carry numeric totals" unless totals.all? { |value| value.is_a?(Numeric) }
      if totals.all? { |value| value.is_a?(Numeric) } && !totals.empty?
        sorted = totals.sort
        p95 = sorted[((sorted.length - 1) * 0.95).round]
        errors << "reported p95 must match the raw samples" unless entry["p95_seconds"].is_a?(Numeric) && (entry["p95_seconds"] - p95).abs < 1e-6
        errors << "p95 start latency #{p95}s exceeds #{LATENCY_BOUND_SECONDS}s" unless p95 <= LATENCY_BOUND_SECONDS
      end
      errors << "latency samples must restore from a base snapshot" unless samples.all? { |sample| non_empty_string?(sample["base"]) }
      errors << "latency bound must be recorded" unless entry["bound_seconds"] == LATENCY_BOUND_SECONDS
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
  result = M7Gate.evaluate(manifest)
  puts JSON.pretty_generate(result)
  exit(result.fetch("passed") ? 0 : 1)
end
