#!/usr/bin/env ruby
# frozen_string_literal: true

# Validate the content-addressed M4 workload data-plane evidence bundle.
# M4 inherits the complete M0 -> M3 chain and requires every network, policy,
# proxy, volume, and mount-security report.  A report from a fake backend, a
# missing address family/backend, or a report with a changed input is rejected.

require "digest"
require "json"
require "open3"
require "rbconfig"
require "time"
require_relative "m3_gate"
require_relative "m3_evidence_support"
require_relative "../../lib/rubernetes/platform/linux/pidfd"
require_relative "../../lib/rubernetes/network/native_observer"

module M4Gate
  MANIFEST_SCHEMA_VERSION = 3
  REPORT_SCHEMA_VERSION = 1
  MAX_JSON_BYTES = 32 * 1024 * 1024
  SHA256_PATTERN = /\A[0-9a-f]{64}\z/.freeze
  SOURCE_EXCLUDED_ROOTS = %w[.git artifacts build pkg tmp .bundle].freeze
  # Anchored generator scratch directories (a11-generated.XXXXXX) are
  # excluded from the source identity by every milestone (M0-M2 rule).
  SOURCE_EXCLUDED_PATTERNS = [%r{\Aa11-generated\.[A-Za-z0-9]{6,}/}, %r{\Aapps/[^/]+/(?:log|tmp|storage)/}].freeze
  PROJECT_ROOT = File.expand_path("../..", __dir__).freeze
  M0_GATE = File.join(__dir__, "m0_gate.rb").freeze
  M1_GATE = File.join(__dir__, "m1_gate.rb").freeze
  M2_GATE = File.join(__dir__, "m2_gate.rb").freeze
  M3_GATE = File.join(__dir__, "m3_gate.rb").freeze
  REQUIRED_ADDRESS_FAMILIES = %w[ipv4 ipv6 dual_stack].freeze
  REQUIRED_NETWORK_CASES = %w[pod_to_pod service dns ingress egress].freeze
  REQUIRED_PROXY_BACKENDS = %w[ebpf nftables].freeze
  REQUIRED_PROXY_CASES = %w[
    ipv4_tcp_cluster_ip ipv4_udp_cluster_ip ipv4_sctp_cluster_ip
    ipv6_tcp_cluster_ip ipv6_udp_cluster_ip ipv6_sctp_cluster_ip
    ipv4_tcp_node_port ipv4_udp_node_port ipv4_sctp_node_port
    ipv6_tcp_node_port ipv6_udp_node_port ipv6_sctp_node_port
    ipv4_tcp_external_ip ipv4_udp_external_ip ipv4_sctp_external_ip
    ipv6_tcp_external_ip ipv6_udp_external_ip ipv6_sctp_external_ip
    ipv4_tcp_load_balancer ipv4_udp_load_balancer ipv4_sctp_load_balancer
    ipv6_tcp_load_balancer ipv6_udp_load_balancer ipv6_sctp_load_balancer
    ipv4_tcp_headless ipv4_udp_headless ipv4_sctp_headless
    ipv6_tcp_headless ipv6_udp_headless ipv6_sctp_headless
    external_name_cname
    ipv4_distinct_address_reverse ipv6_distinct_address_reverse
    health_check_node_port ipv4_fragments ipv6_fragments
    session_affinity_client_ip internal_traffic_policy_local external_traffic_policy_local
    terminating_endpoints dual_stack_service
  ].freeze
  REQUIRED_POLICY_CASES = %w[default_deny selector named_port end_port sctp].freeze
  REQUIRED_VOLUME_KINDS = %w[ephemeral projected local persistent_volume persistent_volume_claim storage_class snapshot csi].freeze
  REQUIRED_VOLUME_ACCESS_MODES = %w[ReadWriteOnce ReadOnlyMany ReadWriteMany ReadWriteOncePod].freeze
  REQUIRED_VOLUME_STAGES = %w[attach mount unmount detach].freeze
  # These operations are the minimum end-to-end CSI lifecycle.  Keep the
  # names at the protocol boundary instead of accepting a generic
  # `observed: true` marker that could describe an unrelated object.
  REQUIRED_CSI_OPERATIONS = %w[
    GetPluginInfo CreateVolume DeleteVolume ControllerPublishVolume ControllerUnpublishVolume
    NodeStageVolume NodeUnstageVolume NodePublishVolume NodeUnpublishVolume NodeGetVolumeStats
  ].freeze
  REQUIRED_SNAPSHOT_OPERATIONS = %w[snapshot_create snapshot_restore crash_recovery].freeze
  VALID_VOLUME_MEASUREMENT_SOURCES = %w[
    production_module production_module_kernel_adapter production_module_unprivileged_adapter
    production_module_object_construction production_module_injected_client
  ].freeze
  VALID_NODE_CRASH_MEASUREMENT_SOURCES = %w[native_mount_namespace real_csi_node_operation].freeze
  REQUIRED_MOUNT_ATTACKS = %w[mount_traversal host_path_escape attach_race node_crash_double_attach].freeze
  REQUIRED_KERNEL_MAJOR = 6
  REQUIRED_KERNEL_MINOR = 12

  REPORTS = {
    "network" => {kind: "m4_network_matrix", names: %w[network-matrix.json network_matrix.json network.json]},
    "policy" => {kind: "m4_policy_differential", names: %w[policy-differential.json policy_differential.json policy.json]},
    "proxy" => {kind: "m4_proxy_backend_parity", names: %w[proxy-backend-parity.json proxy_backend_parity.json proxy.json]},
    "volume" => {kind: "m4_volume_lifecycle_trace", names: %w[volume-lifecycle-trace.json volume_lifecycle_trace.json volume.json]},
    "mount_attack" => {kind: "m4_mount_attack_corpus", names: %w[mount-attack-corpus.json mount_attack_corpus.json mount.json]}
  }.freeze
  REQUIRED_REPORTS = REPORTS
  INVENTORY_NAMES = %w[
    source-inventory.json
    source_inventory.json
    canonical-source-inventory.json
    canonical_source_inventory.json
    canonical-inventory.json
  ].freeze

  class DuplicateJSONKeyError < StandardError; end

  class StrictHash < Hash
    def []=(key, value)
      raise DuplicateJSONKeyError, "duplicate JSON object key #{key.inspect}" if key?(key)

      super
    end
  end

  class << self
    def evaluate(manifest_path)
      manifest_path = File.expand_path(manifest_path)
      directory = File.dirname(manifest_path)
      errors = []
      @accepted_waivers = []
      manifest = parse_json(manifest_path, errors, "manifest")
      return result(errors) unless manifest.is_a?(Hash)

      validate_manifest_shape(manifest, errors)
      artifacts = validate_entries(manifest.fetch("artifacts", []), directory, errors, "artifact")
      subjects = validate_entries(manifest.fetch("subjects", []), directory, errors, "subject")
      artifact_index = index_artifacts(artifacts, errors)
      validate_inventory(manifest, directory, artifact_index, errors)
      validate_prior_milestones(manifest, directory, artifacts, errors)
      REPORTS.each do |name, specification|
        document = report_document(name, specification, directory, artifact_index, errors)
        validate_report(name, document, specification.fetch(:kind), manifest, errors,
                        evidence_directory: directory, artifacts: artifacts) if document
      end
      validate_result_counts(manifest, artifacts, subjects, errors)
      validate_manifest_status(manifest, errors)
      result(errors)
    rescue Errno::ENOENT => error
      result(["evidence file is missing: #{error.message}"])
    rescue JSON::ParserError => error
      result(["invalid JSON in evidence bundle: #{error.message}"])
    rescue StandardError => error
      result(["gate could not validate evidence bundle: #{error.class}: #{error.message}"])
    end

    def canonical_inventory_digest(entries)
      content = entries.sort_by { |entry| entry.fetch("path") }.map do |entry|
        "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n"
      end.join
      Digest::SHA256.hexdigest(content)
    end

    def canonical_document_digest(document, excluded_keys: [])
      M3Gate.canonical_document_digest(document, excluded_keys: excluded_keys)
    end

    private

    def result(errors)
      {"schema_version" => 1, "milestone" => "M4", "passed" => errors.empty?, "error_count" => errors.length, "errors" => errors,
       "waivers" => Array(@accepted_waivers)}
    end

    KERNEL_WAIVER_REQUIREMENT = "linux>=6.12".freeze

    # The kernel release requirement may only be relaxed by an explicit
    # manifest waiver that names the requirement, a reason, and the very host
    # kernel the bundle was captured on.  The accepted waiver is echoed in the
    # gate result so a COMPLETE bundle can never hide it.
    def validate_kernel_requirement(manifest, host, errors)
      @accepted_waivers = []
      return if host.is_a?(Hash) && kernel_at_least?(host["kernel"])

      waivers = manifest["waivers"]
      waiver = Array(waivers).find do |entry|
        entry.is_a?(Hash) && entry["requirement"] == KERNEL_WAIVER_REQUIREMENT &&
          non_empty_string?(entry["reason"]) && non_empty_string?(entry["scope"]) &&
          host.is_a?(Hash) && entry["host_kernel"] == host["kernel"] && iso8601?(entry["waived_at"])
      end
      if waiver
        @accepted_waivers << waiver
      else
        errors << "M4 requires a Linux kernel >= 6.12 (host #{host.is_a?(Hash) ? host["kernel"] : "unknown"}); an explicit manifest waiver naming #{KERNEL_WAIVER_REQUIREMENT}, a reason, and this host kernel is required to proceed"
      end
    end

    def parse_json(path, errors, label)
      unless path && File.file?(path)
        errors << "#{label} is missing"
        return nil
      end
      if File.size(path) > MAX_JSON_BYTES
        errors << "#{label} exceeds the #{MAX_JSON_BYTES}-byte JSON limit"
        return nil
      end
      JSON.parse(File.binread(path), object_class: StrictHash, max_nesting: 512)
    rescue JSON::ParserError, DuplicateJSONKeyError => error
      errors << "#{label} is not valid JSON: #{error.message}"
      nil
    end

    def validate_manifest_shape(manifest, errors)
      errors << "schema_version must be #{MANIFEST_SCHEMA_VERSION}" unless manifest["schema_version"] == MANIFEST_SCHEMA_VERSION
      errors << "milestone must be M4" unless manifest["milestone"] == "M4"
      errors << "manifest status must be COMPLETE" unless manifest["status"] == "COMPLETE"
      errors << "input_sha256 must be a SHA-256 digest" unless valid_digest?(manifest["input_sha256"])
      errors << "input_file_count must be positive" unless positive_integer?(manifest["input_file_count"])
      errors << "source input must remain stable during evidence capture" unless manifest["input_stable"] == true
      host = manifest["host"]
      errors << "host architecture, kernel, and Ruby description are required" unless host.is_a?(Hash) && %w[architecture kernel ruby].all? { |key| non_empty_string?(host[key]) }
      validate_kernel_requirement(manifest, host, errors)
      %w[started_at finished_at].each { |key| errors << "#{key} must be an ISO-8601 timestamp" unless iso8601?(manifest[key]) }
      validate_input_capture(manifest, errors)
      validate_git_metadata_capture(manifest, errors)
      validate_commands(manifest["commands"], errors)
      errors << "artifacts must be an array" unless manifest["artifacts"].is_a?(Array)
      errors << "subjects must be an array" unless manifest["subjects"].is_a?(Array)
      errors << "result_counts must be an object" unless manifest["result_counts"].is_a?(Hash)
    end

    def validate_input_capture(manifest, errors)
      capture = manifest["input_capture"]
      unless capture.is_a?(Hash) && capture["stable"] == true
        errors << "input_capture must record a stable capture"
        return
      end
      start = capture["start"]
      finish = capture["finish"]
      unless identity?(start) && identity?(finish)
        errors << "input_capture must include start and finish identities"
        return
      end
      errors << "input_capture identities must match the manifest input" unless start["sha256"] == manifest["input_sha256"] && finish["sha256"] == manifest["input_sha256"] && start["file_count"] == manifest["input_file_count"] && finish["file_count"] == manifest["input_file_count"]
      errors << "input_capture start and finish identities differ" unless start == finish
    end

    def validate_git_metadata_capture(manifest, errors)
      capture = manifest["git_metadata_capture"]
      unless capture.is_a?(Hash)
        errors << "git_metadata_capture must be an object"
        return
      end
      starts = capture["start_paths"]
      finishes = capture["finish_paths"]
      unless starts.is_a?(Array) && finishes.is_a?(Array) && starts.all? { |path| non_empty_string?(path) } && finishes.all? { |path| non_empty_string?(path) }
        errors << "git_metadata_capture paths must be arrays of paths"
        return
      end
      errors << "git metadata changed during evidence capture" unless capture["stable"] == true && starts == finishes
      errors << "project source tree must contain no Git metadata" unless capture["count"] == 0 && starts.empty? && finishes.empty?
      errors << "project source tree currently contains Git metadata" unless project_git_metadata_paths.empty?
    end

    def project_git_metadata_paths
      Dir.glob(File.join(PROJECT_ROOT, "**/*"), File::FNM_DOTMATCH).filter_map do |path|
        relative = path.delete_prefix("#{PROJECT_ROOT}/")
        relative if relative.split("/").include?(".git")
      end.uniq.sort
    end

    def validate_commands(commands, errors)
      unless commands.is_a?(Array) && !commands.empty?
        errors << "commands must be a non-empty array"
        return
      end
      names = {}
      commands.each_with_index do |command, index|
        unless command.is_a?(Hash)
          errors << "command #{index} must be an object"
          next
        end
        name = command["name"]
        if !non_empty_string?(name)
          errors << "command #{index} has no name"
        elsif names.key?(name)
          errors << "duplicate command name #{name}"
        else
          names[name] = true
        end
        argv = command["command"]
        errors << "command #{index} must record its argv" unless (argv.is_a?(Array) && !argv.empty? && argv.all? { |part| non_empty_string?(part) }) || non_empty_string?(argv)
        errors << "command #{index} must have an exit status" unless integer?(command["exit_status"])
        errors << "command #{index} did not exit zero" unless command["exit_status"] == 0
        %w[started_at finished_at].each { |key| errors << "command #{index} #{key} must be an ISO-8601 timestamp" unless iso8601?(command[key]) }
        if iso8601?(command["started_at"]) && iso8601?(command["finished_at"]) && Time.iso8601(command["finished_at"]) < Time.iso8601(command["started_at"])
          errors << "command #{index} finished before it started"
        end
      end
    end

    def validate_entries(entries, directory, errors, label)
      unless entries.is_a?(Array)
        errors << "#{label}s must be an array"
        return []
      end
      seen = {}
      entries.filter_map.with_index do |entry, index|
        unless entry.is_a?(Hash)
          errors << "#{label} #{index} must be an object"
          next
        end
        path_value = entry["path"]
        unless non_empty_string?(path_value)
          errors << "#{label} #{index} path is required"
          next
        end
        errors << "duplicate #{label} path #{path_value}" if seen.key?(path_value)
        seen[path_value] = true
        path = evidence_path(directory, path_value)
        if path.nil?
          errors << "#{label} escapes evidence directory #{path_value}"
          next
        end
        errors << "#{label} #{path_value} must have a SHA-256 digest" unless valid_digest?(entry["sha256"])
        errors << "#{label} #{path_value} must have a non-negative byte count" unless integer?(entry["bytes"]) && entry["bytes"] >= 0
        stat = begin
          File.lstat(path)
        rescue Errno::ENOENT, Errno::EACCES, Errno::ELOOP
          nil
        end
        unless stat&.file? && !stat.symlink? && !path_component_symlink?(directory, path)
          errors << "missing #{label} #{path_value}"
          next
        end
        errors << "#{label} #{path_value} must not be a symlink" if stat.symlink? || path_component_symlink?(directory, path)
        errors << "#{label} digest mismatch #{path_value}" if valid_digest?(entry["sha256"]) && Digest::SHA256.file(path).hexdigest != entry["sha256"]
        errors << "#{label} byte count mismatch #{path_value}" if integer?(entry["bytes"]) && File.size(path) != entry["bytes"]
        entry
      end
    end

    def evidence_path(directory, relative_path)
      return nil unless non_empty_string?(relative_path)
      return nil if relative_path.include?("\0") || relative_path.start_with?("/") || relative_path.match?(%r{\A[A-Za-z]:[\\/]})
      path = File.expand_path(relative_path, directory)
      return nil unless path.start_with?("#{directory}/")
      return nil if File.exist?(path) && !File.realpath(path).start_with?("#{File.realpath(directory)}/")
      return nil if path_component_symlink?(directory, path)

      path
    rescue Errno::ENOENT, Errno::EACCES
      nil
    end

    def index_artifacts(artifacts, errors)
      artifacts.each_with_object({}) do |artifact, index|
        next unless artifact.is_a?(Hash) && non_empty_string?(artifact["path"])
        next if artifact["path"].include?("/")
        name = File.basename(artifact["path"])
        errors << "duplicate artifact basename #{name}" if index.key?(name)
        index[name] ||= artifact
      end
    end

    def validate_inventory(manifest, directory, artifact_index, errors)
      artifact = find_named_artifact(INVENTORY_NAMES, artifact_index, errors, "source inventory")
      return unless artifact
      document = parse_json(evidence_path(directory, artifact["path"]), errors, "source inventory")
      return unless document.is_a?(Hash)
      errors << "source inventory schema_version must be #{REPORT_SCHEMA_VERSION}" unless document["schema_version"] == REPORT_SCHEMA_VERSION
      errors << "source inventory kind must be m4_source_inventory" unless document["kind"] == "m4_source_inventory"
      errors << "source inventory input_sha256 must match manifest" unless document["input_sha256"] == manifest["input_sha256"]
      errors << "source inventory input_file_count must match manifest" unless document["input_file_count"] == manifest["input_file_count"]
      errors << "source inventory input_stable must be true" unless document["input_stable"] == true
      entries = document["entries"]
      unless entries.is_a?(Array) && !entries.empty?
        errors << "source inventory entries must be a non-empty array"
        return
      end
      valid_entries = []
      paths = []
      entries.each_with_index do |entry, index|
        unless entry.is_a?(Hash)
          errors << "source inventory entry #{index} must be an object"
          next
        end
        path_value = entry["path"]
        invalid_segments = path_value.is_a?(String) && path_value.split("/").any? { |segment| ["", ".", ".."].include?(segment) }
        excluded = path_value.is_a?(String) &&
                   (SOURCE_EXCLUDED_ROOTS.include?(path_value.split("/", 2).first) ||
                    SOURCE_EXCLUDED_PATTERNS.any? { |pattern| pattern.match?(path_value) })
        unless non_empty_string?(path_value) && !path_value.start_with?("/") && !path_value.include?("\0") && !invalid_segments && !excluded
          errors << "source inventory entry #{index} path is invalid"
          next
        end
        errors << "source inventory paths must be unique" if paths.include?(path_value)
        paths << path_value
        errors << "source inventory entry #{path_value} must have a SHA-256 digest" unless valid_digest?(entry["sha256"])
        errors << "source inventory entry #{path_value} has invalid byte count" unless integer?(entry["bytes"]) && entry["bytes"] >= 0
        valid_entries << entry
      end
      errors << "source inventory entries must be sorted by path" unless paths.sort == paths
      errors << "source inventory digest does not match manifest input" unless canonical_inventory_digest(valid_entries) == manifest["input_sha256"]
      errors << "source inventory file count does not match manifest input" unless valid_entries.length == manifest["input_file_count"]
      valid_entries.each do |entry|
        path = File.expand_path(entry.fetch("path"), PROJECT_ROOT)
        errors << "source inventory entry #{entry.fetch("path")} is missing" unless File.file?(path)
        errors << "source inventory digest mismatch #{entry.fetch("path")}" if File.file?(path) && valid_digest?(entry["sha256"]) && Digest::SHA256.file(path).hexdigest != entry["sha256"]
      end
    end

    def validate_prior_milestones(manifest, directory, artifacts, errors)
      prior = manifest["prior_milestones"]
      unless prior.is_a?(Hash)
        errors << "COMPLETE M0, M1, M2, and M3 evidence is required for cumulative M4 completion"
        return
      end
      {"M0" => M0_GATE, "M1" => M1_GATE, "M2" => M2_GATE, "M3" => M3_GATE}.each do |name, gate_path|
        validate_prior_milestone(name, prior[name], manifest, directory, artifacts, errors, gate_path)
      end
    end

    def validate_prior_milestone(name, reference, manifest, directory, artifacts, errors, gate_path)
      unless reference.is_a?(Hash)
        errors << "COMPLETE #{name} evidence is required for cumulative M4 completion"
        return
      end
      manifest_value = reference["manifest_path"]
      result_value = reference["gate_result_path"]
      errors << "#{name} manifest and gate result paths must be distinct" if manifest_value == result_value
      manifest_entry = artifacts.find { |entry| entry["path"] == manifest_value }
      result_entry = artifacts.find { |entry| entry["path"] == result_value }
      errors << "#{name} manifest must be content-addressed by M4" unless manifest_entry
      errors << "#{name} gate result must be content-addressed by M4" unless result_entry
      return unless manifest_entry && result_entry
      manifest_path = evidence_path(directory, manifest_value)
      result_path = evidence_path(directory, result_value)
      return unless manifest_path && result_path
      prior_manifest = parse_json(manifest_path, errors, "#{name} manifest")
      prior_result = parse_json(result_path, errors, "#{name} gate result")
      return unless prior_manifest.is_a?(Hash) && prior_result.is_a?(Hash)
      errors << "#{name} manifest reference digest is incorrect" unless reference["manifest_sha256"] == manifest_entry["sha256"]
      errors << "#{name} gate result reference digest is incorrect" unless reference["gate_result_sha256"] == result_entry["sha256"]
      errors << "#{name} manifest milestone is incorrect" unless prior_manifest["milestone"] == name
      errors << "#{name} manifest status must be COMPLETE" unless prior_manifest["status"] == "COMPLETE"
      errors << "#{name} evidence must use the same source input as M4" unless prior_manifest["input_sha256"] == manifest["input_sha256"] && prior_manifest["input_file_count"] == manifest["input_file_count"]
      errors << "#{name} reference identity must match the M4 source input" unless reference["input_sha256"] == manifest["input_sha256"] && reference["input_file_count"] == manifest["input_file_count"]
      errors << "#{name} reference must record a passing gate" unless reference["gate_passed"] == true
      errors << "stored #{name} gate result must be passing" unless prior_result["passed"] == true && prior_result["milestone"] == name
      %w[artifacts subjects].each do |collection|
        entries = prior_manifest[collection]
        unless entries.is_a?(Array)
          errors << "#{name} manifest #{collection} must be an array"
          next
        end
        entries.each_with_index do |entry, index|
          unless entry.is_a?(Hash) && non_empty_string?(entry["path"])
            errors << "#{name} #{collection} entry #{index} has no path"
            next
          end
          nested_path = File.join(File.dirname(manifest_value.to_s), entry["path"])
          errors << "#{name} #{collection} entry is not content-addressed by M4: #{nested_path}" unless artifacts.any? { |candidate| candidate["path"] == nested_path }
        end
      end
      gate_stdout, gate_stderr, gate_status = Open3.capture3(RbConfig.ruby, gate_path, manifest_path, chdir: PROJECT_ROOT)
      errors << "#{name} gate emitted stderr during cumulative validation" unless gate_stderr.empty?
      unless gate_status.success?
        prior_errors = JSON.parse(gate_stdout).fetch("errors", []) rescue []
        errors << "#{name} gate does not pass: #{prior_errors.join("; ")}"
      end
    rescue SystemCallError => error
      errors << "#{name} gate could not be executed: #{error.message}"
    end

    def report_document(name, specification, directory, artifact_index, errors)
      artifact = find_named_artifact(specification.fetch(:names), artifact_index, errors, "#{name} report")
      return nil unless artifact
      parse_json(evidence_path(directory, artifact["path"]), errors, "#{name} report")
    end

    def find_named_artifact(names, artifact_index, errors, label)
      matches = names.filter_map { |name| artifact_index[name] }
      if matches.empty?
        errors << "#{label} is missing (expected #{names.first})"
        return nil
      end
      errors << "#{label} has multiple aliases" if matches.length > 1
      matches.first
    end

    def validate_report(name, document, expected_kind, manifest, errors, evidence_directory: nil, artifacts: [])
      label = "#{name} report"
      validate_common_document(document, expected_kind, manifest, errors, label)
      return unless document.is_a?(Hash) && document["schema_version"] == REPORT_SCHEMA_VERSION && document["kind"] == expected_kind
      case name
      when "network" then validate_network(document, errors, evidence_directory: evidence_directory, artifacts: artifacts)
      when "policy" then validate_policy(document, errors)
      when "proxy" then validate_proxy(document, errors)
      when "volume" then validate_volume(document, errors)
      when "mount_attack" then validate_mount_attacks(document, errors)
      end
    end

    def validate_common_document(document, expected_kind, manifest, errors, label)
      errors << "#{label} must be a JSON object" unless document.is_a?(Hash)
      return unless document.is_a?(Hash)
      errors << "#{label} schema_version must be #{REPORT_SCHEMA_VERSION}" unless document["schema_version"] == REPORT_SCHEMA_VERSION
      errors << "#{label} kind must be #{expected_kind}" unless document["kind"] == expected_kind
      errors << "#{label} milestone must be M4" unless document["milestone"] == "M4"
      errors << "#{label} input_sha256 must match manifest" unless document["input_sha256"] == manifest["input_sha256"]
      errors << "#{label} input_file_count must match manifest" unless document["input_file_count"] == manifest["input_file_count"]
      errors << "#{label} input_stable must be true" unless document["input_stable"] == true
      measurement_source_valid = if expected_kind == "m4_volume_lifecycle_trace"
                                   VALID_VOLUME_MEASUREMENT_SOURCES.include?(document["measurement_source"])
                                 else
                                   document["measurement_source"] == "production_module"
                                 end
      errors << "#{label} measurement_source is not an allowed production measurement source" unless measurement_source_valid
      errors << "#{label} measurement_level must be L3" unless document["measurement_level"] == "L3"
      errors << "#{label} status must be PASS" unless document["status"] == "PASS"
      errors << "#{label} passed must be true" unless document["passed"] == true
      errors << "#{label} available must be true" unless document["available"] == true
      errors << "#{label} errors must be an empty array" unless document["errors"] == []
      errors << "#{label} attempt_count must be one" unless document["attempt_count"] == 1
      %w[retry_count unexpected_skip_count unclassified_count flake_count failure_count].each { |key| errors << "#{label} #{key} must be zero" unless document[key] == 0 }
      adapter = document["adapter"]
      errors << "#{label} adapter provenance is incomplete" unless adapter.is_a?(Hash) && non_empty_string?(adapter["name"]) && non_empty_string?(adapter["version"]) && valid_digest?(adapter["runner_sha256"])
      provenance = document["provenance"]
      unless provenance.is_a?(Hash)
        errors << "#{label} provenance is required"
      else
        errors << "#{label} provenance source_sha256 must match manifest" unless provenance["source_sha256"] == manifest["input_sha256"]
        errors << "#{label} provenance source_file_count must match manifest" unless provenance["source_file_count"] == manifest["input_file_count"]
        errors << "#{label} provenance runner_sha256 must match adapter" unless valid_digest?(provenance["runner_sha256"]) && provenance["runner_sha256"] == adapter["runner_sha256"]
        errors << "#{label} provenance command must be a non-empty argv" unless provenance["command"].is_a?(Array) && !provenance["command"].empty? && provenance["command"].all? { |part| non_empty_string?(part) }
        errors << "#{label} provenance process_id must be positive" unless provenance["process_id"].is_a?(Integer) && provenance["process_id"].positive?
        errors << "#{label} provenance measurement_id is required" unless non_empty_string?(provenance["measurement_id"])
        %w[started_at finished_at].each { |key| errors << "#{label} provenance #{key} must be ISO-8601" unless iso8601?(provenance[key]) }
        errors << "#{label} provenance_sha256 does not match canonical content" unless valid_digest?(provenance["provenance_sha256"]) && canonical_document_digest(provenance, excluded_keys: ["provenance_sha256"]) == provenance["provenance_sha256"]
      end
      errors << "#{label} report_sha256 does not match canonical content" unless valid_digest?(document["report_sha256"]) && canonical_document_digest(document, excluded_keys: ["report_sha256"]) == document["report_sha256"]
    end

    def validate_network(document, errors, evidence_directory: nil, artifacts: [])
      families = document["address_families"] || document["profiles"]
      errors << "network matrix address families are incomplete" unless families.is_a?(Array) && families.map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["family"]) : nil }.sort == REQUIRED_ADDRESS_FAMILIES.sort
      cases = document["cases"]
      unless cases.is_a?(Array) && cases.map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["case"]) : nil }.sort == REQUIRED_NETWORK_CASES.sort
        errors << "network matrix must cover pod, service, DNS, ingress, and egress"
      end
      Array(families).each_with_index do |entry, index|
        errors << "network family #{index} must pass from production module" unless entry.is_a?(Hash) && entry["passed"] == true && entry["measurement_source"] == "production_module" && entry["packet_trace_sha256"].to_s.match?(SHA256_PATTERN)
      end
      packet_trace_sha256 = document.dig("kernel_observation", "packet_trace", "sha256")
      Array(families).each_with_index do |entry, index|
        errors << "network family #{index} must reference the captured kernel packet trace" unless entry.is_a?(Hash) && entry["packet_trace_source"] == "kernel_capture" && entry["packet_trace_sha256"] == packet_trace_sha256
      end
      Array(cases).each_with_index do |entry, index|
        errors << "network case #{index} must pass once" unless entry.is_a?(Hash) && entry["passed"] == true && entry["attempt_count"] == 1 && entry["packet_trace_sha256"].to_s.match?(SHA256_PATTERN)
        errors << "network case #{index} must reference the captured kernel packet trace" unless entry.is_a?(Hash) && entry["packet_trace_source"] == "kernel_capture" && entry["packet_trace_sha256"] == packet_trace_sha256
      end
      errors << "network connection leak count must be zero" unless document["connection_loss_count"] == 0
      errors << "network IP leak count must be zero" unless document["ip_leak_count"] == 0
      validate_network_observation(document["kernel_observation"], errors, owner_document: document,
                                   evidence_directory: evidence_directory, artifacts: artifacts)
      %w[failure_count difference_count unexpected_skip_count unclassified_count].each { |key| errors << "network #{key} must be zero" unless document[key] == 0 }
    end

    def validate_policy(document, errors)
      cases = document["cases"]
      ids = Array(cases).filter_map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["case"]) : nil }
      errors << "policy differential cases are incomplete" unless ids.sort == REQUIRED_POLICY_CASES.sort && ids.uniq.length == REQUIRED_POLICY_CASES.length
      Array(cases).each_with_index do |entry, index|
        errors << "policy case #{index} must pass from production module" unless entry.is_a?(Hash) && entry["passed"] == true && entry["measurement_source"] == "production_module" && entry["attempt_count"] == 1
        errors << "policy case #{index} oracle result differs" if entry.is_a?(Hash) && entry["expected"] != entry["actual"]
      end
      oracle = document["oracle"]
      errors << "policy oracle differential evidence is incomplete" unless oracle.is_a?(Hash) && oracle["executed"] == true && valid_digest?(oracle["runner_sha256"]) && oracle["comparison_count"] == REQUIRED_POLICY_CASES.length
      validate_external_runner_observation(oracle, errors, "network-policy oracle", owner_document: document)
      if oracle.is_a?(Hash) && oracle["comparisons"].is_a?(Array)
        oracle["comparisons"].each_with_index { |comparison, index| validate_observable_comparison(comparison, errors, "network-policy oracle comparison #{index}") }
      end
      %w[failure_count difference_count default_deny_bypass_count selector_mismatch_count named_port_mismatch_count end_port_mismatch_count sctp_mismatch_count unexpected_skip_count unclassified_count].each { |key| errors << "policy #{key} must be zero" unless document[key] == 0 }
    end

    def validate_proxy(document, errors)
      backends = document["backends"]
      ids = Array(backends).filter_map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["backend"]) : nil }
      errors << "proxy backend inventory must contain eBPF and nftables" unless ids.sort == REQUIRED_PROXY_BACKENDS.sort
      Array(backends).each_with_index do |entry, index|
        errors << "proxy backend #{index} must pass from production module" unless entry.is_a?(Hash) && entry["passed"] == true && entry["measurement_source"] == "production_module" && entry["attempt_count"] == 1
        errors << "proxy backend #{index} must record a packet trace" unless entry.is_a?(Hash) && valid_digest?(entry["packet_trace_sha256"])
        errors << "proxy backend #{index} must reference verified kernel readback" unless entry.is_a?(Hash) && entry["kernel_readback"].is_a?(Hash) && entry["kernel_readback"]["readback"] == true && entry["kernel_readback"]["rules"].is_a?(Array) && !entry["kernel_readback"]["rules"].empty?
      end
      parity = document["parity"]
      errors << "proxy backend parity must be measured" unless parity.is_a?(Hash) && parity["passed"] == true && parity["observable_semantics_equal"] == true && valid_digest?(parity["comparison_sha256"])
      errors << "proxy backend parity must be independently production-verified" unless parity.is_a?(Hash) && parity["production_capable"] == true && parity["production_verified"] == true
      errors << "proxy backend connection loss must be measured and zero" unless document["connection_loss_count"] == 0 && document["connection_loss_measured"] == true
      validate_proxy_external_parity(parity, errors)
      validate_proxy_readback(document["backend_readback"], errors, owner_document: document)
      %w[failure_count difference_count unexpected_skip_count unclassified_count].each { |key| errors << "proxy #{key} must be zero" unless document[key] == 0 }
    end

    def validate_proxy_external_parity(parity, errors)
      external = parity.is_a?(Hash) ? parity["external_observable"] : nil
      unless external.is_a?(Hash)
        errors << "proxy parity must include independently captured packet and kernel evidence"
        return
      end
      packet = external["packetCorpus"] || external["packet_corpus"]
      kernel = external["kernelReadback"] || external["kernel_readback"]
      unless packet.is_a?(Hash) && kernel.is_a?(Hash)
        errors << "proxy parity packet corpus and kernel readback are required"
        return
      end
      errors << "proxy packet corpus must be executed externally" unless packet["executed"] == true && non_empty_string?(packet["measurementSource"])
      errors << "proxy packet runner provenance is incomplete" unless non_empty_string?(packet["runnerIdentity"]) && valid_digest?(packet["runnerDigest"]) && non_empty_string?(packet["mode"]) && packet["mode"] != "model"
      runner = packet["runner"] || packet["runner_provenance"]
      errors << "proxy packet runner PID/start-time/source/argv/stdout provenance is incomplete" unless runner.is_a?(Hash) && runner["pid"].is_a?(Integer) && runner["pid"].positive? && iso8601?(runner["startedAt"] || runner["started_at"] || runner["startTime"] || runner["start_time"]) && non_empty_string?(runner["source"] || runner["sourcePath"] || runner["source_path"]) && Array(runner["argv"] || runner["command"]).any? && Array(runner["argv"] || runner["command"]).all? { |arg| non_empty_string?(arg) } && runner["stdout"].is_a?(String) && valid_digest?(runner["stdoutSha256"] || runner["stdout_sha256"]) && Digest::SHA256.hexdigest(runner["stdout"]) == (runner["stdoutSha256"] || runner["stdout_sha256"])
      execution = packet["executionIdentity"]
      errors << "proxy packet immutable execution identity is incomplete" unless execution.is_a?(Hash) && execution["runnerIdentity"] == packet["runnerIdentity"] && execution["runnerDigest"] == packet["runnerDigest"] && execution["mode"] == packet["mode"] && valid_digest?(packet["executionIdentitySha256"]) && packet["executionIdentitySha256"] == canonical_document_digest(execution)
      binding = packet["inputBinding"]
      errors << "proxy packet immutable input binding is incomplete" unless binding.is_a?(Hash) && valid_digest?(binding["leftDigest"]) && valid_digest?(binding["rightDigest"]) && valid_digest?(packet["inputBindingSha256"]) && packet["inputBindingSha256"] == canonical_document_digest(binding)
      errors << "proxy packet corpus raw trace digest is invalid" unless packet["rawPacketTrace"] && valid_digest?(packet["packetTraceSha256"]) && packet["packetTraceSha256"] == canonical_document_digest(packet["rawPacketTrace"])
      capture = packet["packetCapture"] || packet["packet_capture"] || packet["pcap"]
      capture_count = capture.is_a?(Hash) ? (capture["packetCount"] || capture["packet_count"] || capture["count"]) : nil
      errors << "proxy packet bytes/PCAP provenance is incomplete" unless capture.is_a?(Hash) && %w[pcap packet_bytes raw].include?((capture["format"] || capture["type"]).to_s) && valid_digest?(capture["sha256"] || capture["packetBytesSha256"] || capture["packet_bytes_sha256"] || capture["pcapSha256"] || capture["pcap_sha256"]) && capture_count.is_a?(Integer) && capture_count.positive? && non_empty_string?(capture["source"] || capture["sourcePath"] || capture["source_path"])
      cases = packet["cases"]
      inventory = packet["caseInventory"]
      ids = Array(cases).filter_map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["case"] || entry["caseId"]) : nil }.map(&:to_s)
      inventory_ids = Array(inventory).filter_map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["case"] || entry["caseId"]) : nil }.map(&:to_s)
      errors << "proxy packet corpus case inventory is incomplete" unless ids.sort == REQUIRED_PROXY_CASES.sort && inventory_ids.sort == REQUIRED_PROXY_CASES.sort && ids.uniq.length == REQUIRED_PROXY_CASES.length
      errors << "proxy packet corpus case inventory digest is invalid" unless valid_digest?(packet["caseInventorySha256"]) && packet["caseInventorySha256"] == canonical_document_digest(inventory)
      Array(cases).each_with_index do |entry, index|
        expected = entry.is_a?(Hash) ? entry["expected"] : nil
        actual = entry.is_a?(Hash) ? entry["actual"] : nil
        errors << "proxy packet case #{index} expected/actual mismatch" unless expected == actual
        errors << "proxy packet case #{index} expected digest is invalid" unless entry.is_a?(Hash) && valid_digest?(entry["expectedSha256"]) && entry["expectedSha256"] == canonical_document_digest(expected)
        errors << "proxy packet case #{index} actual digest is invalid" unless entry.is_a?(Hash) && valid_digest?(entry["actualSha256"]) && entry["actualSha256"] == canonical_document_digest(actual)
      end
      errors << "proxy kernel readback must bind packet trace and case inventory" unless valid_digest?(kernel["packetTraceSha256"]) && kernel["packetTraceSha256"] == packet["packetTraceSha256"] && valid_digest?(kernel["caseInventorySha256"]) && kernel["caseInventorySha256"] == packet["caseInventorySha256"]
      errors << "proxy kernel runner provenance must match packet runner" unless kernel["runnerIdentity"] == packet["runnerIdentity"] && kernel["runnerDigest"] == packet["runnerDigest"] && kernel["mode"] == packet["mode"] && valid_digest?(kernel["executionIdentitySha256"])
      kernel_runner = kernel["runner"] || kernel["runner_provenance"]
      errors << "proxy kernel runner PID/start-time/source/argv/stdout provenance is incomplete" unless kernel_runner.is_a?(Hash) && kernel_runner["pid"] == runner["pid"] && (kernel_runner["startedAt"] || kernel_runner["started_at"] || kernel_runner["startTime"] || kernel_runner["start_time"]) == (runner["startedAt"] || runner["started_at"] || runner["startTime"] || runner["start_time"]) && (kernel_runner["source"] || kernel_runner["sourcePath"] || kernel_runner["source_path"]) == (runner["source"] || runner["sourcePath"] || runner["source_path"]) && Array(kernel_runner["argv"] || kernel_runner["command"]) == Array(runner["argv"] || runner["command"]) && kernel_runner["stdout"] == runner["stdout"] && (kernel_runner["stdoutSha256"] || kernel_runner["stdout_sha256"]) == (runner["stdoutSha256"] || runner["stdout_sha256"]) && kernel_runner["stdout"].is_a?(String) && valid_digest?(kernel_runner["stdoutSha256"] || kernel_runner["stdout_sha256"]) && Digest::SHA256.hexdigest(kernel_runner["stdout"]) == (kernel_runner["stdoutSha256"] || kernel_runner["stdout_sha256"])
      errors << "proxy kernel input binding must match packet binding" unless kernel["inputBinding"] == binding && valid_digest?(kernel["inputBindingSha256"]) && kernel["inputBindingSha256"] == packet["inputBindingSha256"]
      errors << "proxy packet/kernel execution identity must match" unless valid_digest?(packet["executionIdentitySha256"]) && packet["executionIdentitySha256"] == kernel["executionIdentitySha256"]
      %w[ebpf nftables].each do |backend|
        entry = kernel[backend]
        expected_input_digest = if backend == "ebpf"
                                  parity["leftDigest"] || parity["left_digest"]
                                else
                                  parity["rightDigest"] || parity["right_digest"]
                                end
        expected_rules = if backend == "ebpf"
                           parity["leftRules"] || parity["left_rules"]
                         else
                           parity["rightRules"] || parity["right_rules"]
                         end
        errors << "proxy #{backend} kernel readback identity is incomplete" unless entry.is_a?(Hash) && entry["readback"] == true && entry["identity"].is_a?(Hash) && entry["identity"].any? && valid_digest?(entry["identityDigest"]) && entry["identityDigest"] == canonical_document_digest(entry["identity"]) && entry["rules"].is_a?(Array) && !entry["rules"].empty? && valid_digest?(entry["rulesDigest"]) && entry["rulesDigest"] == canonical_document_digest(entry["rules"])
        errors << "proxy #{backend} kernel readback must bind model rules" unless entry.is_a?(Hash) && expected_rules.is_a?(Array) && !expected_rules.empty? && entry["inputDigest"] == expected_input_digest && entry["rulesModelDigest"] == expected_input_digest && entry["rules"] == expected_rules && entry["rulesDigest"] == canonical_document_digest(expected_rules)
        if backend == "ebpf"
          program = entry.is_a?(Hash) ? entry["program"] : nil
          maps = entry.is_a?(Hash) ? entry["maps"] : nil
          filters = entry.is_a?(Hash) ? entry["filters"] : nil
          errors << "proxy eBPF program/map/TC readback identities are incomplete" unless program.is_a?(Hash) && program["id"].is_a?(Integer) && program["id"].positive? && valid_bpf_tag?(program["tag"]) && maps.is_a?(Array) && !maps.empty? && filters.is_a?(Array) && !filters.empty?
        else
          errors << "proxy nftables table/chain/set readback identities are incomplete" unless entry.is_a?(Hash) && entry["table"].is_a?(Hash) && non_empty_string?(entry["table"]["name"]) && Array(entry["chains"]).any? && Array(entry["sets"]).any?
        end
      end
    end

    def validate_volume(document, errors)
      kinds = document["volume_kinds"] || document["kinds"]
      ids = Array(kinds).filter_map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["kind"]) : nil }
      errors << "volume lifecycle inventory is incomplete" unless ids.sort == REQUIRED_VOLUME_KINDS.sort && ids.uniq.length == REQUIRED_VOLUME_KINDS.length
      Array(kinds).each_with_index do |entry, index|
        errors << "volume kind #{index} must pass from an identified production measurement source" unless
          entry.is_a?(Hash) && entry["passed"] == true && VALID_VOLUME_MEASUREMENT_SOURCES.include?(entry["measurement_source"]) && entry["attempt_count"] == 1
        validate_volume_component_source(entry, errors, "volume kind #{index}") if entry.is_a?(Hash)
      end
      access_modes = Array(document["access_modes"]).map { |value| value.to_s }.sort
      errors << "volume lifecycle must cover all access modes" unless access_modes == REQUIRED_VOLUME_ACCESS_MODES.sort
      stages = Array(document["stages"]).filter_map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["stage"]) : nil }
      errors << "volume lifecycle must cover attach/mount/unmount/detach" unless stages.sort == REQUIRED_VOLUME_STAGES.sort
      Array(document["stages"]).each_with_index do |entry, index|
        errors << "volume stage #{index} must pass once" unless entry.is_a?(Hash) && entry["passed"] == true && entry["attempt_count"] == 1
        validate_content_bound_observation(entry, errors, "volume stage #{index}") if entry.is_a?(Hash)
      end
      projection = document["projected_atomicity"]
      errors << "projected volume updates must be atomic" unless projection.is_a?(Hash) && projection["passed"] == true && projection["partial_generation_observed"] == false
      errors << "volume duplicate attach count must be zero" unless document["duplicate_attach_count"] == 0
      errors << "volume mount leak count must be zero" unless document["mount_leak_count"] == 0
      validate_volume_observation(document, errors, owner_document: document)
      %w[failure_count difference_count unexpected_skip_count unclassified_count].each { |key| errors << "volume #{key} must be zero" unless document[key] == 0 }
    end

    def validate_volume_component_source(entry, errors, label)
      detail = entry["detail"]
      return unless detail.is_a?(Hash)

      source = entry["measurement_source"]
      adapter_class = detail["adapter_class"] || detail["adapter"] || detail.dig("adapter", "class")
      if source == "production_module" && non_empty_string?(adapter_class) &&
         adapter_class.end_with?("FilesystemAdapter")
        errors << "#{label} must not label FilesystemAdapter evidence as production_module"
      end
      if source == "production_module" && detail["execution"] == "object_construction"
        errors << "#{label} must label object construction separately from production execution"
      end
    end

    def validate_mount_attacks(document, errors)
      cases = document["cases"]
      ids = Array(cases).filter_map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["case"]) : nil }
      errors << "mount attack corpus is incomplete" unless ids.sort == REQUIRED_MOUNT_ATTACKS.sort && ids.uniq.length == REQUIRED_MOUNT_ATTACKS.length
      Array(cases).each_with_index do |entry, index|
        if entry.is_a?(Hash) && (entry["id"] || entry["case"]).to_s == "node_crash_double_attach"
          errors << "mount attack case #{index} must pass from bound native crash evidence" unless
            entry["passed"] == true && entry["blocked"] == true &&
            VALID_NODE_CRASH_MEASUREMENT_SOURCES.include?(entry["measurement_source"]) && entry["attempt_count"] == 1
        else
          errors << "mount attack case #{index} must be rejected by production module" unless entry.is_a?(Hash) && entry["passed"] == true && entry["blocked"] == true && entry["measurement_source"] == "production_module" && entry["attempt_count"] == 1
        end
      end
      validate_node_crash_recovery(document["node_crash_recovery"], errors, owner_document: document)
      validate_mount_observation(document["kernel_observation"], errors, owner_document: document)
      %w[live_escape_count host_path_escape_count attach_race_count double_attach_count failure_count unexpected_skip_count unclassified_count].each { |key| errors << "mount attack #{key} must be zero" unless document[key] == 0 }
    end

    # A crash result is only useful when it proves that a real node operation
    # changed a kernel mount in the crashed process's mount namespace before
    # durable node state was committed. Generic mountinfo/syscall records from
    # an unrelated external runner are intentionally not accepted here.
    def validate_node_crash_recovery(document, errors, owner_document: nil)
      label = "node crash recovery"
      unless document.is_a?(Hash)
        errors << "#{label} must include bound native evidence"
        return
      end
      source = document["measurement_source"]
      errors << "#{label} measurement source must be native" unless VALID_NODE_CRASH_MEASUREMENT_SOURCES.include?(source)
      errors << "#{label} mode must identify a mount namespace or real CSI operation" unless
        %w[native_mount_namespace real_csi_node_operation].include?(document["mode"])
      errors << "#{label} must pass only when native crash evidence is complete" unless document["passed"] == true && document["available"] == true
      errors << "#{label} must report durable recovery with no unknown operations" unless
        document.dig("recovery", "unknown_count") == 0 && document.dig("recovery", "state_after_recovery") == "Attached"
      errors << "#{label} must report durable cleanup after restart" unless document["cleanup_passed"] == true
      operation = document["operation"].to_s
      errors << "#{label} must exercise NodeStageVolume or NodePublishVolume" unless
        %w[NodeStageVolume NodePublishVolume].include?(operation)
      mount_adapter = document["mount_adapter_class"] || document["adapter_class"]
      errors << "#{label} must identify a native mount adapter" unless non_empty_string?(mount_adapter) && !mount_adapter.end_with?("FilesystemAdapter")
      errors << "#{label} must not use FilesystemAdapter as the mount adapter" if non_empty_string?(document["adapter_class"]) && document["adapter_class"].end_with?("FilesystemAdapter")
      errors << "#{label} native mount namespace evidence must use the production NativeMountAdapter" if
        source == "native_mount_namespace" && mount_adapter != "Rubernetes::Volume::NativeMountAdapter"

      local_runner_sha256 = owner_document.is_a?(Hash) ? owner_document.dig("adapter", "runner_sha256") : nil
      errors << "#{label} must bind evidence to the local report runner" unless valid_digest?(local_runner_sha256) && document["runner_sha256"] == local_runner_sha256
      binding = document["binding"]
      expected_binding = {"runner_sha256" => document["runner_sha256"],
                          "child_identity_sha256" => document["child_identity_sha256"],
                          "observation_sha256" => document["observation_sha256"]}
      errors << "#{label} immutable runner/child/observation binding is invalid" unless
        binding.is_a?(Hash) && binding == expected_binding && valid_digest?(document["binding_sha256"]) &&
        document["binding_sha256"] == canonical_document_digest(binding)

      observation = document["observation"]
      unless observation.is_a?(Hash) && valid_digest?(document["observation_sha256"]) &&
             document["observation_sha256"] == canonical_document_digest(observation)
        errors << "#{label} observation digest is invalid or unbound"
        return
      end
      errors << "#{label} observation operation does not match the recorded operation" unless observation["operation"].to_s == operation
      child = observation["child"]
      validate_node_crash_process_identity(child, document["child_identity_sha256"], errors, "#{label} child")
      target = observation["target"]
      validate_node_crash_target_identity(target, document["target_identity_sha256"], errors, "#{label} target")
      effect = observation["effect_boundary"]
      unless effect.is_a?(Hash) && effect["observed"] == true &&
             %w[NodeStageVolume NodePublishVolume].include?(effect["operation"].to_s) &&
             effect["phase"] == "after_effect_before_durable_commit" &&
             valid_digest?(document["effect_boundary_sha256"]) &&
             document["effect_boundary_sha256"] == canonical_document_digest(effect)
        errors << "#{label} effect boundary must bind the native operation before durable commit"
      end
      if child.is_a?(Hash) && effect.is_a?(Hash)
        errors << "#{label} effect boundary PID/start-time/namespace does not match child" unless
          effect["pid"] == child["pid"] && effect["start_time_ticks"] == child["start_time_ticks"] &&
          effect["mount_namespace_inode"] == child["mount_namespace_inode"]
      end
      if target.is_a?(Hash) && effect.is_a?(Hash)
        errors << "#{label} effect boundary does not bind target path/mount identity" unless
          effect["target"] == target["path"] && effect["mount_id"] == target["mount_id"] &&
          effect["target_device"] == target["device"] && effect["target_inode"] == target["inode"]
      end
      mountinfo = observation["mountinfo"]
      unless mountinfo.is_a?(Array) && !mountinfo.empty? && mountinfo.all? { |line| non_empty_string?(line) } &&
             valid_digest?(document["mountinfo_sha256"]) &&
             document["mountinfo_sha256"] == Digest::SHA256.hexdigest(mountinfo.join("\n"))
        errors << "#{label} child mountinfo is missing or not content-bound"
      end
      if target.is_a?(Hash) && mountinfo.is_a?(Array)
        errors << "#{label} target mountinfo line is not in the child mountinfo" unless mountinfo.include?(target["mountinfo_line"])
      end
      errors << "#{label} must record SIGKILL after the effect boundary" unless document["signal"] == "SIGKILL" && document["child_killed"] == true

      restart = document["restart"]
      unless restart.is_a?(Hash) && restart["performed"] == true && restart["marker"].is_a?(Hash)
        errors << "#{label} must include a completed restart observation"
        return
      end
      restart_marker = restart.fetch("marker")
      restart_observation = restart_marker["observation"]
      restart_operations = restart_marker["operations"] || restart["operations"]
      errors << "#{label} restart must exercise NodeStageVolume and NodePublishVolume" unless
        restart_marker["passed"] == true && Array(restart_operations).sort == %w[NodePublishVolume NodeStageVolume]
      errors << "#{label} restart measurement source must be native" unless restart_marker["measurement_source"] == source
      unless restart_observation.is_a?(Hash) && valid_digest?(restart_marker["observation_sha256"]) &&
             restart_marker["observation_sha256"] == canonical_document_digest(restart_observation)
        errors << "#{label} restart observation digest is invalid"
        return
      end
      errors << "#{label} restart observation operations do not bind both node operations" unless
        Array(restart_observation["operation"]).sort == %w[NodePublishVolume NodeStageVolume]
      validate_node_crash_process_identity(restart_observation["child"], restart_marker["child_identity_sha256"], errors, "#{label} restart child")
      %w[stage_target publish_target].each do |key|
        validate_node_crash_target_identity(restart_observation[key], nil, errors, "#{label} restart #{key}")
      end
      restart_mountinfo = restart_observation["mountinfo"]
      errors << "#{label} restart child mountinfo is missing or not content-bound" unless
        restart_mountinfo.is_a?(Array) && !restart_mountinfo.empty? && restart_mountinfo.all? { |line| non_empty_string?(line) } &&
        valid_digest?(restart_marker["mountinfo_sha256"]) &&
        restart_marker["mountinfo_sha256"] == Digest::SHA256.hexdigest(restart_mountinfo.join("\n"))
      if restart_mountinfo.is_a?(Array)
        %w[stage_target publish_target].each do |key|
          target_identity = restart_observation[key]
          errors << "#{label} restart #{key} mountinfo line is not in the child mountinfo" unless
            target_identity.is_a?(Hash) && restart_mountinfo.include?(target_identity["mountinfo_line"])
        end
      end
    end

    def validate_node_crash_process_identity(identity, digest, errors, label)
      unless identity.is_a?(Hash) && identity["pid"].is_a?(Integer) && identity["pid"].positive? &&
             identity["start_time_ticks"].is_a?(Integer) && identity["start_time_ticks"].positive? &&
             identity["mount_namespace_inode"].is_a?(Integer) && identity["mount_namespace_inode"].positive? &&
             identity["path"] == "/proc/#{identity["pid"]}/ns/mnt" && valid_digest?(digest) &&
             digest == canonical_document_digest(identity)
        errors << "#{label} must bind PID, /proc start time, mount namespace inode, and identity digest"
      end
    end

    def validate_node_crash_target_identity(identity, digest, errors, label)
      unless identity.is_a?(Hash) && non_empty_string?(identity["path"]) &&
             identity["device"].is_a?(Integer) && identity["device"].positive? &&
             identity["inode"].is_a?(Integer) && identity["inode"].positive? &&
             identity["mount_id"].is_a?(Integer) && identity["mount_id"].positive? &&
             identity["device_major_minor"].to_s.match?(/\A\d+:\d+\z/) &&
             node_crash_mountinfo_matches_identity?(identity) &&
             (digest.nil? || (valid_digest?(digest) && digest == canonical_document_digest(identity)))
        errors << "#{label} must bind target path, dev/inode, mount ID, and mountinfo"
      end
    end

    def node_crash_mountinfo_matches_identity?(identity)
      fields = identity["mountinfo_line"].to_s.split(" - ", 2).first.to_s.split(" ")
      return false unless fields.length >= 6

      mountpoint = fields[4].gsub(/\\([0-7]{3})/) { Regexp.last_match(1).to_i(8).chr }
      fields[0].to_i == identity["mount_id"] && fields[2] == identity["device_major_minor"].to_s && mountpoint == identity["path"]
    rescue StandardError
      false
    end

    def validate_external_runner_observation(document, errors, label, owner_document: nil)
      unless document.is_a?(Hash) && document["executed"] == true
        errors << "#{label} must be executed by an external runner"
        return
      end
      runner = document["runner"]
      unless runner.is_a?(Hash) && valid_digest?(runner["runner_sha256"]) && document["runner_sha256"] == runner["runner_sha256"] &&
             runner["command"].is_a?(Array) && !runner["command"].empty? && runner["command"].all? { |part| non_empty_string?(part) } &&
             runner["process_id"].is_a?(Integer) && runner["process_id"].positive?
        errors << "#{label} runner provenance is incomplete"
      end
      errors << "#{label} runner provenance mode must be external" unless runner.is_a?(Hash) && runner["mode"] == "external"
      errors << "#{label} runner provenance must not be a self-comparison" unless runner.is_a?(Hash) && runner["self_comparison"] == false
      errors << "#{label} runner implementation is required" unless runner.is_a?(Hash) && non_empty_string?(runner["implementation"])
      errors << "#{label} runner must not be a milestone probe" if Array(runner && runner["command"]).any? { |part| part.to_s.match?(/m4_.*_probe\.rb\z/) }
      local_runner_sha256 = owner_document.is_a?(Hash) ? owner_document.dig("adapter", "runner_sha256") : nil
      errors << "#{label} runner digest must differ from the local probe" if valid_digest?(local_runner_sha256) && runner.is_a?(Hash) && runner["runner_sha256"] == local_runner_sha256
      %w[started_at finished_at].each { |key| errors << "#{label} runner #{key} must be ISO-8601" unless iso8601?(runner && runner[key]) }
      if iso8601?(runner && runner["started_at"]) && iso8601?(runner && runner["finished_at"]) && Time.iso8601(runner["finished_at"]) < Time.iso8601(runner["started_at"])
        errors << "#{label} runner finished before it started"
      end
    end

    def validate_observable_comparison(comparison, errors, label)
      unless comparison.is_a?(Hash)
        errors << "#{label} must be an object"
        return
      end
      expected = comparison["expected_observable"]
      actual = comparison["actual_observable"]
      structured = ->(value) { value.is_a?(Hash) || value.is_a?(Array) }
      errors << "#{label} must include structured expected and actual observations" unless structured.call(expected) && structured.call(actual)
      expected_digest = comparison["expected_sha256"]
      actual_digest = comparison["actual_sha256"]
      errors << "#{label} expected digest does not match observable" unless structured.call(expected) && valid_digest?(expected_digest) && canonical_document_digest(expected) == expected_digest
      errors << "#{label} actual digest does not match observable" unless structured.call(actual) && valid_digest?(actual_digest) && canonical_document_digest(actual) == actual_digest
      errors << "#{label} passed flag does not match observables" unless comparison["passed"] == (valid_digest?(expected_digest) && expected_digest == actual_digest)
      errors << "#{label} must pass the independent comparison" unless comparison["passed"] == true
    end

    def validate_network_observation(observation, errors, owner_document: nil, evidence_directory: nil, artifacts: [])
      label = "network kernel observation"
      validate_external_runner_observation(observation, errors, label, owner_document: owner_document)
      return unless observation.is_a?(Hash)
      netns = observation["netns"] || observation["network_namespace"]
      runner = observation["runner"]
      keeper = observation["keeper"] || (netns.is_a?(Hash) && netns["keeper"]) ||
               (runner.is_a?(Hash) && runner["keeper"])
      live_namespace = validate_live_network_namespace(netns, runner, keeper, errors, label)
      live_resources = live_namespace &&
        live_network_resources(netns.fetch("path"), live_namespace, netns, errors, label)

      objects = observation["kernel_objects"]
      unless objects.is_a?(Array) && !objects.empty?
        errors << "#{label} must record kernel network objects"
      else
        objects.each_with_index do |object, index|
          valid_object = object.is_a?(Hash) && non_empty_string?(object["kind"]) &&
                         non_empty_string?((object["id"] || object["name"]).to_s) &&
                         object["observed"] == true
          errors << "#{label} kernel object #{index} must be observed with an identity" unless valid_object
          next unless object.is_a?(Hash)

          object_inode = object["netns_inode"] || object["namespace_inode"]
          object_digest = object["netns_identity_sha256"] || object["namespace_identity_sha256"]
          errors << "#{label} kernel object #{index} must bind the observed namespace inode" unless
            netns.is_a?(Hash) && object_inode == netns["inode"]
          errors << "#{label} kernel object #{index} must bind the namespace identity digest" unless
            netns.is_a?(Hash) && valid_digest?(object_digest) && object_digest == netns["identity_sha256"]
          validate_live_kernel_object(object, index, live_resources, live_namespace, errors, label)
        end
      end
      packet = observation["packet_trace"]
      unless packet.is_a?(Hash) && %w[pcap pcapng].include?(packet["format"]) &&
             valid_digest?(packet["sha256"]) && packet["packet_count"].is_a?(Integer) &&
             packet["packet_count"].positive? && non_empty_string?(packet["path"] || packet["capture_path"]) &&
             packet["command"].is_a?(Array) && !packet["command"].empty? &&
             packet["command"].all? { |part| non_empty_string?(part) }
        errors << "#{label} must record an actual packet trace"
      end
      validate_materialized_packet_trace(packet, errors, label, evidence_directory: evidence_directory, artifacts: artifacts)
    end

    def validate_live_network_namespace(netns, runner, keeper, errors, label)
      unless netns.is_a?(Hash) && runner.is_a?(Hash) && keeper.is_a?(Hash)
        errors << "#{label} namespace, runner, and live keeper identities are required"
        return nil
      end

      match = netns["path"].to_s.match(/\A\/proc\/(\d+)\/ns\/net\z/)
      path_pid = match && match[1].to_i
      keeper_pid = keeper["pid"] || keeper["keeper_pid"]
      unless match && netns["pid"].is_a?(Integer) && netns["pid"].positive? &&
             keeper_pid.is_a?(Integer) && keeper_pid.positive? &&
             path_pid == netns["pid"] && netns["pid"] == keeper_pid
        errors << "#{label} path PID, namespace PID, and keeper PID must identify one live process"
        return nil
      end

      actual_start_time = proc_start_time_ticks(keeper_pid)
      actual_inode = begin
        File.stat(netns.fetch("path")).ino
      rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
        nil
      end
      unless actual_start_time&.positive? && actual_inode&.positive?
        errors << "#{label} keeper process and /proc/PID/ns/net must remain alive during gate validation"
        return nil
      end
      errors << "#{label} namespace inode does not match /proc readback" unless netns["inode"] == actual_inode
      errors << "#{label} namespace start_time_ticks does not match /proc/PID/stat field 22" unless
        netns["start_time_ticks"] == actual_start_time

      runner_pid = runner["process_id"]
      errors << "#{label} namespace runner_pid must bind to the external runner PID" unless
        runner_pid.is_a?(Integer) && runner_pid.positive? && netns["runner_pid"] == runner_pid
      actual_runner_start_time = runner_pid.is_a?(Integer) && runner_pid.positive? ? proc_start_time_ticks(runner_pid) : nil
      recorded_runner_start_time = runner["start_time_ticks"] || runner["runner_start_time_ticks"]
      errors << "#{label} external runner process must remain alive during gate validation" unless actual_runner_start_time&.positive?
      errors << "#{label} runner start_time_ticks does not match /proc/PID/stat field 22" unless
        recorded_runner_start_time&.positive? && recorded_runner_start_time == actual_runner_start_time
      errors << "#{label} keeper must bind to the external runner PID" unless keeper["runner_pid"] == runner_pid
      errors << "#{label} runner must bind the live keeper PID" unless runner["keeper_pid"] == keeper_pid
      errors << "#{label} runner must bind the live keeper start time" unless
        runner["keeper_start_time_ticks"] == actual_start_time
      errors << "#{label} keeper start time does not match the live process" unless
        keeper["start_time_ticks"] == actual_start_time
      keeper_inode = keeper["netns_inode"] || keeper["namespace_inode"] || keeper["inode"]
      errors << "#{label} keeper must bind the live namespace inode" unless keeper_inode == actual_inode
      errors << "#{label} keeper namespace path is incorrect" unless keeper["path"] == netns["path"]
      errors << "#{label} keeper must be the runner itself or a live runner descendant" unless
        runner_pid.is_a?(Integer) && runner_pid.positive? && keeper_pid.is_a?(Integer) && keeper_pid.positive? &&
        (runner_pid == keeper_pid || proc_descends_from?(keeper_pid, runner_pid))

      keeper_identity = keeper["identity"]
      expected_keeper = {
        "path" => netns["path"],
        "pid" => keeper_pid,
        "runner_pid" => runner_pid,
        "start_time_ticks" => actual_start_time,
        "netns_inode" => actual_inode
      }
      unless keeper_identity.is_a?(Hash) && expected_keeper.all? { |key, value| keeper_identity[key] == value }
        errors << "#{label} keeper identity must include live PID/start-time/netns readback"
      end
      keeper_digest = keeper_identity.is_a?(Hash) ? canonical_document_digest(keeper_identity) : nil
      errors << "#{label} keeper identity digest is invalid" unless
        valid_digest?(keeper["identity_sha256"]) && keeper["identity_sha256"] == keeper_digest
      errors << "#{label} runner keeper identity digest is invalid" unless
        runner["keeper_identity_sha256"] == keeper["identity_sha256"]

      identity = netns["identity"]
      expected_namespace = {
        "path" => netns["path"],
        "pid" => keeper_pid,
        "runner_pid" => runner_pid,
        "start_time_ticks" => actual_start_time,
        "inode" => actual_inode,
        "keeper_identity_sha256" => keeper["identity_sha256"]
      }
      unless identity.is_a?(Hash) && expected_namespace.all? { |key, value| identity[key] == value }
        errors << "#{label} namespace identity must bind live path/PID/start-time/inode/keeper"
      end
      errors << "#{label} namespace identity digest is invalid" unless
        identity.is_a?(Hash) && valid_digest?(netns["identity_sha256"]) &&
        netns["identity_sha256"] == canonical_document_digest(identity)

      # Read both identities again after validation. A keeper exit/PID reuse or
      # namespace replacement during the gate invalidates the evidence.
      unless proc_start_time_ticks(keeper_pid) == actual_start_time &&
             runner_pid.is_a?(Integer) && proc_start_time_ticks(runner_pid) == actual_runner_start_time &&
             (File.stat(netns.fetch("path")).ino rescue nil) == actual_inode
        errors << "#{label} keeper identity changed during gate validation"
        return nil
      end
      {"pid" => keeper_pid, "start_time_ticks" => actual_start_time, "inode" => actual_inode}
    end

    def proc_start_time_ticks(pid)
      value = File.binread("/proc/#{Integer(pid)}/stat", 16 * 1024)
      closing_parenthesis = value.rindex(")")
      return nil unless closing_parenthesis

      fields_from_state = value.byteslice(closing_parenthesis + 2..).to_s.split
      start_time = Integer(fields_from_state.fetch(19))
      start_time.positive? ? start_time : nil
    rescue ArgumentError, TypeError, IndexError, Errno::ENOENT, Errno::EACCES, Errno::ESRCH
      nil
    end

    def proc_parent_pid(pid)
      value = File.binread("/proc/#{Integer(pid)}/stat", 16 * 1024)
      closing_parenthesis = value.rindex(")")
      return nil unless closing_parenthesis

      fields_from_state = value.byteslice(closing_parenthesis + 2..).to_s.split
      parent = Integer(fields_from_state.fetch(1))
      parent.positive? ? parent : nil
    rescue ArgumentError, TypeError, IndexError, Errno::ENOENT, Errno::EACCES, Errno::ESRCH
      nil
    end

    def proc_descends_from?(child_pid, ancestor_pid, max_depth: 64)
      current = Integer(child_pid)
      ancestor = Integer(ancestor_pid)
      seen = {}
      max_depth.times do
        return true if current == ancestor
        return false if seen[current]

        seen[current] = true
        parent = proc_parent_pid(current)
        return false unless parent

        current = parent
      end
      false
    rescue ArgumentError, TypeError
      false
    end

    def live_network_resources(path, live_namespace, netns, errors, label)
      observer = Rubernetes::Network::NativeObserver.new
      unless observer.external_observer?
        errors << "#{label} native rtnetlink readback is unavailable"
        return nil
      end
      self_inode = File.stat("/proc/self/ns/net").ino
      resources = if self_inode == live_namespace.fetch("inode")
                    observer.resources
                  else
                    # The observer enters a foreign namespace only through a
                    # pidfd-verified lease on the live keeper.
                    pidfd = Rubernetes::Platform::Linux::Pidfd.new.open(pid: live_namespace.fetch("pid"), resource_id: "m4-gate:#{live_namespace.fetch("pid")}")
                    begin
                      lease = Rubernetes::Network::Netlink::NamespaceLease.open(
                        "handle" => "m4-gate:#{live_namespace.fetch("pid")}", "path" => path, "inode" => live_namespace.fetch("inode"),
                        "pid" => live_namespace.fetch("pid"), "pidfd" => pidfd, "start_time" => live_namespace.fetch("start_time_ticks")
                      )
                      begin
                        observer.resources(namespace_fd: lease.fileno)
                      ensure
                        lease.close
                      end
                    ensure
                      begin
                        IO.for_fd(pidfd).close
                      rescue IOError, SystemCallError
                        nil
                      end
                    end
                  end
      namespace_resource = {
        "kind" => "netns",
        "id" => "netns:#{live_namespace.fetch("inode")}",
        "identity" => netns.fetch("identity"),
        "owner" => "procfs-observer",
        "state" => "observed",
        "metadata" => {
          "netns_inode" => live_namespace.fetch("inode"),
          "pid" => live_namespace.fetch("pid"),
          "start_time_ticks" => live_namespace.fetch("start_time_ticks"),
          "path" => path
        }
      }
      resources = [namespace_resource, *Array(resources)]
      unless proc_start_time_ticks(live_namespace.fetch("pid")) == live_namespace.fetch("start_time_ticks") &&
             (File.stat(path).ino rescue nil) == live_namespace.fetch("inode")
        errors << "#{label} keeper identity changed during native rtnetlink readback"
        return nil
      end
      resources
    rescue StandardError => error
      errors << "#{label} native rtnetlink readback failed: #{error.class}: #{error.message}"
      nil
    end

    def validate_live_kernel_object(object, index, live_resources, live_namespace, errors, label)
      unless live_resources.is_a?(Array)
        errors << "#{label} kernel object #{index} has no live kernel readback"
        return
      end

      kind = object["kind"]
      id = object["id"] || object["name"]
      live = live_resources.find { |entry| entry["kind"] == kind && entry["id"] == id }
      unless live
        errors << "#{label} kernel object #{index} is absent from native rtnetlink/procfs readback"
        return
      end

      readback = object["readback"]
      errors << "#{label} kernel object #{index} readback differs from the live kernel object" unless readback == live
      errors << "#{label} kernel object #{index} readback digest is invalid" unless
        readback.is_a?(Hash) && valid_digest?(object["readback_sha256"]) &&
        object["readback_sha256"] == canonical_document_digest(live)
      errors << "#{label} kernel object #{index} identity differs from live readback" unless
        object["identity"] == live["identity"]
      errors << "#{label} kernel object #{index} identity digest is invalid" unless
        valid_digest?(object["identity_sha256"]) &&
        object["identity_sha256"] == canonical_document_digest(live["identity"])

      metadata = live["metadata"]
      errors << "#{label} kernel object #{index} readback namespace inode differs" unless
        metadata.is_a?(Hash) && metadata["netns_inode"] == live_namespace["inode"]
      return if kind == "netns"

      ifindex = metadata.is_a?(Hash) ? metadata["ifindex"] : nil
      valid_ifindex = if kind == "route"
                        ifindex.is_a?(Integer) && ifindex >= 0
                      else
                        ifindex.is_a?(Integer) && ifindex.positive?
                      end
      errors << "#{label} kernel object #{index} live readback ifindex is invalid" unless valid_ifindex
      errors << "#{label} kernel object #{index} must record the live ifindex" unless object["ifindex"] == ifindex
      errors << "#{label} kernel object #{index} identity does not bind inode/ifindex" unless
        live["identity"].to_s.include?("netns=#{live_namespace["inode"]}:ifindex=#{ifindex}")
    end

    def validate_proxy_readback(readback, errors, owner_document: nil)
      label = "proxy backend kernel readback"
      validate_external_runner_observation(readback, errors, label, owner_document: owner_document)
      return unless readback.is_a?(Hash)
      ebpf = readback["ebpf"]
      nftables = readback["nftables"]
      unless ebpf.is_a?(Hash) && ebpf["verified"] == true && ebpf["readback"] == true && ebpf["program_id"].is_a?(Integer) && ebpf["program_id"].positive? && ebpf["map_id"].is_a?(Integer) && ebpf["map_id"].positive? && valid_digest?(ebpf["verifier_log_sha256"]) && ebpf["rules"].is_a?(Array) && !ebpf["rules"].empty?
        errors << "proxy eBPF backend must include verifier and kernel readback evidence"
      end
      unless nftables.is_a?(Hash) && nftables["readback"] == true && non_empty_string?(nftables["family"]) && non_empty_string?(nftables["table"]) && nftables["rules"].is_a?(Array) && !nftables["rules"].empty? && valid_digest?(nftables["ruleset_sha256"])
        errors << "proxy nftables backend must include kernel ruleset readback evidence"
      end
      parity = readback["parity"]
      validate_observable_comparison(parity, errors, "proxy backend readback parity")
    end

    def validate_volume_observation(document, errors, owner_document: nil)
      observation = document["kernel_observation"]
      validate_external_runner_observation(observation, errors, "volume kernel/container observation", owner_document: owner_document)
      csi = document["csi_oracle"]
      snapshot = document["snapshot_recovery"]
      validate_external_runner_observation(csi, errors, "CSI oracle", owner_document: owner_document)
      validate_external_runner_observation(snapshot, errors, "snapshot/restore crash-recovery runner", owner_document: owner_document)
      validate_volume_external_operations(csi, REQUIRED_CSI_OPERATIONS, errors, "csi_oracle", owner_document: owner_document)
      validate_volume_external_operations(snapshot, REQUIRED_SNAPSHOT_OPERATIONS, errors, "snapshot_recovery", owner_document: owner_document)
      return unless observation.is_a?(Hash)
      mountinfo = observation["mountinfo"]
      syscalls = observation["syscalls"]
      containers = observation["container_observation"] || observation["containers"]
      unless mountinfo.is_a?(Array) && !mountinfo.empty?
        errors << "volume kernel/container observation must include mountinfo records"
      else
        mountinfo.each_with_index do |entry, index|
          valid_line = entry.is_a?(Hash) && non_empty_string?(entry["line"]) && valid_digest?(entry["line_sha256"]) &&
                       Digest::SHA256.hexdigest(entry["line"]) == entry["line_sha256"]
          errors << "volume mountinfo record #{index} has no content-bound line" unless valid_line
          validate_content_bound_observation(entry, errors, "volume mountinfo record #{index}") if entry.is_a?(Hash)
        end
      end
      unless syscalls.is_a?(Array) && !syscalls.empty?
        errors << "volume kernel/container observation must include syscall records"
      else
        syscalls.each_with_index do |entry, index|
          errors << "volume syscall record #{index} has no syscall identity" unless
            entry.is_a?(Hash) && non_empty_string?(entry["name"]) && entry.key?("return")
          validate_content_bound_observation(entry, errors, "volume syscall record #{index}") if entry.is_a?(Hash)
        end
      end
      unless containers.is_a?(Array) && !containers.empty?
        errors << "volume kernel/container observation must include container observations"
      else
        containers.each_with_index do |entry, index|
          errors << "volume container observation #{index} has no process identity" unless
            entry.is_a?(Hash) && non_empty_string?((entry["container_id"] || entry["id"]).to_s) &&
            entry["pid"].is_a?(Integer) && entry["pid"].positive?
          validate_content_bound_observation(entry, errors, "volume container observation #{index}") if entry.is_a?(Hash)
        end
      end

    end

    # Volume observations are comparisons, not liveness flags.  Every record
    # must bind both sides to its content digest and derive `passed` from the
    # digest equality.  The old `observed: true` field is intentionally not
    # accepted as a substitute for either side of the comparison.
    def validate_content_bound_observation(observation, errors, label)
      unless observation.is_a?(Hash)
        errors << "#{label} must be an object"
        return
      end
      expected_key = observation.key?("expected") ? "expected" : (observation.key?("expected_observable") ? "expected_observable" : nil)
      actual_key = observation.key?("actual") ? "actual" : (observation.key?("actual_observable") ? "actual_observable" : nil)
      unless expected_key && actual_key
        errors << "#{label} must include expected and actual observations"
        return
      end
      expected = observation[expected_key]
      actual = observation[actual_key]
      structured = ->(value) { value.is_a?(Hash) || value.is_a?(Array) }
      errors << "#{label} expected and actual observations must be structured" unless structured.call(expected) && structured.call(actual)
      errors << "#{label} expected observation must not be empty" if structured.call(expected) && expected.empty?
      errors << "#{label} actual observation must not be empty" if structured.call(actual) && actual.empty?

      expected_digest = observation["expected_sha256"]
      actual_digest = observation["actual_sha256"]
      errors << "#{label} must include valid expected and actual SHA-256 digests" unless valid_digest?(expected_digest) && valid_digest?(actual_digest)
      errors << "#{label} expected digest does not match observation" unless valid_digest?(expected_digest) && canonical_document_digest(expected) == expected_digest
      errors << "#{label} actual digest does not match observation" unless valid_digest?(actual_digest) && canonical_document_digest(actual) == actual_digest
      expected_pass = valid_digest?(expected_digest) && valid_digest?(actual_digest) && expected_digest == actual_digest
      errors << "#{label} passed flag must match content-bound observations" unless observation["passed"] == expected_pass
      errors << "#{label} must pass the content-bound comparison" unless observation["passed"] == true
    end

    def validate_volume_external_operations(document, required_operations, errors, label, owner_document: nil)
      comparisons = document.is_a?(Hash) ? document["comparisons"] : nil
      unless comparisons.is_a?(Array) && !comparisons.empty?
        errors << "#{label} must include structured comparison records"
        return
      end
      observed_operations = []
      comparisons.each_with_index do |entry, index|
        unless entry.is_a?(Hash) && non_empty_string?(entry["id"] || entry["case"] || entry["operation"] || entry["name"] || entry["operation_id"] || entry["operationId"])
          errors << "#{label} comparison #{index} must identify an operation"
          next
        end
        validate_content_bound_observation(entry, errors, "#{label} comparison #{index}")
        operation = canonical_volume_operation(entry)
        observed_operations << operation if operation
      end
      required_operations.each do |required|
        unless observed_operations.any? { |operation| volume_operation_matches?(operation, required) }
          errors << "#{label} is missing required operation #{required}"
        end
      end
    end

    def canonical_volume_operation(entry)
      values = %w[operation name id case operation_id operationId].filter_map { |key| entry[key] if non_empty_string?(entry[key]) }
      values.each do |value|
        normalized = value.gsub(/[^A-Za-z0-9]/, "").downcase
        return "GetPluginInfo" if %w[getplugininfo identity plugininfo].include?(normalized)
        return "CreateVolume" if %w[createvolume createvolumeoperation create].include?(normalized)
        return "DeleteVolume" if %w[deletevolume delete].include?(normalized)
        return "ControllerPublishVolume" if %w[controllerpublishvolume controllerpublish attach publish].include?(normalized)
        return "ControllerUnpublishVolume" if %w[controllerunpublishvolume controllerunpublish detach unpublish].include?(normalized)
        return "NodeStageVolume" if %w[nodestagevolume nodestage stage mount].include?(normalized)
        return "NodeUnstageVolume" if %w[nodeunstagevolume nodeunstage unstage unmount].include?(normalized)
        return "NodePublishVolume" if %w[nodepublishvolume nodepublish publishnode].include?(normalized)
        return "NodeUnpublishVolume" if %w[nodeunpublishvolume nodeunpublish unpublishnode].include?(normalized)
        return "NodeGetVolumeStats" if %w[nodegetvolumestats nodegetvolumestats stats].include?(normalized)
        return "CreateSnapshot" if %w[createsnapshot snapshotsnapshot snapshotcreate snapshot].include?(normalized)
        return "ListVolumes" if %w[listvolumes volumeinventory].include?(normalized)
        return "ListSnapshots" if %w[listsnapshots snapshotinventory].include?(normalized)
        return "snapshot_create" if %w[snapshotcreate createsnapshotoperation].include?(normalized)
        return "snapshot_restore" if %w[snapshotrestore restoresnapshot restore].include?(normalized)
        return "crash_recovery" if %w[crashrecovery nodecrash crash].include?(normalized)
      end
      nil
    end

    def volume_operation_matches?(observed, required)
      return true if required.to_s == "snapshot_create" && %w[CreateSnapshot snapshot_create].include?(observed.to_s)

      return true if observed.to_s.casecmp?(required.to_s)

      normalized_observed = observed.to_s.gsub(/[^A-Za-z0-9]/, "").downcase
      normalized_required = required.to_s.gsub(/[^A-Za-z0-9]/, "").downcase
      normalized_observed == normalized_required
    end

    def validate_mount_observation(observation, errors, owner_document: nil)
      label = "mount attack kernel observation"
      validate_external_runner_observation(observation, errors, label, owner_document: owner_document)
      return unless observation.is_a?(Hash)
      mountinfo = observation["mountinfo"]
      syscalls = observation["syscalls"]
      containers = observation["containers"] || observation["container_observation"]
      errors << "#{label} must include actual mountinfo" unless mountinfo.is_a?(Array) && !mountinfo.empty? && mountinfo.all? { |entry| entry.is_a?(Hash) && non_empty_string?(entry["line"]) }
      errors << "#{label} must include actual syscall observations" unless syscalls.is_a?(Array) && !syscalls.empty? && syscalls.all? { |entry| entry.is_a?(Hash) && non_empty_string?(entry["name"]) && entry.key?("return") }
      errors << "#{label} must include actual container observations" unless containers.is_a?(Array) && !containers.empty? && containers.all? { |entry| entry.is_a?(Hash) && non_empty_string?(entry["container_id"] || entry["id"]) && entry["pid"].is_a?(Integer) && entry["pid"].positive? && entry["observed"] == true }
    end

    def validate_materialized_packet_trace(packet, errors, label, evidence_directory:, artifacts:)
      return unless packet.is_a?(Hash)

      path = packet["path"] || packet["capture_path"]
      unless non_empty_string?(path) && !path.start_with?("/") && !path.include?("\0") &&
             !path.split("/").any? { |segment| ["", ".", ".."].include?(segment) }
        errors << "#{label} packet trace must use a normalized bundle-relative path"
        return
      end
      errors << "#{label} packet trace must be marked materialized" unless packet["materialized"] == true
      errors << "#{label} packet trace artifact_path must match its path" unless packet["artifact_path"] == path

      unless evidence_directory.is_a?(String) && !evidence_directory.empty?
        errors << "#{label} packet trace bundle directory is unavailable"
        return
      end
      full_path = evidence_path(evidence_directory, path)
      artifact = Array(artifacts).find { |entry| entry.is_a?(Hash) && entry["path"] == path }
      unless full_path && artifact
        errors << "#{label} packet trace must be a content-addressed bundle artifact"
        return
      end

      capture = begin
        M34EvidenceSupport.read_bundle_file(evidence_directory, path)
      rescue StandardError => error
        errors << "#{label} packet trace artifact could not be securely opened: #{error.message}"
        return
      end
      stat_size = capture.fetch("bytesize")
      actual_bytes = capture.fetch("bytes")
      actual_sha256 = Digest::SHA256.hexdigest(actual_bytes)
      errors << "#{label} packet trace bytes must record the actual file size" unless
        packet["bytes"].is_a?(Integer) && packet["bytes"] == stat_size &&
        packet["size"].is_a?(Integer) && packet["size"] == stat_size
      errors << "#{label} packet trace SHA-256 does not match the copied bytes" unless
        valid_digest?(packet["sha256"]) && packet["sha256"] == actual_sha256 &&
        artifact["sha256"] == actual_sha256
      errors << "#{label} packet trace artifact byte count is incorrect" unless
        artifact["bytes"].is_a?(Integer) && artifact["bytes"] == stat_size

      format = packet["format"]
      parsed = begin
        M34EvidenceSupport.parse_packet_capture_bytes(actual_bytes)
      rescue StandardError => error
        errors << "#{label} packet trace is structurally invalid: #{error.message}"
        nil
      end
      if parsed
        errors << "#{label} packet trace format is not encoded by the capture bytes" unless
          %w[pcap pcapng].include?(format) && parsed["format"] == format
        errors << "#{label} packet trace packet_count does not match parsed records" unless
          packet["packet_count"].is_a?(Integer) && packet["packet_count"].positive? &&
          packet["packet_count"] == parsed["packet_count"] &&
          packet["parsed_packet_count"] == parsed["packet_count"]
        errors << "#{label} packet trace parser identity is invalid" unless
          packet["parser"] == "rubernetes-m4-packet-capture-v1"
      end
    end

    def path_component_symlink?(root, path)
      root_real = File.realpath(root)
      expanded = File.expand_path(path)
      return true unless expanded == root_real || expanded.start_with?("#{root_real}/")

      relative = expanded.delete_prefix("#{root_real}/")
      current = root_real
      relative.split("/").reject(&:empty?).each do |component|
        current = File.join(current, component)
        begin
          return true if File.lstat(current).symlink?
        rescue Errno::ENOENT, Errno::EACCES, Errno::ELOOP
          return false
        end
      end
      false
    rescue Errno::ENOENT, Errno::EACCES, Errno::ELOOP
      true
    end

    def validate_result_counts(manifest, artifacts, subjects, errors)
      counts = manifest["result_counts"]
      return unless counts.is_a?(Hash)
      expected = {"commands" => manifest.fetch("commands", []).length, "command_failures" => manifest.fetch("commands", []).count { |command| command["exit_status"] != 0 }, "artifacts" => artifacts.length, "subjects" => subjects.length, "reports" => REPORTS.length, "source_files" => manifest["input_file_count"]}
      expected.each do |key, value|
        errors << "result_counts #{key} is missing or invalid" unless integer?(counts[key])
        errors << "result_counts #{key} is incorrect" if integer?(counts[key]) && counts[key] != value
      end
    end

    def validate_manifest_status(manifest, errors)
      errors << "manifest status must be INCOMPLETE when any M4 gate requirement fails" if errors.any? && manifest["status"] == "COMPLETE"
    end

    def kernel_at_least?(value)
      match = value.to_s.match(/\A(\d+)\.(\d+)/)
      return false unless match

      major = match[1].to_i
      minor = match[2].to_i
      major > REQUIRED_KERNEL_MAJOR || (major == REQUIRED_KERNEL_MAJOR && minor >= REQUIRED_KERNEL_MINOR)
    end

    def identity?(value)
      value.is_a?(Hash) && valid_digest?(value["sha256"]) && positive_integer?(value["file_count"])
    end

    def valid_digest?(value)
      value.is_a?(String) && value.match?(SHA256_PATTERN)
    end

    # BPF_OBJ_GET_INFO_BY_FD's program tag is an eight-byte kernel value,
    # rendered as sixteen hexadecimal characters by the native adapter. It
    # must not be confused with a forgeable SHA-256 evidence digest.
    def valid_bpf_tag?(value)
      value.is_a?(String) && value.match?(/\A[0-9a-f]{16}\z/i)
    end

    def positive_integer?(value)
      integer?(value) && value.positive?
    end

    def integer?(value)
      value.is_a?(Integer)
    end

    def non_empty_string?(value)
      value.is_a?(String) && !value.empty?
    end

    def iso8601?(value)
      Time.iso8601(value.to_s)
      true
    rescue ArgumentError, TypeError
      false
    end
  end
end

if $PROGRAM_NAME == __FILE__
  manifest_path = ARGV.fetch(0) { abort "Usage: m4_gate.rb PATH/manifest.json" }
  output = M4Gate.evaluate(manifest_path)
  puts(JSON.pretty_generate(output))
  exit(output.fetch("passed") ? 0 : 1)
end
