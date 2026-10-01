#!/usr/bin/env ruby
# frozen_string_literal: true

# Validate the content-addressed evidence bundle for Milestone M2.
#
# M2 is intentionally evidence-driven.  This gate validates the adapter
# contract, rather than trusting human-readable output or a successful command
# exit status. The x86_64 release profile must be measured on real adapters;
# optional architectures are not part of the milestone completion contract.

require "digest"
require "json"
require "open3"
require "rbconfig"
require "time"

require_relative "m1_gate"

module M2Gate
  MANIFEST_SCHEMA_VERSION = 3
  REPORT_SCHEMA_VERSION = 1
  MAX_JSON_BYTES = 32 * 1024 * 1024
  SHA256_PATTERN = /\A[0-9a-f]{64}\z/
  REQUIRED_ARCHITECTURES = %w[x86_64].freeze
  REQUIRED_LEVELS = %w[L0 L1 L2 L3].freeze
  MEASUREMENT_LEVELS = REQUIRED_LEVELS
  REQUIRED_RESOURCE_KINDS = %w[mount ns cgroup process pidfd temp].freeze
  ALLOWED_INVENTORY_RESOURCE_KINDS = (REQUIRED_RESOURCE_KINDS + %w[namespace workspace]).freeze
  CLONE_PIDFD = 0x0000_1000
  CLONE_NEWNS = 0x0002_0000
  CLONE_NEWPID = 0x2000_0000
  REQUIRED_SUBRESOURCES = %w[logs exec attach port_forward].freeze
  REQUIRED_SUBRESOURCE_ROUTES = {
    "logs" => "/api/v1/namespaces/default/pods/m2-subresource-probe/log",
    "exec" => "/api/v1/namespaces/default/pods/m2-subresource-probe/exec",
    "attach" => "/api/v1/namespaces/default/pods/m2-subresource-probe/attach",
    "port_forward" => "/api/v1/namespaces/default/pods/m2-subresource-probe/portforward"
  }.freeze
  REQUIRED_SUBRESOURCE_SERVICES = {
    "logs" => "Rubernetes::Node::LogService",
    "exec" => "Rubernetes::Node::ExecService",
    "attach" => "Rubernetes::Node::AttachService",
    "port_forward" => "Rubernetes::Node::PortForwardService"
  }.freeze
  REQUIRED_ATTACKS = %w[
    image_digest_mismatch
    path_traversal
    whiteout_escape
    symlink_race
  ].freeze
  REQUIRED_EFFECT_POINTS = %w[
    workspace_allocated
    isolation_created
    resources_attached
    workload_stopped
  ].freeze
  EFFECT_CHECKPOINTS = {
    "workspace_allocated" => {
      "state" => "WorkspaceAllocated", "from" => "ImagePinned",
      "operation" => "sandbox.workspace.prepare", "kernel_kinds" => %w[temp workspace]
    },
    "isolation_created" => {
      "state" => "IsolationCreated", "from" => "WorkspaceAllocated",
      "operation" => "sandbox.isolation.create",
      "kernel_kinds" => %w[mount namespace ns pidfd temp workspace]
    },
    "resources_attached" => {
      "state" => "ResourcesAttached", "from" => "IsolationCreated",
      "operation" => "sandbox.resources.attach",
      "kernel_kinds" => %w[cgroup mount namespace ns pidfd temp workspace]
    },
    "workload_stopped" => {
      "state" => "WorkloadStopped", "from" => "ResourcesAttached",
      "operation" => "sandbox.workload_gate.close",
      "kernel_kinds" => %w[cgroup mount namespace ns pidfd temp workspace]
    }
  }.freeze
  REQUIRED_LIFECYCLE_SEMANTICS = %w[
    init_sidecar_app_order
    startup_liveness_readiness_thresholds
    restart_policy_and_backoff
    graceful_termination_oracle
  ].freeze
  LIFECYCLE_SEMANTICS_ACTUAL_SOURCE = "rubernetes_production_semantics"
  LIFECYCLE_SEMANTICS_PROVENANCE = {
    "init_sidecar_app_order" => {
      "execution_mode" => "in_process",
      "native_effects_executed" => false,
      "production_classes" => ["Rubernetes::Node::Lifecycle", "Rubernetes::Node::ProbeManager"],
      "support_classes" => ["M2LifecycleProbe::SemanticsRuntime"],
      "support_doubles" => %w[clock sleeper]
    },
    "startup_liveness_readiness_thresholds" => {
      "execution_mode" => "in_process",
      "native_effects_executed" => false,
      "production_classes" => ["Rubernetes::Node::Lifecycle", "Rubernetes::Node::ProbeManager", "Rubernetes::Node::RestartManager"],
      "support_classes" => ["M2LifecycleProbe::SemanticsRuntime"],
      "support_doubles" => %w[clock sleeper]
    },
    "restart_policy_and_backoff" => {
      "execution_mode" => "in_process",
      "native_effects_executed" => false,
      "production_classes" => ["Rubernetes::Node::Lifecycle", "Rubernetes::Node::RestartManager"],
      "support_classes" => ["M2LifecycleProbe::SemanticsRuntime"],
      "support_doubles" => %w[clock sleeper]
    },
    "graceful_termination_oracle" => {
      "execution_mode" => "in_process",
      "native_effects_executed" => false,
      "production_classes" => ["Rubernetes::Node::Lifecycle"],
      "support_classes" => ["M2LifecycleProbe::SemanticsRuntime"],
      "support_doubles" => %w[clock sleeper]
    }
  }.freeze
  KUBERNETES_VERSION = M1Gate::KUBERNETES_VERSION
  KUBERNETES_SOURCE_COMMIT = M1Gate::KUBERNETES_SOURCE_COMMIT
  KUBERNETES_SEMANTICS_ORACLE_KIND = M1Gate::KUBERNETES_SEMANTICS_ORACLE_KIND
  LIFECYCLE_CNI_LOCK_BLOCKER = "M2 external lifecycle oracle is blocked: no repository lock selects an immutable CNI plugin digest; add third_party/locks/m2-lifecycle-cni.json with plugin, version, source_commit, image_reference, image_digest, and config_sha256 before running the privileged oracle"
  REQUIRED_MEASUREMENT_SOURCES = {
    "runtime" => "production_native_runtime",
    "attacks" => "production_image_layer_extractor",
    "lifecycle" => "production_native_lifecycle",
    "ledger" => "production_native_l3_cycles",
    "kernel" => "production_native_kernel"
  }.freeze
  REQUIRED_ADAPTER_NAMES = {
    "runtime" => "m2-runtime-probe",
    "attacks" => "m2-attack-probe",
    "lifecycle" => "m2-lifecycle-probe",
    "ledger" => "m2-ledger-probe",
    "kernel" => "m2-kernel-probe"
  }.freeze
  SOURCE_EXCLUDED_ROOTS = %w[.git artifacts build pkg tmp .bundle].freeze
  SOURCE_EXCLUDED_PATTERNS = [%r{\Aa11-generated\.[A-Za-z0-9]{6,}/}, %r{\Aapps/[^/]+/(?:log|tmp|storage)/}].freeze
  PROJECT_ROOT = File.expand_path("../..", __dir__).freeze
  M0_GATE = File.join(__dir__, "m0_gate.rb").freeze
  M1_GATE = File.join(__dir__, "m1_gate.rb").freeze
  LIFECYCLE_ORACLE_RUNNER_PATH = File.join(PROJECT_ROOT, "test/conformance/kubernetes/m2_lifecycle_oracle/runner.rb").freeze
  LIFECYCLE_ORACLE_RUNNER_LOCK_PATH = File.join(PROJECT_ROOT, "third_party/locks/m2-lifecycle-oracle-runner.json").freeze
  LIFECYCLE_ORACLE_CNI_LOCK_PATH = File.join(PROJECT_ROOT, "third_party/locks/m2-lifecycle-cni.json").freeze
  DIGEST_PINNED_IMAGE_PATTERN = /\A[^@\s]+@sha256:[0-9a-f]{64}\z/

  REPORTS = {
    "runtime" => {
      kind: "m2_runtime_profiles",
      names: %w[runtime-report.json runtime-profiles.json runtime.json]
    },
    "attacks" => {
      kind: "m2_oci_attack_corpus",
      names: %w[oci-attack-corpus.json attack-corpus.json attacks.json]
    },
    "lifecycle" => {
      kind: "m2_pod_lifecycle_trace",
      names: %w[pod-lifecycle-trace.json lifecycle-trace.json lifecycle.json]
    },
    "ledger" => {
      kind: "m2_resource_ledger",
      names: %w[resource-ledger.json cycle-ledger.json ledger.json]
    },
    "kernel" => {
      kind: "m2_kernel_inventory",
      names: %w[kernel-inventory.json kernel-object-inventory.json]
    }
  }.freeze

  FORMAL_REPORTS = {
    kind: "m2_formal_verification",
    names: %w[formal-report.json m2-formal-report.json formal-verification-report.json]
  }.freeze
  FORMAL_TOOL_NAMES = %w[tlc lean apalache].freeze
  FORMAL_SOURCE_LABELS = %w[
    tla_source tla_config apalache_config lean_source ruby_trace_verifier ruby_formal_verifier
  ].freeze
  FORMAL_PROPERTY_BINDINGS = {
    "tla" => %w[
      TypeOK ActiveResourceInvariant IdentityNonReuseInvariant CleanupOrderInvariant
      LiveOwnerInvariant RunningInvariant DigestMismatchInvariant WorkloadStoppedInvariant
      UnknownInvariant StoppedInvariant RemovedInvariant EventuallyStoppedOrRemoved
    ],
    # Apalache has no fairness semantics; the liveness property is TLC's.
    "apalache" => %w[
      TypeOK ActiveResourceInvariant IdentityNonReuseInvariant CleanupOrderInvariant
      LiveOwnerInvariant RunningInvariant DigestMismatchInvariant WorkloadStoppedInvariant
      UnknownInvariant StoppedInvariant RemovedInvariant
    ],
    "lean" => %w[initial_is_safe step_preserves_safety reachable_is_safe],
    "ruby" => %w[
      live_owner_not_released running_requires_sandbox_ready running_requires_workload_effect
      running_requires_live_process digest_mismatch_has_no_workload_effect unknown_only_cleanup_or_observe
      unknown_stop_requires_observation running_stop_result failure_rollback_preconditions
      workload_stopped_has_no_effect stopped_has_no_live_process removed_has_no_owned_resources
      resource_identity_non_reuse cleanup_reverse_acquisition
    ]
  }.freeze

  INVENTORY_NAMES = %w[
    source-inventory.json
    source_inventory.json
    canonical-source-inventory.json
    canonical_source_inventory.json
    canonical-inventory.json
  ].freeze

  ALLOWED_STATES = %w[
    New
    Validated
    ImagePinned
    WorkspaceAllocated
    IsolationCreated
    ResourcesAttached
    WorkloadStopped
    Running
    Stopping
    Stopped
    Removed
    RollingBack
    CleanupPending
    StateUnknown
  ].freeze

  TRANSITIONS = {
    "New" => %w[Validated StateUnknown],
    "Validated" => %w[ImagePinned StateUnknown],
    "ImagePinned" => %w[WorkspaceAllocated],
    "WorkspaceAllocated" => %w[IsolationCreated RollingBack StateUnknown],
    "IsolationCreated" => %w[ResourcesAttached RollingBack StateUnknown],
    "ResourcesAttached" => %w[WorkloadStopped RollingBack StateUnknown],
    "WorkloadStopped" => %w[Running RollingBack StateUnknown],
    "Running" => %w[Stopping StateUnknown],
    "Stopping" => %w[Stopped],
    "Stopped" => %w[Removed CleanupPending],
    "RollingBack" => %w[Stopped CleanupPending],
    "CleanupPending" => %w[RollingBack],
    "StateUnknown" => %w[Stopping]
  }.freeze

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
      manifest = parse_json(manifest_path, errors, "manifest")
      return result(errors) unless manifest.is_a?(Hash)

      validate_manifest_shape(manifest, errors)
      artifacts = validate_entries(manifest.fetch("artifacts", []), directory, errors, "artifact")
      subjects = validate_entries(manifest.fetch("subjects", []), directory, errors, "subject")
      artifact_index = index_artifacts(artifacts, errors)

      validate_inventory(manifest, directory, artifact_index, errors)
      validate_prior_milestones(manifest, directory, artifacts, errors)

      documents = {}
      REPORTS.each do |name, specification|
        document = report_document(name, specification, directory, artifact_index, errors)
        documents[name] = document if document
        validate_report(name, document, specification.fetch(:kind), manifest, errors) if document
      end
      validate_formal_report_if_claimed(documents["lifecycle"], manifest, directory, artifact_index, errors)
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

    def canonical_kernel_inventory_digest(objects)
      content = objects.sort_by { |object| [object.fetch("kind"), object.fetch("identity")] }.map do |object|
        [object.fetch("kind"), object.fetch("identity"), object.fetch("before"), object.fetch("after")].join("\0") + "\n"
      end.join
      Digest::SHA256.hexdigest(content)
    end

    # Digest machine-readable evidence after recursively sorting object keys.
    # JSON object insertion order is not evidence: equivalent reports must
    # have the same digest regardless of producer serialization order.
    def canonical_document_digest(document, excluded_keys: [])
      value = canonical_value(document, excluded_keys.map(&:to_s))
      Digest::SHA256.hexdigest(JSON.generate(value))
    end

    private

    def result(errors)
      {
        "schema_version" => 1,
        "milestone" => "M2",
        "passed" => errors.empty?,
        "error_count" => errors.length,
        "errors" => errors
      }
    end

    def parse_json(path, errors, label)
      size = File.size(path)
      if size > MAX_JSON_BYTES
        errors << "#{label} exceeds the #{MAX_JSON_BYTES}-byte JSON limit"
        return nil
      end

      JSON.parse(File.binread(path), object_class: StrictHash, max_nesting: 512)
    rescue Errno::ENOENT
      errors << "#{label} is missing"
      nil
    rescue JSON::ParserError, DuplicateJSONKeyError => error
      errors << "#{label} is not valid JSON: #{error.message}"
      nil
    end

    def validate_manifest_shape(manifest, errors)
      errors << "schema_version must be #{MANIFEST_SCHEMA_VERSION}" unless manifest["schema_version"] == MANIFEST_SCHEMA_VERSION
      errors << "milestone must be M2" unless manifest["milestone"] == "M2"
      errors << "manifest status must be COMPLETE" unless manifest["status"] == "COMPLETE"
      errors << "input_sha256 must be a SHA-256 digest" unless valid_digest?(manifest["input_sha256"])
      errors << "input_file_count must be positive" unless positive_integer?(manifest["input_file_count"])
      errors << "source input must remain stable during evidence capture" unless manifest["input_stable"] == true

      host = manifest["host"]
      unless host.is_a?(Hash) && %w[architecture kernel ruby].all? { |key| non_empty_string?(host[key]) }
        errors << "host architecture, kernel, and Ruby description are required"
      end

      %w[started_at finished_at].each do |key|
        Time.iso8601(manifest[key].to_s)
      rescue ArgumentError
        errors << "#{key} must be an ISO-8601 timestamp"
      end

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
      unless start["sha256"] == manifest["input_sha256"] && finish["sha256"] == manifest["input_sha256"] &&
             start["file_count"] == manifest["input_file_count"] && finish["file_count"] == manifest["input_file_count"]
        errors << "input_capture identities must match the manifest input"
      end
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
      unless starts.is_a?(Array) && finishes.is_a?(Array) && starts.all? { |path| non_empty_string?(path) } &&
             finishes.all? { |path| non_empty_string?(path) }
        errors << "git_metadata_capture paths must be arrays of paths"
        return
      end
      errors << "git metadata changed during evidence capture" unless capture["stable"] == true && starts == finishes
      # A Git checkout is allowed (the repository records every cycle); the
      # capture must only be stable across the run, so evidence never depends
      # on metadata that changed underneath it.
    end

    def project_git_metadata_paths
      Dir.glob(File.join(PROJECT_ROOT, "**/.git"), File::FNM_DOTMATCH)
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
        errors << "command #{index} must record its argv" unless (argv.is_a?(Array) && !argv.empty?) || non_empty_string?(argv)
        errors << "command #{index} must have an exit status" unless integer?(command["exit_status"])
        errors << "command #{index} did not exit zero" unless command["exit_status"] == 0
        %w[started_at finished_at].each do |key|
          Time.iso8601(command[key].to_s)
        rescue ArgumentError
          errors << "command #{index} #{key} must be an ISO-8601 timestamp"
        end
        begin
          started_at = Time.iso8601(command["started_at"].to_s)
          finished_at = Time.iso8601(command["finished_at"].to_s)
          errors << "command #{index} finished before it started" if finished_at < started_at
        rescue ArgumentError
          # The timestamp-specific errors above are the actionable diagnostics.
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
        unless File.file?(path)
          errors << "missing #{label} #{path_value}"
          next
        end
        resolved = File.realpath(path)
        errors << "#{label} digest mismatch #{path_value}" if valid_digest?(entry["sha256"]) && Digest::SHA256.file(resolved).hexdigest != entry["sha256"]
        errors << "#{label} byte count mismatch #{path_value}" if integer?(entry["bytes"]) && File.size(resolved) != entry["bytes"]
        entry
      end
    end

    def evidence_path(directory, relative_path)
      return nil unless non_empty_string?(relative_path)
      return nil if relative_path.include?("\0") || relative_path.start_with?("/") || relative_path.match?(%r{\A[A-Za-z]:[\\/]})

      path = File.expand_path(relative_path, directory)
      return nil unless path.start_with?("#{directory}/")
      return nil if File.exist?(path) && !File.realpath(path).start_with?("#{File.realpath(directory)}/")

      path
    rescue Errno::ENOENT, Errno::EACCES
      nil
    end

    def index_artifacts(artifacts, errors)
      artifacts.each_with_object({}) do |artifact, index|
        next unless artifact.is_a?(Hash) && non_empty_string?(artifact["path"])
        # Reports and the source inventory are top-level M2 artifacts. Prior
        # milestone bundles are nested and may contain repeated basenames
        # such as manifest.json; they are addressed by their full paths.
        next if artifact["path"].include?("/")

        basename = File.basename(artifact["path"])
        if index.key?(basename)
          errors << "duplicate artifact basename #{basename}"
        else
          index[basename] = artifact
        end
      end
    end

    def validate_inventory(manifest, directory, artifact_index, errors)
      artifact = find_named_artifact(INVENTORY_NAMES, artifact_index, errors, "source inventory")
      return unless artifact

      document = parse_json(evidence_path(directory, artifact["path"]), errors, "source inventory")
      return unless document.is_a?(Hash)

      errors << "source inventory schema_version must be #{REPORT_SCHEMA_VERSION}" unless document["schema_version"] == REPORT_SCHEMA_VERSION
      errors << "source inventory kind must be m2_source_inventory" unless document["kind"] == "m2_source_inventory"
      errors << "source inventory input_sha256 must match manifest" unless document["input_sha256"] == manifest["input_sha256"]
      errors << "source inventory input_file_count must match manifest" unless document["input_file_count"] == manifest["input_file_count"]
      errors << "source inventory input_stable must be true" unless document["input_stable"] == true
      entries = document["entries"]
      unless entries.is_a?(Array) && !entries.empty?
        errors << "source inventory entries must be a non-empty array"
        return
      end
      paths = []
      valid_entries = entries.filter_map.with_index do |entry, index|
        unless entry.is_a?(Hash)
          errors << "source inventory entry #{index} must be an object"
          next
        end
        path_value = entry["path"]
        invalid_segments = path_value.is_a?(String) && path_value.split("/").any? { |segment| ["", ".", ".."].include?(segment) }
        excluded_root = excluded_source_path?(path_value)
        unless non_empty_string?(path_value) && !path_value.start_with?("/") && !path_value.include?("\0") && !invalid_segments && !excluded_root
          errors << "source inventory entry #{index} path is invalid"
          next
        end
        errors << "source inventory paths must be unique" if paths.include?(path_value)
        paths << path_value
        errors << "source inventory entry #{path_value} must have a SHA-256 digest" unless valid_digest?(entry["sha256"])
        errors << "source inventory entry #{path_value} has invalid byte count" unless integer?(entry["bytes"]) && entry["bytes"] >= 0
        entry
      end
      errors << "source inventory entries must be sorted by path" unless valid_entries.map { |entry| entry.fetch("path") }.sort == paths
      errors << "source inventory digest does not match manifest input" unless canonical_inventory_digest(valid_entries) == manifest["input_sha256"]
      errors << "source inventory file count does not match manifest input" unless valid_entries.length == manifest["input_file_count"]
    end

    def validate_prior_milestones(manifest, directory, artifacts, errors)
      prior = manifest["prior_milestones"]
      unless prior.is_a?(Hash)
        errors << "COMPLETE M0 and M1 evidence is required for cumulative M2 completion"
        return
      end
      validate_prior_milestone("M0", prior["M0"], manifest, directory, artifacts, errors, M0_GATE)
      validate_prior_milestone("M1", prior["M1"], manifest, directory, artifacts, errors, M1_GATE)
    end

    def validate_prior_milestone(name, reference, manifest, directory, artifacts, errors, gate_path)
      unless reference.is_a?(Hash)
        errors << "COMPLETE #{name} evidence is required for cumulative M2 completion"
        return
      end
      manifest_value = reference["manifest_path"]
      result_value = reference["gate_result_path"]
      errors << "#{name} manifest and gate result paths must be distinct" if manifest_value == result_value
      manifest_entry = artifacts.find { |entry| entry["path"] == manifest_value }
      result_entry = artifacts.find { |entry| entry["path"] == result_value }
      errors << "#{name} manifest must be content-addressed by M2" unless manifest_entry
      errors << "#{name} gate result must be content-addressed by M2" unless result_entry
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
      errors << "#{name} evidence must use the same source input as M2" unless prior_manifest["input_sha256"] == manifest["input_sha256"] &&
                                                                               prior_manifest["input_file_count"] == manifest["input_file_count"]
      errors << "#{name} reference identity must match the M2 source input" unless reference["input_sha256"] == manifest["input_sha256"] &&
                                                                                   reference["input_file_count"] == manifest["input_file_count"]
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
          nested_path = File.join(File.dirname(manifest_value), entry["path"])
          errors << "#{name} #{collection} entry is not content-addressed by M2: #{nested_path}" unless artifacts.any? do |artifact|
            artifact["path"] == nested_path
          end
        end
      end

      return unless gate_path

      gate_stdout, gate_stderr, gate_status = Open3.capture3(RbConfig.ruby, gate_path, manifest_path, chdir: PROJECT_ROOT)
      errors << "#{name} gate emitted stderr during cumulative validation" unless gate_stderr.empty?
      unless gate_status.success?
        prior_errors = begin
          JSON.parse(gate_stdout).fetch("errors", [])
        rescue StandardError
          []
        end
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

    def validate_formal_report_if_claimed(lifecycle_document, manifest, directory, artifact_index, errors)
      claims = lifecycle_document.is_a?(Hash) ? lifecycle_document["formal_claims"] : nil
      return unless claims

      unless claims.is_a?(Array) && claims.all? { |claim| non_empty_string?(claim) }
        errors << "Pod lifecycle formal_claims must be an array of names"
        return
      end
      return unless claims.include?("RuntimeLifecycle")

      artifact = find_named_artifact(FORMAL_REPORTS.fetch(:names), artifact_index, errors, "RuntimeLifecycle formal report")
      return unless artifact

      path = evidence_path(directory, artifact["path"])
      return unless path

      formal = parse_json(path, errors, "RuntimeLifecycle formal report")
      return unless formal.is_a?(Hash)

      validate_formal_report(formal, lifecycle_document, manifest, errors)
    end

    def validate_formal_report(document, lifecycle_document, _manifest, errors)
      label = "RuntimeLifecycle formal report"
      errors << "#{label} schema_version must be #{REPORT_SCHEMA_VERSION}" unless document["schema_version"] == REPORT_SCHEMA_VERSION
      errors << "#{label} kind must be #{FORMAL_REPORTS.fetch(:kind)}" unless document["kind"] == FORMAL_REPORTS.fetch(:kind)
      errors << "#{label} milestone must be M2" unless document["milestone"] == "M2"
      errors << "#{label} claim must be RuntimeLifecycle" unless document["claim"] == "RuntimeLifecycle"
      errors << "#{label} report_sha256 is required" unless valid_digest?(document["report_sha256"])
      if valid_digest?(document["report_sha256"]) && document["report_sha256"] != canonical_document_digest(document,
                                                                                                            excluded_keys: ["report_sha256"])
        errors << "#{label} report_sha256 does not match canonical content"
      end

      validate_formal_sources(document["formal_sources"], errors, label)
      errors << "#{label} properties must bind the required RuntimeLifecycle properties" unless
        document["properties"] == FORMAL_PROPERTY_BINDINGS
      validate_formal_property_results(document, errors, label)
      trace_sha256 = document["trace_sha256"]
      errors << "#{label} trace_sha256 is required" unless valid_digest?(trace_sha256)
      errors << "#{label} trace_sha256 must match the lifecycle report" if valid_digest?(trace_sha256) &&
                                                                           trace_sha256 != lifecycle_document["trace_sha256"]

      %w[ruby_trace_verifier tla lean external_proof_profile].each do |name|
        result = document[name]
        unless result.is_a?(Hash)
          errors << "#{label} #{name} result is required"
          next
        end
        errors << "#{label} #{name} result must record success" unless result.key?("success")
      end

      status = document["status"]
      errors << "#{label} status must be PASS or INCOMPLETE" unless %w[PASS INCOMPLETE].include?(status)
      errors << "#{label} passed must match success" unless document["passed"] == (document["success"] == true)
      if status == "PASS"
        errors << "#{label} cannot claim PASS with unavailable or failed formal results" unless document["success"] == true
        %w[ruby_trace_verifier tla lean external_proof_profile].each do |name|
          errors << "#{label} #{name} must pass for a PASS formal report" unless document.dig(name, "success") == true
        end
        validate_external_tool_results(document.dig("external_proof_profile", "tools"), errors, label)
      elsif document["success"] == true
        errors << "#{label} INCOMPLETE report cannot claim success"
      end
    end

    def validate_formal_sources(source_manifest, errors, label)
      unless source_manifest.is_a?(Hash) && source_manifest["files"].is_a?(Array) && valid_digest?(source_manifest["sha256"])
        errors << "#{label} formal_sources must include files and a digest"
        return
      end
      files = source_manifest["files"]
      labels = files.filter_map { |entry| entry.is_a?(Hash) ? entry["label"] : nil }
      errors << "#{label} formal source labels must be exactly #{FORMAL_SOURCE_LABELS.join(", ")}" unless
        labels.sort == FORMAL_SOURCE_LABELS.sort && labels.uniq.length == FORMAL_SOURCE_LABELS.length
      errors << "#{label} formal source manifest digest does not match files" unless
        source_manifest["sha256"] == canonical_document_digest(files)
      files.each_with_index do |entry, index|
        unless entry.is_a?(Hash) && FORMAL_SOURCE_LABELS.include?(entry["label"]) &&
               non_empty_string?(entry["path"]) && valid_digest?(entry["sha256"])
          errors << "#{label} formal source #{index} is invalid"
          next
        end
        path = File.expand_path(entry["path"], PROJECT_ROOT)
        unless path.start_with?("#{PROJECT_ROOT}/") && File.file?(path) && !File.symlink?(path)
          errors << "#{label} formal source #{entry["label"]} is not a regular project file"
          next
        end
        errors << "#{label} formal source #{entry["label"]} digest does not match content" unless
          Digest::SHA256.file(path).hexdigest == entry["sha256"]
      end
    end

    def validate_formal_property_results(document, errors, label)
      results = document["property_results"]
      unless results.is_a?(Hash)
        errors << "#{label} property_results are required"
        return
      end
      %w[tla lean ruby].each do |name|
        expected = FORMAL_PROPERTY_BINDINGS.fetch(name)
        actual = results[name]
        unless actual.is_a?(Hash) && actual.keys.sort == expected.sort
          errors << "#{label} #{name} property results must cover the declared properties"
          next
        end
        expected.each do |property|
          result = actual[property]
          errors << "#{label} property #{name}.#{property} must pass in a PASS report" if
            document["status"] == "PASS" && (!result.is_a?(Hash) || result["success"] != true)
        end
      end
    end

    def validate_external_tool_results(tools, errors, label)
      unless tools.is_a?(Array) && tools.length == FORMAL_TOOL_NAMES.length
        errors << "#{label} external proof tools must contain exactly #{FORMAL_TOOL_NAMES.join(", ")}"
        return
      end
      names = tools.filter_map { |tool| tool.is_a?(Hash) ? tool["name"] : nil }
      errors << "#{label} external proof tool names are not unique and complete" unless names.uniq.sort == FORMAL_TOOL_NAMES.sort
      tools.each do |tool|
        next unless tool.is_a?(Hash)

        tool_label = "#{label} external tool #{tool["name"]}"
        errors << "#{tool_label} must be executed in an isolated workdir" unless tool["executed"] == true && tool["isolated_workdir"] == true
        errors << "#{tool_label} must pass with exit status zero" unless tool["success"] == true && tool["exit_status"] == 0
        errors << "#{tool_label} argv is required" unless tool["argv"].is_a?(Array) && !tool["argv"].empty?
        errors << "#{tool_label} output digest is required" unless valid_digest?(tool["output_sha256"])
      end
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

    def validate_report(name, document, expected_kind, manifest, errors)
      label = "#{name} report"
      validate_common_document(document, expected_kind, manifest, errors, label)
      return unless document["schema_version"] == REPORT_SCHEMA_VERSION && document["kind"] == expected_kind

      validate_measurement_source(document, name, errors, label)
      errors << "#{label} adapter name must be #{REQUIRED_ADAPTER_NAMES.fetch(name)}" unless document.dig("adapter",
                                                                                                          "name") == REQUIRED_ADAPTER_NAMES.fetch(name)

      case name
      when "runtime"
        validate_runtime(document, errors)
      when "attacks"
        validate_attacks(document, errors)
      when "lifecycle"
        validate_lifecycle(document, errors)
      when "ledger"
        validate_ledger(document, errors)
      when "kernel"
        validate_kernel(document, errors)
      end
    end

    def validate_common_document(document, expected_kind, manifest, errors, label)
      errors << "#{label} schema_version must be #{REPORT_SCHEMA_VERSION}" unless document["schema_version"] == REPORT_SCHEMA_VERSION
      errors << "#{label} kind must be #{expected_kind}" unless document["kind"] == expected_kind
      errors << "#{label} input_sha256 must match manifest" unless document["input_sha256"] == manifest["input_sha256"]
      errors << "#{label} input_file_count must match manifest" unless document["input_file_count"] == manifest["input_file_count"]
      errors << "#{label} input_stable must be true" unless document["input_stable"] == true
      errors << "#{label} must record milestone M2" unless document["milestone"] == "M2"

      validate_provenance(document, manifest, errors, label)
      measurement_level = document["measurement_level"]
      errors << "#{label} measurement_level must be one of #{MEASUREMENT_LEVELS.join(", ")}" unless MEASUREMENT_LEVELS.include?(measurement_level)
      errors << "#{label} report_sha256 is required" unless valid_digest?(document["report_sha256"])
      if valid_digest?(document["report_sha256"])
        expected_digest = canonical_document_digest(document, excluded_keys: ["report_sha256"])
        errors << "#{label} report_sha256 does not match canonical content" unless document["report_sha256"] == expected_digest
      end

      adapter = document["adapter"]
      unless adapter.is_a?(Hash) && non_empty_string?(adapter["name"]) && non_empty_string?(adapter["version"])
        errors << "#{label} adapter name and version are required"
      end
      if adapter.is_a?(Hash) && adapter.key?("runner_sha256") && !valid_digest?(adapter["runner_sha256"])
        errors << "#{label} adapter runner_sha256 must be a SHA-256 digest"
      end

      errors << "#{label} status must be PASS" unless document["status"] == "PASS"
      errors << "#{label} passed must be true" unless document["passed"] == true
      errors << "#{label} SKIP is not an acceptable M2 result" if document["status"] == "SKIP" || document["skip"] == true
      %w[retry_count unexpected_skip_count unclassified_count flake_count failure_count].each do |key|
        errors << "#{label} #{key} must be zero" unless integer?(document[key]) && document[key].zero?
      end
      errors << "#{label} errors must be an array" unless document["errors"].is_a?(Array)
      errors << "#{label} must run exactly once" if document.key?("attempt_count") && document["attempt_count"] != 1
      errors << "#{label} cannot claim PASS with unavailable profiles" if document["available"] == false
    end

    def validate_provenance(document, manifest, errors, label)
      provenance = document["provenance"]
      unless provenance.is_a?(Hash)
        errors << "#{label} provenance is required"
        return
      end

      errors << "#{label} provenance source_sha256 must match manifest" unless provenance["source_sha256"] == manifest["input_sha256"]
      errors << "#{label} provenance source_file_count must match manifest" unless provenance["source_file_count"] == manifest["input_file_count"]
      errors << "#{label} provenance mode must be production" unless provenance["mode"] == "production"
      errors << "#{label} provenance must not be a self-comparison" unless provenance["self_comparison"] == false
      expected_source = document["measurement_source"]
      unless non_empty_string?(expected_source) && provenance["measurement_source"] == expected_source
        errors << "#{label} provenance measurement_source must match report"
      end
      errors << "#{label} provenance runner_sha256 must match adapter" unless valid_digest?(provenance["runner_sha256"]) &&
                                                                              provenance["runner_sha256"] == document.dig("adapter",
                                                                                                                          "runner_sha256")
      command = provenance["command"]
      errors << "#{label} provenance command must be a non-empty argv" unless command.is_a?(Array) && !command.empty? && command.all? do |part|
        non_empty_string?(part)
      end
      errors << "#{label} provenance command_kind must be ruby_probe" unless provenance["command_kind"] == "ruby_probe"
      errors << "#{label} provenance command must name the Ruby probe" unless command.is_a?(Array) && command.any? do |part|
        part.is_a?(String) && part.end_with?(".rb")
      end
      errors << "#{label} provenance process_id must be positive" unless provenance["process_id"].is_a?(Integer) && provenance["process_id"].positive?
      errors << "#{label} provenance measurement_id is required" unless non_empty_string?(provenance["measurement_id"])
      %w[started_at finished_at].each do |key|
        Time.iso8601(provenance[key].to_s)
      rescue ArgumentError
        errors << "#{label} provenance #{key} must be ISO-8601"
      end
      errors << "#{label} provenance_sha256 is required" unless valid_digest?(provenance["provenance_sha256"])
      return unless valid_digest?(provenance["provenance_sha256"])

      expected = canonical_document_digest(provenance, excluded_keys: ["provenance_sha256"])
      errors << "#{label} provenance_sha256 does not match canonical content" unless provenance["provenance_sha256"] == expected
    end

    def validate_measurement_source(document, name, errors, label)
      expected = REQUIRED_MEASUREMENT_SOURCES.fetch(name)
      errors << "#{label} measurement_source must be #{expected}" unless document["measurement_source"] == expected
    end

    def validate_runtime(document, errors)
      profiles = document["profiles"] || document["architectures"]
      profiles = profiles.map { |architecture, profile| profile.merge("architecture" => architecture) } if profiles.is_a?(Hash)
      unless profiles.is_a?(Array)
        errors << "runtime report profiles are missing"
        return
      end
      validate_required_architectures(document, "runtime report", errors)
      validate_architecture_set(profiles, "runtime", errors)
      profiles.each_with_index do |profile, index|
        validate_profile_identity(profile, "runtime profile #{index}", errors)
        next unless profile.is_a?(Hash)

        levels = profile["levels"] || profile["runtime_levels"]
        unless levels.is_a?(Array)
          errors << "runtime profile #{index} levels are missing"
          next
        end
        names = levels.map { |level| level.is_a?(Hash) ? level["level"] : nil }
        errors << "runtime profile #{index} must contain exactly L0-L3" unless names.sort == REQUIRED_LEVELS.sort && names.uniq.length == REQUIRED_LEVELS.length
        levels.each_with_index do |level, level_index|
          unless level.is_a?(Hash)
            errors << "runtime profile #{index} level #{level_index} must be an object"
            next
          end
          label = "runtime profile #{index} #{level["level"] || "level #{level_index}"}"
          errors << "#{label} status must be PASS" unless level["status"] == "PASS"
          errors << "#{label} passed must be true" unless level["passed"] == true
          errors << "#{label} attempt_count must be one" unless level["attempt_count"] == 1
          errors << "#{label} evidence_sha256 is required" unless valid_digest?(level["evidence_sha256"])
          %w[failure_count unexpected_skip_count unclassified_count].each do |key|
            errors << "#{label} #{key} must be zero" unless integer?(level[key]) && level[key].zero?
          end
          next unless level["level"] == "L3"

          evidence = level["evidence"]
          native_workload = evidence.is_a?(Hash) ? evidence.dig("details", "native_workload") : nil
          errors << "#{label} Native workload evidence is required" unless native_workload.is_a?(Hash)
          next unless native_workload.is_a?(Hash)

          errors << "#{label} Native workload must be measured by production L3 adapters" unless native_workload["measurement_source"] == "production_native_l3"
          errors << "#{label} Native workload must pass" unless native_workload["passed"] == true
          errors << "#{label} Native workload runtime class is not production Native" unless native_workload["runtime_class"] == "Rubernetes::Runtime::Native"
          unless native_workload["adapter_class"] == "Rubernetes::Platform::Linux::NativeAdapters"
            errors << "#{label} Native workload adapter class is not production Native"
          end
        end
      end
    end

    def validate_profile_identity(profile, label, errors)
      unless profile.is_a?(Hash)
        errors << "#{label} must be an object"
        return
      end
      architecture = canonical_architecture(profile["architecture"])
      errors << "#{label} architecture is unsupported" unless architecture
      errors << "#{label} must be available" unless profile["available"] == true
      errors << "#{label} status must be PASS" unless profile["status"] == "PASS"
      errors << "#{label} passed must be true" unless profile["passed"] == true
      errors << "#{label} profile digest is required" unless valid_digest?(profile["profile_sha256"])
      errors << "#{label} SKIP is not an acceptable M2 result" if profile.key?("skip") && profile["skip"] == true
      errors << "#{label} architecture is missing" unless architecture
    end

    def validate_architecture_set(entries, label, errors)
      actual = entries.filter_map { |entry| entry.is_a?(Hash) ? canonical_architecture(entry["architecture"]) : nil }
      errors << "#{label} architecture profiles must be exactly #{REQUIRED_ARCHITECTURES.join(", ")}" unless actual.uniq.sort == REQUIRED_ARCHITECTURES.sort
      errors << "#{label} architecture profiles must not be duplicated" unless actual.uniq.length == actual.length
    end

    def validate_required_architectures(document, label, errors)
      values = document["required_architectures"]
      actual = Array(values).filter_map { |architecture| canonical_architecture(architecture) }
      return if values.is_a?(Array) && actual.length == values.length && actual.uniq.sort == REQUIRED_ARCHITECTURES.sort

      errors << "#{label} required_architectures must be exactly #{REQUIRED_ARCHITECTURES.join(", ")}"
    end

    def validate_attacks(document, errors)
      cases = document["cases"]
      unless cases.is_a?(Array)
        errors << "OCI attack corpus cases are missing"
        return
      end
      ids = cases.map { |entry| entry.is_a?(Hash) ? entry["id"] : nil }
      errors << "OCI attack corpus cases must be unique" unless ids.all? { |id| non_empty_string?(id) } && ids.uniq.length == ids.length
      REQUIRED_ATTACKS.each do |attack|
        matching = cases.select { |entry| entry.is_a?(Hash) && (entry["id"] == attack || entry["category"] == attack) }
        errors << "OCI attack corpus case #{attack} is missing" unless matching.length == 1
      end
      cases.each_with_index do |entry, index|
        unless entry.is_a?(Hash)
          errors << "OCI attack corpus case #{index} must be an object"
          next
        end
        label = "OCI attack corpus case #{entry["id"] || index}"
        errors << "#{label} did not pass" unless entry["passed"] == true && entry["status"] == "PASS"
        errors << "#{label} must run exactly once" unless entry["attempt_count"] == 1
        errors << "#{label} expected fail-closed result is required" unless entry["fail_closed"] == true
        errors << "#{label} observable_sha256 is required" unless valid_digest?(entry["observable_sha256"])
        unless entry["measurement_source"] == "production_image_layer_extractor"
          errors << "#{label} measurement_source must be production image-layer extraction"
        end
        errors << "#{label} adapter class must be the production LayerExtractor" unless entry["adapter_class"] == "Rubernetes::Image::LayerExtractor"
      end
      %w[coverage_count case_count].each do |key|
        next unless document.key?(key)

        expected = key == "coverage_count" ? REQUIRED_ATTACKS.length : cases.length
        errors << "OCI attack corpus #{key} is incorrect" unless document[key] == expected
      end
    end

    def validate_lifecycle(document, errors)
      trace = document["trace"] || document["events"]
      unless trace.is_a?(Array) && !trace.empty?
        errors << "Pod lifecycle trace events are missing"
        return
      end
      errors << "Pod lifecycle trace digest is required" unless valid_digest?(document["trace_sha256"])
      if valid_digest?(document["trace_sha256"]) && document["trace_sha256"] != Digest::SHA256.hexdigest(JSON.generate(trace))
        errors << "Pod lifecycle trace digest does not match events"
      end
      unless integer?(document["failure_injection_count"]) && document["failure_injection_count"].positive?
        errors << "Pod lifecycle trace effect failures are required"
      end
      errors << "Pod lifecycle trace live leak count must be zero" unless document["live_leak_count"] == 0
      errors << "Pod lifecycle trace orphan count must be zero" unless document["orphan_count"] == 0
      errors << "Pod lifecycle evidence must be measured at L3" if document["status"] == "PASS" && document["measurement_level"] != "L3"
      validate_sigkill_matrix(document, "Pod lifecycle", errors)
      validate_inventory_measurement(document, "Pod lifecycle", errors, matrix: document["sigkill_matrix"])
      validate_subresource_e2e(document, "Pod lifecycle", errors)
      flow = document["apply_lifecycle_native_flow"]
      if flow.is_a?(Hash)
        errors << "Pod lifecycle Apply -> Node::Lifecycle -> Native flow must be observed" unless flow["apply_preceded_lifecycle"] == true
        errors << "Pod lifecycle flow must use Node::Lifecycle" unless flow["node_lifecycle_class"] == "Rubernetes::Node::Lifecycle"
        errors << "Pod lifecycle flow must use Node::Agent" unless flow["node_agent_class"] == "Rubernetes::Node::Agent"
        errors << "Pod lifecycle flow must use Node::SyncLoop" unless flow["sync_loop_class"] == "Rubernetes::Node::SyncLoop"
        errors << "Pod lifecycle flow must use an API watch source" unless non_empty_string?(flow["watch_source_class"])
        unless integer?(flow["watch_event_count"]) && flow["watch_event_count"] >= 2
          errors << "Pod lifecycle flow must consume Apply and deletion watch batches"
        end
        errors << "Pod lifecycle flow watch resourceVersion is required" unless flow["watch_resource_version"].to_s.match?(/\A\d+\z/)
        errors << "Pod lifecycle flow Agent must register before reconciliation" unless flow["agent_registered"] == true
        errors << "Pod lifecycle must be started from the Agent watch path" unless flow["lifecycle_started_from_watch"] == true
        unless flow["agent_start_path"] == "Rubernetes::Bootstrap::AgentService#start"
          errors << "Pod lifecycle flow must start through Bootstrap::AgentService#start"
        end
        unless flow["agent_service_class"] == "Rubernetes::Bootstrap::AgentService" && flow["agent_service_started"] == true
          errors << "Pod lifecycle flow must use a started AgentService"
        end
        errors << "Pod lifecycle flow AgentService must be ready" unless flow["agent_service_ready"] == true
        errors << "Pod lifecycle flow must register the AgentService node endpoint" unless flow["node_endpoint_registered"] == true
        unless flow["node_resolver_class"] == "Rubernetes::API::SubresourceBridge::NodeResolver"
          errors << "Pod lifecycle flow must use the production NodeResolver"
        end
        errors << "Pod lifecycle flow must dispatch through API::Server" unless flow["api_server_class"] == "Rubernetes::API::Server"
        errors << "Pod lifecycle flow must serve through Transport::HTTPServer" unless flow["http_server_class"] == "Rubernetes::Transport::HTTPServer"
        errors << "Pod lifecycle Apply event must bind to the API watch" unless flow["apply_watch_binding"] == true
        errors << "Pod lifecycle Delete event must bind to the API watch" unless flow["delete_watch_binding"] == true
        routes = flow["subresource_routes"]
        errors << "Pod lifecycle production subresource routes are required" unless routes.is_a?(Hash) && REQUIRED_SUBRESOURCES.all? do |name|
          routes[name].to_s.split("?", 2).first == REQUIRED_SUBRESOURCE_ROUTES[name]
        end
        services = flow["subresource_service_classes"]
        errors << "Pod lifecycle production subresource service classes are required" unless services.is_a?(Hash) && REQUIRED_SUBRESOURCES.all? do |name|
          services[name] == REQUIRED_SUBRESOURCE_SERVICES[name]
        end
        errors << "Pod lifecycle flow must use the production Native runtime" unless flow["runtime_class"] == "Rubernetes::Runtime::Native"
        errors << "Pod lifecycle flow must finish in Removed" unless flow["finish_state"] == "Removed"
        errors << "Pod lifecycle flow measurement_source must be production Native" unless flow["measurement_source"] == "production_native_lifecycle"
      else
        errors << "Pod lifecycle Apply -> Node::Lifecycle -> Native flow evidence is required"
      end
      semantics = document["lifecycle_semantics_matrix"]
      errors << "Pod lifecycle semantics measurement_source must be #{LIFECYCLE_SEMANTICS_ACTUAL_SOURCE}" unless
        document["lifecycle_semantics_measurement_source"] == LIFECYCLE_SEMANTICS_ACTUAL_SOURCE
      if semantics.is_a?(Array)
        names = semantics.filter_map { |entry| entry.is_a?(Hash) ? entry["name"] : nil }
        unless names.uniq.sort == REQUIRED_LIFECYCLE_SEMANTICS.sort
          errors << "Pod lifecycle semantics matrix must cover init/sidecar, probes, restart policies, and graceful termination"
        end
        semantics.each_with_index do |entry, index|
          unless entry.is_a?(Hash)
            errors << "Pod lifecycle semantics case #{index} must be an object"
            next
          end
          name = entry["name"] || index
          errors << "Pod lifecycle semantics case #{name} did not match its oracle" unless entry["passed"] == true
          errors << "Pod lifecycle semantics case #{name} evidence digest is required" unless valid_digest?(entry["evidence_sha256"])
          if valid_digest?(entry["evidence_sha256"])
            expected = canonical_document_digest(entry, excluded_keys: ["evidence_sha256"])
            errors << "Pod lifecycle semantics case #{name} evidence digest does not match" unless entry["evidence_sha256"] == expected
          end
          validate_lifecycle_semantics_provenance(name, entry["actual_provenance"], errors)
        end
      else
        errors << "Pod lifecycle semantics matrix is required"
      end
      errors << "Pod lifecycle oracle difference count must be zero" unless document["oracle_difference_count"] == 0
      errors << "Pod lifecycle semantics matrix digest is required" unless valid_digest?(document["lifecycle_semantics_matrix_sha256"])
      if semantics.is_a?(Array) && valid_digest?(document["lifecycle_semantics_matrix_sha256"]) && document["lifecycle_semantics_matrix_sha256"] != canonical_document_digest(semantics)
        errors << "Pod lifecycle semantics matrix digest does not match"
      end
      validate_lifecycle_oracle(document, errors)

      grouped = trace.group_by { |event| event.is_a?(Hash) ? event["operation_id"] : nil }
      errors << "Pod lifecycle trace operation IDs must be present" if grouped.key?(nil)
      completed = 0
      grouped.each do |operation_id, events|
        next unless non_empty_string?(operation_id)

        current = "New"
        events.each_with_index do |event, index|
          unless event.is_a?(Hash)
            errors << "Pod lifecycle event #{operation_id}/#{index} must be an object"
            next
          end
          from = event["from"]
          to = event["to"]
          label = "Pod lifecycle event #{operation_id}/#{index}"
          errors << "#{label} has an unknown state" unless ALLOWED_STATES.include?(from) && ALLOWED_STATES.include?(to)
          errors << "#{label} is not sequential" unless from == current
          errors << "#{label} transition is not allowed" unless TRANSITIONS.fetch(from, []).include?(to)
          errors << "#{label} operation_id mismatch" unless event["operation_id"] == operation_id
          errors << "#{label} config_digest is required" unless valid_digest?(event["config_digest"])
          errors << "#{label} owned_resources must be an array" unless event["owned_resources"].is_a?(Array)
          errors << "#{label} must be fsynced" unless event["fsynced"] == true
          begin
            Time.iso8601(event["timestamp"].to_s)
          rescue ArgumentError
            errors << "#{label} timestamp must be ISO-8601"
          end
          current = to
        end
        completed += 1 if current == "Removed"
      end
      errors << "Pod lifecycle trace must contain a complete Removed operation" if completed.zero?
    end

    def validate_lifecycle_semantics_provenance(name, provenance, errors, label: "Pod lifecycle semantics")
      expected = LIFECYCLE_SEMANTICS_PROVENANCE[name.to_s]
      label = "#{label} case #{name}"
      unless expected
        errors << "#{label} is not a required lifecycle semantics case"
        return
      end
      unless provenance.is_a?(Hash)
        errors << "#{label} actual provenance is required"
        return
      end
      errors << "#{label} actual source must be #{LIFECYCLE_SEMANTICS_ACTUAL_SOURCE}" unless provenance["source"] == LIFECYCLE_SEMANTICS_ACTUAL_SOURCE
      expected.each do |key, value|
        errors << "#{label} actual provenance #{key} is not truthful" unless provenance[key] == value
      end
    end

    def validate_lifecycle_oracle(document, errors)
      label = "Pod lifecycle Kubernetes semantic oracle"
      oracle = document["lifecycle_oracle"]
      unless oracle.is_a?(Hash)
        errors << "#{label} evidence is missing"
        return
      end
      provenance = oracle["provenance"]
      if provenance.is_a?(Hash)
        errors << "#{label} provenance kind must be #{KUBERNETES_SEMANTICS_ORACLE_KIND}" unless provenance["kind"] == KUBERNETES_SEMANTICS_ORACLE_KIND
        errors << "#{label} provenance mode must be external" unless provenance["mode"] == "external"
        errors << "#{label} provenance must not be a self-comparison" unless provenance["self_comparison"] == false
        errors << "#{label} provenance implementation is required" unless non_empty_string?(provenance["implementation"])
        source = provenance["source"]
        if source.is_a?(Hash)
          errors << "#{label} provenance Kubernetes version must be #{KUBERNETES_VERSION}" unless source["version"] == KUBERNETES_VERSION
          errors << "#{label} provenance Kubernetes source commit must be #{KUBERNETES_SOURCE_COMMIT}" unless source["commit"] == KUBERNETES_SOURCE_COMMIT
          errors << "#{label} provenance Kubernetes source tag must be #{KUBERNETES_VERSION}" unless source["tag"] == KUBERNETES_VERSION
          errors << "#{label} provenance image identity is required" unless non_empty_string?(source["apiserver_image"])
          errors << "#{label} provenance etcd image identity is required" unless non_empty_string?(source["etcd_image"])
          errors << "#{label} provenance network isolation must be true" unless source["network_isolated"] == true
        else
          errors << "#{label} provenance source identity is required"
        end
        unless valid_digest?(provenance["runner_sha256"]) && provenance["runner_sha256"] == oracle["runner_sha256"]
          errors << "#{label} provenance runner SHA-256 must match oracle"
        end
        unless valid_digest?(provenance["request_seed_sha256"]) && provenance["request_seed_sha256"] == oracle["request_seed_sha256"]
          errors << "#{label} provenance request seed SHA-256 must match oracle"
        end
        errors << "#{label} provenance SHA-256 is required" unless valid_digest?(provenance["provenance_sha256"])
        if valid_digest?(provenance["provenance_sha256"])
          expected_digest = canonical_document_digest(provenance, excluded_keys: ["provenance_sha256"])
          errors << "#{label} provenance SHA-256 does not match canonical content" unless provenance["provenance_sha256"] == expected_digest
        end
      else
        errors << "#{label} provenance is required"
      end
      errors << "#{label} status must be PASS" unless oracle["status"] == "PASS"
      errors << "#{label} passed must be true" unless oracle["passed"] == true
      oracle_errors = oracle["errors"]
      errors << "#{label} errors must be an array" unless oracle_errors.is_a?(Array)
      errors << "#{label} errors must be empty for PASS" unless oracle_errors.is_a?(Array) && oracle_errors.empty?
      errors << "#{label} was not executed" unless oracle["executed"] == true
      if (oracle["status"] == "BLOCKED") && oracle["blocker"] != LIFECYCLE_CNI_LOCK_BLOCKER
        errors << "#{label} blocked status must report the exact product-defining CNI lock blocker"
      end
      errors << "#{label} Kubernetes version must be #{KUBERNETES_VERSION}" unless oracle["kubernetes_version"] == KUBERNETES_VERSION
      errors << "#{label} Kubernetes source commit must be #{KUBERNETES_SOURCE_COMMIT}" unless oracle["source_commit"] == KUBERNETES_SOURCE_COMMIT
      errors << "#{label} runner SHA-256 is required" unless valid_digest?(oracle["runner_sha256"])
      errors << "#{label} request seed SHA-256 is required" unless valid_digest?(oracle["request_seed_sha256"])
      if oracle["executed"] == true
        %w[input_sha256 fixture_sha256 timeline_sha256 raw_trace_sha256 canonical_trace_sha256].each do |key|
          errors << "#{label} #{key} is required" unless valid_digest?(oracle[key])
        end
        if valid_digest?(oracle["input_sha256"]) && oracle["input_sha256"] != document["input_sha256"]
          errors << "#{label} input SHA-256 must match the lifecycle report input"
        end
      end
      unless oracle["comparison_count"] == REQUIRED_LIFECYCLE_SEMANTICS.length
        errors << "#{label} comparison count must equal #{REQUIRED_LIFECYCLE_SEMANTICS.length}"
      end
      errors << "#{label} missing comparison count must be zero" unless oracle["missing_comparison_count"] == 0
      comparisons = oracle["comparisons"]
      unless comparisons.is_a?(Array)
        errors << "#{label} comparisons are required"
        return
      end
      errors << "#{label} comparison entries must match comparison_count" unless comparisons.length == oracle["comparison_count"]
      ids = comparisons.filter_map.with_index do |comparison, index|
        unless comparison.is_a?(Hash)
          errors << "#{label} comparison #{index} must be an object"
          next
        end
        identifier = comparison["id"] || comparison["name"]
        errors << "#{label} comparison #{index} has no identifier" unless non_empty_string?(identifier)
        errors << "#{label} comparison #{index} did not pass" unless comparison["passed"] == true
        errors << "#{label} comparison #{index} must run exactly once" unless comparison["attempt_count"] == 1
        expected = comparison["expected_sha256"]
        actual = comparison["actual_sha256"]
        unless comparison["expected_source"] == "kubernetes_external"
          errors << "#{label} comparison #{index} expected source must be external Kubernetes"
        end
        unless comparison["actual_source"] == LIFECYCLE_SEMANTICS_ACTUAL_SOURCE
          errors << "#{label} comparison #{index} actual source must be #{LIFECYCLE_SEMANTICS_ACTUAL_SOURCE}"
        end
        unless valid_digest?(expected) && valid_digest?(actual)
          errors << "#{label} comparison #{index} must record expected and actual SHA-256 digests"
        end
        if valid_digest?(expected) && valid_digest?(actual) && expected != actual
          errors << "#{label} comparison #{index} observable digests differ"
        end
        validate_lifecycle_semantics_provenance(identifier, comparison["actual_provenance"], errors, label: "#{label} comparison")
        semantic_case = Array(document["lifecycle_semantics_matrix"]).find { |entry| entry.is_a?(Hash) && entry["name"] == identifier }
        errors << "#{label} comparison #{index} provenance does not match the measured semantics case" unless
          semantic_case.is_a?(Hash) && comparison["actual_provenance"] == semantic_case["actual_provenance"]
        identifier if non_empty_string?(identifier)
      end
      unless ids.uniq.length == ids.length && ids.sort == REQUIRED_LIFECYCLE_SEMANTICS.sort
        errors << "#{label} comparison inventory differs from required lifecycle semantics"
      end
      return unless oracle["executed"] == true

      source = provenance.is_a?(Hash) ? provenance["source"] : nil
      unless source.is_a?(Hash) && non_empty_string?(source["kubelet_image"])
        errors << "#{label} provenance kubelet image identity is required"
      end
      runtime = source.is_a?(Hash) ? source["runtime"] : nil
      cni = source.is_a?(Hash) ? source["cni"] : nil
      unless runtime.is_a?(Hash) && %w[containerd runc].all? do |name|
               identity = runtime[name]
               identity.is_a?(Hash) && non_empty_string?(identity["version"]) && valid_digest?(identity["binary_sha256"]) && non_empty_string?(identity["identity_method"])
             end
        errors << "#{label} provenance containerd and runc immutable identities are required"
      end
      unless cni.is_a?(Hash) && %w[plugin version source_commit image_reference image_digest config_sha256].all? do |key|
               value = cni[key]
               value.is_a?(String) && !value.empty?
             end && valid_digest?(cni["image_digest"]) && valid_digest?(cni["config_sha256"])
        errors << "#{label} provenance explicitly locked CNI identity is required"
      end
      trace = oracle["trace"]
      if trace.is_a?(Array) && valid_digest?(oracle["canonical_trace_sha256"]) && oracle["canonical_trace_sha256"] != canonical_document_digest(trace)
        errors << "#{label} canonical trace SHA-256 does not match trace"
      end
      %w[input_sha256 fixture_sha256 timeline_sha256 raw_trace_sha256 canonical_trace_sha256 request_seed_sha256].each do |key|
        errors << "#{label} provenance #{key} must match oracle" if provenance.is_a?(Hash) && provenance[key] != oracle[key]
      end
      validate_lifecycle_oracle_runner_binding(oracle, provenance, errors, label)
      validate_lifecycle_oracle_identity_bindings(oracle, provenance, errors, label)
    end

    def validate_lifecycle_oracle_runner_binding(oracle, provenance, errors, label)
      return unless provenance.is_a?(Hash)

      command = provenance["command"]
      expected_command = [RbConfig.ruby, LIFECYCLE_ORACLE_RUNNER_PATH]
      expected_path = LIFECYCLE_ORACLE_RUNNER_PATH
      expected_digest = File.file?(expected_path) && !File.symlink?(expected_path) ? Digest::SHA256.file(expected_path).hexdigest : nil
      if command == expected_command
        errors << "#{label} built-in runner source must be a regular non-symlink file" unless expected_digest
        unless expected_digest && oracle["runner_sha256"] == expected_digest
          errors << "#{label} runner SHA-256 must match the built-in runner file"
        end
        unless expected_digest && provenance["runner_sha256"] == expected_digest
          errors << "#{label} provenance runner SHA-256 must match the built-in runner file"
        end
        unless provenance["runner_path"] == File.realpath(expected_path)
          errors << "#{label} provenance runner path must match the built-in runner"
        end
        return
      end

      unless File.file?(LIFECYCLE_ORACLE_RUNNER_LOCK_PATH) && !File.symlink?(LIFECYCLE_ORACLE_RUNNER_LOCK_PATH)
        errors << "#{label} external runner argv is not the built-in runner and has no immutable lock"
        return
      end
      lock = begin
        JSON.parse(File.binread(LIFECYCLE_ORACLE_RUNNER_LOCK_PATH), max_nesting: 64)
      rescue JSON::ParserError, Errno::ENOENT => error
        errors << "#{label} external runner lock is invalid: #{error.message}"
        return
      end
      unless lock.is_a?(Hash) && lock["schema_version"] == 1 && lock["command"] == command &&
             valid_digest?(lock["runner_sha256"]) && valid_digest?(lock["executable_sha256"]) && valid_digest?(lock["lock_sha256"])
        errors << "#{label} external runner lock does not bind the exact argv and immutable identities"
        return
      end
      errors << "#{label} external runner lock digest does not match canonical content" unless
        lock["lock_sha256"] == canonical_document_digest(lock, excluded_keys: ["lock_sha256"])
      begin
        runner_path = File.realpath(lock.fetch("runner_path"))
        executable_path = File.realpath(lock.fetch("executable_path"))
        unless File.file?(runner_path) && !File.symlink?(runner_path) && Digest::SHA256.file(runner_path).hexdigest == lock["runner_sha256"]
          errors << "#{label} external runner path is not content-addressed"
        end
        unless File.file?(executable_path) && !File.symlink?(executable_path) && Digest::SHA256.file(executable_path).hexdigest == lock["executable_sha256"]
          errors << "#{label} external runner executable is not content-addressed"
        end
        unless oracle["runner_sha256"] == lock["runner_sha256"] && provenance["runner_sha256"] == lock["runner_sha256"]
          errors << "#{label} external runner SHA-256 must match the locked runner"
        end
        errors << "#{label} external runner path must match the lock" unless provenance["runner_path"] == runner_path
      rescue KeyError, Errno::ENOENT, Errno::EACCES => error
        errors << "#{label} external runner identity could not be recomputed: #{error.message}"
      end
    end

    def validate_lifecycle_oracle_identity_bindings(_oracle, provenance, errors, label)
      source = provenance.is_a?(Hash) ? provenance["source"] : nil
      return unless source.is_a?(Hash)

      %w[kubelet_image apiserver_image etcd_image].each do |key|
        unless source[key].is_a?(String) && DIGEST_PINNED_IMAGE_PATTERN.match?(source[key])
          errors << "#{label} #{key} must be digest-pinned"
        end
      end
      runtime = source["runtime"]
      if runtime.is_a?(Hash)
        %w[containerd runc].each do |name|
          identity = runtime[name]
          unless identity.is_a?(Hash) && identity["path"].is_a?(String) && !identity["path"].empty? &&
                 valid_digest?(identity["binary_sha256"]) && identity["identity_method"] == "realpath+version+binary_sha256"
            errors << "#{label} #{name} executable path and SHA-256 are required"
            next
          end
          begin
            real_path = File.realpath(identity["path"])
            unless real_path == identity["path"] && File.file?(real_path) && !File.symlink?(identity["path"])
              errors << "#{label} #{name} executable path is not the real path"
            end
            unless Digest::SHA256.file(real_path).hexdigest == identity["binary_sha256"]
              errors << "#{label} #{name} executable SHA-256 does not match the real file"
            end
          rescue Errno::ENOENT, Errno::EACCES, Errno::EINVAL => error
            errors << "#{label} #{name} executable identity could not be recomputed: #{error.message}"
          end
        end
      else
        errors << "#{label} runtime executable identities are required"
      end
      cni = source["cni"]
      unless cni.is_a?(Hash) && File.file?(LIFECYCLE_ORACLE_CNI_LOCK_PATH) && !File.symlink?(LIFECYCLE_ORACLE_CNI_LOCK_PATH)
        errors << "#{label} immutable CNI lock identity is required"
        return
      end
      lock = begin
        JSON.parse(File.binread(LIFECYCLE_ORACLE_CNI_LOCK_PATH), max_nesting: 64)
      rescue JSON::ParserError, Errno::ENOENT => error
        errors << "#{label} CNI lock is invalid: #{error.message}"
        return
      end
      identity_keys = %w[plugin version source_commit image_reference image_digest config_sha256]
      unless lock.is_a?(Hash) && cni.slice(*identity_keys) == lock.slice(*identity_keys)
        errors << "#{label} CNI identity must match the repository lock"
      end
      unless cni["image_reference"].is_a?(String) && DIGEST_PINNED_IMAGE_PATTERN.match?(cni["image_reference"])
        errors << "#{label} CNI image reference must be digest-pinned"
      end
      return unless cni["image_reference"].is_a?(String) && DIGEST_PINNED_IMAGE_PATTERN.match?(cni["image_reference"])

      errors << "#{label} CNI image reference digest must match image_digest" unless cni["image_reference"].split("@sha256:",
                                                                                                                  2).last == cni["image_digest"]
    end

    def validate_ledger(document, errors)
      cycles = document["cycles"]
      unless cycles.is_a?(Array) && cycles.length == 1000
        errors << "resource ledger must contain exactly 1000 cycles"
        return
      end
      cycle_ids = cycles.map { |cycle| cycle.is_a?(Hash) ? cycle["cycle"] : nil }
      errors << "resource ledger cycles must be exactly 1 through 1000" unless cycle_ids == (1..1000).to_a
      inventory_measurement_id = document.dig("cycle_inventory_measurement", "measurement_id")
      errors << "resource ledger inventory measurement binding is required" unless non_empty_string?(inventory_measurement_id)
      cycles.each_with_index do |cycle, index|
        unless cycle.is_a?(Hash)
          errors << "resource ledger cycle #{index} must be an object"
          next
        end
        label = "resource ledger cycle #{cycle["cycle"] || index}"
        fault = cycle["fault_injection"]
        operations = cycle["operations"]
        expected_operations = fault.is_a?(Hash) ? %w[create fault rollback recover] : %w[create start stop delete]
        errors << "#{label} operations do not match its measured path" unless operations == expected_operations
        errors << "#{label} did not pass" unless cycle["passed"] == true && cycle["status"] == "PASS"
        errors << "#{label} must run exactly once" unless cycle["attempt_count"] == 1
        errors << "#{label} failure count does not match its fault path" unless
          cycle["failure_count"] == (fault.is_a?(Hash) ? 1 : 0)
        errors << "#{label} live leak count must be zero" unless cycle["live_leak_count"] == 0
        errors << "#{label} orphan count must be zero" unless cycle["orphan_count"] == 0
        unless integer?(cycle["resource_reuse_count"]) && cycle["resource_reuse_count"] >= 0
          errors << "#{label} resource reuse count must be a non-negative integer"
        end
        errors << "#{label} resource reuse count must be zero" unless cycle["resource_reuse_count"] == 0
        errors << "#{label} released resources do not match acquired resources" unless integer?(cycle["resource_count"]) && cycle["resource_count"] >= 0 &&
                                                                                       cycle["released_resource_count"] == cycle["resource_count"]
        expected_cycle_id = format("m2-native-cycle-%04d", cycle["cycle"].to_i)
        errors << "#{label} cycle_id must bind the production sandbox identity" unless cycle["cycle_id"] == expected_cycle_id
        errors << "#{label} measurement_id must bind the production sandbox identity" unless cycle["measurement_id"] == expected_cycle_id
        active_inventory = cycle["active_inventory"]
        unless active_inventory.is_a?(Array) && !active_inventory.empty?
          errors << "#{label} active_inventory must record the raw active inventory"
          active_inventory = []
        end
        validate_inventory_entries(active_inventory, "#{label} active inventory", errors)
        validate_inventory_duplicates(active_inventory, "#{label} active inventory", errors)
        active_digest = canonical_document_digest(active_inventory)
        errors << "#{label} active_inventory_sha256 must match the raw active inventory" unless
          valid_digest?(cycle["active_inventory_sha256"]) && cycle["active_inventory_sha256"] == active_digest
        unless cycle["active_inventory_count"] == active_inventory.length
          errors << "#{label} active_inventory_count must match the raw active inventory"
        end
        active_kinds = active_inventory.filter_map { |resource| resource.is_a?(Hash) ? resource["kind"] : nil }.uniq.sort
        errors << "#{label} active_inventory_kinds must match the raw active inventory" unless
          Array(cycle["active_inventory_kinds"]).map(&:to_s).uniq.sort == active_kinds
        errors << "#{label} resource_count must match the raw active inventory" unless cycle["resource_count"] == active_inventory.length
        cycle_kinds = Array(cycle["resource_kinds"]).map(&:to_s).uniq.sort
        errors << "#{label} resource_kinds must match the raw active inventory" unless cycle_kinds == active_kinds
        unless cycle["kernel_identity_sha256"] == active_digest
          errors << "#{label} kernel identity digest must match the raw active inventory"
        end
        unless cycle["active_inventory_measurement_id"] == inventory_measurement_id
          errors << "#{label} active inventory measurement binding is required"
        end
        residual_inventory = cycle["residual_inventory"]
        unless residual_inventory.is_a?(Array)
          errors << "#{label} residual_inventory must record the raw residual inventory"
          residual_inventory = []
        end
        validate_inventory_entries(residual_inventory, "#{label} residual inventory", errors)
        validate_inventory_duplicates(residual_inventory, "#{label} residual inventory", errors)
        errors << "#{label} residual_inventory_sha256 must match the raw residual inventory" unless
          valid_digest?(cycle["residual_inventory_sha256"]) && cycle["residual_inventory_sha256"] == canonical_document_digest(residual_inventory)
        unless cycle["residual_inventory_count"] == residual_inventory.length
          errors << "#{label} residual_inventory_count must match the raw residual inventory"
        end
        residual_kinds = residual_inventory.filter_map { |resource| resource.is_a?(Hash) ? resource["kind"] : nil }.uniq.sort
        errors << "#{label} residual_inventory_kinds must match the raw residual inventory" unless
          Array(cycle["residual_inventory_kinds"]).map(&:to_s).uniq.sort == residual_kinds
        errors << "#{label} resource_kinds must be a non-empty measured set" if cycle_kinds.empty?
        errors << "#{label} resource_kinds contain unknown kinds" unless (cycle_kinds - REQUIRED_RESOURCE_KINDS).empty?
        unless cycle["measurement_source"] == "production_native_l3_cycles"
          errors << "#{label} measurement_source must be production Native L3 cycles"
        end
        errors << "#{label} kernel identity digest is required" unless valid_digest?(cycle["kernel_identity_sha256"])
        expected_identity_source = if fault.is_a?(Hash)
                                     "production_native_l3_effect_fault_inventory"
                                   else
                                     "production_native_l3_kernel_inventory"
                                   end
        errors << "#{label} kernel identity must come from its production Native path" unless
          cycle["kernel_identity_source"] == expected_identity_source
        # The SIGKILL inventory measurement also carries the durable ledger
        # claims (workspace/namespace) enriched with kernel proof; a
        # production cycle's active inventory is the pure kernel readback, so
        # it must cover exactly the measured kernel resource kinds.
        measured_kinds = Array(document.dig("inventory_measurement", "resource_kinds")).map(&:to_s).uniq.sort
        measured_kernel_kinds = measured_kinds & REQUIRED_RESOURCE_KINDS
        if !fault.is_a?(Hash) && !measured_kernel_kinds.empty? && cycle_kinds != measured_kernel_kinds
          errors << "#{label} resource_kinds must match measured inventory"
        end
        unless cycle["inventory_measurement_id"] == inventory_measurement_id
          errors << "#{label} inventory_measurement_id must match measured inventory"
        end
        validate_effect_fault_record(cycle, label, errors) if fault.is_a?(Hash)
      end
      effects = document["effect_points"]
      unless effects.is_a?(Array)
        errors << "resource ledger effect_points are missing"
        return
      end
      REQUIRED_EFFECT_POINTS.each do |point|
        entries = effects.select { |entry| entry.is_a?(Hash) && (entry["name"] || entry["effect_point"]) == point }
        errors << "resource ledger effect point #{point} is missing" unless entries.length == 1
        next unless entries.length == 1

        entry = entries.first
        unless integer?(entry["injected_count"]) && entry["injected_count"].positive?
          errors << "resource ledger effect point #{point} must inject at least once"
        end
        errors << "resource ledger effect point #{point} live leak count must be zero" unless entry["live_leak_count"] == 0
        unless entry["measurement_source"] == "production_native_effect_injection"
          errors << "resource ledger effect point #{point} measurement_source must be production Native"
        end
        fault_cycle = cycles.find { |cycle| cycle.is_a?(Hash) && cycle["cycle"] == entry["cycle"] }
        fault = fault_cycle&.fetch("fault_injection", nil)
        errors << "resource ledger effect point #{point} is not bound to an actual fault cycle" unless
          fault.is_a?(Hash) && fault["effect_point"] == point
        next unless fault.is_a?(Hash)

        errors << "resource ledger effect point #{point} fault token does not match its cycle" unless entry["fault_token"] == fault["token"]
        errors << "resource ledger effect point #{point} observed error is not bound to its cycle" unless
          entry["observed_error_sha256"] == fault.dig("observed_error", "message_sha256")
        errors << "resource ledger effect point #{point} WAL transition is not bound to its cycle" unless
          entry["wal_transition_digest"] == fault.dig("checkpoint", "wal_transition", "digest")
        errors << "resource ledger effect point #{point} evidence digest is not bound to its cycle" unless
          entry["fault_evidence_sha256"] == fault["evidence_sha256"]
        errors << "resource ledger effect point #{point} rollback state must be Stopped" unless
          entry["rollback_state"] == "Stopped" && fault["rollback_state"] == "Stopped"
      end
      %w[cycle_count failure_injection_count live_leak_count orphan_count resource_reuse_count].each do |key|
        errors << "resource ledger #{key} must be present and valid" unless integer?(document[key]) && document[key] >= 0
      end
      errors << "resource ledger cycle_count must be 1000" unless document["cycle_count"] == 1000
      %w[live_leak_count orphan_count resource_reuse_count].each do |key|
        errors << "resource ledger #{key} must be zero" unless document[key] == 0
      end
      cycle_reuse_count = cycles.sum { |cycle| integer?(cycle["resource_reuse_count"]) ? cycle["resource_reuse_count"] : 0 }
      unless document["resource_reuse_count"] == cycle_reuse_count
        errors << "resource ledger aggregate resource reuse count must equal cycle counts"
      end
      unless document["failure_injection_count"].to_i >= REQUIRED_EFFECT_POINTS.length
        errors << "resource ledger must inject every required effect point"
      end
      errors << "resource ledger digest is required" unless valid_digest?(document["ledger_sha256"])
      if valid_digest?(document["ledger_sha256"])
        canonical_payload = {
          "cycle_count" => document["cycle_count"],
          "cycles" => cycles,
          "effect_points" => effects,
          "failure_injection_count" => document["failure_injection_count"],
          "live_leak_count" => document["live_leak_count"],
          "orphan_count" => document["orphan_count"],
          "resource_reuse_count" => document["resource_reuse_count"]
        }
        unless document["ledger_sha256"] == canonical_document_digest(canonical_payload)
          errors << "resource ledger digest does not match canonical content"
        end
      end
      errors << "resource ledger evidence must be measured at L3" if document["status"] == "PASS" && document["measurement_level"] != "L3"
      validate_sigkill_matrix(document, "resource ledger", errors)
      validate_inventory_measurement(document, "resource ledger", errors, matrix: document["sigkill_matrix"])
      cycle_inventory = document["cycle_inventory_measurement"]
      if cycle_inventory.is_a?(Hash)
        validate_inventory_measurement(document.merge("inventory_measurement" => cycle_inventory),
                                       "resource ledger lifecycle cycles", errors)
        errors << "resource ledger lifecycle inventory cycle_count must be 1000" unless cycle_inventory["cycle_count"] == 1000
        unless cycle_inventory["adapter_class"] == "Rubernetes::Platform::Linux::NativeAdapters"
          errors << "resource ledger lifecycle inventory must identify production adapters"
        end
        expected_cycle_before = cycles.flat_map { |cycle| cycle.is_a?(Hash) ? Array(cycle["active_inventory"]) : [] }
        expected_cycle_after = cycles.flat_map { |cycle| cycle.is_a?(Hash) ? Array(cycle["residual_inventory"]) : [] }
        validate_inventory_duplicates(expected_cycle_before, "resource ledger lifecycle cycle aggregate active inventory", errors)
        validate_inventory_duplicates(expected_cycle_after, "resource ledger lifecycle cycle aggregate residual inventory", errors)
        unless cycle_inventory["before"] == expected_cycle_before
          errors << "resource ledger lifecycle inventory before is not bound to cycle active inventories"
        end
        unless cycle_inventory["after"] == expected_cycle_after
          errors << "resource ledger lifecycle inventory after is not bound to cycle residual inventories"
        end
      else
        errors << "resource ledger lifecycle cycle inventory is required"
      end
    end

    def validate_effect_fault_record(cycle, label, errors)
      fault = cycle["fault_injection"]
      point = fault["effect_point"]
      expected = EFFECT_CHECKPOINTS[point]
      errors << "#{label} fault effect point is unknown" unless expected
      return unless expected

      errors << "#{label} fault cycle binding changed" unless fault["cycle"] == cycle["cycle"]
      errors << "#{label} fault injection must be recorded" unless fault["injected"] == true
      checkpoint = fault["checkpoint"]
      unless checkpoint.is_a?(Hash)
        errors << "#{label} fault checkpoint is required"
        return
      end
      operation_id = format("m2-native-cycle-%04d", cycle["cycle"])
      errors << "#{label} fault checkpoint operation changed" unless
        checkpoint["operation_id"] == operation_id && checkpoint["request_id"] == operation_id
      errors << "#{label} fault checkpoint state does not match its effect" unless
        checkpoint["effect_point"] == point && checkpoint["native_state"] == expected["state"] &&
        checkpoint["actual_operation"] == expected["operation"]
      errors << "#{label} fault executed workload code before Running" unless
        checkpoint["workload_gate"] == "closed" && checkpoint["workload_process_count"] == 0

      transition = checkpoint["wal_transition"]
      unless transition.is_a?(Hash)
        errors << "#{label} fault WAL transition is required"
        transition = {}
      end
      errors << "#{label} fault WAL transition does not match its effect" unless
        positive_integer?(transition["sequence"]) && transition["event"] == "state_transition" &&
        transition["operation_id"] == operation_id && transition["from"] == expected["from"] &&
        transition["to"] == expected["state"] && transition["state"] == expected["state"] &&
        valid_digest?(transition["digest"])
      token = Digest::SHA256.hexdigest([cycle["cycle"], point, transition["digest"]].join("\0"))
      errors << "#{label} fault token is not bound to the durable transition" unless
        valid_digest?(fault["token"]) && fault["token"] == token

      observed_error = fault["observed_error"]
      expected_message = "injected Native effect fault #{point} token=#{fault["token"]}"
      errors << "#{label} injected error was not observed exactly" unless
        observed_error.is_a?(Hash) && observed_error["class"] == "M2ProbeSupport::NativeEffectFault" &&
        observed_error["message"] == expected_message &&
        observed_error["message_sha256"] == Digest::SHA256.hexdigest(expected_message)

      active = fault["active_inventory"]
      unless active.is_a?(Array) && !active.empty?
        errors << "#{label} fault active kernel inventory is required"
        active = []
      end
      validate_inventory_entries(active, "#{label} fault active inventory", errors)
      active_kinds = active.filter_map { |resource| resource.is_a?(Hash) ? resource["kind"] : nil }.uniq.sort
      errors << "#{label} fault active inventory does not match the effect point" unless
        active_kinds == expected["kernel_kinds"].sort
      errors << "#{label} fault active resources must be live at injection" unless
        active.all? { |resource| resource.dig("metadata", "live") == true }
      errors << "#{label} fault checkpoint inventory digest does not match" unless
        checkpoint["kernel_inventory_sha256"] == canonical_document_digest(active)

      wal_records = fault["wal_records"]
      unless wal_records.is_a?(Array) && !wal_records.empty?
        errors << "#{label} fault WAL records are required"
        wal_records = []
      end
      errors << "#{label} fault WAL digest does not match its records" unless
        valid_digest?(fault["wal_records_sha256"]) &&
        fault["wal_records_sha256"] == canonical_document_digest(wal_records)
      transitions = wal_records.filter_map do |record|
        next unless record.is_a?(Hash) && record["event"] == "state_transition"

        record.dig("payload", "to")
      end
      expected_tail = [expected["state"], "RollingBack", "Stopped"]
      position = transitions.index(expected["state"])
      errors << "#{label} fault WAL must contain effect -> RollingBack -> Stopped" unless
        position && transitions[position, 3] == expected_tail
      errors << "#{label} fault WAL path must be the production JSONL ownership journal" unless
        non_empty_string?(fault["wal_path"]) && File.basename(fault["wal_path"]) == "journal.jsonl"

      recovery = fault["recovery"]
      errors << "#{label} fault recovery report is required" unless recovery.is_a?(Hash)
      if recovery.is_a?(Hash)
        errors << "#{label} fault recovery digest does not match" unless
          valid_digest?(fault["recovery_sha256"]) && fault["recovery_sha256"] == canonical_document_digest(recovery)
        %w[errors identity_mismatch orphans].each do |key|
          errors << "#{label} fault recovery #{key} must be empty" unless Array(recovery[key]).empty?
        end
      end
      residual = fault["residual_inventory"]
      errors << "#{label} fault residual inventory must be empty" unless residual == []
      errors << "#{label} fault residual inventory digest does not match" unless
        residual.is_a?(Array) && valid_digest?(fault["residual_inventory_sha256"]) &&
        fault["residual_inventory_sha256"] == canonical_document_digest(residual)
      errors << "#{label} fault rollback state must be Stopped" unless fault["rollback_state"] == "Stopped"
      errors << "#{label} fault evidence digest does not match" unless
        valid_digest?(fault["evidence_sha256"]) &&
        fault["evidence_sha256"] == canonical_document_digest(fault, excluded_keys: ["evidence_sha256"])
    end

    def validate_inventory_measurement(document, label, errors, matrix: nil)
      measurement = document["inventory_measurement"]
      unless measurement.is_a?(Hash)
        errors << "#{label} inventory_measurement is required"
        return
      end
      errors << "#{label} inventory_measurement source must be real_adapter" unless measurement["source"] == "real_adapter"
      expected_measurement_source = label.include?("lifecycle cycles") ? "production_native_l3_cycles" : "production_native_agent_sigkill"
      unless measurement["measurement_source"] == expected_measurement_source
        errors << "#{label} inventory_measurement measurement_source must be #{expected_measurement_source}"
      end
      errors << "#{label} inventory_measurement measurement_id is required" unless non_empty_string?(measurement["measurement_id"])
      before = measurement["before"]
      after = measurement["after"]
      unless before.is_a?(Array) && after.is_a?(Array)
        errors << "#{label} inventory before and after must be arrays"
        return
      end
      validate_inventory_entries(before, "#{label} inventory before", errors)
      validate_inventory_entries(after, "#{label} inventory after", errors)
      if matrix.is_a?(Array)
        matrix.each_with_index do |entry, index|
          next unless entry.is_a?(Hash)

          validate_inventory_duplicates(Array(entry["inventory_before"]), "#{label} SIGKILL #{index} inventory before", errors)
          validate_inventory_duplicates(Array(entry["inventory_after"]), "#{label} SIGKILL #{index} inventory after", errors)
          errors << "#{label} SIGKILL #{index} inventory measurement binding is required" unless
            entry["inventory_measurement_id"] == measurement["measurement_id"]
        end
        expected_before = matrix.flat_map { |entry| entry.is_a?(Hash) ? Array(entry["inventory_before"]) : [] }
        expected_after = matrix.flat_map { |entry| entry.is_a?(Hash) ? Array(entry["inventory_after"]) : [] }
        validate_inventory_duplicates(expected_before, "#{label} aggregate inventory before", errors)
        validate_inventory_duplicates(expected_after, "#{label} aggregate inventory after", errors)
        errors << "#{label} inventory before is not bound to SIGKILL measurements" unless before == expected_before
        errors << "#{label} inventory after is not bound to SIGKILL measurements" unless after == expected_after
        expected_wrong_deletions = matrix.sum { |entry| entry.is_a?(Hash) ? entry["live_wrong_deletion_count"].to_i : 1 }
        unless measurement["live_wrong_deletion_count"] == expected_wrong_deletions
          errors << "#{label} inventory live_wrong_deletion_count is not bound to SIGKILL measurements"
        end
      end
      validate_inventory_duplicates(before, "#{label} inventory before", errors)
      validate_inventory_duplicates(after, "#{label} inventory after", errors)
      before_keys = inventory_keys(before)
      after_keys = inventory_keys(after)
      unless before_keys.uniq.length == before_keys.length && after_keys.uniq.length == after_keys.length
        errors << "#{label} inventory identities must be unique"
      end

      diff = measurement["diff"]
      unless diff.is_a?(Hash)
        errors << "#{label} inventory diff is required"
        return
      end
      expected = {
        "added" => (after_keys - before_keys).sort,
        "removed" => (before_keys - after_keys).sort,
        "retained" => (after_keys & before_keys).sort
      }
      expected.each do |key, value|
        errors << "#{label} inventory diff #{key} does not match before/after" unless diff[key] == value
      end
      errors << "#{label} inventory_diff_sha256 is required" unless valid_digest?(measurement["inventory_diff_sha256"])
      if valid_digest?(measurement["inventory_diff_sha256"])
        expected_digest = canonical_document_digest({"before" => before, "after" => after, "diff" => diff})
        unless measurement["inventory_diff_sha256"] == expected_digest
          errors << "#{label} inventory_diff_sha256 does not match canonical content"
        end
      end
      %w[live_leak_count orphan_count live_wrong_deletion_count].each do |key|
        errors << "#{label} inventory #{key} must be zero" unless measurement[key] == 0
      end
      kinds = Array(measurement["resource_kinds"]).map(&:to_s).uniq.sort
      errors << "#{label} inventory resource_kinds must be non-empty" if kinds.empty?
      errors << "#{label} inventory resource_kinds contain unknown kinds" unless (kinds - ALLOWED_INVENTORY_RESOURCE_KINDS).empty?
      required_kinds = Array(measurement["required_resource_kinds"]).map(&:to_s).uniq.sort
      unless required_kinds == REQUIRED_RESOURCE_KINDS.sort
        errors << "#{label} inventory required_resource_kinds must be mount/ns/cgroup/process/pidfd/temp"
      end
      missing_kinds = Array(measurement["missing_resource_kinds"]).map(&:to_s).uniq.sort
      unless missing_kinds == (REQUIRED_RESOURCE_KINDS - kinds).sort
        errors << "#{label} inventory missing_resource_kinds does not match observed kinds"
      end
      expected_profile_status = missing_kinds.empty? ? "PASS" : "INCOMPLETE"
      unless measurement["profile_status"] == expected_profile_status
        errors << "#{label} inventory profile_status does not match missing kinds"
      end
      return unless document["status"] == "PASS"

      errors << "#{label} inventory must cover mount/ns/cgroup/process/pidfd/temp" unless REQUIRED_RESOURCE_KINDS - kinds == []
      errors << "#{label} inventory profile must be PASS" unless measurement["profile_status"] == "PASS"
    end

    def validate_inventory_entries(entries, label, errors)
      entries.each_with_index do |entry, index|
        unless entry.is_a?(Hash)
          errors << "#{label} entry #{index} must be an object"
          next
        end
        %w[kind id identity owner].each do |key|
          errors << "#{label} entry #{index} #{key} is required" unless non_empty_string?(entry[key])
        end
        metadata = entry["metadata"]
        errors << "#{label} entry #{index} metadata must be an object" unless metadata.is_a?(Hash)
      end
    end

    def inventory_keys(entries)
      entries.filter_map do |entry|
        next unless entry.is_a?(Hash) && non_empty_string?(entry["kind"]) && non_empty_string?(entry["id"])

        "#{entry["kind"]}:#{entry["id"]}"
      end
    end

    def validate_inventory_duplicates(entries, label, errors)
      identities = entries.filter_map do |entry|
        entry.is_a?(Hash) && non_empty_string?(entry["identity"]) ? entry["identity"] : nil
      end
      duplicates = identities.group_by(&:itself).filter_map { |identity, values| identity if values.length > 1 }
      errors << "#{label} contains duplicate raw inventory identities: #{duplicates.sort.join(", ")}" unless duplicates.empty?
    end

    def validate_sigkill_matrix(document, label, errors)
      matrix = document["sigkill_matrix"]
      unless matrix.is_a?(Array)
        errors << "#{label} sigkill_matrix is required"
        return
      end
      ids = matrix.filter_map { |entry| entry.is_a?(Hash) ? (entry["effect_point"] || entry["name"]) : nil }
      unless ids.sort == REQUIRED_EFFECT_POINTS.sort && ids.uniq.length == REQUIRED_EFFECT_POINTS.length
        errors << "#{label} sigkill_matrix must contain each required effect point exactly once"
      end
      matrix.each_with_index do |entry, index|
        unless entry.is_a?(Hash)
          errors << "#{label} SIGKILL entry #{index} must be an object"
          next
        end
        effect = entry["effect_point"] || entry["name"] || index
        entry_label = "#{label} SIGKILL #{effect}"
        errors << "#{entry_label} signal must be SIGKILL" unless entry["signal"] == "SIGKILL"
        errors << "#{entry_label} target_pid must be positive" unless entry["target_pid"].is_a?(Integer) && entry["target_pid"].positive?
        errors << "#{entry_label} restart_pid must be positive" unless entry["restart_pid"].is_a?(Integer) && entry["restart_pid"].positive?
        errors << "#{entry_label} restart_process must be fork" unless entry["restart_process"] == "fork"
        errors << "#{entry_label} kill_observed must be true" unless entry["kill_observed"] == true
        errors << "#{entry_label} restart_observed must be true" unless entry["restart_observed"] == true
        errors << "#{entry_label} wal_replayed must be true" unless entry["wal_replayed"] == true
        unless entry["target_start_time"].to_s.match?(/\A\d+\z/)
          errors << "#{entry_label} target_start_time must be a numeric /proc start time"
        end
        errors << "#{entry_label} measurement_id is required" unless non_empty_string?(entry["measurement_id"])
        errors << "#{entry_label} wal_path is required" unless non_empty_string?(entry["wal_path"])
        errors << "#{entry_label} WAL change must be observed across recovery" unless entry["wal_changed"] == true
        wait_status = entry["wait_status"]
        unless wait_status.is_a?(Hash) && wait_status["signaled"] == true && wait_status["signal"] == "SIGKILL"
          errors << "#{entry_label} wait_status must record SIGKILL"
        end
        %w[wal_before_sha256 wal_after_sha256 inventory_before_sha256 inventory_after_sha256 evidence_sha256].each do |key|
          errors << "#{entry_label} #{key} is required" unless valid_digest?(entry[key])
        end
        %w[inventory_before inventory_after].each do |key|
          values = entry[key]
          errors << "#{entry_label} #{key} must be an inventory array" unless values.is_a?(Array)
          validate_inventory_duplicates(values, "#{entry_label} #{key}", errors) if values.is_a?(Array)
          digest_key = "#{key}_sha256"
          if values.is_a?(Array) && valid_digest?(entry[digest_key])
            expected = canonical_document_digest(values)
            errors << "#{entry_label} #{digest_key} does not match inventory" unless entry[digest_key] == expected
          end
        end
        %w[live_wrong_deletion_count dead_residual_count].each do |key|
          errors << "#{entry_label} #{key} must be zero" unless entry[key] == 0
        end
        unless entry["measurement_source"] == "production_native_agent_sigkill"
          errors << "#{entry_label} measurement must come from production Native L3 Node Agent SIGKILL"
        end
        validate_native_sigkill_kernel_evidence(entry, entry_label, errors)
        native_agent = entry["native_agent"]
        if native_agent.is_a?(Hash)
          errors << "#{entry_label} Native Node Agent must be ready after restart" unless native_agent["ready"] == true
          errors << "#{entry_label} Native Node Agent must be registered after restart" unless native_agent["registered"] == true
          unless native_agent["agent_pid"].is_a?(Integer) && native_agent["agent_pid"].positive?
            errors << "#{entry_label} Native Node Agent PID must be positive"
          end
          unless native_agent["agent_pid"] == entry["restart_pid"]
            errors << "#{entry_label} Native Node Agent PID must be the restarted child process"
          end
          unless native_agent["agent_start_time"].to_s.match?(/\A\d+\z/)
            errors << "#{entry_label} Native Node Agent start time must be a numeric /proc start time"
          end
          expected_agent_identity = if native_agent["agent_pid"] && native_agent["agent_start_time"]
                                      "process:node-agent:#{native_agent["agent_pid"]}:#{native_agent["agent_start_time"]}"
                                    end
          unless native_agent["agent_process_identity"] == expected_agent_identity
            errors << "#{entry_label} Native Node Agent process identity is required"
          end
          unless native_agent["agent_class"] == "Rubernetes::Node::Agent"
            errors << "#{entry_label} agent_class must be Rubernetes::Node::Agent"
          end
          unless native_agent["sync_loop_class"] == "Rubernetes::Node::SyncLoop"
            errors << "#{entry_label} sync_loop_class must be Rubernetes::Node::SyncLoop"
          end
          unless native_agent["lifecycle_class"] == "Rubernetes::Node::Lifecycle"
            errors << "#{entry_label} lifecycle_class must be Rubernetes::Node::Lifecycle"
          end
          unless native_agent["runtime_class"] == "Rubernetes::Runtime::Native"
            errors << "#{entry_label} runtime_class must be Rubernetes::Runtime::Native"
          end
          errors << "#{entry_label} runtime_profile must be l3" unless native_agent["runtime_profile"] == "l3"
          recovery = native_agent["recovery"]
          errors << "#{entry_label} Native Node Agent recovery report is required" unless recovery.is_a?(Hash)
          if recovery.is_a?(Hash)
            errors << "#{entry_label} Native Node Agent recovery must be ready" unless recovery["ready"] == true
            errors << "#{entry_label} Native Node Agent recovery has errors" unless Array(recovery["errors"]).empty?
            errors << "#{entry_label} Native Node Agent recovery has blocked records" unless Array(recovery["blocked"]).empty?
            runtime_recovery = recovery["runtime"]
            if runtime_recovery.is_a?(Hash)
              unless Array(runtime_recovery["identity_mismatch"]).empty?
                errors << "#{entry_label} Native Node Agent runtime recovery has identity mismatches"
              end
              cleaned_orphans = Array(runtime_recovery["cleaned_orphans"]).map(&:to_s)
              unresolved_orphans = Array(runtime_recovery["orphans"]).filter_map do |orphan|
                key = orphan.is_a?(Hash) ? "#{orphan["kind"] || orphan[:kind]}:#{orphan["id"] || orphan[:id]}" : orphan.to_s
                key unless cleaned_orphans.include?(key)
              end
              errors << "#{entry_label} Native Node Agent runtime recovery has unresolved orphans" unless unresolved_orphans.empty?
            end
          end
        else
          errors << "#{entry_label} Native Node Agent restart evidence is required"
        end
        if valid_digest?(entry["evidence_sha256"])
          expected = canonical_document_digest(entry, excluded_keys: ["evidence_sha256"])
          errors << "#{entry_label} evidence_sha256 does not match canonical content" unless entry["evidence_sha256"] == expected
        end
      end
      checkpoints = matrix.filter_map do |entry|
        checkpoint = entry.is_a?(Hash) ? entry["crash_checkpoint"] : nil
        next unless checkpoint.is_a?(Hash)

        [checkpoint["native_state"], checkpoint["actual_operation"],
         checkpoint.dig("wal_transition", "sequence"), checkpoint["barrier_token"]]
      end
      errors << "#{label} SIGKILL effect points must bind four distinct durable crash checkpoints" unless
        checkpoints.length == REQUIRED_EFFECT_POINTS.length && checkpoints.uniq.length == REQUIRED_EFFECT_POINTS.length
    end

    def validate_native_sigkill_kernel_evidence(entry, label, errors)
      effect_point = entry["effect_point"]
      expected_checkpoint = EFFECT_CHECKPOINTS[effect_point]
      checkpoint = entry["crash_checkpoint"]
      unless checkpoint.is_a?(Hash) && expected_checkpoint
        errors << "#{label} must record a recognized Native effect checkpoint"
        checkpoint = {}
        expected_checkpoint ||= {}
      end
      errors << "#{label} effect checkpoint name does not match the matrix point" unless checkpoint["effect_point"] == effect_point
      errors << "#{label} Native state does not match the effect point" unless checkpoint["native_state"] == expected_checkpoint["state"]
      unless checkpoint["actual_operation"] == expected_checkpoint["operation"]
        errors << "#{label} actual operation does not match the effect point"
      end
      errors << "#{label} workload gate must still be closed" unless checkpoint["workload_gate"] == "closed"
      errors << "#{label} workload code must not exist before the Running transition" unless
        checkpoint["workload_process_count"] == 0 && !checkpoint.key?("actual_workload")
      expected_request_id = "sigkill-#{effect_point}-sandbox"
      errors << "#{label} checkpoint request ID must bind the sandbox operation" unless checkpoint["request_id"] == expected_request_id
      errors << "#{label} checkpoint operation ID is required" unless non_empty_string?(checkpoint["operation_id"])
      errors << "#{label} checkpoint kernel inventory digest is required" unless valid_digest?(checkpoint["kernel_inventory_sha256"])

      actual_workload = entry["actual_workload"]
      if actual_workload.is_a?(Hash)
        %w[pid start_time command executable_digest cgroup_path cgroup_membership pid_namespace mount_namespace
           workload_pidfd workload_pidfd_link creation_method clone_flags].each do |key|
          errors << "#{label} actual Native workload #{key} is required" unless actual_workload.key?(key)
        end
        errors << "#{label} actual Native workload must use clone3" unless actual_workload["creation_method"] == "clone3"
        errors << "#{label} actual Native workload must have CLONE_PIDFD and CLONE_NEWPID" unless
          integer?(actual_workload["clone_flags"]) &&
          actual_workload["clone_flags"].allbits?(CLONE_PIDFD | CLONE_NEWPID)
        unless valid_digest?(actual_workload["executable_digest"].to_s.delete_prefix("sha256:"))
          errors << "#{label} actual Native workload executable digest is invalid"
        end
      else
        errors << "#{label} actual Native workload evidence is required"
      end

      wal_transition = checkpoint["wal_transition"]
      unless wal_transition.is_a?(Hash)
        errors << "#{label} fsynced WAL transition evidence is required"
        wal_transition = {}
      end
      errors << "#{label} WAL transition sequence must be positive" unless positive_integer?(wal_transition["sequence"])
      errors << "#{label} WAL transition must be a state_transition" unless wal_transition["event"] == "state_transition"
      unless wal_transition["operation_id"] == checkpoint["operation_id"]
        errors << "#{label} WAL transition operation does not match the checkpoint"
      end
      unless wal_transition["from"] == expected_checkpoint["from"]
        errors << "#{label} WAL transition source does not match the effect point"
      end
      errors << "#{label} WAL transition target does not match the effect point" unless
        wal_transition["to"] == expected_checkpoint["state"] && wal_transition["state"] == expected_checkpoint["state"]
      errors << "#{label} WAL transition digest is required" unless valid_digest?(wal_transition["digest"])
      token_input = [checkpoint["request_id"], effect_point, wal_transition["sequence"],
                     wal_transition["digest"]].join("\0")
      errors << "#{label} crash barrier token is not bound to the WAL transition" unless
        valid_digest?(checkpoint["barrier_token"]) && checkpoint["barrier_token"] == Digest::SHA256.hexdigest(token_input)

      native_wal = entry["native_wal_path"]
      errors << "#{label} must replay the exact Native ownership WAL" unless
        non_empty_string?(native_wal) && native_wal == entry["wal_path"] &&
        File.basename(native_wal) == "native-agent.wal"
      errors << "#{label} WAL kind must be the Native ownership ledger" unless
        entry["wal_kind"] == "rubernetes_native_ownership_ledger"
      errors << "#{label} replayed operation must be reconciled to Stopped" unless
        entry["replayed_operation_state"] == "Stopped"
      replayed = entry["replayed_request_ids"]
      unless replayed.is_a?(Hash) && replayed.keys == [expected_request_id] && replayed[expected_request_id] == true
        errors << "#{label} Native sandbox request ID must be replayed from the WAL"
      end

      observer = entry["kernel_observer"]
      unless observer.is_a?(Hash) && observer["external"] == true
        errors << "#{label} independent kernel observer evidence is required"
        return
      end
      observer_pid = observer["observer_pid"]
      errors << "#{label} kernel observer must run outside the killed Agent" unless
        observer_pid.is_a?(Integer) && observer_pid.positive? && observer_pid != entry["target_pid"]
      at_kill = observer["inventory_at_kill"]
      unless at_kill.is_a?(Array) && !at_kill.empty?
        errors << "#{label} kernel observer inventory_at_kill is required"
        return
      end
      validate_inventory_entries(at_kill, "#{label} kernel inventory at kill", errors)
      validate_inventory_duplicates(at_kill, "#{label} kernel inventory at kill", errors)
      errors << "#{label} kernel inventory_at_kill digest is required" unless
        valid_digest?(observer["inventory_at_kill_sha256"])
      if valid_digest?(observer["inventory_at_kill_sha256"]) && observer["inventory_at_kill_sha256"] != canonical_document_digest(at_kill)
        errors << "#{label} kernel inventory_at_kill digest does not match"
      end

      victim = at_kill.select { |resource| resource.is_a?(Hash) && resource.dig("metadata", "observer_role") == "victim" }
      guard = at_kill.select { |resource| resource.is_a?(Hash) && resource.dig("metadata", "observer_role") == "guard" }
      victim_kinds = victim.filter_map { |resource| resource["kind"] }.uniq.sort
      effect_inventory = checkpoint["effect_inventory"]
      if effect_inventory.is_a?(Array)
        validate_inventory_entries(effect_inventory, "#{label} effect-boundary inventory", errors)
        validate_inventory_duplicates(effect_inventory, "#{label} effect-boundary inventory", errors)
        effect_kinds = effect_inventory.filter_map { |resource| resource.is_a?(Hash) ? resource["kind"] : nil }.uniq.sort
        errors << "#{label} effect-boundary inventory does not match the effect point" unless
          effect_kinds == Array(expected_checkpoint["kernel_kinds"]).sort
        errors << "#{label} checkpoint kernel digest does not match effect-boundary inventory" unless
          valid_digest?(checkpoint["kernel_inventory_sha256"]) &&
          checkpoint["kernel_inventory_sha256"] == canonical_document_digest(effect_inventory)
      else
        errors << "#{label} victim kernel inventory does not match the effect point" unless
          victim_kinds == Array(expected_checkpoint["kernel_kinds"]).sort
      end
      errors << "#{label} kill-boundary inventory must include the effect-point resources" unless
        (Array(expected_checkpoint["kernel_kinds"]) - victim_kinds).empty?
      if actual_workload.is_a?(Hash)
        actual_process = victim.find { |resource| resource["kind"] == "process" }
        errors << "#{label} actual Native workload process is missing from independent kernel inventory" unless actual_process
        if actual_process
          process_metadata = actual_process.fetch("metadata", {})
          errors << "#{label} actual Native workload PID is not bound to kernel inventory" unless
            process_metadata["pid"].to_i == actual_workload["pid"].to_i &&
            process_metadata["start_time"].to_s == actual_workload["start_time"].to_s
          errors << "#{label} actual Native workload executable is not bound to kernel inventory" unless
            process_metadata["executable_digest"] == actual_workload["executable_digest"]
        end
      end
      errors << "#{label} live guard kernel inventory is required" if guard.empty?
      errors << "#{label} victim and guard resources must be live at the kill boundary" unless
        (victim + guard).all? { |resource| resource.dig("metadata", "live") == true }
      # The checkpoint digest binds the effect-boundary inventory (checked
      # above).  The workload that is started after the durable barrier
      # extends the victim set, so the binding to the independent kill-boundary
      # inventory is that every effect-boundary resource is still observed
      # there with the same kernel identity and owner.
      if effect_inventory.is_a?(Array)
        victim_index = victim.to_h { |resource| [[resource["kind"], resource["id"]], resource] }
        unbound = effect_inventory.reject do |resource|
          observed = resource.is_a?(Hash) ? victim_index[[resource["kind"], resource["id"]]] : nil
          observed && observed["identity"] == resource["identity"] && observed["owner"] == resource["owner"]
        end
        errors << "#{label} checkpoint kernel digest does not bind the victim inventory" unless
          valid_digest?(checkpoint["kernel_inventory_sha256"]) && unbound.empty?
      else
        errors << "#{label} checkpoint kernel digest does not bind the victim inventory" unless
          valid_digest?(checkpoint["kernel_inventory_sha256"]) &&
          checkpoint["kernel_inventory_sha256"] == canonical_document_digest(victim)
      end
      if effect_point != "workspace_allocated"
        victim_mount = victim.find do |resource|
          resource["kind"] == "mount" && resource.dig("metadata", "filesystem") == "overlay" &&
            resource.dig("metadata", "mountinfo").to_s.include?(" - overlay ") &&
            valid_digest?(resource.dig("metadata", "mountinfo_sha256"))
        end
        errors << "#{label} OverlayFS mountinfo readback is required after isolation" unless victim_mount
        victim_namespace = victim.find { |resource| resource["kind"] == "namespace" }
        namespace_flags = victim_namespace&.dig("metadata", "clone_flags")
        required_namespace_flags = CLONE_PIDFD | CLONE_NEWNS | CLONE_NEWPID
        errors << "#{label} namespace holder must be created by clone3 with namespace flags and pidfd" unless
          victim_namespace&.dig("metadata", "creation_method") == "clone3" && integer?(namespace_flags) &&
          namespace_flags.allbits?(required_namespace_flags)
      end

      before = Array(entry["inventory_before"])
      after = Array(entry["inventory_after"])
      errors << "#{label} post-SIGKILL kernel inventory must observe the victim as dead" unless
        before.any? do |resource|
          resource.is_a?(Hash) && resource.dig("metadata", "observer_role") == "victim" && resource.dig("metadata", "live") == false
        end
      errors << "#{label} recovered kernel inventory must contain no victim residual" if
        after.any? { |resource| resource.is_a?(Hash) && resource.dig("metadata", "observer_role") == "victim" }
      errors << "#{label} recovered kernel inventory must retain a live guard" unless
        after.any? do |resource|
          resource.is_a?(Hash) && resource.dig("metadata", "observer_role") == "guard" && resource.dig("metadata", "live") == true
        end
    end

    def validate_subresource_e2e(document, label, errors)
      e2e = document["subresource_e2e"] || document["subresources"]
      unless e2e.is_a?(Hash)
        errors << "#{label} subresource_e2e is required"
        return
      end
      REQUIRED_SUBRESOURCES.each do |name|
        entry = e2e[name] || e2e[name.tr("_", "-")]
        unless entry.is_a?(Hash)
          errors << "#{label} subresource #{name} evidence is missing"
          next
        end
        unless entry["requested"] == true && entry["observed"] == true && entry["passed"] == true
          errors << "#{label} subresource #{name} must be observed end-to-end"
        end
        errors << "#{label} subresource #{name} request_id is required" unless non_empty_string?(entry["request_id"])
        errors << "#{label} subresource #{name} response_sha256 is required" unless valid_digest?(entry["response_sha256"])
        route = entry["route"].to_s.split("?", 2).first
        errors << "#{label} subresource #{name} must use the production HTTP route" unless route == REQUIRED_SUBRESOURCE_ROUTES[name]
        unless entry["server_class"] == "Rubernetes::Transport::HTTPServer"
          errors << "#{label} subresource #{name} must use Transport::HTTPServer"
        end
        unless entry["api_server_class"] == "Rubernetes::API::Server"
          errors << "#{label} subresource #{name} must be dispatched by API::Server"
        end
        unless entry["agent_service_class"] == "Rubernetes::Bootstrap::AgentService"
          errors << "#{label} subresource #{name} must resolve through Bootstrap::AgentService"
        end
        unless entry["node_resolver_class"] == "Rubernetes::API::SubresourceBridge::NodeResolver"
          errors << "#{label} subresource #{name} must use the production NodeResolver"
        end
        unless entry["node_endpoint_registered"] == true
          errors << "#{label} subresource #{name} must observe the registered AgentService endpoint"
        end
        unless entry["service_class"] == REQUIRED_SUBRESOURCE_SERVICES[name]
          errors << "#{label} subresource #{name} service class is not the production Node service"
        end
      end
      errors << "#{label} subresource_e2e_sha256 is required" unless valid_digest?(document["subresource_e2e_sha256"])
      return unless valid_digest?(document["subresource_e2e_sha256"])

      expected = canonical_document_digest(e2e)
      errors << "#{label} subresource_e2e_sha256 does not match canonical content" unless document["subresource_e2e_sha256"] == expected
    end

    def validate_kernel(document, errors)
      profiles = document["architectures"] || document["profiles"]
      profiles = profiles.map { |architecture, profile| profile.merge("architecture" => architecture) } if profiles.is_a?(Hash)
      unless profiles.is_a?(Array)
        errors << "kernel inventory profiles are missing"
        return
      end
      validate_required_architectures(document, "kernel report", errors)
      validate_architecture_set(profiles, "kernel inventory", errors)
      profiles.each_with_index do |profile, index|
        validate_profile_identity(profile, "kernel inventory profile #{index}", errors)
        next unless profile.is_a?(Hash)

        objects = profile["objects"]
        unless objects.is_a?(Array)
          errors << "kernel inventory profile #{index} objects are missing"
          next
        end
        ids = objects.map { |object| object.is_a?(Hash) ? [object["kind"], object["identity"]] : nil }
        errors << "kernel inventory profile #{index} object identities must be unique" unless ids.all? do |id|
          id.is_a?(Array) && id.all? do |part|
            non_empty_string?(part)
          end
        end && ids.uniq.length == ids.length
        objects.each_with_index do |object, object_index|
          unless object.is_a?(Hash)
            errors << "kernel inventory profile #{index} object #{object_index} must be an object"
            next
          end
          label = "kernel inventory profile #{index} object #{object_index}"
          %w[kind identity before after].each do |key|
            errors << "#{label} #{key} is required" unless non_empty_string?(object[key])
          end
          next unless profile["status"] == "PASS"

          errors << "#{label} active kernel observation is required" unless non_empty_string?(object["active"])
          errors << "#{label} must come from production Native adapters" unless object["measurement_source"] == "production_native_adapter"
          errors << "#{label} active_sha256 is required" unless valid_digest?(object["active_sha256"])
          if valid_digest?(object["active_sha256"]) && non_empty_string?(object["active"]) && object["active_sha256"] != Digest::SHA256.hexdigest(object["active"])
            errors << "#{label} active_sha256 does not match"
          end
        end
        if profile["status"] == "PASS"
          child_object = objects.find { |object| object.is_a?(Hash) && object["kind"] == "child_security" }
          if child_object
            begin
              child = JSON.parse(child_object.fetch("active"))
              errors << "kernel inventory profile #{index} actual workload PID is required" unless
                child["pid"].is_a?(Integer) && child["pid"].positive?
              errors << "kernel inventory profile #{index} actual workload start time is required" unless
                child["start_time"].to_s.match?(/\A\d+\z/)
              errors << "kernel inventory profile #{index} actual workload executable digest is required" unless
                child["executable_digest"].to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
              flags = child["clone_flags"]
              required_workload_flags = CLONE_PIDFD | CLONE_NEWPID
              errors << "kernel inventory profile #{index} actual workload must use clone3 with CLONE_PIDFD and CLONE_NEWPID" unless
                child["creation_method"] == "clone3" && integer?(flags) &&
                flags.allbits?(required_workload_flags)
            rescue JSON::ParserError, KeyError => error
              errors << "kernel inventory profile #{index} actual workload security evidence is invalid: #{error.message}"
            end
          else
            errors << "kernel inventory profile #{index} actual Native workload security evidence is required"
          end
        end
        errors << "kernel inventory profile #{index} inventory_sha256 is required" unless valid_digest?(profile["inventory_sha256"])
        if objects.all? { |object| object.is_a?(Hash) && %w[kind identity before after].all? { |key| non_empty_string?(object[key]) } }
          expected = canonical_kernel_inventory_digest(objects)
          unless profile["inventory_sha256"] == expected
            errors << "kernel inventory profile #{index} inventory_sha256 does not match objects"
          end
        end
        %w[difference_count live_leak_count orphan_count].each do |key|
          errors << "kernel inventory profile #{index} #{key} must be zero" unless profile[key] == 0
        end
        errors << "kernel inventory profile #{index} baseline_sha256 is required" unless valid_digest?(profile["baseline_sha256"])
        errors << "kernel inventory profile #{index} final_sha256 is required" unless valid_digest?(profile["final_sha256"])
      end
    end

    def validate_result_counts(manifest, artifacts, subjects, errors)
      counts = manifest["result_counts"]
      return unless counts.is_a?(Hash)

      expected = {
        "commands" => manifest.fetch("commands", []).length,
        "command_failures" => manifest.fetch("commands", []).count { |command| command["exit_status"] != 0 },
        "artifacts" => artifacts.length,
        "subjects" => subjects.length,
        "reports" => REPORTS.length + artifacts.count do |entry|
          !entry["path"].to_s.include?("/") && FORMAL_REPORTS.fetch(:names).include?(File.basename(entry["path"].to_s))
        end,
        "source_files" => manifest["input_file_count"]
      }
      expected.each do |key, value|
        errors << "result_counts #{key} is missing or invalid" unless integer?(counts[key])
        errors << "result_counts #{key} is incorrect" if integer?(counts[key]) && counts[key] != value
      end
    end

    def validate_manifest_status(manifest, errors)
      return if manifest["status"] == "COMPLETE" && errors.empty?

      errors << "manifest status must be INCOMPLETE when any M2 gate requirement fails" if errors.any? && manifest["status"] == "COMPLETE"
    end

    def canonical_architecture(value)
      case value.to_s
      when "amd64", "x86_64" then "x86_64"
      when "arm64", "aarch64" then "aarch64"
      end
    end

    def canonical_value(value, excluded_keys = [])
      excluded = excluded_keys.map(&:to_s)
      case value
      when Hash
        value.keys.map(&:to_s).reject { |key| excluded.include?(key) }.sort.each_with_object({}) do |key, result|
          source_key = value.keys.find { |candidate| candidate.to_s == key }
          result[key] = canonical_value(value.fetch(source_key), [])
        end
      when Array
        value.map { |child| canonical_value(child, []) }
      else
        value
      end
    end

    def identity?(value)
      value.is_a?(Hash) && valid_digest?(value["sha256"]) && positive_integer?(value["file_count"])
    end

    def valid_digest?(value)
      value.is_a?(String) && SHA256_PATTERN.match?(value)
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

    def excluded_source_path?(path)
      return false unless path.is_a?(String)

      SOURCE_EXCLUDED_ROOTS.include?(path.split("/", 2).first) ||
        SOURCE_EXCLUDED_PATTERNS.any? { |pattern| pattern.match?(path) }
    end
  end
end

if $PROGRAM_NAME == __FILE__
  manifest_path = ARGV.fetch(0) { abort "Usage: m2_gate.rb PATH/manifest.json" }
  output = M2Gate.evaluate(manifest_path)
  puts(JSON.pretty_generate(output))
  exit(output.fetch("passed") ? 0 : 1)
end
