#!/usr/bin/env ruby
# frozen_string_literal: true

# Validate the content-addressed evidence bundle for Milestone M3.
#
# M3 is cumulative: a passing report is not enough on its own.  The gate
# verifies the source inventory, re-runs every prior COMPLETE gate, checks all
# required control-loop reports, and rejects any report which can only claim
# success by hiding retries, skips, missing production adapters, or a changed
# input tree.

require "digest"
require "json"
require "open3"
require "rbconfig"
require "time"

module M3Gate
  MANIFEST_SCHEMA_VERSION = 3
  REPORT_SCHEMA_VERSION = 1
  MAX_JSON_BYTES = 32 * 1024 * 1024
  SHA256_PATTERN = /\A[0-9a-f]{64}\z/
  SOURCE_EXCLUDED_ROOTS = %w[.git artifacts build pkg tmp .bundle].freeze
  # Anchored generator scratch directories (a11-generated.XXXXXX) are
  # excluded from the source identity by every milestone (M0-M2 rule).
  SOURCE_EXCLUDED_PATTERNS = [%r{\Aa11-generated\.[A-Za-z0-9]{6,}/}, %r{\Aapps/[^/]+/(?:log|tmp|storage)/}].freeze
  PROJECT_ROOT = File.expand_path("../..", __dir__).freeze
  M0_GATE = File.join(__dir__, "m0_gate.rb").freeze
  M1_GATE = File.join(__dir__, "m1_gate.rb").freeze
  M2_GATE = File.join(__dir__, "m2_gate.rb").freeze
  KUBERNETES_VERSION = "v1.36.2"
  KUBERNETES_SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"

  # This is the pinned v1.36.2 built-in controller corpus exposed by the
  # production registry.  Keeping it in the gate prevents a registry from
  # reporting only the controllers it happened to instantiate.
  REQUIRED_CONTROLLER_NAMES = %w[
    serviceaccount-token-controller endpoints-controller endpointslice-controller
    endpointslice-mirroring-controller replicationcontroller-controller
    pod-garbage-collector-controller resourcequota-controller namespace-controller
    serviceaccount-controller garbage-collector-controller daemonset-controller
    job-controller deployment-controller replicaset-controller
    horizontal-pod-autoscaler-controller disruption-controller statefulset-controller
    cronjob-controller certificatesigningrequest-signing-controller
    certificatesigningrequest-approving-controller certificatesigningrequest-cleaner-controller
    podcertificaterequest-cleaner-controller ttl-controller bootstrap-signer-controller
    token-cleaner-controller node-ipam-controller node-lifecycle-controller
    taint-eviction-controller device-taint-eviction-controller service-lb-controller
    node-route-controller cloud-node-lifecycle-controller persistentvolume-binder-controller
    persistent-volume-attach-detach-controller persistent-volume-expander-controller
    clusterrole-aggregation-controller persistentvolumeclaim-protection-controller
    persistent-volume-protection-controller podgroup-protection-controller
    volume-attributes-class-protection-controller ttl-after-finished-controller
    root-ca-certificate-publisher-controller
    kube-apiserver-serving-clustertrustbundle-publisher-controller
    ephemeral-volume-controller storageversion-garbage-collector-controller
    resourceclaim-controller resourcepoolstatusrequest-controller
    legacy-serviceaccount-token-cleaner-controller validatingadmissionpolicy-status-controller
    service-cidr-controller storage-version-migrator-controller selinux-warning-controller
  ].freeze
  REQUIRED_CONTROLLERS = REQUIRED_CONTROLLER_NAMES
  REQUIRED_IDEMPOTENCY_CASES = REQUIRED_CONTROLLER_NAMES
  REQUIRED_SCHEDULER_CASES = %w[filter score tie_break preemption binding volume_binding].freeze
  REQUIRED_SCHEDULER_PLUGIN_NAMES = %w[
    SchedulingGates PrioritySort NodeUnschedulable NodeName TaintToleration NodeAffinity
    NodePorts NodeResourcesFit VolumeRestrictions NodeVolumeLimits VolumeBinding VolumeZone
    PodTopologySpread InterPodAffinity DynamicResources DefaultPreemption NodeResourcesBalancedAllocation
    ImageLocality DefaultBinder NodeDeclaredFeatures
  ].freeze
  REQUIRED_SCHEDULER_PLUGIN_WEIGHTS = {
    "SchedulingGates" => 1, "PrioritySort" => 1, "NodeUnschedulable" => 1, "NodeName" => 1,
    "TaintToleration" => 3, "NodeAffinity" => 2, "NodePorts" => 1, "NodeResourcesFit" => 1,
    "VolumeRestrictions" => 1, "NodeVolumeLimits" => 1, "VolumeBinding" => 1, "VolumeZone" => 1,
    "PodTopologySpread" => 2, "InterPodAffinity" => 2, "DefaultPreemption" => 1,
    "NodeResourcesBalancedAllocation" => 1, "ImageLocality" => 1, "DefaultBinder" => 1,
    # getDefaultPlugins + applyFeatureGates (NodeDeclaredFeatures is Beta, on;
    # applyDynamicResources: DynamicResourceAllocation is GA).
    "NodeDeclaredFeatures" => 1, "DynamicResources" => 2
  }.freeze
  REQUIRED_WORKLOAD_TYPES = %w[deployment statefulset daemonset job cronjob].freeze
  REQUIRED_WORKLOAD_OPERATIONS = %w[rollout rollback scale delete].freeze
  REQUIRED_QUEUE_PROPERTIES = %w[duplicate_suppression out_of_order_delivery watch_reconnect resync].freeze

  REPORTS = {
    "controller_registry" => {
      kind: "m3_controller_registry",
      names: %w[controller-registry.json controller_registry.json]
    },
    "reconcile_idempotency" => {
      kind: "m3_reconcile_idempotency",
      names: %w[reconcile-idempotency.json reconcile_idempotency.json idempotency-matrix.json]
    },
    "scheduler" => {
      kind: "m3_scheduler_differential",
      names: %w[scheduler-differential.json scheduler_differential.json scheduler.json]
    },
    "workload" => {
      kind: "m3_workload_differential",
      names: %w[workload-differential.json workload_differential.json workload.json]
    },
    "leader_loss" => {
      kind: "m3_leader_loss_trace",
      names: %w[leader-loss-trace.json leader_loss_trace.json leader.json]
    },
    "queue_informer" => {
      kind: "m3_queue_informer_property",
      names: %w[queue-informer-property.json queue_informer_property.json queue.json informer.json]
    }
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
        validate_report(name, document, specification.fetch(:kind), manifest, errors) if document
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
      Digest::SHA256.hexdigest(JSON.generate(canonical_value(document, excluded_keys.map(&:to_s))))
    end

    # Return the complete, serializable binding between one production
    # ControllerDefinition and its authoritative corpus entry.  Registry
    # evidence must carry this value so a report cannot pass by naming the
    # right controller while silently changing its GVK, ownership graph,
    # watch/index/queue wiring, or corpus metadata.
    def controller_registry_binding(definition, corpus_entry)
      authoritative_descriptor = registry_descriptor_binding(corpus_entry.descriptor)
      registered_descriptor = registry_descriptor_binding(definition.kind)
      ownership_edges = Array(definition.owns).map do |edge|
        {
          "owner" => registry_descriptor_binding(edge.owner),
          "dependent" => registry_descriptor_binding(edge.dependent),
          "controller" => edge.controller,
          "block_owner_deletion" => edge.block_owner_deletion
        }
      end.sort_by { |edge| canonical_document_digest(edge) }
      watch_wiring = Array(definition.watches).map do |watch|
        {
          "resource" => registry_descriptor_binding(watch.resource),
          "via" => watch.via.to_s,
          "scope" => watch.scope&.to_s,
          "index_name" => watch.index_name,
          "predicate" => callable_binding(watch.predicate),
          "queue_key" => callable_binding(watch.queue_key)
        }
      end.sort_by { |watch| canonical_document_digest(watch) }
      registered_metadata = {
        "featureGates" => Array(definition.feature_gates).map(&:to_s),
        "startupConditions" => Array(definition.startup_conditions).map(&:to_s),
        "syncTargets" => Array(definition.sync_targets).map(&:to_s),
        "statusFields" => Array(definition.status_fields).map(&:to_s),
        "events" => Array(definition.events).map(&:to_s)
      }
      corpus_metadata = corpus_entry.to_h
      binding = {
        "authoritative_corpus" => {
          "name" => corpus_entry.name.to_s,
          "kind" => corpus_entry.kind.to_s,
          "descriptor" => authoritative_descriptor,
          "gvk" => authoritative_descriptor.fetch("gvk"),
          "gvr" => authoritative_descriptor.fetch("gvr"),
          "metadata" => corpus_metadata
        },
        "registered_definition" => {
          "name" => definition.name.to_s,
          "descriptor" => registered_descriptor,
          "gvk" => registered_descriptor.fetch("gvk"),
          "gvr" => registered_descriptor.fetch("gvr"),
          "implementation_class" => definition.implementation_name.to_s,
          "reconcile_declared" => definition.reconcile_block.respond_to?(:call)
        },
        "ownership_edges" => ownership_edges,
        "watch_wiring" => watch_wiring,
        "registered_metadata" => registered_metadata,
        "metadata_digest" => canonical_document_digest({
                                                         "corpus" => corpus_metadata,
                                                         "registered" => registered_metadata
                                                       }),
        "ownership_edges_digest" => canonical_document_digest(ownership_edges),
        "watch_wiring_digest" => canonical_document_digest(watch_wiring)
      }
      binding["binding_digest"] = canonical_document_digest(binding)
      binding
    end

    private

    def result(errors)
      {"schema_version" => 1, "milestone" => "M3", "passed" => errors.empty?, "error_count" => errors.length, "errors" => errors}
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
      errors << "milestone must be M3" unless manifest["milestone"] == "M3"
      errors << "manifest status must be COMPLETE" unless manifest["status"] == "COMPLETE"
      errors << "input_sha256 must be a SHA-256 digest" unless valid_digest?(manifest["input_sha256"])
      errors << "input_file_count must be positive" unless positive_integer?(manifest["input_file_count"])
      errors << "source input must remain stable during evidence capture" unless manifest["input_stable"] == true
      host = manifest["host"]
      unless host.is_a?(Hash) && %w[architecture kernel ruby].all? { |key| non_empty_string?(host[key]) }
        errors << "host architecture, kernel, and Ruby description are required"
      end
      %w[started_at finished_at].each do |key|
        errors << "#{key} must be an ISO-8601 timestamp" unless iso8601?(manifest[key])
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
        unless (argv.is_a?(Array) && !argv.empty? && argv.all? { |part| non_empty_string?(part) }) || non_empty_string?(argv)
          errors << "command #{index} must record its argv"
        end
        errors << "command #{index} must have an exit status" unless integer?(command["exit_status"])
        errors << "command #{index} did not exit zero" unless command["exit_status"] == 0
        %w[started_at finished_at].each do |key|
          errors << "command #{index} #{key} must be an ISO-8601 timestamp" unless iso8601?(command[key])
        end
        if iso8601?(command["started_at"]) && iso8601?(command["finished_at"]) &&
           Time.iso8601(command["finished_at"]) < Time.iso8601(command["started_at"])
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
        unless File.file?(path)
          errors << "missing #{label} #{path_value}"
          next
        end
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
      errors << "source inventory kind must be m3_source_inventory" unless document["kind"] == "m3_source_inventory"
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
        if File.file?(path) && valid_digest?(entry["sha256"]) && Digest::SHA256.file(path).hexdigest != entry["sha256"]
          errors << "source inventory digest mismatch #{entry.fetch("path")}"
        end
      end
    end

    def validate_prior_milestones(manifest, directory, artifacts, errors)
      prior = manifest["prior_milestones"]
      unless prior.is_a?(Hash)
        errors << "COMPLETE M0, M1, and M2 evidence is required for cumulative M3 completion"
        return
      end
      {"M0" => M0_GATE, "M1" => M1_GATE, "M2" => M2_GATE}.each do |name, gate_path|
        validate_prior_milestone(name, prior[name], manifest, directory, artifacts, errors, gate_path)
      end
    end

    def validate_prior_milestone(name, reference, manifest, directory, artifacts, errors, gate_path)
      unless reference.is_a?(Hash)
        errors << "COMPLETE #{name} evidence is required for cumulative M3 completion"
        return
      end
      manifest_value = reference["manifest_path"]
      result_value = reference["gate_result_path"]
      errors << "#{name} manifest and gate result paths must be distinct" if manifest_value == result_value
      manifest_entry = artifacts.find { |entry| entry["path"] == manifest_value }
      result_entry = artifacts.find { |entry| entry["path"] == result_value }
      errors << "#{name} manifest must be content-addressed by M3" unless manifest_entry
      errors << "#{name} gate result must be content-addressed by M3" unless result_entry
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
      errors << "#{name} evidence must use the same source input as M3" unless prior_manifest["input_sha256"] == manifest["input_sha256"] &&
                                                                               prior_manifest["input_file_count"] == manifest["input_file_count"]
      errors << "#{name} reference identity must match the M3 source input" unless reference["input_sha256"] == manifest["input_sha256"] &&
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
          nested_path = File.join(File.dirname(manifest_value.to_s), entry["path"])
          errors << "#{name} #{collection} entry is not content-addressed by M3: #{nested_path}" unless artifacts.any? do |candidate|
            candidate["path"] == nested_path
          end
        end
      end
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
      return unless document.is_a?(Hash) && document["schema_version"] == REPORT_SCHEMA_VERSION && document["kind"] == expected_kind

      case name
      when "controller_registry" then validate_controller_registry(document, errors)
      when "reconcile_idempotency" then validate_idempotency(document, errors)
      when "scheduler" then validate_scheduler(document, errors)
      when "workload" then validate_workload(document, errors)
      when "leader_loss" then validate_leader(document, errors)
      when "queue_informer" then validate_queue(document, errors)
      end
    end

    def validate_common_document(document, expected_kind, manifest, errors, label)
      errors << "#{label} must be a JSON object" unless document.is_a?(Hash)
      return unless document.is_a?(Hash)

      errors << "#{label} schema_version must be #{REPORT_SCHEMA_VERSION}" unless document["schema_version"] == REPORT_SCHEMA_VERSION
      errors << "#{label} kind must be #{expected_kind}" unless document["kind"] == expected_kind
      errors << "#{label} milestone must be M3" unless document["milestone"] == "M3"
      errors << "#{label} input_sha256 must match manifest" unless document["input_sha256"] == manifest["input_sha256"]
      errors << "#{label} input_file_count must match manifest" unless document["input_file_count"] == manifest["input_file_count"]
      errors << "#{label} input_stable must be true" unless document["input_stable"] == true
      errors << "#{label} measurement_source must be production_module" unless document["measurement_source"] == "production_module"
      errors << "#{label} measurement_level must be L3" unless document["measurement_level"] == "L3"
      errors << "#{label} status must be PASS" unless document["status"] == "PASS"
      errors << "#{label} passed must be true" unless document["passed"] == true
      errors << "#{label} available must be true" unless document["available"] == true
      errors << "#{label} errors must be an empty array" unless document["errors"] == []
      errors << "#{label} attempt_count must be one" unless document["attempt_count"] == 1
      %w[retry_count unexpected_skip_count unclassified_count flake_count failure_count].each do |key|
        errors << "#{label} #{key} must be zero" unless document[key] == 0
      end
      adapter = document["adapter"]
      unless adapter.is_a?(Hash) && non_empty_string?(adapter["name"]) && non_empty_string?(adapter["version"]) && valid_digest?(adapter["runner_sha256"])
        errors << "#{label} adapter provenance is incomplete"
      end
      provenance = document["provenance"]
      if provenance.is_a?(Hash)
        errors << "#{label} provenance source_sha256 must match manifest" unless provenance["source_sha256"] == manifest["input_sha256"]
        errors << "#{label} provenance source_file_count must match manifest" unless provenance["source_file_count"] == manifest["input_file_count"]
        unless valid_digest?(provenance["runner_sha256"]) && provenance["runner_sha256"] == adapter["runner_sha256"]
          errors << "#{label} provenance runner_sha256 must match adapter"
        end
        errors << "#{label} provenance command must be a non-empty argv" unless provenance["command"].is_a?(Array) && !provenance["command"].empty? && provenance["command"].all? do |part|
          non_empty_string?(part)
        end
        errors << "#{label} provenance process_id must be positive" unless provenance["process_id"].is_a?(Integer) && provenance["process_id"].positive?
        errors << "#{label} provenance measurement_id is required" unless non_empty_string?(provenance["measurement_id"])
        %w[started_at finished_at].each { |key| errors << "#{label} provenance #{key} must be ISO-8601" unless iso8601?(provenance[key]) }
        if valid_digest?(provenance["provenance_sha256"])
          expected = canonical_document_digest(provenance, excluded_keys: ["provenance_sha256"])
          errors << "#{label} provenance_sha256 does not match canonical content" unless expected == provenance["provenance_sha256"]
        else
          errors << "#{label} provenance_sha256 is required"
        end
      else
        errors << "#{label} provenance is required"
      end
      if valid_digest?(document["report_sha256"])
        expected = canonical_document_digest(document, excluded_keys: ["report_sha256"])
        errors << "#{label} report_sha256 does not match canonical content" unless expected == document["report_sha256"]
      else
        errors << "#{label} report_sha256 is required"
      end
    end

    def registry_descriptor_binding(descriptor)
      value = descriptor.to_h
      value.merge(
        "gvk" => Array(descriptor.gvk).map(&:to_s),
        "gvr" => Array(descriptor.gvr).map(&:to_s),
        "identifier" => descriptor.identifier.to_s
      )
    end

    def callable_binding(callable)
      return nil unless callable

      location = callable.respond_to?(:source_location) ? callable.source_location : nil
      location = if location.is_a?(Array) && location.length >= 2
                   path = File.expand_path(location[0].to_s)
                   relative = path.start_with?("#{PROJECT_ROOT}/") ? path.delete_prefix("#{PROJECT_ROOT}/") : path
                   [relative, Integer(location[1])]
                 end
      {
        "class" => callable.class.name.to_s,
        "arity" => callable.respond_to?(:arity) ? callable.arity : nil,
        "parameters" => callable.respond_to?(:parameters) ? callable.parameters.map { |kind, name| [kind.to_s, name&.to_s] } : [],
        "source_location" => location
      }
    rescue ArgumentError, TypeError
      {"class" => callable.class.name.to_s, "arity" => nil, "parameters" => [], "source_location" => nil}
    end

    def authoritative_controller_bindings
      require File.join(PROJECT_ROOT, "lib", "rubernetes")
      controller_module = Rubernetes::Controller
      registry = controller_module.build_default_registry
      registry.startup_validate!
      corpus = Rubernetes::Controller::BuiltinControllerCorpus
      bindings = REQUIRED_CONTROLLER_NAMES.each_with_object({}) do |name, result|
        definition = registry.fetch(name)
        entry = corpus.fetch(name)
        result[name] = controller_registry_binding(definition, entry)
      end
      [bindings, nil]
    rescue StandardError => error
      [nil, error]
    end

    def validate_controller_registry(document, errors)
      required = Array(document["required_controller_names"])
      registered = Array(document["registered_controller_names"] || document["registered_names"])
      errors << "controller registry required controller corpus differs" unless required.sort == REQUIRED_CONTROLLER_NAMES.sort
      errors << "controller registry registered controller count must equal corpus" unless registered.length == REQUIRED_CONTROLLER_NAMES.length
      errors << "controller registry contains duplicate names" unless registered.uniq.length == registered.length
      errors << "controller registry has missing or unexpected controllers" unless registered.sort == REQUIRED_CONTROLLER_NAMES.sort
      entries = document["controllers"] || document["entries"]
      unless entries.is_a?(Array) && entries.length == REQUIRED_CONTROLLER_NAMES.length
        errors << "controller registry controller entries must cover the complete corpus"
        return
      end
      startup = document["startup_validation"]
      unless startup.is_a?(Hash) && startup.key?("exception_class") && startup.key?("error") &&
             startup["attempt_count"] == 1 && startup["passed"] == true &&
             startup["exception_class"].nil? && startup["error"].nil?
        errors << "controller registry startup_validate! evidence must be one successful production call"
      end
      ids = entries.filter_map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["name"]) : nil }
      errors << "controller registry entry identifiers must be unique" unless ids.length == ids.uniq.length
      errors << "controller registry entry inventory differs from corpus" unless ids.sort == REQUIRED_CONTROLLER_NAMES.sort
      authoritative_bindings, startup_error = authoritative_controller_bindings
      errors << "controller registry authoritative corpus recomputation failed: #{startup_error.class}: #{startup_error.message}" if startup_error
      entries.each_with_index do |entry, index|
        unless entry.is_a?(Hash)
          errors << "controller registry entry #{index} must be an object"
          next
        end
        errors << "controller registry entry #{index} did not pass" unless entry["passed"] == true
        unless entry["owns_declared"] == true && entry["reconcile_declared"] == true
          errors << "controller registry entry #{index} must validate ownership and reconcile"
        end
        errors << "controller registry entry #{index} must execute against production registry" unless entry["measurement_source"] == "production_module"
        errors << "controller registry entry #{index} must run once" unless entry["attempt_count"] == 1
        implementation = entry["implementation_class"]
        unless entry["implementation_present"] == true && non_empty_string?(implementation)
          errors << "controller registry entry #{index} must record a concrete implementation"
        end
        if entry["uses_corpus_controller"] == true || implementation.to_s.end_with?("::CorpusController") || implementation.to_s == "Rubernetes::Controller::CorpusController"
          errors << "controller registry entry #{index} must not use CorpusController fallback"
        end
        expected_binding = authoritative_bindings && authoritative_bindings[entry["id"].to_s]
        next unless expected_binding

        unless entry["binding"] == expected_binding
          errors << "controller registry entry #{index} is not bound to the authoritative descriptor/GVK/ownership/watch corpus"
        end
        errors << "controller registry entry #{index} descriptor evidence aliases disagree with the authoritative binding" unless
          entry["authoritative_descriptor"] == expected_binding.dig("authoritative_corpus", "descriptor") &&
          entry["authoritative_gvk"] == expected_binding.dig("authoritative_corpus", "gvk") &&
          entry["authoritative_gvr"] == expected_binding.dig("authoritative_corpus", "gvr") &&
          entry["ownership_edges"] == expected_binding["ownership_edges"] &&
          entry["watch_wiring"] == expected_binding["watch_wiring"]
        unless entry["metadata_digest"] == expected_binding["metadata_digest"]
          errors << "controller registry entry #{index} metadata digest is not bound to the authoritative corpus"
        end
        errors << "controller registry entry #{index} binding digest is invalid" unless entry["binding_digest"] == expected_binding["binding_digest"]
      end
      %w[duplicate_count missing_count unexpected_count unregistered_count failure_count binding_failure_count].each do |key|
        errors << "controller registry #{key} must be zero" unless document[key] == 0
      end
      expected_duplicate_error = "Rubernetes::Controller::DuplicateControllerError"
      unless document["duplicate_exception_class"] == expected_duplicate_error
        errors << "controller registry duplicate registration must raise #{expected_duplicate_error}"
      end
      errors << "controller registry duplicate registration check did not pass" unless document["duplicate_check_passed"] == true
    end

    def validate_idempotency(document, errors)
      cases = document["cases"]
      unless cases.is_a?(Array) && cases.length == REQUIRED_IDEMPOTENCY_CASES.length
        errors << "reconcile idempotency cases must cover every built-in controller"
        return
      end
      ids = cases.filter_map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["controller"]) : nil }
      errors << "reconcile idempotency case identifiers must be unique" unless ids.length == ids.uniq.length
      errors << "reconcile idempotency case inventory differs from controller corpus" unless ids.sort == REQUIRED_IDEMPOTENCY_CASES.sort
      cases.each_with_index do |entry, index|
        unless entry.is_a?(Hash)
          errors << "reconcile idempotency case #{index} must be an object"
          next
        end
        errors << "reconcile idempotency case #{index} did not pass" unless entry["passed"] == true
        errors << "reconcile idempotency case #{index} must execute exactly twice" unless entry["execution_count"] == 2
        errors << "reconcile idempotency case #{index} must use production Manager" unless entry["manager_class"].to_s.end_with?("::Manager")
        backend_class = entry["store_backend_class"].to_s
        errors << "reconcile idempotency case #{index} must use production StoreAdapter" unless entry["store_class"] == "Rubernetes::Controller::StoreAdapter" &&
                                                                                                (backend_class.end_with?("::MemoryStore") || backend_class == "M3TransientMemoryStore")
        first_observable = entry["first_effect_observable"]
        # A status-subresource write is an update for conflict/retry purposes
        # (upstream issues it as its own PUT and retries it on Conflict).
        update_observed = first_observable.is_a?(Hash) && Array(first_observable["api_mutations"]).any? do |mutation|
          (Array(mutation["actions"]) & %w[update status_update]).any?
        end
        if update_observed
          unless entry["error_class"] == "Rubernetes::Storage::Conflict" && entry["queue_retry_observed"] == true
            errors << "reconcile idempotency case #{index} must observe a real queue retry"
          end
        else
          errors << "reconcile idempotency case #{index} must report that no update retry was applicable" unless entry["queue_retry_observed"] == false
        end
        unless entry["owner_scope_checked"] == true && entry["foreign_resource_preserved"] == true
          errors << "reconcile idempotency case #{index} must check owner scope and foreign resources"
        end
        errors << "reconcile idempotency case #{index} attempt_count must be one" unless entry["attempt_count"] == 1
        first = entry["first_effect_sha256"] || entry["first_result_sha256"]
        second = entry["second_effect_sha256"] || entry["second_result_sha256"]
        errors << "reconcile idempotency case #{index} must record effect digests" unless valid_digest?(first) && valid_digest?(second)
        second_observable = entry["second_effect_observable"]
        unless structured_observable?(first_observable) && structured_observable?(second_observable)
          errors << "reconcile idempotency case #{index} must record structured effect observables"
        end
        validate_idempotency_step_observable(first_observable, errors, index, "first")
        validate_idempotency_step_observable(second_observable, errors, index, "second")
        validate_provider_applicability(first_observable, second_observable, errors, index)
        validate_idempotency_effect_inventory(first_observable, second_observable, errors, index)
        if structured_observable?(first_observable) && valid_digest?(first) && canonical_document_digest(first_observable) != first
          errors << "reconcile idempotency case #{index} first effect digest does not match observable"
        end
        if structured_observable?(second_observable) && valid_digest?(second) && canonical_document_digest(second_observable) != second
          errors << "reconcile idempotency case #{index} second effect digest does not match observable"
        end
        if first_observable.is_a?(Hash) && second_observable.is_a?(Hash) && first_observable["store"] != second_observable["store"]
          errors << "reconcile idempotency case #{index} final store state changed during replay"
        end
        first_snapshot = entry["first_run_raw_snapshot"]
        second_snapshot = entry["second_run_raw_snapshot"]
        errors << "reconcile idempotency case #{index} must record a first-run raw snapshot" unless first_snapshot.is_a?(Hash)
        errors << "reconcile idempotency case #{index} must record a second-run raw snapshot" unless second_snapshot.is_a?(Hash)
        if first_snapshot.is_a?(Hash) && !(entry["first_run_snapshot"] == first_snapshot &&
                                                                                                     entry["first_run_raw_entries"] == first_snapshot["raw_entries"])
          errors << "reconcile idempotency case #{index} first-run snapshot aliases disagree"
        end
        if second_snapshot.is_a?(Hash) && !(entry["second_run_snapshot"] == second_snapshot &&
                                                                                                      entry["second_run_raw_entries"] == second_snapshot["raw_entries"])
          errors << "reconcile idempotency case #{index} second-run snapshot aliases disagree"
        end
        if first_snapshot.is_a?(Hash) && first_observable.is_a?(Hash)
          journal_snapshot = first_observable.dig("durable_journal", "raw_snapshot")
          errors << "reconcile idempotency case #{index} first-run snapshot is not bound to the observable" unless journal_snapshot == first_snapshot
        end
        if second_snapshot.is_a?(Hash) && second_observable.is_a?(Hash)
          journal_snapshot = second_observable.dig("durable_journal", "raw_snapshot")
          errors << "reconcile idempotency case #{index} second-run snapshot is not bound to the observable" unless journal_snapshot == second_snapshot
        end
        durable_journal = entry["durable_journal"]
        unless durable_journal.is_a?(Hash) && durable_journal["first_run"] == first_snapshot && durable_journal["second_run"] == second_snapshot &&
               durable_journal["first_run_inventory"] == first_observable&.dig("durable_journal", "after") &&
               durable_journal["second_run_inventory"] == second_observable&.dig("durable_journal", "after")
          errors << "reconcile idempotency case #{index} durable journal must contain separate first and second run snapshots"
        end
        errors << "reconcile idempotency case #{index} must come from production module" unless entry["measurement_source"] == "production_module"
        implementation = entry["implementation_class"]
        unless entry["implementation_present"] == true && non_empty_string?(implementation)
          errors << "reconcile idempotency case #{index} must record a concrete implementation"
        end
        if entry["uses_corpus_controller"] == true || implementation.to_s.end_with?("::CorpusController") || implementation.to_s == "Rubernetes::Controller::CorpusController"
          errors << "reconcile idempotency case #{index} must not use CorpusController fallback"
        end
      end
      %w[failure_count difference_count non_idempotent_count unexpected_skip_count unclassified_count].each do |key|
        errors << "reconcile idempotency #{key} must be zero" unless document[key] == 0
      end
    end

    def validate_idempotency_effect_inventory(first_observable, second_observable, errors, index)
      label = "reconcile idempotency case #{index}"
      required = %w[api_mutations events provider_calls durable_journal]
      [first_observable, second_observable].each_with_index do |observable, run_index|
        next unless observable.is_a?(Hash)

        required.each do |key|
          errors << "#{label} #{key} inventory is required for run #{run_index + 1}" unless observable.key?(key)
        end
        %w[api_mutations events provider_calls].each do |key|
          errors << "#{label} #{key} inventory must be an array for run #{run_index + 1}" unless observable[key].is_a?(Array)
        end
        journal = observable["durable_journal"]
        unless journal.is_a?(Hash)
          errors << "#{label} durable side-effect journal is required for run #{run_index + 1}"
          next
        end
        errors << "#{label} durable journal run label is invalid for run #{run_index + 1}" unless journal["run"] == (run_index.zero? ? "first" : "second")
        errors << "#{label} durable journal before inventory is required for run #{run_index + 1}" unless journal["before"].is_a?(Hash)
        errors << "#{label} durable journal after inventory is required for run #{run_index + 1}" unless journal["after"].is_a?(Hash)
        snapshot = journal["raw_snapshot"]
        unless snapshot.is_a?(Hash)
          errors << "#{label} durable journal raw snapshot is required for run #{run_index + 1}"
          next
        end
        inventory = validate_idempotency_run_snapshot(snapshot, observable, errors, label, run_index + 1)
        next unless inventory

        errors << "#{label} durable journal after inventory is not bound to raw snapshot for run #{run_index + 1}" unless journal["after"] == inventory
        %w[api_mutations events provider_calls].each do |inventory_key|
          unless observable[inventory_key] == inventory[inventory_key]
            errors << "#{label} #{inventory_key} inventory is not bound to durable journal for run #{run_index + 1}"
          end
        end
      end

      first_inventory = first_observable.is_a?(Hash) ? first_observable.dig("durable_journal", "after") : nil
      second_inventory = second_observable.is_a?(Hash) ? second_observable.dig("durable_journal", "after") : nil
      return unless first_inventory.is_a?(Hash) && second_inventory.is_a?(Hash)

      errors << "#{label} replay must not apply API mutations" unless second_inventory["api_mutation_count"] == 0
      errors << "#{label} replay must not append controller events" unless second_inventory["event_count"] == 0
      errors << "#{label} replay must not append provider calls" unless second_inventory["provider_call_count"] == 0
    end

    def validate_idempotency_step_observable(observable, errors, index, run_label)
      label = "reconcile idempotency case #{index} #{run_label} run"
      unless observable.is_a?(Hash)
        errors << "#{label} step observable is required"
        return
      end
      step = observable["step"]
      unless step.is_a?(Hash)
        errors << "#{label} step observable must be an object"
        return
      end
      errors << "#{label} must prove leader execution" unless step["leader_execution"] == true && step["follower"] == false
      errors << "#{label} must reconcile exactly once" unless step["reconciled"] == 1
      errors << "#{label} must report reconcile success" unless step["reconcile_success"] == true
      errors << "#{label} must not report a step error" unless step["step_error_class"].nil?
      errors << "#{label} must not leave a pending retry" unless step["pending_retry"] == false
      errors << "#{label} must not be a follower no-op" unless step["follower_noop"] == false
      errors << "#{label} must identify its expected controller" unless non_empty_string?(step["controller"])
      errors << "#{label} must identify its reconcile key" unless non_empty_string?(step["reconcile_key"])
    end

    def validate_provider_applicability(first_observable, second_observable, errors, index)
      label = "reconcile idempotency case #{index}"
      first = first_observable.is_a?(Hash) ? first_observable["provider_effect_applicability"] : nil
      second = second_observable.is_a?(Hash) ? second_observable["provider_effect_applicability"] : nil
      unless first.is_a?(Hash) && second.is_a?(Hash) && first == second &&
             [true, false].include?(first["applicable"]) && non_empty_string?(first["reason"])
        errors << "#{label} provider side-effect applicability must be explicit and stable"
        return
      end
      first_calls = first_observable.fetch("provider_calls", []) if first_observable.is_a?(Hash)
      second_calls = second_observable.fetch("provider_calls", []) if second_observable.is_a?(Hash)
      if first["applicable"] == true
        errors << "#{label} applicable provider path must record a first-run provider call" unless first_calls.is_a?(Array) && !first_calls.empty?
      elsif first_calls.is_a?(Array) && !first_calls.empty?
        errors << "#{label} inapplicable provider path must not record a provider call"
      end
      errors << "#{label} provider replay must not record a provider call" unless second_calls.is_a?(Array) && second_calls.empty?
    end

    def validate_idempotency_run_snapshot(snapshot, _observable, errors, label, run_number)
      raw_entries = snapshot["raw_entries"]
      unless raw_entries.is_a?(Array)
        errors << "#{label} raw snapshot must contain raw entries for run #{run_number}"
        return nil
      end
      errors << "#{label} raw snapshot contains a non-object entry for run #{run_number}" unless raw_entries.all?(Hash)
      errors << "#{label} raw snapshot entry count is incorrect for run #{run_number}" unless snapshot["raw_entry_count"] == raw_entries.length
      unless valid_digest?(snapshot["raw_sha256"]) && snapshot["raw_sha256"] == canonical_document_digest(raw_entries)
        errors << "#{label} raw snapshot digest is invalid for run #{run_number}"
      end
      inventory = recompute_idempotency_inventory(raw_entries)
      errors << "#{label} raw snapshot inventory was not recomputed for run #{run_number}" unless snapshot["inventory"] == inventory
      %w[effect_ids effect_id_counts effect_signature_counts api_effect_key_counts api_mutation_count event_count provider_call_count
         event_effect_key_counts provider_effect_key_counts event_signatures event_signature_counts
         provider_call_signatures provider_call_signature_counts].each do |key|
        errors << "#{label} raw snapshot #{key} is not recomputed for run #{run_number}" unless snapshot[key] == inventory[key]
      end
      duplicate_effects = inventory.fetch("effect_signature_counts").select { |_signature, count| count > 1 }
      errors << "#{label} duplicate API effects detected in run #{run_number}" unless duplicate_effects.empty?
      duplicate_effect_keys = inventory.fetch("api_effect_key_counts").select { |_key, count| count > 1 }
      unless duplicate_effect_keys.empty?
        errors << "#{label} duplicate semantic API effect keys detected in run #{run_number}: #{duplicate_effect_keys.keys.join(", ")}"
      end
      duplicate_event_keys = inventory.fetch("event_effect_key_counts").select { |_key, count| count > 1 }
      errors << "#{label} duplicate controller events detected in run #{run_number}: #{duplicate_event_keys.keys.join(", ")}" unless duplicate_event_keys.empty?
      duplicate_event_signatures = inventory.fetch("event_signature_counts").select { |_signature, count| count > 1 }
      errors << "#{label} duplicate controller event signatures detected in run #{run_number}" unless duplicate_event_signatures.empty?
      duplicate_provider_keys = inventory.fetch("provider_effect_key_counts").select { |_key, count| count > 1 }
      unless duplicate_provider_keys.empty?
        errors << "#{label} duplicate provider calls detected in run #{run_number}: #{duplicate_provider_keys.keys.join(", ")}"
      end
      duplicate_provider_signatures = inventory.fetch("provider_call_signature_counts").select { |_signature, count| count > 1 }
      errors << "#{label} duplicate provider call signatures detected in run #{run_number}" unless duplicate_provider_signatures.empty?
      missing_effect_ids = raw_entries.select do |entry|
        entry.is_a?(Hash) && entry["kind"] == "api_mutation" && !lease_mutation_entry?(entry) && !non_empty_string?(entry["effect_id"])
      end
      errors << "#{label} semantic API mutations must record effect IDs for run #{run_number}" unless missing_effect_ids.empty?
      inventory
    end

    def recompute_idempotency_inventory(raw_entries)
      entries = raw_entries.grep(Hash)
      mutations = entries.select { |entry| entry["kind"] == "api_mutation" }
      semantic_mutations = mutations.reject { |entry| lease_mutation_entry?(entry) }
      events = entries.select { |entry| entry["kind"] == "controller_event" }
      providers = entries.select { |entry| entry["kind"] == "provider_event" }
      effect_ids = semantic_mutations.filter_map { |entry| entry["effect_id"] }
      effect_signatures = semantic_mutations.map do |entry|
        {"effect_id" => entry["effect_id"], "effect_key" => entry["effect_key"],
         "object_sha256" => entry["object_sha256"], "response_sha256" => entry["response_sha256"]}
      end
      api_effect_key_counts = semantic_mutations.map { |entry| entry["effect_key"].to_s }.tally
      event_signatures = events.map { |entry| {"effect_key" => entry["effect_key"], "event_sha256" => entry["event_sha256"]} }
      provider_signatures = providers.map do |entry|
        {"effect_key" => entry["effect_key"], "provider" => entry["provider"], "operation" => entry["operation"]}
      end
      {
        "api_mutations" => semantic_mutations.group_by { |entry| entry["effect_key"].to_s }.map do |key, grouped|
          {"effect_key" => key, "effect_ids" => grouped.filter_map { |entry| entry["effect_id"] }.sort,
           "actions" => grouped.filter_map { |entry| entry["action"] }.sort,
           "mutation_count" => grouped.length,
           "object_digests" => grouped.filter_map { |entry| entry["object_sha256"] }.sort,
           "response_digests" => grouped.filter_map { |entry| entry["response_sha256"] }.sort}
        end.sort_by { |entry| entry.fetch("effect_key") },
        "events" => event_signatures.sort_by(&:to_s),
        "provider_calls" => provider_signatures.sort_by(&:to_s),
        "effect_ids" => effect_ids.sort,
        "effect_id_counts" => effect_ids.tally,
        "effect_signature_counts" => effect_signatures.map { |signature| canonical_document_digest(signature) }.tally,
        "api_effect_key_counts" => api_effect_key_counts,
        "api_mutation_count" => semantic_mutations.length,
        "event_count" => events.length,
        "provider_call_count" => providers.length,
        "event_effect_key_counts" => events.map { |entry| entry["effect_key"].to_s }.tally,
        "provider_effect_key_counts" => providers.map { |entry| entry["effect_key"].to_s }.tally,
        "event_signatures" => event_signatures.sort_by(&:to_s),
        "event_signature_counts" => event_signatures.map { |signature| canonical_document_digest(signature) }.tally,
        "provider_call_signatures" => provider_signatures.sort_by(&:to_s),
        "provider_call_signature_counts" => provider_signatures.map { |signature| canonical_document_digest(signature) }.tally
      }
    end

    def lease_mutation_entry?(entry)
      entry["kind"] == "api_mutation" &&
        entry["reconcile_key"].to_s.include?("/leases/") &&
        %w[create update].include?(entry["effect_type"].to_s)
    end

    def validate_scheduler(document, errors)
      cases = document["cases"]
      if cases.is_a?(Array) && cases.length == REQUIRED_SCHEDULER_CASES.length
        ids = cases.filter_map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["name"]) : nil }
        errors << "scheduler case identifiers must be unique" unless ids.length == ids.uniq.length
        errors << "scheduler case inventory is incomplete" unless ids.sort == REQUIRED_SCHEDULER_CASES.sort
        cases.each_with_index do |entry, index|
          unless entry.is_a?(Hash)
            errors << "scheduler case #{index} must be an object"
            next
          end
          errors << "scheduler case #{index} did not pass" unless entry["passed"] == true
          errors << "scheduler case #{index} must run once" unless entry["attempt_count"] == 1
          errors << "scheduler case #{index} must record an observable digest" unless valid_digest?(entry["evidence_sha256"])
          unless structured_observable?(entry["actual_observable"]) && structured_observable?(entry["expected_observable"])
            errors << "scheduler case #{index} must include structured local and oracle observables"
          end
          if structured_observable?(entry["actual_observable"]) && valid_digest?(entry["evidence_sha256"]) && canonical_document_digest(entry["actual_observable"]) != entry["evidence_sha256"]
            errors << "scheduler case #{index} observable digest does not match local result"
          end
          next unless structured_observable?(entry["actual_observable"]) && structured_observable?(entry["expected_observable"])

          expected_sha = canonical_document_digest(entry["expected_observable"])
          actual_sha = canonical_document_digest(entry["actual_observable"])
          errors << "scheduler case #{index} passed flag does not match independent observables" unless entry["passed"] == (expected_sha == actual_sha)
        end
      else
        errors << "scheduler cases must cover filter, score, tie_break, preemption, binding, and volume_binding"
      end
      plugins = document["plugins"]
      if plugins.is_a?(Array) && !plugins.empty?
        plugin_ids = plugins.filter_map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["name"]) : nil }
        errors << "scheduler plugin identifiers must be unique" unless plugin_ids.length == plugin_ids.uniq.length
        unless plugin_ids.sort == REQUIRED_SCHEDULER_PLUGIN_NAMES.sort
          errors << "scheduler plugin inventory must match the pinned Kubernetes v1.36.2 default inventory"
        end
        plugins.each_with_index do |plugin, index|
          unless plugin.is_a?(Hash) && plugin["measurement_source"] == "production_module" && plugin["passed"] == true
            errors << "scheduler plugin #{index} must be measured from production module"
          end
          next unless plugin.is_a?(Hash)

          name = (plugin["id"] || plugin["name"]).to_s
          errors << "scheduler plugin #{index} has an unexpected default weight" unless REQUIRED_SCHEDULER_PLUGIN_WEIGHTS[name] == plugin["weight"]
        end
      else
        errors << "scheduler plugin inventory is required"
      end
      oracle = document["oracle"]
      if oracle.is_a?(Hash)
        validate_external_runner(oracle, document, errors, "scheduler oracle")
        errors << "scheduler oracle comparison count must cover every scheduler case" unless oracle["comparison_count"] == REQUIRED_SCHEDULER_CASES.length
        comparisons = oracle["comparisons"]
        if comparisons.is_a?(Array) && comparisons.length == REQUIRED_SCHEDULER_CASES.length
          ids = comparisons.filter_map { |entry| entry.is_a?(Hash) ? entry["id"] : nil }
          unless ids.sort == REQUIRED_SCHEDULER_CASES.sort && ids.uniq.length == REQUIRED_SCHEDULER_CASES.length
            errors << "scheduler oracle comparison identifiers are incomplete"
          end
          comparisons.each_with_index do |comparison, index|
            validate_observable_comparison(comparison, errors, "scheduler oracle comparison #{index}")
          end
        else
          errors << "scheduler oracle comparisons are required for every scheduler case"
        end
      else
        errors << "scheduler oracle differential evidence is incomplete"
      end
      %w[failure_count difference_count filter_mismatch_count score_mismatch_count tie_break_mismatch_count preemption_mismatch_count
         binding_mismatch_count unexpected_skip_count unclassified_count].each do |key|
        errors << "scheduler #{key} must be zero" unless document[key] == 0
      end
    end

    def validate_external_runner(document, owner_document, errors, label)
      runner = document["runner"]
      errors << "#{label} must execute an independent runner" unless document["executed"] == true
      errors << "#{label} version must be #{KUBERNETES_VERSION}" unless document["version"] == KUBERNETES_VERSION
      errors << "#{label} source commit must be #{KUBERNETES_SOURCE_COMMIT}" unless document["source_commit"] == KUBERNETES_SOURCE_COMMIT
      errors << "#{label} runner_sha256 is required" unless valid_digest?(document["runner_sha256"])
      unless runner.is_a?(Hash)
        errors << "#{label} runner provenance is required"
        return
      end
      errors << "#{label} runner provenance digest must match oracle" unless runner["runner_sha256"] == document["runner_sha256"]
      errors << "#{label} runner provenance version is invalid" unless runner["version"] == KUBERNETES_VERSION
      errors << "#{label} runner provenance source commit is invalid" unless runner["source_commit"] == KUBERNETES_SOURCE_COMMIT
      errors << "#{label} runner command must be an argv" unless runner["command"].is_a?(Array) && !runner["command"].empty? && runner["command"].all? do |part|
        non_empty_string?(part)
      end
      errors << "#{label} runner process_id must be positive" unless runner["process_id"].is_a?(Integer) && runner["process_id"].positive?
      errors << "#{label} runner provenance mode must be external" unless runner["mode"] == "external"
      errors << "#{label} runner provenance must not be a self-comparison" unless runner["self_comparison"] == false
      errors << "#{label} runner implementation is required" unless non_empty_string?(runner["implementation"])
      local_runner_sha256 = owner_document.is_a?(Hash) ? owner_document.dig("adapter", "runner_sha256") : nil
      if valid_digest?(local_runner_sha256) && runner["runner_sha256"] == local_runner_sha256
        errors << "#{label} runner_sha256 must differ from the Ruby probe runner"
      end
      errors << "#{label} runner command must not invoke this Ruby probe" if Array(runner["command"]).any? do |part|
        part.to_s.match?(/m3_(?:scheduler|workload)_probe\.rb\z/)
      end
      source = runner["source"]
      unless source.is_a?(Hash) && non_empty_string?(source["root"]) && non_empty_string?(source["repository"]) &&
             source["version"] == KUBERNETES_VERSION && source["tag"] == KUBERNETES_VERSION &&
             source["commit"] == KUBERNETES_SOURCE_COMMIT && source["tree_clean"] == true &&
             source["tree"].is_a?(String) && source["tree"].match?(/\A[0-9a-f]{40}\z/) &&
             valid_digest?(source["source_tree_sha256"]) &&
             valid_digest?(source["source_inventory_sha256"]) && positive_integer?(source["source_inventory_file_count"]) &&
             non_empty_string?(source["runner_source"]) && valid_digest?(source["runner_sha256"]) &&
             source["runner_sha256"] == document["runner_sha256"]
        errors << "#{label} exact Kubernetes source provenance is required"
      end
      image = runner["image"]
      unless image.is_a?(Hash) && image["used"] == false && image["reference"].nil? && image["digest"].nil? && non_empty_string?(image["reason"])
        errors << "#{label} image provenance must explicitly record direct source execution"
      end
      if valid_digest?(runner["provenance_sha256"])
        expected_provenance = canonical_document_digest(runner, excluded_keys: ["provenance_sha256"])
        errors << "#{label} runner provenance digest does not match canonical content" unless expected_provenance == runner["provenance_sha256"]
      else
        errors << "#{label} runner provenance digest is required"
      end
      %w[started_at finished_at].each do |key|
        errors << "#{label} runner #{key} must be ISO-8601" unless iso8601?(runner[key])
      end
      if iso8601?(runner["started_at"]) && iso8601?(runner["finished_at"]) && Time.iso8601(runner["finished_at"]) < Time.iso8601(runner["started_at"])
        errors << "#{label} runner finished before it started"
      end
      input = document["input"]
      output = document["output"]
      if input.is_a?(Hash) && output.is_a?(Hash) && valid_digest?(input["raw_sha256"]) && valid_digest?(input["canonical_sha256"]) &&
         valid_digest?(output["raw_sha256"]) && valid_digest?(output["canonical_sha256"]) &&
         positive_integer?(input["bytes"]) && positive_integer?(output["bytes"]) && input["case_ids"].is_a?(Array)
        # The transported stdin is byte-bound to the reported input payload
        # (validate_external_execution), which makes the raw input bytes the
        # canonical serialisation; raw and canonical input digests therefore
        # legitimately coincide.  The runner's own output is never canonical.
        errors << "#{label} raw and canonical output digests must differ" if output["raw_sha256"] == output["canonical_sha256"]
        all_digests = [document["runner_sha256"], input["raw_sha256"], output["raw_sha256"], output["canonical_sha256"]]
        all_digests << input["canonical_sha256"] unless input["canonical_sha256"] == input["raw_sha256"]
        errors << "#{label} runner/input/raw/canonical digests must remain distinct" unless all_digests.uniq.length == all_digests.length
      else
        errors << "#{label} raw and canonical input/output digests are required"
      end
      validate_external_execution(document, owner_document, source, errors, label)
      validate_pinned_source(source, errors, label)
    end

    def validate_external_execution(document, _owner_document, source, errors, label)
      execution = document["execution"]
      unless execution.is_a?(Hash)
        errors << "#{label} exact external execution transcript is required"
        execution = {}
      end
      expected_runner = if label.include?("scheduler")
                          File.expand_path("m3_kubernetes_scheduler_oracle.rb", __dir__)
                        else
                          File.expand_path("m3_workload_oracle/runner.rb", File.join(PROJECT_ROOT, "test", "conformance", "kubernetes"))
                        end
      expected_argv = [RbConfig.ruby, expected_runner]
      errors << "#{label} execution argv is not the built-in runner" unless execution["argv"] == expected_argv && execution["built_in"] == expected_argv
      errors << "#{label} evidence mode must be enabled" unless execution["evidence_mode"] == true
      errors << "#{label} external execution must exit successfully" unless execution["success"] == true && execution["exit_status"] == 0
      %w[stdin stdout stderr].each do |stream|
        value = execution[stream]
        digest = execution["#{stream}_sha256"]
        unless value.is_a?(String) && valid_digest?(digest) && Digest::SHA256.hexdigest(value) == digest
          errors << "#{label} execution #{stream} transcript is required"
        end
      end
      if execution["stdin"].is_a?(String) && document["input_payload"].is_a?(Hash)
        expected_stdin = JSON.generate(document["input_payload"])
        errors << "#{label} execution stdin is not bound to the reported input payload" unless execution["stdin"] == expected_stdin
      else
        errors << "#{label} input payload is required for execution binding"
      end
      if execution["stdout"].is_a?(String)
        begin
          transcript = JSON.parse(execution["stdout"], max_nesting: 512)
          unless valid_digest?(document["external_document_sha256"]) && canonical_document_digest(transcript) == document["external_document_sha256"]
            errors << "#{label} execution stdout is not bound to the returned oracle document"
          end
        rescue JSON::ParserError
          errors << "#{label} execution stdout is not valid JSON"
        end
      end
      expected_source = if label.include?("scheduler")
                          File.expand_path("m3_scheduler_oracle/main.go", File.join(PROJECT_ROOT, "test", "conformance", "kubernetes"))
                        else
                          File.expand_path("m3_workload_oracle/runner.rb", File.join(PROJECT_ROOT, "test", "conformance", "kubernetes"))
                        end
      return unless source.is_a?(Hash)

      actual_source = source["runner_source"].to_s
      errors << "#{label} runner source path is not the project-owned pinned wrapper" unless File.expand_path(actual_source) == expected_source
      return unless File.file?(expected_source) && valid_digest?(source["runner_sha256"])

      return if Digest::SHA256.file(expected_source).hexdigest == source["runner_sha256"]

      errors << "#{label} runner source digest does not match the checked-in source"
    end

    def validate_pinned_source(source, errors, label)
      return unless source.is_a?(Hash) && non_empty_string?(source["root"])

      root = File.expand_path(source["root"])
      unless File.directory?(root)
        errors << "#{label} pinned source root must be an existing clean Git checkout"
        return
      end
      commit = git_output(root, "rev-parse", "HEAD")
      tag = git_output(root, "describe", "--tags", "--exact-match", "HEAD")
      tree = git_output(root, "rev-parse", "HEAD^{tree}")
      source_inventory = git_output(root, "ls-tree", "-r", "--full-tree", "--name-only", "HEAD")
      status = git_output(root, "status", "--porcelain", "--untracked-files=all")
      errors << "#{label} pinned source commit was not recomputed from the checkout" unless commit == KUBERNETES_SOURCE_COMMIT && source["commit"] == commit
      errors << "#{label} pinned source tag was not recomputed from the checkout" unless tag == KUBERNETES_VERSION && source["tag"] == tag
      errors << "#{label} pinned source tree was not recomputed from the checkout" unless tree == source["tree"]
      errors << "#{label} pinned source tree is dirty" unless status.to_s.empty? && source["tree_clean"] == true
      expected_tree_digest = Digest::SHA256.hexdigest("#{KUBERNETES_SOURCE_COMMIT}\0#{tree}")
      errors << "#{label} pinned source tree digest is not content-bound" unless source["source_tree_sha256"] == expected_tree_digest
      expected_inventory_digest = Digest::SHA256.hexdigest("#{source_inventory}\n")
      expected_inventory_count = source_inventory.lines.reject { |line| line.strip.empty? }.length
      errors << "#{label} pinned source inventory digest was not recomputed" unless source["source_inventory_sha256"] == expected_inventory_digest
      errors << "#{label} pinned source inventory count was not recomputed" unless source["source_inventory_file_count"] == expected_inventory_count
      errors << "#{label} pinned source repository is not the official Kubernetes repository" unless source["repository"] == "https://github.com/kubernetes/kubernetes.git"
    rescue StandardError => error
      errors << "#{label} pinned source verification failed closed: #{error.class}: #{error.message}"
    end

    def git_output(directory, *command)
      stdout, stderr, status = Open3.capture3("git", *command, chdir: directory)
      raise "git #{command.join(" ")} failed: #{stderr.to_s.strip}" unless status.success?

      stdout.strip
    end

    def validate_observable_comparison(comparison, errors, label)
      unless comparison.is_a?(Hash)
        errors << "#{label} must be an object"
        return
      end
      expected = comparison["expected_observable"]
      actual = comparison["actual_observable"]
      errors << "#{label} must include expected and actual observables" if expected.nil? || actual.nil?
      errors << "#{label} observables must contain structured observations" unless structured_observable?(expected) && structured_observable?(actual)
      expected_digest = comparison["expected_sha256"]
      actual_digest = comparison["actual_sha256"]
      errors << "#{label} expected observable digest is invalid" unless valid_digest?(expected_digest)
      errors << "#{label} actual observable digest is invalid" unless valid_digest?(actual_digest)
      if expected.nil? || !valid_digest?(expected_digest) || canonical_document_digest(expected) != expected_digest
        errors << "#{label} expected digest does not match observable"
      end
      if actual.nil? || !valid_digest?(actual_digest) || canonical_document_digest(actual) != actual_digest
        errors << "#{label} actual digest does not match observable"
      end
      unless comparison["passed"] == (valid_digest?(expected_digest) && expected_digest == actual_digest)
        errors << "#{label} passed flag does not match independent observables"
      end
      errors << "#{label} must pass the independent comparison" unless comparison["passed"] == true
    end

    def structured_observable?(value)
      value.is_a?(Hash) || value.is_a?(Array)
    end

    def runtime_observation?(value)
      return false unless value.is_a?(Hash) && !value.empty?

      value.any? do |key, child|
        next false if %w[passed observed ok].include?(key.to_s)

        ![true, false, nil].include?(child)
      end
    end

    def validate_leader(document, errors)
      trace = document["trace"]
      unless trace.is_a?(Array) && !trace.empty?
        errors << "leader-loss trace is required"
        return
      end
      ids = trace.filter_map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["event"]) : nil }
      %w[acquire loss fence recovery].each do |required|
        errors << "leader-loss trace event #{required} is missing" unless ids.include?(required)
      end
      trace.each_with_index do |entry, index|
        errors << "leader-loss trace entry #{index} must pass" unless entry.is_a?(Hash) && entry["passed"] == true && entry["attempt_count"] == 1
      end
      errors << "leader-loss trace must not double-apply side effects" unless document["double_side_effect_count"] == 0
      errors << "leader-loss trace must fence stale leaders" unless document["stale_side_effect_count"] == 0
      errors << "leader-loss trace must resume after quorum recovery" unless document["quorum_recovered"] == true
      unless document["recovery_seconds"].is_a?(Numeric) && document["recovery_seconds"] >= 0 && document["recovery_seconds"] <= 60
        errors << "leader-loss trace recovery must be within 60 seconds"
      end
      validate_process_chaos(document, errors, "leader-loss process chaos", %w[acquire process_kill fence recovery])
      %w[failure_count duplicate_side_effect_count unexpected_skip_count unclassified_count].each do |key|
        errors << "leader-loss #{key} must be zero" unless document[key] == 0
      end
    end

    def validate_process_chaos(document, errors, label, required_events)
      chaos = document["chaos"]
      unless chaos.is_a?(Hash)
        errors << "#{label} evidence must be executed by an external runner"
        return
      end
      if chaos["status"] == "BLOCKED"
        if non_empty_string?(chaos["blocker"])
          errors << chaos["blocker"] unless errors.include?(chaos["blocker"])
        else
          errors << "#{label} blocker must be recorded"
        end
        return
      end
      unless chaos["executed"] == true
        errors << "#{label} evidence must be executed by an external runner"
        return
      end
      runner = chaos["runner"]
      unless runner.is_a?(Hash) && valid_digest?(runner["runner_sha256"]) && runner["command"].is_a?(Array) && !runner["command"].empty? && runner["command"].all? do |part|
        non_empty_string?(part)
      end && runner["process_id"].is_a?(Integer) && runner["process_id"].positive?
        errors << "#{label} runner provenance is incomplete"
      end
      errors << "#{label} runner provenance mode must be external" unless runner.is_a?(Hash) && runner["mode"] == "external"
      errors << "#{label} runner provenance must not be a self-comparison" unless runner.is_a?(Hash) && runner["self_comparison"] == false
      errors << "#{label} runner implementation is required" unless runner.is_a?(Hash) && non_empty_string?(runner["implementation"])
      if runner.is_a?(Hash)
        source = runner["source"]
        expected_source = File.expand_path("../../test/conformance/kubernetes/m3_control_plane_chaos/runner.rb", __dir__)
        unless source.is_a?(Hash) && File.expand_path(source["runner_source"].to_s) == expected_source &&
               valid_digest?(source["runner_sha256"]) && source["runner_sha256"] == runner["runner_sha256"] &&
               File.file?(expected_source) && Digest::SHA256.file(expected_source).hexdigest == source["runner_sha256"]
          errors << "#{label} runner source digest is not bound to the project-owned chaos runner"
        end
      end
      %w[started_at finished_at].each { |key| errors << "#{label} runner #{key} must be ISO-8601" unless iso8601?(runner && runner[key]) }
      errors << "#{label} runner must not be the Ruby probe" if Array(runner && runner["command"]).any? do |part|
        part.to_s.match?(/m3_(?:leader|queue)_probe\.rb\z/)
      end
      local_runner_sha256 = document.dig("adapter", "runner_sha256")
      if valid_digest?(local_runner_sha256) && runner.is_a?(Hash) && runner["runner_sha256"] == local_runner_sha256
        errors << "#{label} runner digest must differ from the local probe"
      end
      if iso8601?(runner && runner["started_at"]) && iso8601?(runner && runner["finished_at"]) && Time.iso8601(runner["finished_at"]) < Time.iso8601(runner["started_at"])
        errors << "#{label} runner finished before it started"
      end
      processes = chaos["processes"] || chaos["process_observations"]
      if processes.is_a?(Array) && !processes.empty?
        processes.each_with_index do |process, index|
          unless process.is_a?(Hash) && process["pid"].is_a?(Integer) && process["pid"].positive? && process["start_time"].is_a?(Integer) && process["start_time"].positive? && non_empty_string?(process["generation"]) && process["generation"].include?(":#{process["pid"]}:") && process["observed_exit"] == true && process["exit_status"].is_a?(Integer)
            errors << "#{label} process observation #{index} must include pid, kernel start time, process generation, and exit status"
          end
          validate_process_provenance(process, errors, "#{label} process observation #{index}") if process.is_a?(Hash)
        end
      else
        errors << "#{label} must include process observations"
      end
      events = chaos["events"]
      ids = Array(events).filter_map { |event| event.is_a?(Hash) ? event["id"] || event["event"] : nil }
      errors << "#{label} event inventory is incomplete" unless events.is_a?(Array) && required_events.all? { |event| ids.include?(event) }
      Array(events).each_with_index do |event, index|
        unless event.is_a?(Hash) && non_empty_string?(event["observed_at"]) && runtime_observation?(event["observation"])
          errors << "#{label} event #{index} must record a structured runtime observation"
        end
      end
      validate_chaos_trace_digests(chaos, errors, label)
      validate_chaos_leases_and_effects(chaos, errors, label)
      validate_chaos_components(chaos, errors, label)
      validate_chaos_effect_journal(chaos, errors, label)
    end

    def validate_process_provenance(process, errors, label)
      namespace = process["namespace"]
      unless namespace.is_a?(Hash) && %w[pid mnt net ipc uts user].all? { |name| non_empty_string?(namespace[name]) }
        errors << "#{label} must record pid/mount/network namespace identities"
      end
      errors << "#{label} role is required" unless non_empty_string?(process["role"])
      errors << "#{label} identity is required" unless non_empty_string?(process["identity"])
      command = process["command"]
      return if command.is_a?(Array) && !command.empty? && command.all? { |part| non_empty_string?(part) }

      errors << "#{label} command provenance is required"
    end

    def validate_chaos_trace_digests(chaos, errors, label)
      raw = chaos["raw_trace_sha256"]
      canonical = chaos["canonical_trace_sha256"]
      errors << "#{label} raw trace digest is required" unless valid_digest?(raw)
      errors << "#{label} canonical trace digest is required" unless valid_digest?(canonical)
      trace = chaos["trace"]
      return unless valid_digest?(canonical) && trace.is_a?(Array)

      errors << "#{label} canonical trace digest does not match trace" unless canonical_document_digest(trace) == canonical
    end

    def validate_chaos_leases_and_effects(chaos, errors, label)
      leases = chaos["lease_observations"]
      if leases.is_a?(Array) && !leases.empty?
        leases.each_with_index do |observation, index|
          next if observation.is_a?(Hash) && non_empty_string?(observation["namespace"]) &&
                  non_empty_string?(observation["name"]) && non_empty_string?(observation["resource_version"]) &&
                  non_empty_string?(observation["observed_at"])

          errors << "#{label} lease observation #{index} must include namespace, name, resourceVersion, and timestamp"
        end
      else
        errors << "#{label} lease observations are required"
      end
      effect_ids = chaos["effect_ids"]
      if effect_ids.is_a?(Array) && !effect_ids.empty? && effect_ids.all? { |value| non_empty_string?(value) }
        errors << "#{label} effect IDs must be unique" unless effect_ids.length == effect_ids.uniq.length
      else
        errors << "#{label} effect IDs are required"
      end
    end

    def validate_chaos_components(chaos, errors, label)
      components = chaos["component_runs"]
      unless components.is_a?(Array) && components.map do |entry|
        entry.is_a?(Hash) ? entry["component"] : nil
      end.sort == %w[controller-manager scheduler]
        errors << "#{label} must record separate controller-manager and scheduler runs"
        return
      end
      components.each_with_index do |component, index|
        errors << "#{label} component #{index} must pass" unless component["passed"] == true
        errors << "#{label} component #{index} must record at least two process identities" unless Array(component["process_identities"]).uniq.length >= 2
        versions = Array(component["lease_resource_versions"])
        errors << "#{label} component #{index} must record lease resourceVersions" if versions.empty? || versions.any? do |value|
          !non_empty_string?(value)
        end
        seconds = component["recovery_seconds"]
        errors << "#{label} component #{index} recovery must be measured within 60 seconds" unless seconds.is_a?(Numeric) && seconds >= 0 && seconds <= 60
        errors << "#{label} component #{index} duplicate side effects must be zero" unless component["duplicate_side_effect_count"] == 0
        recovery = component["recovery_observation"]
        next if recovery.is_a?(Hash) && recovery["restarted_process_alive"] == true && recovery["resource_version_changed"] == true &&
                recovery["renew_time_changed"] == true && recovery["holder_transition"] == true && recovery["generation_changed"] == true &&
                non_empty_string?(recovery["process_generation"]) && non_empty_string?(recovery["resource_version_before"]) &&
                non_empty_string?(recovery["resource_version_after"])

        errors << "#{label} component #{index} recovery must prove live process generation and Lease resourceVersion/renewTime transition"
      end
    end

    def validate_chaos_effect_journal(chaos, errors, label)
      journal = chaos["effect_journal"]
      unless journal.is_a?(Hash)
        errors << "#{label} durable effect journal is required"
        return
      end
      %w[entries inventory api_mutations api_events provider_events].each do |key|
        errors << "#{label} durable effect journal #{key} inventory is required" unless journal[key].is_a?(Array)
      end
      unless integer?(journal["entry_count"]) && journal["entry_count"] == journal["entries"].length
        errors << "#{label} durable effect journal entry count is invalid"
      end
      unless valid_digest?(journal["inventory_sha256"]) && journal["inventory_sha256"] == canonical_document_digest(journal["inventory"])
        errors << "#{label} durable effect journal inventory digest is invalid"
      end
      unless valid_digest?(journal["canonical_sha256"]) && journal["canonical_sha256"] == canonical_document_digest(journal["entries"])
        errors << "#{label} durable effect journal canonical digest is invalid"
      end
      errors << "#{label} durable effect journal raw digest is required" unless valid_digest?(journal["raw_sha256"])
      errors << "#{label} durable effect journal must report zero duplicate semantic effects" unless journal["duplicate_effect_count"] == 0
      journal["api_mutations"].each_with_index do |entry, index|
        unless entry.is_a?(Hash) && non_empty_string?(entry["effect_id"]) && non_empty_string?(entry["effect_key"]) &&
               non_empty_string?(entry["reconcile_key"]) && non_empty_string?(entry["effect_type"]) && entry["mutation"] == true
          errors << "#{label} durable effect journal mutation #{index} is not correlated to a deterministic effect identity"
        end
      end
    end

    def validate_workload(document, errors)
      types = Array(document["workload_types"]).map(&:to_s).sort
      operations = Array(document["operations"]).map(&:to_s).sort
      errors << "workload differential must cover deployment, statefulset, daemonset, job, and cronjob" unless types == REQUIRED_WORKLOAD_TYPES.sort
      errors << "workload differential must cover rollout, rollback, scale, and delete" unless operations == REQUIRED_WORKLOAD_OPERATIONS.sort
      unless document["execution_component"] == "Rubernetes::Bootstrap::ControllerManagerService"
        errors << "workload differential must execute the production ControllerManagerService"
      end
      unless document["independent_case_count"] == REQUIRED_WORKLOAD_TYPES.length * REQUIRED_WORKLOAD_OPERATIONS.length
        errors << "workload differential must execute 20 independent cases"
      end
      errors << "workload differential stream version must be 1" unless document["stream_version"] == 1
      errors << "workload differential deadline must be positive" unless document["deadline_seconds"].is_a?(Numeric) && document["deadline_seconds"] > 0
      errors << "workload differential deadline failure count must be zero" unless document["deadline_failure_count"] == 0
      errors << "workload differential stream mismatch count must be zero" unless document["stream_mismatch_count"] == 0
      cases = document["cases"]
      expected_ids = REQUIRED_WORKLOAD_TYPES.product(REQUIRED_WORKLOAD_OPERATIONS).map { |type, operation| "#{type}:#{operation}" }.sort
      case_streams = document["case_stream_sha256"]
      unless case_streams.is_a?(Hash) && case_streams.keys.map(&:to_s).sort == expected_ids &&
             case_streams.values.all? { |digest| valid_digest?(digest) }
        errors << "workload differential case input stream digest inventory is incomplete"
      end
      errors << "workload differential stream bundle digest is required" unless valid_digest?(document["stream_bundle_sha256"])
      ids = Array(cases).filter_map { |entry| entry.is_a?(Hash) ? entry["id"] : nil }
      errors << "workload differential case inventory is incomplete" unless ids.sort == expected_ids && ids.uniq.length == expected_ids.length
      Array(cases).each_with_index do |entry, index|
        unless entry.is_a?(Hash) && entry["passed"] == true && entry["attempt_count"] == 1 && entry["measurement_source"] == "production_module"
          errors << "workload differential case #{index} must pass once from production module"
        end
        unless entry.is_a?(Hash) && structured_observable?(entry["actual_observable"]) && structured_observable?(entry["expected_observable"])
          errors << "workload differential case #{index} must include structured local and oracle observables"
        end
        next unless entry.is_a?(Hash)

        errors << "workload differential case #{index} must be independent" unless entry["independent"] == true
        unless entry["execution_component"] == "Rubernetes::Bootstrap::ControllerManagerService"
          errors << "workload differential case #{index} must execute through ControllerManagerService"
        end
        errors << "workload differential case #{index} deadline must match the report" unless entry["deadline_seconds"] == document["deadline_seconds"]
        errors << "workload differential case #{index} stream digest is required" unless valid_digest?(entry["stream_sha256"])
        if case_streams.is_a?(Hash) && case_streams[entry["id"].to_s] != entry["stream_sha256"]
          errors << "workload differential case #{index} stream digest is not bound to its input inventory"
        end
        validate_workload_observable(entry["actual_observable"], errors, "workload differential case #{index} actual")
        validate_workload_observable(entry["expected_observable"], errors, "workload differential case #{index} expected")
        validate_observable_comparison(
          entry.merge("expected_sha256" => entry["expected_sha256"],
                      "actual_sha256" => entry["actual_sha256"]), errors, "workload differential case #{index}"
        )
      end
      oracle = document["oracle"]
      if oracle.is_a?(Hash)
        validate_external_runner(oracle, document, errors, "workload oracle")
        errors << "workload oracle comparison count must be 20" unless oracle["comparison_count"] == expected_ids.length
        validate_workload_oracle_provenance(oracle, errors)
        errors << "workload oracle stream bundle digest does not match local input" unless
          oracle.dig("input", "stream_sha256") == document["stream_bundle_sha256"]
        raw_comparisons = oracle["raw_comparisons"]
        if raw_comparisons.is_a?(Array) && raw_comparisons.length == expected_ids.length
          raw_ids = raw_comparisons.filter_map { |entry| entry.is_a?(Hash) ? entry["id"] : nil }
          unless raw_ids.sort == expected_ids && raw_ids.uniq.length == expected_ids.length
            errors << "workload oracle raw comparison identifiers are incomplete"
          end
          raw_comparisons.each_with_index do |comparison, index|
            unless comparison.is_a?(Hash) && structured_observable?(comparison["expected_observable"]) &&
                   valid_digest?(comparison["expected_sha256"]) && comparison["passed"] == true &&
                   valid_digest?(comparison["stream_sha256"])
              errors << "workload oracle raw comparison #{index} is not a structured passing observation"
            end
            if comparison.is_a?(Hash) && case_streams.is_a?(Hash) &&
               case_streams[comparison["id"].to_s] != comparison["stream_sha256"]
              errors << "workload oracle raw comparison #{index} stream digest is not bound to the local input"
            end
          end
        else
          errors << "workload oracle raw comparisons must cover all 20 workload operations"
        end
        comparisons = oracle["comparisons"]
        if comparisons.is_a?(Array) && comparisons.length == expected_ids.length
          comparison_ids = comparisons.filter_map { |entry| entry.is_a?(Hash) ? entry["id"] : nil }
          unless comparison_ids.sort == expected_ids && comparison_ids.uniq.length == expected_ids.length
            errors << "workload oracle comparison identifiers are incomplete"
          end
          comparisons.each_with_index do |comparison, index|
            validate_observable_comparison(comparison, errors, "workload oracle comparison #{index}")
            if comparison.is_a?(Hash) && case_streams.is_a?(Hash) &&
               case_streams[comparison["id"].to_s] != comparison["stream_sha256"]
              errors << "workload oracle comparison #{index} stream digest is not bound to the local input"
            end
          end
        else
          errors << "workload oracle comparisons must cover all 20 workload operations"
        end
      else
        errors << "workload differential oracle evidence is incomplete"
      end
      return if document["difference_count"] == 0 && document["workload_mismatch_count"] == 0

      errors << "workload differential mismatch count must be zero"
    end

    def validate_workload_observable(observable, errors, label)
      unless observable.is_a?(Hash)
        errors << "#{label} must be an object"
        return
      end
      %w[resource owned_resources status conditions events request_trace deadline].each do |key|
        errors << "#{label} must include #{key}" unless observable.key?(key)
      end
      deadline = observable["deadline"]
      unless deadline.is_a?(Hash) && deadline["met"] == true && deadline["seconds"].is_a?(Numeric) && deadline["seconds"] > 0
        errors << "#{label} deadline must be met"
      end
      errors << "#{label} request trace must be structured" unless observable["request_trace"].is_a?(Array)
    end

    def validate_workload_oracle_provenance(oracle, errors)
      input = oracle["input"]
      output = oracle["output"]
      unless input.is_a?(Hash) && valid_digest?(input["raw_sha256"]) && valid_digest?(input["canonical_sha256"]) && input["bytes"].is_a?(Integer) && input["bytes"] > 0
        errors << "workload oracle input raw and canonical digests are required"
      end
      case_streams = input.is_a?(Hash) ? input["case_stream_sha256"] : nil
      unless case_streams.is_a?(Hash) && case_streams.keys.map(&:to_s).sort == REQUIRED_WORKLOAD_TYPES.product(REQUIRED_WORKLOAD_OPERATIONS).map { |type, operation|
        "#{type}:#{operation}"
      }.sort &&
             case_streams.values.all? { |digest| valid_digest?(digest) }
        errors << "workload oracle input case stream digest binding is incomplete"
      end
      unless output.is_a?(Hash) && valid_digest?(output["raw_sha256"]) && valid_digest?(output["canonical_sha256"]) && output["bytes"].is_a?(Integer) && output["bytes"] > 0
        errors << "workload oracle output raw and canonical digests are required"
      end
      raw_comparisons = oracle["raw_comparisons"] || oracle["comparisons"]
      if output.is_a?(Hash) && valid_digest?(output["comparisons_sha256"])
        comparisons_digest = canonical_document_digest(raw_comparisons)
        errors << "workload oracle output comparisons digest does not match comparisons" unless comparisons_digest == output["comparisons_sha256"]
      else
        errors << "workload oracle output comparisons digest is required"
      end
      runner = oracle["runner"]
      source = runner.is_a?(Hash) ? runner["source"] : nil
      build = runner.is_a?(Hash) ? runner["build"] : nil
      image = runner.is_a?(Hash) ? runner["image"] : nil
      unless source.is_a?(Hash) && source["version"] == KUBERNETES_VERSION && source["tag"] == KUBERNETES_VERSION && source["commit"] == KUBERNETES_SOURCE_COMMIT && source["tree_clean"] == true && valid_digest?(source["source_tree_sha256"])
        errors << "workload oracle pinned source provenance is incomplete"
      end
      unless build.is_a?(Hash) && build["source_build"] == true && valid_digest?(build["binary_sha256"])
        errors << "workload oracle controller-manager source build provenance is incomplete"
      end
      unless image.is_a?(Hash) && non_empty_string?(image["kube_apiserver"]) && non_empty_string?(image["etcd"]) && image["network_isolated"] == true && image.dig(
        "controller_manager", "used"
      ) == false
        errors << "workload oracle image provenance is incomplete"
      end
      controller_process = runner.is_a?(Hash) ? runner.dig("cluster", "controller_manager") : nil
      unless controller_process.is_a?(Hash) && controller_process["pid"].is_a?(Integer) && controller_process["pid"] > 0 && controller_process["command"].is_a?(Array) && !controller_process["command"].empty? && valid_digest?(controller_process["binary_sha256"])
        errors << "workload oracle controller-manager process provenance is incomplete"
      end
    end

    def validate_queue(document, errors)
      properties = document["properties"]
      unless properties.is_a?(Array) && properties.length == REQUIRED_QUEUE_PROPERTIES.length
        errors << "queue/informer properties must cover duplicate, ordering, reconnect, and resync"
        return
      end
      ids = properties.filter_map { |entry| entry.is_a?(Hash) ? (entry["id"] || entry["property"]) : nil }
      errors << "queue/informer property identifiers must be unique" unless ids.length == ids.uniq.length
      errors << "queue/informer property inventory is incomplete" unless ids.sort == REQUIRED_QUEUE_PROPERTIES.sort
      properties.each_with_index do |entry, index|
        errors << "queue/informer property #{index} must pass once" unless entry.is_a?(Hash) && entry["passed"] == true && entry["attempt_count"] == 1
        unless entry.is_a?(Hash) && entry["measurement_source"] == "production_module"
          errors << "queue/informer property #{index} must record production module"
        end
      end
      validate_process_chaos(document, errors, "queue/informer process chaos",
                             %w[process_kill duplicate_suppression out_of_order_delivery watch_reconnect resync])
      %w[failure_count duplicate_loss_count out_of_order_count reconnect_loss_count resync_loss_count unexpected_skip_count
         unclassified_count].each do |key|
        errors << "queue/informer #{key} must be zero" unless document[key] == 0
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
        "reports" => REPORTS.length,
        "source_files" => manifest["input_file_count"]
      }
      expected.each do |key, value|
        errors << "result_counts #{key} is missing or invalid" unless integer?(counts[key])
        errors << "result_counts #{key} is incorrect" if integer?(counts[key]) && counts[key] != value
      end
    end

    def validate_manifest_status(manifest, errors)
      errors << "manifest status must be INCOMPLETE when any M3 gate requirement fails" if errors.any? && manifest["status"] == "COMPLETE"
    end

    def canonical_value(value, excluded_keys = [])
      excluded = excluded_keys.map(&:to_s)
      case value
      when Hash
        value.keys.map(&:to_s).reject { |key| excluded.include?(key) }.sort.each_with_object({}) do |key, result|
          source_key = value.keys.find { |candidate| candidate.to_s == key }
          result[key] = canonical_value(value.fetch(source_key), [])
        end
      when Array then value.map { |child| canonical_value(child, []) }
      else value
      end
    end

    def project_git_metadata_paths_for_inventory
      Dir.glob(File.join(PROJECT_ROOT, "**/*"), File::FNM_DOTMATCH).filter_map do |path|
        relative = path.delete_prefix("#{PROJECT_ROOT}/")
        relative if relative.split("/").include?(".git")
      end
    end

    def identity?(value)
      value.is_a?(Hash) && valid_digest?(value["sha256"]) && positive_integer?(value["file_count"])
    end

    def valid_digest?(value)
      value.is_a?(String) && value.match?(SHA256_PATTERN)
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
  manifest_path = ARGV.fetch(0) { abort "Usage: m3_gate.rb PATH/manifest.json" }
  output = M3Gate.evaluate(manifest_path)
  puts(JSON.pretty_generate(output))
  exit(output.fetch("passed") ? 0 : 1)
end
