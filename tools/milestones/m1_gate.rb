#!/usr/bin/env ruby
# frozen_string_literal: true

# Validate the content-addressed evidence bundle for Milestone M1.
#
# This gate deliberately knows only the machine-readable evidence contract. The
# schema compiler, API server, and kubectl adapters are supplied by the evidence
# runner, which keeps this command deterministic and independent of Git metadata.

require "digest"
require "json"
require "open3"
require "rbconfig"
require "time"

require_relative "m1_probe_support"

module M1Gate
  MANIFEST_SCHEMA_VERSION = 3
  REPORT_SCHEMA_VERSION = 1
  MAX_JSON_BYTES = 32 * 1024 * 1024
  SHA256_PATTERN = /\A[0-9a-f]{64}\z/
  # The transcript exercises the typed (protobuf) client paths kubectl uses
  # for create/scale/expose, strict client-side validation over the served
  # OpenAPI v2 protobuf document, and the JSON CRUD/watch paths.
  REQUIRED_OPERATIONS = %w[get create-namespace create-deployment scale expose apply apply-invalid patch label delete watch].freeze
  REQUIRED_VALIDATION_OPERATIONS = %w[create invalid update missing].freeze
  REQUIRED_API_OPERATIONS = %w[
    create-defaulting
    get
    list
    duplicate-create-status
    validation-status
    initial-watch-validation-status
    apply-create
    apply-conflict-status
    apply-force
    merge-patch
    initial-watch
    watch
    delete
    not-found-status
    tokenreview-create
    tokenreview-missing-token
    selfsubjectreview-create
    selfsubjectrulesreview-create
    selfsubjectrulesreview-missing-namespace
    eviction-invalid-delete-options
    eviction-create
    componentstatus-list
    componentstatus-get
  ].freeze
  API_REVIEW_TOKEN = "m1-review-token-6f1c0d2a"
  API_TOKEN_REVIEW_PATH = "/apis/authentication.k8s.io/v1/tokenreviews"
  API_SELF_SUBJECT_REVIEW_PATH = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
  API_SELF_SUBJECT_RULES_REVIEW_PATH = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"
  API_USER_AGENT = "rubernetes-m1-oracle-probe/1"
  API_NAMESPACE = "m1-oracle"
  API_COLLECTION_PATH = "/api/v1/namespaces/#{API_NAMESPACE}/configmaps".freeze
  API_APPLY_PATH = "#{API_COLLECTION_PATH}/m1-applied".freeze
  REQUIRED_API_OPERATION_INVENTORY = [
    ["create-defaulting", "POST", API_COLLECTION_PATH,
     {}, {}, {"metadata" => {"name" => "m1-created"}}],
    ["get", "GET", "#{API_COLLECTION_PATH}/m1-created", {}, {}, nil],
    ["list", "GET", API_COLLECTION_PATH, {}, {}, nil],
    ["duplicate-create-status", "POST", API_COLLECTION_PATH,
     {}, {}, {"metadata" => {"name" => "m1-created"}}],
    ["validation-status", "POST", API_COLLECTION_PATH, {}, {},
     {"apiVersion" => "v1", "kind" => "ConfigMap", "data" => {"key" => "value"}}],
    ["initial-watch-validation-status", "GET", "#{API_COLLECTION_PATH}?watch=true&sendInitialEvents=true",
     {"watch" => "true", "sendInitialEvents" => "true"}, {}, nil],
    ["apply-create", "PATCH", "#{API_APPLY_PATH}?fieldManager=manager-one",
     {"fieldManager" => "manager-one"}, {"content-type" => "application/apply-patch+yaml"},
     {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "m1-applied"}, "data" => {"owned" => "one"}}],
    ["apply-conflict-status", "PATCH", "#{API_APPLY_PATH}?fieldManager=manager-two",
     {"fieldManager" => "manager-two"}, {"content-type" => "application/apply-patch+yaml"},
     {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "m1-applied"}, "data" => {"owned" => "two"}}],
    ["apply-force", "PATCH", "#{API_APPLY_PATH}?fieldManager=manager-two&force=true",
     {"fieldManager" => "manager-two", "force" => "true"}, {"content-type" => "application/apply-patch+yaml"},
     {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "m1-applied"}, "data" => {"owned" => "two"}}],
    ["merge-patch", "PATCH", API_APPLY_PATH, {}, {"content-type" => "application/merge-patch+json"},
     {"data" => {"watch" => "ready"}}],
    ["initial-watch", "GET",
     "#{API_COLLECTION_PATH}?watch=true&sendInitialEvents=true&allowWatchBookmarks=true&resourceVersionMatch=NotOlderThan&resourceVersion=0&timeoutSeconds=1",
     {"watch" => "true", "sendInitialEvents" => "true", "allowWatchBookmarks" => "true",
      "resourceVersionMatch" => "NotOlderThan", "resourceVersion" => "0", "timeoutSeconds" => "1"}, {}, nil],
    ["watch", "GET", "#{API_COLLECTION_PATH}?watch=true&resourceVersion=<per-target>&timeoutSeconds=1",
     {"watch" => "true", "resourceVersion" => "<per-target>", "timeoutSeconds" => "1"}, {}, nil],
    ["delete", "DELETE", "#{API_COLLECTION_PATH}/m1-created", {}, {}, nil],
    ["not-found-status", "GET", "#{API_COLLECTION_PATH}/m1-created", {}, {}, nil],
    ["tokenreview-create", "POST", API_TOKEN_REVIEW_PATH, {}, {},
     {"apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenReview", "spec" => {"token" => API_REVIEW_TOKEN}}],
    ["tokenreview-missing-token", "POST", API_TOKEN_REVIEW_PATH, {}, {},
     {"apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenReview", "spec" => {}}],
    ["selfsubjectreview-create", "POST", API_SELF_SUBJECT_REVIEW_PATH, {}, {},
     {"apiVersion" => "authentication.k8s.io/v1", "kind" => "SelfSubjectReview"}],
    ["selfsubjectrulesreview-create", "POST", API_SELF_SUBJECT_RULES_REVIEW_PATH, {}, {},
     {"apiVersion" => "authorization.k8s.io/v1", "kind" => "SelfSubjectRulesReview", "spec" => {"namespace" => API_NAMESPACE}}],
    ["selfsubjectrulesreview-missing-namespace", "POST", API_SELF_SUBJECT_RULES_REVIEW_PATH, {}, {},
     {"apiVersion" => "authorization.k8s.io/v1", "kind" => "SelfSubjectRulesReview", "spec" => {}}],
    ["eviction-invalid-delete-options", "POST", "/api/v1/namespaces/#{API_NAMESPACE}/pods/m1-evict/eviction", {}, {},
     {"apiVersion" => "policy/v1", "kind" => "Eviction", "metadata" => {"name" => "m1-evict", "namespace" => API_NAMESPACE},
      "deleteOptions" => {"propagationPolicy" => "Invalid"}}],
    ["eviction-create", "POST", "/api/v1/namespaces/#{API_NAMESPACE}/pods/m1-evict/eviction", {}, {},
     {"apiVersion" => "policy/v1", "kind" => "Eviction", "metadata" => {"name" => "m1-evict", "namespace" => API_NAMESPACE}}],
    ["componentstatus-list", "GET", "/api/v1/componentstatuses", {}, {}, nil],
    ["componentstatus-get", "GET", "/api/v1/componentstatuses/etcd-0", {}, {}, nil]
  ].map do |id, method, report_path, query, headers, body|
    {
      "id" => id,
      "method" => method,
      "path" => report_path,
      "request" => {
        "method" => method,
        "path" => report_path.split("?", 2).first,
        "query" => query,
        "headers" => {"user-agent" => API_USER_AGENT}.merge(headers),
        "body" => body
      }
    }
  end.freeze
  API_SURFACE_GVK_COUNT = 321
  API_SURFACE_GVR_COUNT = 153
  API_SURFACE_ENDPOINT_COUNT = 60
  API_SURFACE_FIELDS = %w[
    group version resource kind scope plural singular verbs subresources
    shortNames categories listKind schema_contract_present
  ].freeze
  DEFAULT_PROFILE = "kubernetes-v1.36.2-default"
  DEFAULT_OFF_GVR_IDS = %w[
    admissionregistration.k8s.io/v1alpha1/mutatingadmissionpolicies
    admissionregistration.k8s.io/v1alpha1/mutatingadmissionpolicybindings
    admissionregistration.k8s.io/v1beta1/mutatingadmissionpolicies
    admissionregistration.k8s.io/v1beta1/mutatingadmissionpolicybindings
    certificates.k8s.io/v1alpha1/clustertrustbundles
    certificates.k8s.io/v1beta1/clustertrustbundles
    certificates.k8s.io/v1beta1/podcertificaterequests
    certificates.k8s.io/v1beta1/podcertificaterequests/status
    coordination.k8s.io/v1alpha2/leasecandidates
    coordination.k8s.io/v1beta1/leasecandidates
    internal.apiserver.k8s.io/v1alpha1/storageversions
    internal.apiserver.k8s.io/v1alpha1/storageversions/status
    networking.k8s.io/v1beta1/ipaddresses
    networking.k8s.io/v1beta1/servicecidrs
    networking.k8s.io/v1beta1/servicecidrs/status
    resource.k8s.io/v1alpha3/devicetaintrules
    resource.k8s.io/v1alpha3/devicetaintrules/status
    resource.k8s.io/v1alpha3/resourcepoolstatusrequests
    resource.k8s.io/v1alpha3/resourcepoolstatusrequests/status
    resource.k8s.io/v1beta1/deviceclasses
    resource.k8s.io/v1beta1/resourceclaims
    resource.k8s.io/v1beta1/resourceclaims/status
    resource.k8s.io/v1beta1/resourceclaimtemplates
    resource.k8s.io/v1beta1/resourceslices
    resource.k8s.io/v1beta2/deviceclasses
    resource.k8s.io/v1beta2/devicetaintrules
    resource.k8s.io/v1beta2/devicetaintrules/status
    resource.k8s.io/v1beta2/resourceclaims
    resource.k8s.io/v1beta2/resourceclaims/status
    resource.k8s.io/v1beta2/resourceclaimtemplates
    resource.k8s.io/v1beta2/resourceslices
    scheduling.k8s.io/v1alpha2/podgroups
    scheduling.k8s.io/v1alpha2/podgroups/status
    scheduling.k8s.io/v1alpha2/workloads
    storage.k8s.io/v1beta1/volumeattributesclasses
    storagemigration.k8s.io/v1beta1/storageversionmigrations
    storagemigration.k8s.io/v1beta1/storageversionmigrations/status
  ].freeze
  DEFAULT_OFF_GVK_IDS = %w[
    admissionregistration.k8s.io/v1alpha1/MutatingAdmissionPolicy
    admissionregistration.k8s.io/v1alpha1/MutatingAdmissionPolicyBinding
    admissionregistration.k8s.io/v1alpha1/MutatingAdmissionPolicyBindingList
    admissionregistration.k8s.io/v1alpha1/MutatingAdmissionPolicyList
    admissionregistration.k8s.io/v1beta1/MutatingAdmissionPolicy
    admissionregistration.k8s.io/v1beta1/MutatingAdmissionPolicyBinding
    admissionregistration.k8s.io/v1beta1/MutatingAdmissionPolicyBindingList
    admissionregistration.k8s.io/v1beta1/MutatingAdmissionPolicyList
    certificates.k8s.io/v1alpha1/ClusterTrustBundle
    certificates.k8s.io/v1alpha1/ClusterTrustBundleList
    certificates.k8s.io/v1beta1/ClusterTrustBundle
    certificates.k8s.io/v1beta1/ClusterTrustBundleList
    certificates.k8s.io/v1beta1/PodCertificateRequest
    certificates.k8s.io/v1beta1/PodCertificateRequestList
    coordination.k8s.io/v1alpha2/LeaseCandidate
    coordination.k8s.io/v1alpha2/LeaseCandidateList
    coordination.k8s.io/v1beta1/LeaseCandidate
    coordination.k8s.io/v1beta1/LeaseCandidateList
    internal.apiserver.k8s.io/v1alpha1/StorageVersion
    internal.apiserver.k8s.io/v1alpha1/StorageVersionList
    networking.k8s.io/v1beta1/IPAddress
    networking.k8s.io/v1beta1/IPAddressList
    networking.k8s.io/v1beta1/ServiceCIDR
    networking.k8s.io/v1beta1/ServiceCIDRList
    resource.k8s.io/v1alpha3/DeviceTaintRule
    resource.k8s.io/v1alpha3/DeviceTaintRuleList
    resource.k8s.io/v1alpha3/ResourcePoolStatusRequest
    resource.k8s.io/v1alpha3/ResourcePoolStatusRequestList
    resource.k8s.io/v1beta1/DeviceClass
    resource.k8s.io/v1beta1/DeviceClassList
    resource.k8s.io/v1beta1/ResourceClaim
    resource.k8s.io/v1beta1/ResourceClaimList
    resource.k8s.io/v1beta1/ResourceClaimTemplate
    resource.k8s.io/v1beta1/ResourceClaimTemplateList
    resource.k8s.io/v1beta1/ResourceSlice
    resource.k8s.io/v1beta1/ResourceSliceList
    resource.k8s.io/v1beta2/DeviceClass
    resource.k8s.io/v1beta2/DeviceClassList
    resource.k8s.io/v1beta2/DeviceTaintRule
    resource.k8s.io/v1beta2/DeviceTaintRuleList
    resource.k8s.io/v1beta2/ResourceClaim
    resource.k8s.io/v1beta2/ResourceClaimList
    resource.k8s.io/v1beta2/ResourceClaimTemplate
    resource.k8s.io/v1beta2/ResourceClaimTemplateList
    resource.k8s.io/v1beta2/ResourceSlice
    resource.k8s.io/v1beta2/ResourceSliceList
    scheduling.k8s.io/v1alpha2/PodGroup
    scheduling.k8s.io/v1alpha2/PodGroupList
    scheduling.k8s.io/v1alpha2/Workload
    scheduling.k8s.io/v1alpha2/WorkloadList
    storage.k8s.io/v1beta1/VolumeAttributesClass
    storage.k8s.io/v1beta1/VolumeAttributesClassList
    storagemigration.k8s.io/v1beta1/StorageVersionMigration
    storagemigration.k8s.io/v1beta1/StorageVersionMigrationList
  ].freeze
  DEFAULT_OFF_DISCOVERY_PATHS = %w[
    /apis/admissionregistration.k8s.io/v1alpha1
    /apis/admissionregistration.k8s.io/v1beta1
    /apis/certificates.k8s.io/v1alpha1
    /apis/certificates.k8s.io/v1beta1
    /apis/coordination.k8s.io/v1alpha2
    /apis/coordination.k8s.io/v1beta1
    /apis/internal.apiserver.k8s.io
    /apis/internal.apiserver.k8s.io/v1alpha1
    /apis/networking.k8s.io/v1beta1
    /apis/resource.k8s.io/v1alpha3
    /apis/resource.k8s.io/v1beta1
    /apis/resource.k8s.io/v1beta2
    /apis/scheduling.k8s.io/v1alpha2
    /apis/storage.k8s.io/v1beta1
    /apis/storagemigration.k8s.io
    /apis/storagemigration.k8s.io/v1beta1
  ].freeze
  DEFAULT_OFF_REASON = "the pinned Kubernetes v1.36.2 default API profile does not serve this compiled API version"
  DISCOVERY_NOT_FOUND_BODY = "404 page not found\n"
  ROUTER_NOT_FOUND_DISCOVERY_PATHS = %w[
    /apis/internal.apiserver.k8s.io
    /apis/internal.apiserver.k8s.io/v1alpha1
    /apis/storagemigration.k8s.io
    /apis/storagemigration.k8s.io/v1beta1
  ].freeze
  DISCOVERY_STATUS_NOT_FOUND_BODY = {
    "kind" => "Status", "apiVersion" => "v1", "metadata" => {},
    "status" => "Failure", "message" => "the server could not find the requested resource",
    "reason" => "NotFound", "details" => {}, "code" => 404
  }.freeze
  HEADER_EXCLUSION_ALLOWLIST = {
    "audit-id" => {
      "class" => "dynamic",
      "reason" => "kube-apiserver generates a fresh audit identifier per request"
    },
    "connection" => {
      "class" => "hop-by-hop",
      "reason" => "HTTP/1.1 connection control is transport-specific"
    },
    "content-length" => {
      "class" => "dynamic",
      "reason" => "serialized response length differs between transports"
    },
    "date" => {
      "class" => "dynamic",
      "reason" => "HTTP date is generated at response time"
    },
    "keep-alive" => {
      "class" => "hop-by-hop",
      "reason" => "HTTP/1.1 connection persistence is transport-specific"
    },
    "x-kubernetes-pf-flowschema-uid" => {
      "class" => "dynamic",
      "reason" => "kube-apiserver priority-and-fairness assigns a run-local flow-schema UID"
    },
    "x-kubernetes-pf-prioritylevel-uid" => {
      "class" => "dynamic",
      "reason" => "kube-apiserver priority-and-fairness assigns a run-local priority-level UID"
    },
    "proxy-authenticate" => {
      "class" => "hop-by-hop",
      "reason" => "proxy authentication challenge is not API semantics"
    },
    "proxy-authorization" => {
      "class" => "hop-by-hop",
      "reason" => "proxy authorization is not API semantics"
    },
    "te" => {
      "class" => "hop-by-hop",
      "reason" => "transfer codings are transport-specific"
    },
    "trailer" => {
      "class" => "hop-by-hop",
      "reason" => "HTTP trailer declaration is transport-specific"
    },
    "transfer-encoding" => {
      "class" => "hop-by-hop",
      "reason" => "transfer coding is transport-specific"
    },
    "upgrade" => {
      "class" => "hop-by-hop",
      "reason" => "protocol upgrade is transport-specific"
    }
  }.freeze
  SOURCE_EXCLUDED_ROOTS = %w[.git artifacts build pkg tmp .bundle].freeze
  SOURCE_EXCLUDED_PATTERNS = [%r{\Aa11-generated\.[A-Za-z0-9]{6,}/}, %r{\Aapps/[^/]+/(?:log|tmp|storage)/}].freeze
  KUBERNETES_VERSION = "v1.36.2"
  KUBERNETES_SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"
  KUBE_APISERVER_IMAGE = "registry.k8s.io/kube-apiserver@sha256:0535dde1a857029209d7effe681c919a1580d2eb24eda4bd122d24e9a372e1b8"
  ETCD_IMAGE = "registry.k8s.io/etcd@sha256:397189418d1a00e500c0605ad18d1baf3b541a1004d768448c367e48071622e5"
  KUBERNETES_PROTOBUF_ORACLE_KIND = "kubernetes_generated_protobuf"
  KUBERNETES_API_ORACLE_KIND = "kubernetes_apiserver"
  KUBERNETES_SEMANTICS_ORACLE_KIND = "kubernetes_api_semantics"
  M0_GATE = File.join(__dir__, "m0_gate.rb").freeze
  PROJECT_ROOT = File.expand_path("../..", __dir__).freeze

  class DuplicateJSONKeyError < StandardError; end

  class StrictHash < Hash
    def []=(key, value)
      raise DuplicateJSONKeyError, "duplicate JSON object key #{key.inspect}" if key?(key)

      super
    end
  end

  REPORTS = {
    "corpus" => {
      kind: "m1_corpus_coverage",
      names: %w[corpus-coverage.json corpus_coverage.json]
    },
    "generation" => {
      kind: "m1_generation_diff",
      names: %w[generation-diff.json generation_diff.json]
    },
    "roundtrip" => {
      kind: "m1_roundtrip_report",
      names: %w[roundtrip-report.json roundtrip_report.json roundtrip.json gvk-roundtrip.json gvk-roundtrip-report.json]
    },
    "api" => {
      kind: "m1_api_differential",
      names: %w[api-differential.json api_differential.json api-differential-result.json api-test-result.json api_test_result.json
                api-result.json]
    },
    "kubectl" => {
      kind: "m1_kubectl_transcript",
      names: %w[kubectl-transcript.json kubectl_transcript.json kubectl.json kubectl-result.json]
    }
  }.freeze

  INVENTORY_NAMES = %w[
    source-inventory.json
    source_inventory.json
    canonical-source-inventory.json
    canonical_source_inventory.json
    canonical-inventory.json
  ].freeze

  class << self
    def evaluate(manifest_path)
      manifest_path = File.expand_path(manifest_path)
      directory = File.dirname(manifest_path)
      @evidence_directory = directory
      @api_differential_operations = nil
      errors = []
      manifest = parse_json(manifest_path, errors, "manifest")
      return result(errors) unless manifest.is_a?(Hash)

      validate_manifest_shape(manifest, errors)
      artifacts = validate_entries(manifest.fetch("artifacts", []), directory, errors, "artifact")
      subjects = validate_entries(manifest.fetch("subjects", []), directory, errors, "subject")
      artifact_index = index_artifacts(artifacts, errors)

      validate_inventory(manifest, directory, artifact_index, errors)
      validate_prior_m0(manifest, directory, artifacts, errors)
      REPORTS.each do |name, specification|
        document = report_document(name, specification, directory, artifact_index, errors)
        validate_report(name, document, specification[:kind], manifest, errors) if document
      end

      validate_result_counts(manifest, artifacts, subjects, errors)
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

    # Digest machine-readable evidence after recursively sorting object keys.
    # Producers use this for nested oracle provenance so equivalent JSON
    # serialization orders cannot alter the attestation.
    def canonical_document_digest(document, excluded_keys: [])
      value = canonical_value(document, excluded_keys.map(&:to_s))
      Digest::SHA256.hexdigest(JSON.generate(value))
    end

    private

    def result(errors)
      {
        "schema_version" => 1,
        "milestone" => "M1",
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

      JSON.parse(File.binread(path), object_class: StrictHash, max_nesting: 100)
    rescue Errno::ENOENT
      errors << "#{label} is missing"
      nil
    rescue JSON::ParserError, DuplicateJSONKeyError => error
      errors << "#{label} is not valid JSON: #{error.message}"
      nil
    end

    def validate_manifest_shape(manifest, errors)
      errors << "schema_version must be #{MANIFEST_SCHEMA_VERSION}" unless manifest["schema_version"] == MANIFEST_SCHEMA_VERSION
      errors << "milestone must be M1" unless manifest["milestone"] == "M1"
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

      validate_capture(manifest, errors)
      validate_git_metadata_capture(manifest, errors)
      validate_commands(manifest["commands"], errors)

      errors << "artifacts must be an array" unless manifest["artifacts"].is_a?(Array)
      errors << "subjects must be an array" unless manifest["subjects"].is_a?(Array)
      errors << "result_counts must be an object" unless manifest["result_counts"].is_a?(Hash)
    end

    def validate_capture(manifest, errors)
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

      start_paths = capture["start_paths"]
      finish_paths = capture["finish_paths"]
      unless start_paths.is_a?(Array) && finish_paths.is_a?(Array) &&
             start_paths.all? { |path| non_empty_string?(path) } &&
             finish_paths.all? { |path| non_empty_string?(path) }
        errors << "git_metadata_capture paths must be arrays of paths"
        return
      end
      errors << "git metadata changed during evidence capture" unless capture["stable"] == true && start_paths == finish_paths
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

      names = []
      commands.each_with_index do |command, index|
        unless command.is_a?(Hash)
          errors << "command #{index} must be an object"
          next
        end
        errors << "command #{index} has no name" unless non_empty_string?(command["name"])
        if non_empty_string?(command["name"])
          errors << "duplicate command name #{command["name"]}" if names.include?(command["name"])
          names << command["name"]
        end
        command_value = command["command"]
        errors << "command #{index} must record its argv" unless (command_value.is_a?(Array) && !command_value.empty?) || non_empty_string?(command_value)
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

      seen_paths = {}
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
        if seen_paths.key?(path_value)
          errors << "duplicate #{label} path #{path_value}"
        else
          seen_paths[path_value] = true
        end

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
        resolved_path = File.realpath(path)
        errors << "#{label} digest mismatch #{path_value}" if valid_digest?(entry["sha256"]) && Digest::SHA256.file(resolved_path).hexdigest != entry["sha256"]
        errors << "#{label} byte count mismatch #{path_value}" if integer?(entry["bytes"]) && File.size(resolved_path) != entry["bytes"]
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
        # Required M1 reports live at the bundle root. Nested prior-milestone
        # evidence may legitimately contain the same basename in artifacts and
        # subjects, and is addressed by its full path instead.
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
      return nil unless artifact

      path = evidence_path(directory, artifact["path"])
      document = parse_json(path, errors, "source inventory")
      return nil unless document.is_a?(Hash)

      validate_common_document(document, "m1_source_inventory", manifest, errors, "source inventory")
      entries = document["entries"]
      unless entries.is_a?(Array) && !entries.empty?
        errors << "source inventory entries must be a non-empty array"
        return document
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
        unless non_empty_string?(path_value) && !path_value.start_with?("/") && !path_value.include?("\0") &&
               !invalid_segments && !excluded_root
          errors << "source inventory entry #{index} path is invalid"
          next
        end
        errors << "source inventory paths must be unique" if paths.include?(path_value)
        paths << path_value
        errors << "source inventory entry #{path_value} must have a SHA-256 digest" unless valid_digest?(entry["sha256"])
        errors << "source inventory entry #{path_value} has invalid byte count" unless integer?(entry["bytes"]) && entry["bytes"] >= 0
        entry
      end

      sorted_paths = valid_entries.map { |entry| entry.fetch("path") }.sort
      errors << "source inventory entries must be sorted by path" unless sorted_paths == paths
      digest = canonical_inventory_digest(valid_entries)
      errors << "source inventory digest does not match manifest input" unless digest == manifest["input_sha256"]
      errors << "source inventory file count does not match manifest input" unless valid_entries.length == manifest["input_file_count"]
      document
    end

    def validate_prior_m0(manifest, directory, artifacts, errors)
      prior_milestones = manifest["prior_milestones"]
      unless prior_milestones.is_a?(Hash) && prior_milestones["M0"].is_a?(Hash)
        errors << "COMPLETE M0 evidence is required for cumulative M1 completion"
        return
      end
      reference = prior_milestones.fetch("M0")
      manifest_path_value = reference["manifest_path"]
      result_path_value = reference["gate_result_path"]
      errors << "M0 manifest and gate result paths must be distinct" if manifest_path_value == result_path_value
      manifest_entry = artifacts.find { |artifact| artifact["path"] == manifest_path_value }
      result_entry = artifacts.find { |artifact| artifact["path"] == result_path_value }
      errors << "M0 manifest must be a content-addressed M1 artifact" unless manifest_entry
      errors << "M0 gate result must be a content-addressed M1 artifact" unless result_entry
      return unless manifest_entry && result_entry

      manifest_path = evidence_path(directory, manifest_path_value)
      result_path = evidence_path(directory, result_path_value)
      return unless manifest_path && result_path

      m0_manifest = parse_json(manifest_path, errors, "M0 manifest")
      m0_result = parse_json(result_path, errors, "M0 gate result")
      return unless m0_manifest.is_a?(Hash) && m0_result.is_a?(Hash)

      errors << "M0 manifest reference digest is incorrect" unless reference["manifest_sha256"] == manifest_entry["sha256"]
      errors << "M0 gate result reference digest is incorrect" unless reference["gate_result_sha256"] == result_entry["sha256"]
      errors << "M0 manifest milestone must be M0" unless m0_manifest["milestone"] == "M0"
      errors << "M0 manifest status must be COMPLETE" unless m0_manifest["status"] == "COMPLETE"
      %w[artifacts subjects].each do |collection|
        entries = m0_manifest[collection]
        unless entries.is_a?(Array)
          errors << "M0 manifest #{collection} must be an array"
          next
        end
        entries.each_with_index do |entry, index|
          unless entry.is_a?(Hash) && non_empty_string?(entry["path"])
            errors << "M0 #{collection} entry #{index} has no path"
            next
          end
          nested_path = File.join(File.dirname(manifest_path_value), entry["path"])
          errors << "M0 #{collection} entry is not content-addressed by M1: #{nested_path}" unless artifacts.any? { |artifact| artifact["path"] == nested_path }
        end
      end
      same_input = m0_manifest["input_sha256"] == manifest["input_sha256"] &&
                   m0_manifest["input_file_count"] == manifest["input_file_count"]
      errors << "M0 evidence must use the same source input as M1" unless same_input
      unless reference["input_sha256"] == manifest["input_sha256"] &&
             reference["input_file_count"] == manifest["input_file_count"]
        errors << "M0 reference identity must match the M1 source input"
      end
      errors << "M0 reference must record a passing gate" unless reference["gate_passed"] == true
      errors << "stored M0 gate result must be passing" unless m0_result["passed"] == true && m0_result["milestone"] == "M0"

      gate_stdout, gate_stderr, gate_status = Open3.capture3(
        RbConfig.ruby,
        M0_GATE,
        manifest_path,
        chdir: PROJECT_ROOT
      )
      errors << "M0 gate emitted stderr during cumulative validation" unless gate_stderr.empty?
      unless gate_status.success?
        gate_errors = begin
          JSON.parse(gate_stdout).fetch("errors", [])
        rescue StandardError
          []
        end
        errors << "M0 gate does not pass: #{gate_errors.join("; ")}"
      end
    rescue SystemCallError => error
      errors << "M0 gate could not be executed: #{error.message}"
    end

    def report_document(name, specification, directory, artifact_index, errors)
      artifact = find_named_artifact(specification[:names], artifact_index, errors, "#{name} report")
      return nil unless artifact

      path = evidence_path(directory, artifact["path"])
      parse_json(path, errors, "#{name} report")
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
      validate_common_document(document, expected_kind, manifest, errors, "#{name} report")
      return unless document["schema_version"] == REPORT_SCHEMA_VERSION && document["kind"] == expected_kind

      errors << "#{name} report must be marked passed" unless report_passed?(document)
      validate_report_execution_metadata(document, errors, "#{name} report")
      case name
      when "corpus"
        validate_corpus(document, errors)
      when "generation"
        validate_generation(document, errors)
      when "roundtrip"
        validate_roundtrip(document, errors)
      when "api"
        validate_api(document, errors)
      when "kubectl"
        validate_kubectl(document, errors)
      end
    end

    def validate_common_document(document, expected_kind, manifest, errors, label)
      errors << "#{label} must be a JSON object" unless document.is_a?(Hash)
      return unless document.is_a?(Hash)

      errors << "#{label} schema_version must be #{REPORT_SCHEMA_VERSION}" unless document["schema_version"] == REPORT_SCHEMA_VERSION
      errors << "#{label} kind must be #{expected_kind}" unless document["kind"] == expected_kind
      errors << "#{label} input_sha256 must match manifest" unless document["input_sha256"] == manifest["input_sha256"]
      errors << "#{label} input_file_count must match manifest" unless document["input_file_count"] == manifest["input_file_count"]
      errors << "#{label} input must remain stable" unless document["input_stable"] == true
    end

    def validate_report_execution_metadata(document, errors, label)
      check_zero(document, %w[retry_count retries], errors, "#{label} retry count")
      check_zero(document, %w[unexpected_skip_count unexpected_skips skipped_count skips], errors, "#{label} unexpected skip count")
      check_zero(document, %w[unclassified_count unclassified], errors, "#{label} unclassified count")
      check_zero(document, %w[flake_count flaked_count flakes], errors, "#{label} flake count")
    end

    def validate_corpus(document, errors)
      %w[gvk gvr].each do |kind|
        coverage = document[kind]
        unless coverage.is_a?(Hash)
          errors << "corpus #{kind} coverage is missing"
          next
        end
        expected = required_integer(coverage, %w[expected_count expected], errors, "corpus #{kind} expected count")
        registered = required_integer(coverage, %w[registered_count registered], errors, "corpus #{kind} registered count")
        errors << "corpus #{kind} expected count must be positive" unless expected&.positive?
        required_count = kind == "gvk" ? 321 : 153
        errors << "corpus #{kind} expected count must equal #{required_count}" unless expected == required_count
        errors << "corpus #{kind} registered count must equal expected count" unless expected && registered == expected
        validate_item_inventory(coverage, expected, registered, errors, "corpus #{kind}")
        check_zero(coverage, %w[duplicate_count duplicates], errors, "corpus #{kind} duplicate count")
        check_zero(coverage, %w[missing_count missing], errors, "corpus #{kind} missing count")
        check_zero(coverage, %w[unexpected_count unexpected], errors, "corpus #{kind} unexpected count")
      end
      check_zero(document, %w[failure_count failures], errors, "corpus failure count")
    end

    def validate_item_inventory(coverage, expected_count, registered_count, errors, label)
      expected_items = coverage["expected_items"] || coverage["expected_entries"]
      registered_items = coverage["registered_items"] || coverage["registered_entries"]
      unless expected_items.is_a?(Array) && registered_items.is_a?(Array)
        errors << "#{label} expected_items and registered_items are required"
        return
      end
      errors << "#{label} expected item count does not match expected_count" unless expected_count == expected_items.length
      errors << "#{label} registered item count does not match registered_count" unless registered_count == registered_items.length
      expected_ids = item_ids(expected_items, errors, "#{label} expected items")
      registered_ids = item_ids(registered_items, errors, "#{label} registered items")
      errors << "#{label} expected item identifiers are duplicated" unless expected_ids.uniq.length == expected_ids.length
      errors << "#{label} registered item identifiers are duplicated" unless registered_ids.uniq.length == registered_ids.length
      errors << "#{label} expected and registered item sets differ" unless expected_ids.sort == registered_ids.sort
    end

    def item_ids(items, errors, label)
      items.filter_map.with_index do |item, index|
        identifier = if item.is_a?(String)
                       item
                     elsif item.is_a?(Hash)
                       item["id"] || item["name"]
                     end
        unless non_empty_string?(identifier)
          errors << "#{label} item #{index} has no identifier"
          next
        end
        identifier
      end
    end

    def validate_generation(document, errors)
      runs = document["runs"]
      unless runs.is_a?(Array) && runs.length == 2
        errors << "generation report must record exactly two generation runs"
        runs = []
      end
      run_digests = runs.filter_map.with_index do |run, index|
        unless run.is_a?(Hash)
          errors << "generation run #{index} must be an object"
          next
        end
        digest = run["tree_sha256"] || run["output_sha256"]
        errors << "generation run #{index} must include a tree SHA-256" unless valid_digest?(digest)
        digest
      end
      errors << "generation runs must produce the same tree digest" unless run_digests.length == 2 && run_digests.uniq.length == 1
      canonical_digest = document["canonical_tree_sha256"]
      errors << "generation report must include the canonical tree SHA-256" unless valid_digest?(canonical_digest)
      errors << "generation output must match the canonical tree" unless valid_digest?(canonical_digest) && run_digests.all?(canonical_digest)
      byte_differences = document["byte_differences"] || document["byte_diff_entries"]
      canonical_differences = document["canonical_differences"] || document["canonical_diff_entries"]
      errors << "generation byte difference entries are required" unless byte_differences.is_a?(Array)
      errors << "generation canonical difference entries are required" unless canonical_differences.is_a?(Array)
      check_zero(document, %w[byte_diff_count tree_diff_count], errors, "generation byte diff count")
      check_zero(document, %w[canonical_diff_count canonical_tree_diff_count], errors, "generation canonical diff count")
      check_zero(document, %w[missing_count missing], errors, "generation missing count")
      check_zero(document, %w[unexpected_count unexpected], errors, "generation unexpected count")
      check_zero(document, %w[failure_count failures], errors, "generation failure count")
    end

    def validate_roundtrip(document, errors)
      gvk_count = required_integer(document, %w[gvk_count type_count], errors, "roundtrip GVK count")
      case_count = required_integer(document, %w[case_count test_case_count], errors, "roundtrip case count")
      errors << "roundtrip GVK count must be positive" unless gvk_count&.positive?
      errors << "roundtrip case count must be positive" unless case_count&.positive?
      errors << "roundtrip GVK count must equal 311" unless gvk_count == 311
      errors << "roundtrip case count must equal 770" unless case_count == 770
      errors << "roundtrip registry GVK count must equal 321" unless document["registry_gvk_count"] == 321
      errors << "roundtrip expected protobuf-supported count must equal 770" unless document["protobuf_expected_supported_count"] == 770
      errors << "roundtrip protobuf-supported count must equal 770" unless document["protobuf_supported_count"] == 770
      errors << "roundtrip protobuf unsupported count must equal 1" unless document["protobuf_unsupported_count"] == 1
      validate_protobuf_unsupported_inventory(document, errors)
      gvks = document["gvks"] || document["types"]
      cases = document["cases"] || document["test_cases"]
      if gvks.is_a?(Array) && cases.is_a?(Array)
        errors << "roundtrip GVK item count does not match gvk_count" unless gvk_count == gvks.length
        errors << "roundtrip case count does not match case entries" unless case_count == cases.length
        gvk_ids = item_ids(gvks, errors, "roundtrip GVKs")
        case_ids = item_ids(cases, errors, "roundtrip cases")
        errors << "roundtrip GVK identifiers are duplicated" unless gvk_ids.uniq.length == gvk_ids.length
        errors << "roundtrip case identifiers are duplicated" unless case_ids.uniq.length == case_ids.length
        cases.each_with_index do |entry, index|
          unless entry.is_a?(Hash)
            errors << "roundtrip case #{index} must be an object"
            next
          end
          errors << "roundtrip case #{index} did not pass" unless entry["passed"] == true
          attempt_count = entry["attempt_count"] || entry["attempts"]
          errors << "roundtrip case #{index} must run exactly once" unless attempt_count == 1
          %w[json_roundtrip protobuf_roundtrip unknown_field defaulting validation].each do |check|
            errors << "roundtrip case #{index} #{check} check did not pass" unless entry[check] == true
          end
          errors << "roundtrip case #{index} semantic oracle check did not pass" unless entry["semantic_oracle"] == true
        end
      else
        errors << "roundtrip gvks and cases are required"
      end
      check_zero(document, %w[failure_count failures], errors, "roundtrip failure count")
      check_zero(document, %w[json_roundtrip_failures json_failures], errors, "roundtrip JSON failures")
      check_zero(document, %w[protobuf_roundtrip_failures protobuf_failures], errors, "roundtrip Protobuf failures")
      check_zero(document, %w[unknown_field_failures unknown_fields_failures], errors, "roundtrip unknown-field failures")
      check_zero(document, %w[defaulting_failures defaulting_mismatches], errors, "roundtrip defaulting failures")
      check_zero(document, %w[validation_failures validation_mismatches], errors, "roundtrip validation failures")
      check_zero(document, %w[oracle_difference_count oracle_mismatch_count], errors, "roundtrip oracle difference count")
      check_zero(document, %w[semantic_difference_count semantic_mismatch_count], errors, "roundtrip semantic difference count")
      validate_oracle(document, case_count, cases, errors, "roundtrip")
      validate_semantic_oracle(document, case_count, cases, errors)
      validate_validation_oracle(document, case_count, cases, errors)
      validate_unknown_field_mismatch_packet(document, case_count, cases, errors)
    end

    def validate_api(document, errors)
      operation_count = required_integer(document, %w[operation_count total_count], errors, "API operation count")
      passed_count = required_integer(document, %w[passed_count success_count], errors, "API passed count")
      errors << "API operation count must be positive" unless operation_count&.positive?
      errors << "API operation count must equal #{REQUIRED_API_OPERATIONS.length}" unless operation_count == REQUIRED_API_OPERATIONS.length
      errors << "API passed count must equal operation count" unless operation_count && passed_count == operation_count
      operations = document["operations"] || document["results"]
      if operations.is_a?(Array)
        errors << "API operation count does not match operation entries" unless operation_count == operations.length
        operation_ids = item_ids(operations, errors, "API operations")
        errors << "API operation identifiers are duplicated" unless operation_ids.uniq.length == operation_ids.length
        unless operation_ids == REQUIRED_API_OPERATION_INVENTORY.map { |entry| entry.fetch("id") }
          errors << "API operation inventory differs from the required Kubernetes differential sequence"
        end
        operations.each_with_index do |operation, index|
          unless operation.is_a?(Hash)
            errors << "API operation #{index} must be an object"
            next
          end
          errors << "API operation #{index} did not pass" unless operation["passed"] == true
          expected_inventory = REQUIRED_API_OPERATION_INVENTORY[index]
          if expected_inventory
            %w[id method path request].each do |key|
              errors << "API operation #{index} #{key} differs from the exact request inventory" unless
                operation[key] == expected_inventory[key]
            end
          end
          errors << "API operation #{index} request digest is invalid" unless valid_digest?(operation["request_sha256"])
          if valid_digest?(operation["request_sha256"]) && operation["request"].is_a?(Hash) && operation["request_sha256"] != canonical_document_digest(operation["request"])
            errors << "API operation #{index} request digest does not match its preimage"
          end
          attempt_count = operation["attempt_count"] || operation["attempts"]
          errors << "API operation #{index} must run exactly once" unless attempt_count == 1
          errors << "API operation #{index} semantic header comparison did not pass" unless operation["header_matches"] == true
          %w[defaulting_matches validation_matches].each do |check|
            errors << "API operation #{index} #{check} must be recorded as true" unless operation[check] == true
          end
          validate_api_operation_observables(operation, errors, "API operation #{index}")
        end
      else
        errors << "API operations are required"
      end
      check_zero(document, %w[failure_count failures], errors, "API failure count")
      check_zero(document, %w[unexpected_skip_count unexpected_skips], errors, "API unexpected skip count")
      check_zero(document, %w[unclassified_count unclassified], errors, "API unclassified count")
      check_zero(document, %w[self_check_difference_count self_check_differences], errors, "API self-check difference count")
      check_zero(document, %w[difference_count differences], errors, "API difference count")
      check_zero(document, %w[oracle_difference_count oracle_mismatch_count], errors, "API oracle difference count")
      check_zero(document, %w[status_mismatch_count status_mismatches], errors, "API status mismatch count")
      check_zero(document, %w[header_mismatch_count header_mismatches], errors, "API header mismatch count")
      check_zero(document, %w[status_body_mismatch_count status_body_mismatches], errors, "API status body mismatch count")
      check_zero(document, %w[defaulting_mismatch_count defaulting_mismatches], errors, "API defaulting mismatch count")
      check_zero(document, %w[validation_mismatch_count validation_mismatches], errors, "API validation mismatch count")
      check_zero(document, %w[ownership_mismatch_count ownership_mismatches], errors, "API ownership mismatch count")
      check_zero(document, %w[watch_failure_count watch_failures], errors, "API watch failure count")
      validate_api_header_policy(document, errors)
      validate_api_surface(document, errors)
      validate_oracle(document, operation_count, operations, errors, "API")
    end

    def validate_api_operation_observables(operation, errors, label)
      expected = operation["oracle_observable"]
      actual = operation["rubernetes_observable"]
      unless expected.is_a?(Hash) && actual.is_a?(Hash)
        errors << "#{label} must include complete oracle and Rubernetes observable packets"
        return
      end
      %w[oracle_observable rubernetes_observable].each do |packet_name|
        packet = operation.fetch(packet_name)
        %w[status headers body ownership].each do |key|
          errors << "#{label} #{packet_name} must include #{key}" unless packet.key?(key)
        end
        errors << "#{label} #{packet_name} status must be an HTTP status" unless
          integer?(packet["status"]) && packet["status"].between?(100, 599)
        errors << "#{label} #{packet_name} headers must be an object" unless packet["headers"].is_a?(Hash)
        errors << "#{label} #{packet_name} ownership must be an array of objects or per-event object arrays" unless
          valid_ownership_observation?(packet["ownership"])
        if packet["headers"].is_a?(Hash)
          errors << "#{label} #{packet_name} header names must be normalized lowercase tokens" unless
            packet["headers"].keys.all? { |name| name.is_a?(String) && name == name.downcase && name.match?(/\A[a-z0-9-]+\z/) }
          errors << "#{label} #{packet_name} header values must be strings" unless packet["headers"].values.all?(String)
        end
        if packet.key?("resourceVersion_causality") && !packet["resourceVersion_causality"].is_a?(Hash)
          errors << "#{label} #{packet_name} resourceVersion causality must be a measured signature"
        end
      end
      validate_resource_version_observation(operation, expected, actual, errors, label)
      %w[status_matches header_matches body_matches ownership_matches status_body_matches
         resource_version_causality_matches watch_matches].each do |check|
        errors << "#{label} #{check} must be boolean" unless [true, false].include?(operation[check])
      end
      %w[expected_sha256 actual_sha256].each do |key|
        errors << "#{label} #{key} must be a SHA-256 digest" unless valid_digest?(operation[key])
      end
      if valid_digest?(operation["expected_sha256"]) && operation["expected_sha256"] != canonical_document_digest(expected)
        errors << "#{label} expected digest does not match observable packet"
      end
      if valid_digest?(operation["actual_sha256"]) && operation["actual_sha256"] != canonical_document_digest(actual)
        errors << "#{label} actual digest does not match observable packet"
      end
      errors << "#{label} observable packets differ while operation is marked passed" if
        operation["passed"] == true && canonical_document_digest(expected) != canonical_document_digest(actual)

      header_observation = operation["header_observation"]
      if header_observation.is_a?(Hash)
        expected_headers = header_observation.dig("expected", "compared")
        actual_headers = header_observation.dig("actual", "compared")
        errors << "#{label} oracle observable headers differ from header observation" unless
          expected["headers"] == expected_headers
        errors << "#{label} Rubernetes observable headers differ from header observation" unless
          actual["headers"] == actual_headers
      end

      if integer?(expected["status"]) && integer?(actual["status"]) && operation["status_matches"] != (expected["status"] == actual["status"])
        errors << "#{label} status_matches is inconsistent with observable packets"
      end
      if expected["headers"].is_a?(Hash) && actual["headers"].is_a?(Hash) && operation["header_matches"] != (expected["headers"] == actual["headers"])
        errors << "#{label} header_matches is inconsistent with observable packets"
      end
      if expected.key?("body") && actual.key?("body") && operation["body_matches"] != (expected["body"] == actual["body"])
        errors << "#{label} body_matches is inconsistent with observable packets"
      end
      if expected["ownership"].is_a?(Array) && actual["ownership"].is_a?(Array) && operation["ownership_matches"] != (expected["ownership"] == actual["ownership"])
        errors << "#{label} ownership_matches is inconsistent with observable packets"
      end
      if expected.key?("resourceVersion_causality") || actual.key?("resourceVersion_causality")
        expected_causality = expected["resourceVersion_causality"]
        actual_causality = actual["resourceVersion_causality"]
        errors << "#{label} resourceVersion causality must be recorded on both observable packets" unless
          expected.key?("resourceVersion_causality") && actual.key?("resourceVersion_causality")
        if expected_causality.is_a?(Hash) && actual_causality.is_a?(Hash)
          both_valid = expected_causality["valid"] == true && actual_causality["valid"] == true
          if operation["resource_version_causality_matches"] != both_valid
            errors << "#{label} resource_version_causality_matches is inconsistent with observable packets"
          end
        end
      else
        errors << "#{label} resource_version_causality_matches must be true when no causality packet is present" unless
          operation["resource_version_causality_matches"] == true
      end

      expected_status_body = expected["body"].is_a?(Hash) && expected["body"]["kind"] == "Status"
      if expected_status_body
        errors << "#{label} status_body_matches is inconsistent with observable packets" unless
          operation["status_body_matches"] == (expected["body"] == actual["body"])
      else
        errors << "#{label} status_body_matches must be true for resource observables" unless operation["status_body_matches"] == true
      end

      if expected["body"].is_a?(Array) || actual["body"].is_a?(Array)
        errors << "#{label} watch_matches is inconsistent with observable packets" unless
          operation["watch_matches"] == (expected["body"] == actual["body"] && expected["ownership"] == actual["ownership"] &&
                                           operation["resource_version_causality_matches"] == true)
      else
        errors << "#{label} watch_matches must be true for non-watch observables" unless operation["watch_matches"] == true
      end
    end

    def validate_resource_version_observation(operation, expected_packet, actual_packet, errors, label)
      observation = operation["resource_version_observation"]
      packet_has_causality = expected_packet.key?("resourceVersion_causality") || actual_packet.key?("resourceVersion_causality")
      unless packet_has_causality
        errors << "#{label} non-watch operation must not carry a resourceVersion observation" unless observation.nil?
        return
      end
      unless observation.is_a?(Hash)
        errors << "#{label} measured resourceVersion observation is required"
        return
      end

      [["expected", expected_packet], ["actual", actual_packet]].each do |source, packet|
        trace = observation[source]
        digest_key = "#{source}_sha256"
        unless trace.is_a?(Hash)
          errors << "#{label} #{source} resourceVersion trace must be an object"
          next
        end
        errors << "#{label} #{source} resourceVersion trace digest is invalid" unless valid_digest?(observation[digest_key])
        if valid_digest?(observation[digest_key]) && observation[digest_key] != canonical_document_digest(trace)
          errors << "#{label} #{source} resourceVersion trace digest does not match its preimage"
        end
        calculated_valid = valid_resource_version_trace?(trace)
        errors << "#{label} #{source} resourceVersion trace validity is not derived from raw revisions" unless
          trace["valid"] == calculated_valid
        expected_signature = resource_version_signature(trace)
        errors << "#{label} #{source} observable causality signature is not derived from its raw trace" unless
          packet["resourceVersion_causality"] == expected_signature
      end
    end

    def valid_resource_version_trace?(trace)
      return false unless trace.is_a?(Hash) && trace["response_status"] == 200 && trace["events"].is_a?(Array)

      records = trace["events"]
      case trace["mode"]
      when "initial-watch"
        bookmark_indices = records.each_index.select do |index|
          records[index].is_a?(Hash) && records[index]["initial_events_end"] == true
        end
        return false unless bookmark_indices.one? && bookmark_indices.first == records.length - 1

        bookmark = records.fetch(bookmark_indices.first)
        return false unless trace["list_resourceVersion"] == bookmark["resourceVersion"]

        list_version = positive_resource_version(trace["list_resourceVersion"])
        initial_records = records.reject { |record| record.is_a?(Hash) && record["initial_events_end"] == true }
        event_versions = initial_records.map do |record|
          positive_resource_version(record.is_a?(Hash) ? record["resourceVersion"] : nil)
        end
        !initial_records.empty? && initial_records.all? { |record| record.is_a?(Hash) && record["type"] == "ADDED" } &&
          list_version && event_versions.all? && event_versions.all? { |version| version <= list_version }
      when "watch"
        start_version = positive_resource_version(trace["start_resourceVersion"])
        mutation_version = positive_resource_version(trace["mutation_resourceVersion"])
        event_versions = records.map do |record|
          positive_resource_version(record.is_a?(Hash) ? record["resourceVersion"] : nil)
        end
        start_version && mutation_version && mutation_version > start_version && records.length == 1 &&
          records.first.is_a?(Hash) && records.first["type"] == "MODIFIED" && event_versions == [mutation_version]
      else
        false
      end == true
    end

    def resource_version_signature(trace)
      return nil unless trace.is_a?(Hash)

      records = Array(trace["events"])
      case trace["mode"]
      when "initial-watch"
        bookmark_indices = records.each_index.select do |index|
          records[index].is_a?(Hash) && records[index]["initial_events_end"] == true
        end
        list_version = positive_resource_version(trace["list_resourceVersion"])
        event_versions = records.reject { |record| record.is_a?(Hash) && record["initial_events_end"] == true }
          .map { |record| positive_resource_version(record.is_a?(Hash) ? record["resourceVersion"] : nil) }
        {
          "mode" => "initial-watch",
          "event_count" => records.length,
          "event_types" => records.map { |record| record.is_a?(Hash) ? record["type"].to_s : "" },
          "initial_events_end_index" => bookmark_indices.one? ? bookmark_indices.first : nil,
          "resourceVersions_valid" => !!(list_version && event_versions.all?),
          "events_not_newer_than_list" => !!(list_version && event_versions.all? && event_versions.all? do |version|
            version <= list_version
          end),
          "valid" => trace["valid"] == true
        }
      when "watch"
        start_version = positive_resource_version(trace["start_resourceVersion"])
        mutation_version = positive_resource_version(trace["mutation_resourceVersion"])
        event_versions = records.map do |record|
          positive_resource_version(record.is_a?(Hash) ? record["resourceVersion"] : nil)
        end
        {
          "mode" => "watch",
          "event_count" => records.length,
          "event_types" => records.map { |record| record.is_a?(Hash) ? record["type"].to_s : "" },
          "resourceVersions_valid" => !!(start_version && mutation_version && event_versions.all?),
          "mutation_after_start" => !!(start_version && mutation_version && mutation_version > start_version),
          "events_match_mutation" => !!(mutation_version && event_versions == [mutation_version]),
          "valid" => trace["valid"] == true
        }
      end
    end

    def positive_resource_version(value)
      parsed = Integer(value, 10)
      parsed.positive? ? parsed : nil
    rescue ArgumentError, TypeError
      nil
    end

    # Resource responses carry one ownership list. Watch responses carry one
    # ownership list per event, so their observable is an array of arrays of
    # objects. Keep the shape deliberately shallow and closed: accepting
    # arbitrary nested data here would let a forged evidence producer hide
    # unvalidated ownership state inside the packet preimage.
    def valid_ownership_observation?(value)
      value.is_a?(Array) && value.all? do |entry|
        entry.is_a?(Hash) || (entry.is_a?(Array) && entry.all?(Hash))
      end
    end

    def validate_api_header_policy(document, errors)
      policy = document["header_policy"]
      unless policy.is_a?(Hash)
        errors << "API semantic header exclusion allowlist is required"
        return
      end
      errors << "API semantic header exclusion allowlist must exactly match the pinned policy" unless policy == HEADER_EXCLUSION_ALLOWLIST
      policy.each do |name, metadata|
        errors << "API semantic header exclusion name must be lowercase" unless name.is_a?(String) && name == name.downcase && name.match?(/\A[a-z0-9-]+\z/)
        unless metadata.is_a?(Hash) && %w[dynamic hop-by-hop].include?(metadata["class"]) && non_empty_string?(metadata["reason"])
          errors << "API semantic header exclusion #{name.inspect} must have a class and machine-readable reason"
        end
      end
      digest = document["header_policy_sha256"]
      errors << "API semantic header exclusion policy digest is required" unless valid_digest?(digest)
      errors << "API semantic header exclusion policy digest does not match policy" if valid_digest?(digest) && digest != canonical_document_digest(policy)

      operations = document["operations"] || document["results"]
      return unless operations.is_a?(Array)

      operations.each_with_index do |operation, index|
        next unless operation.is_a?(Hash)

        observation = operation["header_observation"]
        unless observation
          errors << "API operation #{index} header observation is required"
          next
        end
        validate_header_observation_pair(observation, errors, "API operation #{index}")
      end
    end

    def validate_api_surface(document, errors)
      surface = document["api_surface"]
      unless surface.is_a?(Hash)
        errors << "API corpus-driven surface matrix is required"
        return
      end
      errors << "API surface registry GVK count must equal #{API_SURFACE_GVK_COUNT}" unless surface["registry_gvk_count"] == API_SURFACE_GVK_COUNT
      errors << "API surface registry GVR count must equal #{API_SURFACE_GVR_COUNT}" unless surface["registry_gvr_count"] == API_SURFACE_GVR_COUNT
      unless surface["discovery_endpoint_count"] == API_SURFACE_ENDPOINT_COUNT
        errors << "API surface discovery endpoint count must equal #{API_SURFACE_ENDPOINT_COUNT}"
      end
      %w[oracle_missing_count rubernetes_missing_count duplicate_count unexpected_count difference_count
         schema_contract_missing_count].each do |key|
        check_zero(surface, [key], errors, "API surface #{key}")
      end
      errors << "API corpus-driven surface matrix must be marked passed" unless surface["passed"] == true

      registry_gvk_ids = surface["registry_gvk_ids"]
      registry_gvr_ids = surface["registry_gvr_ids"]
      unless registry_gvk_ids.is_a?(Array) && registry_gvk_ids.length == API_SURFACE_GVK_COUNT && registry_gvk_ids.all? do |id|
        non_empty_string?(id)
      end
        errors << "API surface registry GVK inventory must contain exactly #{API_SURFACE_GVK_COUNT} identifiers"
      end
      unless registry_gvr_ids.is_a?(Array) && registry_gvr_ids.length == API_SURFACE_GVR_COUNT && registry_gvr_ids.all? do |id|
        non_empty_string?(id)
      end
        errors << "API surface registry GVR inventory must contain exactly #{API_SURFACE_GVR_COUNT} identifiers"
      end
      generated_inventory = generated_surface_inventory(errors)
      if generated_inventory
        if registry_gvk_ids.is_a?(Array) && registry_gvk_ids.sort != generated_inventory.fetch("gvk_ids").sort
          errors << "API surface GVK inventory does not match generated/schema/registry.json"
        end
        if registry_gvr_ids.is_a?(Array) && registry_gvr_ids.sort != generated_inventory.fetch("gvr_ids").sort
          errors << "API surface GVR inventory does not match generated/schema/registry.json"
        end
      end

      validate_feature_profile(surface["feature_profile"], errors)

      pinned_surface = pinned_surface_expectations(errors)
      validate_surface_endpoints(surface["discovery_endpoints"], errors)
      validate_surface_matrix(
        surface["gvr_matrix"], registry_gvr_ids, errors, "GVR",
        require_applicability: false, pinned_expected_by_id: pinned_surface && pinned_surface.fetch("gvr")
      )
      validate_surface_matrix(
        surface["gvk_matrix"], registry_gvk_ids, errors, "GVK",
        require_applicability: true, pinned_expected_by_id: pinned_surface && pinned_surface.fetch("gvk")
      )
    end

    def validate_feature_profile(profile, errors)
      unless profile.is_a?(Hash)
        errors << "API surface feature profile is required"
        return
      end
      errors << "API surface feature profile name must be #{DEFAULT_PROFILE}" unless profile["name"] == DEFAULT_PROFILE
      gates = profile["feature_gates"]
      expected_gates = {
        "MutatingAdmissionPolicy" => true,
        "ClusterTrustBundle" => false,
        "PodCertificateRequest" => false,
        "CoordinatedLeaderElection" => false,
        "MultiCIDRServiceAllocator" => true,
        "DynamicResourceAllocation" => true,
        "GenericWorkload" => false,
        "VolumeAttributesClass" => true,
        "StorageVersionMigrator" => false,
        "StorageVersionAPI" => false
      }
      errors << "API surface feature profile default gates are invalid" unless gates == expected_gates
      unless profile["default_off_gvr_ids"] == DEFAULT_OFF_GVR_IDS
        errors << "API surface feature profile default-off GVR inventory is invalid"
      end
      unless profile["default_off_gvk_ids"] == DEFAULT_OFF_GVK_IDS
        errors << "API surface feature profile default-off GVK inventory is invalid"
      end
      unless profile["default_off_discovery_paths"] == DEFAULT_OFF_DISCOVERY_PATHS
        errors << "API surface feature profile default-off endpoint inventory is invalid"
      end
      errors << "API surface feature profile reason is invalid" unless profile["reason"] == DEFAULT_OFF_REASON
    end

    def generated_surface_inventory(errors)
      path = File.join(PROJECT_ROOT, "generated/schema/registry.json")
      unless File.file?(path)
        errors << "API surface generated schema registry is missing"
        return nil
      end
      document = JSON.parse(File.binread(path), max_nesting: 100)
      gvk_ids = Array(document.fetch("gvks")).map do |entry|
        identifier = entry["identifier"]
        next identifier if non_empty_string?(identifier)

        "#{entry.fetch("group", "").to_s.empty? ? "core" : entry.fetch("group")}/#{entry.fetch("version")}/#{entry.fetch("kind")}"
      end
      gvr_ids = Array(document.fetch("gvrs")).map do |entry|
        identifier = entry["identifier"]
        next identifier if non_empty_string?(identifier)

        "#{entry.fetch("group", "").to_s.empty? ? "core" : entry.fetch("group")}/#{entry.fetch("version")}/#{entry.fetch("resource")}"
      end
      {
        "gvk_ids" => gvk_ids,
        "gvr_ids" => gvr_ids
      }
    rescue JSON::ParserError, KeyError, TypeError => error
      errors << "API surface generated schema registry is invalid: #{error.message}"
      nil
    end

    # Rebuild the expected discovery rows inside the gate from the pinned
    # v1.36.2 artifacts.  Report-provided `expected` packets are evidence, not
    # an authority: accepting them without this recomputation lets a producer
    # forge both sides of a comparison in the same way.
    def pinned_surface_expectations(errors)
      rows = M1ProbeSupport.canonical_discovery_surface(PROJECT_ROOT)
      gvr = rows.to_h do |row|
        [M1ProbeSupport.surface_identifier(row), pinned_surface_fields(row)]
      end
      gvk = {}
      rows.each do |row|
        kind_id = M1ProbeSupport.identifier(row.fetch("group", ""), row.fetch("version"), row.fetch("kind"))
        gvk[kind_id] ||= pinned_surface_fields(row)
        next if row.fetch("listKind", "").empty?

        list_row = row.merge(
          "kind" => row.fetch("listKind"), "listKind" => "", "singular" => "",
          "subresources" => [], "shortNames" => [], "categories" => []
        )
        list_id = M1ProbeSupport.identifier(
          list_row.fetch("group", ""), list_row.fetch("version"), list_row.fetch("kind")
        )
        gvk[list_id] ||= pinned_surface_fields(list_row)
      end
      {"gvr" => gvr, "gvk" => gvk}
    rescue JSON::ParserError, KeyError, TypeError => error
      errors << "API surface pinned discovery corpus is invalid: #{error.message}"
      nil
    end

    def pinned_surface_fields(row)
      row.slice(*API_SURFACE_FIELDS).tap do |fields|
        fields["verbs"] = Array(fields["verbs"]).map(&:to_s).sort
        %w[subresources shortNames categories].each do |key|
          fields[key] = Array(fields[key]).map(&:to_s).sort
        end
        fields["schema_contract_present"] = false
      end
    end

    def validate_surface_endpoints(endpoints, errors)
      unless endpoints.is_a?(Array) && endpoints.length == API_SURFACE_ENDPOINT_COUNT
        errors << "API surface discovery endpoint inventory must contain exactly #{API_SURFACE_ENDPOINT_COUNT} endpoints"
        return
      end
      pinned_endpoints = pinned_discovery_endpoint_inventory
      pinned_by_path = pinned_endpoints.to_h { |entry| [entry.fetch("path"), entry] }
      ids = endpoints.filter_map.with_index do |entry, index|
        unless entry.is_a?(Hash)
          errors << "API surface discovery endpoint #{index} must be an object"
          next
        end
        id = entry["id"] || entry["path"]
        errors << "API surface discovery endpoint #{index} has no identifier" unless non_empty_string?(id)
        errors << "API surface discovery endpoint #{index} id and path must match" unless id == entry["path"]
        expected_endpoint = pinned_by_path[id]
        errors << "API surface discovery endpoint #{index} is not in the pinned v1.36.2 inventory" unless expected_endpoint
        if expected_endpoint && entry["source_path"] != expected_endpoint.fetch("source_path")
          errors << "API surface discovery endpoint #{index} source path does not match the pinned v1.36.2 file"
        end
        errors << "API surface discovery endpoint #{index} must run exactly once" unless entry["attempt_count"] == 1
        default_off = DEFAULT_OFF_DISCOVERY_PATHS.include?(id)
        expected_availability = default_off ? "not_served_default" : "served"
        unless entry["availability"] == expected_availability
          errors << "API surface discovery endpoint #{index} availability profile is invalid"
        end
        if default_off
          unless entry["availability_reason"] == DEFAULT_OFF_REASON
            errors << "API surface discovery endpoint #{index} default-off reason is invalid"
          end
        else
          unless entry["availability_reason"].nil?
            errors << "API surface discovery endpoint #{index} served endpoint must not carry a default-off reason"
          end
        end
        unless entry["expected_source"] == "pinned_kubernetes_discovery"
          errors << "API surface discovery endpoint #{index} expected source is invalid"
        end
        errors << "API surface discovery endpoint #{index} oracle source is invalid" unless entry["oracle_source"] == "kubernetes_external"
        errors << "API surface discovery endpoint #{index} Rubernetes source is invalid" unless entry["rubernetes_source"] == "rubernetes"
        errors << "API surface discovery endpoint #{index} comparison scope is invalid" unless entry["comparison_scope"] == "full_semantic"
        %w[expected_sha256 oracle_sha256 rubernetes_sha256].each do |key|
          errors << "API surface discovery endpoint #{index} #{key} must be a SHA-256 digest" unless valid_digest?(entry[key])
        end
        %w[expected_body oracle_body rubernetes_body].each do |key|
          valid_body = entry[key].is_a?(Hash) || (default_off && entry[key].is_a?(String))
          errors << "API surface discovery endpoint #{index} #{key} must be an object" unless valid_body
          next unless valid_body && valid_digest?(entry[key.sub(/_body\z/,
                                                                "_sha256")]) && entry[key.sub(/_body\z/,
                                                                                              "_sha256")] != canonical_discovery_digest(entry[key])

          errors << "API surface discovery endpoint #{index} #{key} digest does not match the body"
        end
        if expected_endpoint && valid_digest?(entry["expected_sha256"])
          pinned_digest = pinned_discovery_digest(expected_endpoint.fetch("source_path"), errors, path: id)
          errors << "API surface discovery endpoint #{index} expected digest does not match the pinned file" unless
            pinned_digest.nil? || entry["expected_sha256"] == pinned_digest
        end
        errors << "API surface discovery endpoint #{index} must pass" unless entry["passed"] == true
        if default_off
          unless entry["oracle_status"] == 404 && entry["rubernetes_status"] == 404
            errors << "API surface discovery endpoint #{index} default-off status must be 404 for both sources"
          end
          errors << "API surface discovery endpoint #{index} default-off expected body differs from upstream 404 semantics" unless
            entry["expected_body"] == canonical_discovery_value(default_off_discovery_body(id))
        else
          unless entry["oracle_status"] == 200 && entry["rubernetes_status"] == 200
            errors << "API surface discovery endpoint #{index} status must be 200 for both sources"
          end
        end
        errors << "API surface discovery endpoint #{index} header comparison must pass" unless entry["header_matches"] == true
        validate_header_observation_pair(
          entry["header_observation"], errors,
          "API surface discovery endpoint #{index}"
        )
        id if non_empty_string?(id)
      end
      errors << "API surface discovery endpoint identifiers must be unique" unless ids.uniq.length == ids.length
      unless pinned_endpoints.length == API_SURFACE_ENDPOINT_COUNT && ids.sort == pinned_endpoints.map { |entry| entry.fetch("path") }.sort
        errors << "API surface discovery endpoint inventory differs from the pinned v1.36.2 inventory"
      end
    end

    def pinned_discovery_endpoint_inventory
      discovery_root = File.join(PROJECT_ROOT, "schema/kubernetes/v1.36.2/discovery")
      Dir.glob(File.join(discovery_root, "*.json")).filter_map do |path|
        basename = File.basename(path, ".json")
        endpoint = case basename
                   when "api"
                     "/api"
                   when "api__v1"
                     "/api/v1"
                   when "apis"
                     "/apis"
                   when /\Aapis__(.+)__(.+)\z/
                     "/apis/#{Regexp.last_match(1)}/#{Regexp.last_match(2)}"
                   when /\Aapis__(.+)\z/
                     "/apis/#{Regexp.last_match(1)}"
                   end
        next unless endpoint

        {
          "path" => endpoint,
          "source_path" => path.delete_prefix("#{PROJECT_ROOT}/")
        }
      end.sort_by { |entry| entry.fetch("path") }
    end

    def pinned_discovery_digest(source_path, errors, path: nil)
      endpoint = path
      file_path = File.expand_path(source_path, PROJECT_ROOT)
      unless file_path.start_with?("#{File.join(PROJECT_ROOT, "schema/kubernetes/v1.36.2/discovery")}/") && File.file?(file_path)
        errors << "API surface pinned discovery source path is unavailable"
        return nil
      end
      document = JSON.parse(File.binread(file_path), max_nesting: 100)
      return canonical_discovery_digest(default_off_discovery_body(endpoint)) if DEFAULT_OFF_DISCOVERY_PATHS.include?(endpoint)

      canonical_discovery_digest(default_profile_discovery_value(path: file_path, document: document, endpoint: endpoint))
    rescue JSON::ParserError => error
      errors << "API surface pinned discovery source is invalid: #{error.message}"
      nil
    end

    def canonical_discovery_digest(document)
      canonical_document_digest(canonical_discovery_value(document))
    end

    def default_off_discovery_body(path)
      ROUTER_NOT_FOUND_DISCOVERY_PATHS.include?(path) ? DISCOVERY_NOT_FOUND_BODY : DISCOVERY_STATUS_NOT_FOUND_BODY
    end

    def default_profile_discovery_value(path:, document:, endpoint: nil)
      endpoint ||= begin
        basename = File.basename(path, ".json")
        basename == "apis" ? "/apis" : nil
      end
      canonical = canonical_discovery_value(document)
      return canonical unless canonical.is_a?(Hash)

      if canonical["groups"].is_a?(Array)
        groups = canonical.fetch("groups").filter_map do |group|
          next group unless group.is_a?(Hash)

          name = group["name"].to_s
          versions = Array(group["versions"]).reject do |version|
            DEFAULT_OFF_DISCOVERY_PATHS.include?("/apis/#{name}/#{version["version"]}")
          end
          next nil if versions.empty?

          preferred = group["preferredVersion"]
          preferred = versions.first unless versions.any?(preferred)
          group.merge("versions" => versions, "preferredVersion" => preferred)
        end
        return canonical.merge("groups" => groups)
      end

      if canonical["versions"].is_a?(Array) && endpoint.to_s.start_with?("/apis/")
        group = endpoint.to_s.split("/")[2]
        versions = canonical.fetch("versions").reject do |version|
          DEFAULT_OFF_DISCOVERY_PATHS.include?("/apis/#{group}/#{version["version"]}")
        end
        preferred = canonical["preferredVersion"]
        preferred = versions.first unless versions.any?(preferred)
        return canonical.merge("versions" => versions, "preferredVersion" => preferred)
      end

      canonical
    end

    def canonical_discovery_value(value)
      case value
      when Hash
        normalized = value.keys.map(&:to_s).uniq.sort.each_with_object({}) do |key, result|
          next if %w[apiVersion serverAddressByClientCIDRs storageVersionHash].include?(key)

          source_key = value.key?(key) ? key : key.to_sym
          result[key] = canonical_discovery_value(value[source_key])
        end
        if normalized["kind"] == "APIResourceList" && normalized["resources"].is_a?(Array)
          normalized["resources"] = normalized["resources"].map do |resource|
            next resource unless resource.is_a?(Hash)

            canonical_discovery_value(
              resource.merge(
                "shortNames" => Array(resource["shortNames"]),
                "categories" => Array(resource["categories"])
              )
            )
          end
        end
        normalized
      when Array
        values = value.map { |entry| canonical_discovery_value(entry) }
        if values.all? { |entry| entry.is_a?(Hash) && (entry.key?("name") || entry.key?("resource")) }
          values.sort_by { |entry| [entry["name"].to_s, entry["resource"].to_s] }
        else
          values
        end
      else
        value
      end
    end

    def validate_surface_matrix(entries, expected_ids, errors, label, require_applicability:, pinned_expected_by_id:)
      unless entries.is_a?(Array) && expected_ids.is_a?(Array) && entries.length == expected_ids.length
        errors << "API surface #{label} matrix must match its registry inventory"
        return
      end
      ids = entries.filter_map.with_index do |entry, index|
        unless entry.is_a?(Hash)
          errors << "API surface #{label} matrix entry #{index} must be an object"
          next
        end
        id = entry["id"]
        errors << "API surface #{label} matrix entry #{index} has no identifier" unless non_empty_string?(id)
        errors << "API surface #{label} matrix entry #{index} must run exactly once" unless entry["attempt_count"] == 1
        errors << "API surface #{label} matrix entry #{index} must pass" unless entry["passed"] == true
        default_off = (label == "GVR" ? DEFAULT_OFF_GVR_IDS : DEFAULT_OFF_GVK_IDS).include?(id.to_s)
        expected_availability = default_off ? "not_served_default" : "served"
        unless entry["availability"] == expected_availability
          errors << "API surface #{label} matrix entry #{index} availability profile is invalid"
        end
        if default_off
          unless entry["availability_reason"] == DEFAULT_OFF_REASON
            errors << "API surface #{label} matrix entry #{index} default-off reason is invalid"
          end
        else
          unless entry["availability_reason"].nil?
            errors << "API surface #{label} matrix entry #{index} served entry must not carry a default-off reason"
          end
        end
        API_SURFACE_FIELDS.each do |field|
          value = entry[field]
          case field
          when "verbs", "subresources", "shortNames", "categories"
            errors << "API surface #{label} matrix entry #{index} #{field} must be an array" unless value.is_a?(Array)
          when "schema_contract_present"
            errors << "API surface #{label} matrix entry #{index} schema contract presence must be boolean" unless [true,
                                                                                                                    false].include?(value)
          else
            errors << "API surface #{label} matrix entry #{index} #{field} must be a string" unless value.is_a?(String)
          end
        end
        validate_surface_fields(
          entry.slice(*API_SURFACE_FIELDS), errors,
          "API surface #{label} matrix entry #{index}"
        )
        %w[expected_present oracle_present rubernetes_present].each do |presence_key|
          if require_applicability && !entry.key?(presence_key)
            errors << "API surface #{label} matrix entry #{index} #{presence_key} is required"
            next
          end
          if entry.key?(presence_key) && entry[presence_key] != true && entry[presence_key] != false
            errors << "API surface #{label} matrix entry #{index} #{presence_key} must be boolean"
          end
        end
        validate_surface_identity(
          id, entry, errors, "API surface #{label} matrix entry #{index}", label
        )
        validate_surface_fields(
          entry["expected"], errors,
          "API surface #{label} matrix entry #{index} expected",
          allow_nil: require_applicability && entry["expected_present"] == false
        )
        validate_surface_identity(
          id, entry["expected"], errors, "API surface #{label} matrix entry #{index} expected", label
        )
        if pinned_expected_by_id.is_a?(Hash)
          pinned_expected = pinned_expected_by_id[id]
          if require_applicability
            errors << "API surface #{label} matrix entry #{index} expected presence differs from pinned discovery" unless
              entry["expected_present"] == !pinned_expected.nil?
          elsif pinned_expected.nil?
            errors << "API surface #{label} matrix entry #{index} is absent from pinned discovery"
          end
          errors << "API surface #{label} matrix entry #{index} expected fields differ from pinned discovery" unless
            entry["expected"] == pinned_expected
        end
        if require_applicability
          applicable = entry["schema_contract_applicable"]
          errors << "API surface #{label} matrix entry #{index} schema contract applicability must be boolean" unless [true,
                                                                                                                       false].include?(applicable)
          if (applicable == true) && entry["schema_contract_present"] != true
            errors << "API surface #{label} matrix entry #{index} requires a schema contract"
          end
        else
          errors << "API surface #{label} matrix entry #{index} requires a schema contract" unless entry["schema_contract_present"] == true
        end
        %w[oracle rubernetes].each do |source|
          observation = entry[source]
          unless observation.is_a?(Hash) && [true, false].include?(observation["present"])
            errors << "API surface #{label} matrix entry #{index} #{source} observation must record presence"
            next
          end
          if !default_off && (!require_applicability || entry["expected_present"] == true) && observation["present"] != true
            errors << "API surface #{label} matrix entry #{index} #{source} must be present for a discovered surface"
          end
          if observation["present"] == true
            validate_surface_fields(
              observation["fields"], errors,
              "API surface #{label} matrix entry #{index} #{source}"
            )
            validate_surface_identity(
              id, observation["fields"], errors,
              "API surface #{label} matrix entry #{index} #{source}", label
            )
            errors << "API surface #{label} matrix entry #{index} #{source} digest is required" unless valid_digest?(observation["sha256"])
            if valid_digest?(observation["sha256"]) && observation["fields"].is_a?(Hash)
              expected_digest = canonical_document_digest(observation["fields"])
              errors << "API surface #{label} matrix entry #{index} #{source} digest does not match fields" unless
                observation["sha256"] == expected_digest
            end
          else
            unless observation["fields"].nil?
              errors << "API surface #{label} matrix entry #{index} #{source} absent observation must not carry fields"
            end
            unless observation["sha256"].nil?
              errors << "API surface #{label} matrix entry #{index} #{source} absent observation must not carry a digest"
            end
          end
        end
        if entry["expected"].is_a?(Hash) && entry["oracle"].is_a?(Hash) && entry["rubernetes"].is_a?(Hash) &&
           entry["oracle"]["present"] == true && entry["rubernetes"]["present"] == true
          expected_fields = entry["expected"]
          errors << "API surface #{label} matrix entry #{index} oracle fields differ from pinned discovery" unless
            entry["oracle"]["fields"] == expected_fields
          errors << "API surface #{label} matrix entry #{index} Rubernetes fields differ from pinned discovery" unless
            entry["rubernetes"]["fields"] == expected_fields
        end
        id if non_empty_string?(id)
      end
      errors << "API surface #{label} matrix identifiers must be unique" unless ids.uniq.length == ids.length
      return unless expected_ids.all? { |id| non_empty_string?(id) }

      errors << "API surface #{label} matrix inventory differs from registry" unless ids.sort == expected_ids.sort
    end

    def validate_surface_fields(fields, errors, label, allow_nil: false)
      return if fields.nil? && allow_nil

      unless fields.is_a?(Hash)
        errors << "#{label} fields must be an object"
        return
      end
      keys = fields.keys
      errors << "#{label} fields must contain exactly the API surface fields" unless
        keys.all?(String) && keys.sort == API_SURFACE_FIELDS.sort
      API_SURFACE_FIELDS.each do |field|
        value = fields[field]
        case field
        when "verbs", "subresources", "shortNames", "categories"
          errors << "#{label} #{field} must be an array of strings" unless value.is_a?(Array) && value.all?(String)
        when "schema_contract_present"
          errors << "#{label} schema contract presence must be boolean" unless [true, false].include?(value)
        else
          errors << "#{label} #{field} must be a string" unless value.is_a?(String)
        end
      end
    end

    def validate_surface_identity(id, fields, errors, label, matrix_label)
      return unless non_empty_string?(id) && fields.is_a?(Hash)

      parts = id.split("/", 3)
      unless parts.length == 3 && parts.all? { |part| non_empty_string?(part) }
        errors << "#{label} identifier must contain group, version, and name"
        return
      end
      expected_group = parts.fetch(0) == "core" ? "" : parts.fetch(0)
      expected_version = parts.fetch(1)
      errors << "#{label} group does not match its identifier" if fields["group"] != expected_group
      errors << "#{label} version does not match its identifier" if fields["version"] != expected_version
      expected_name = parts.fetch(2)
      field_name = matrix_label == "GVR" ? fields["resource"] : fields["kind"]
      return unless field_name != expected_name

      errors << "#{label} #{matrix_label == "GVR" ? "resource" : "kind"} does not match its identifier"
    end

    def validate_header_observation_pair(observation, errors, label, compare: true)
      unless observation.is_a?(Hash) && %w[expected actual].all? { |key| observation[key].is_a?(Hash) }
        errors << "#{label} header observation must include expected and actual objects"
        return
      end
      %w[expected actual].each do |source|
        source_observation = observation.fetch(source)
        all_headers = source_observation["all"]
        compared_headers = source_observation["compared"]
        excluded = source_observation["excluded"]
        unless all_headers.is_a?(Hash) && compared_headers.is_a?(Hash) && excluded.is_a?(Array)
          errors << "#{label} #{source} header observation is malformed"
          next
        end
        %w[all_sha256 compared_sha256].each do |digest_key|
          errors << "#{label} #{source} header observation #{digest_key} is invalid" unless valid_digest?(source_observation[digest_key])
        end
        if valid_digest?(source_observation["all_sha256"]) && source_observation["all_sha256"] != canonical_document_digest(all_headers)
          errors << "#{label} #{source} all-header digest does not match its preimage"
        end
        if valid_digest?(source_observation["compared_sha256"]) && source_observation["compared_sha256"] != canonical_document_digest(compared_headers)
          errors << "#{label} #{source} compared-header digest does not match its preimage"
        end
        unless all_headers.keys.all? { |name| name.is_a?(String) && name == name.downcase && name.match?(/\A[a-z0-9-]+\z/) }
          errors << "#{label} #{source} header observation names must be normalized lowercase tokens"
        end
        errors << "#{label} #{source} header observation values must be strings" unless all_headers.values.all?(String)
        errors << "#{label} #{source} header observation excludes an unexpected header" unless
          excluded.all? { |name| HEADER_EXCLUSION_ALLOWLIST.key?(name) }
        expected_compared = all_headers.reject { |name, _value| HEADER_EXCLUSION_ALLOWLIST.key?(name) }
        errors << "#{label} #{source} header observation hides a semantic header" unless compared_headers == expected_compared
        expected_excluded = all_headers.keys.select { |name| HEADER_EXCLUSION_ALLOWLIST.key?(name) }.sort
        errors << "#{label} #{source} header observation exclusion inventory is incorrect" unless excluded.sort == expected_excluded
      end
      expected_headers = observation.dig("expected", "compared")
      actual_headers = observation.dig("actual", "compared")
      return unless compare && expected_headers.is_a?(Hash) && actual_headers.is_a?(Hash)

      errors << "#{label} semantic header comparison differs" unless expected_headers == actual_headers
    end

    def validate_oracle(document, expected_count, expected_items, errors, label)
      oracle = document["oracle"]
      unless oracle.is_a?(Hash)
        errors << "#{label} Kubernetes oracle evidence is missing"
        return
      end
      expected_kind = label == "roundtrip" ? KUBERNETES_PROTOBUF_ORACLE_KIND : KUBERNETES_API_ORACLE_KIND
      validate_oracle_provenance(oracle, errors, "#{label} Kubernetes oracle", expected_kind: expected_kind)
      errors << "#{label} Kubernetes oracle was not executed" unless oracle["executed"] == true
      errors << "#{label} Kubernetes oracle version must be #{KUBERNETES_VERSION}" unless oracle["kubernetes_version"] == KUBERNETES_VERSION
      unless oracle["source_commit"] == KUBERNETES_SOURCE_COMMIT
        errors << "#{label} Kubernetes oracle source commit must be #{KUBERNETES_SOURCE_COMMIT}"
      end
      comparison_count = oracle["comparison_count"]
      unless integer?(comparison_count) && comparison_count == expected_count
        errors << "#{label} Kubernetes oracle comparison count must match the report inventory"
      end
      missing_count = oracle["missing_comparison_count"]
      errors << "#{label} Kubernetes oracle missing comparison count must be zero" unless integer?(missing_count) && missing_count.zero?
      errors << "#{label} Kubernetes oracle runner SHA-256 is required" unless valid_digest?(oracle["runner_sha256"])
      errors << "#{label} Kubernetes oracle request seed SHA-256 is required" unless valid_digest?(oracle["request_seed_sha256"])
      validate_api_execution_evidence(oracle, expected_items, errors) if label == "API"
      comparisons = oracle["comparisons"]
      unless comparisons.is_a?(Array)
        errors << "#{label} Kubernetes oracle comparisons are required"
        return
      end
      errors << "#{label} Kubernetes oracle comparison entries must match comparison_count" unless comparisons.length == comparison_count
      expected_ids = Array(expected_items).filter_map do |item|
        item.is_a?(Hash) ? (item["id"] || item["name"]) : item
      end
      expected_by_id = Array(expected_items).each_with_object({}) do |item, index|
        next unless item.is_a?(Hash)

        identifier = item["id"] || item["name"]
        index[identifier] = item if non_empty_string?(identifier)
      end
      comparison_ids = comparisons.filter_map.with_index do |comparison, index|
        unless comparison.is_a?(Hash)
          errors << "#{label} Kubernetes oracle comparison #{index} must be an object"
          next
        end
        identifier = comparison["id"] || comparison["name"]
        errors << "#{label} Kubernetes oracle comparison #{index} has no identifier" unless non_empty_string?(identifier)
        errors << "#{label} Kubernetes oracle comparison #{index} did not pass" unless comparison["passed"] == true
        attempts = comparison["attempt_count"] || comparison["attempts"]
        errors << "#{label} Kubernetes oracle comparison #{index} must run exactly once" unless attempts == 1
        expected_digest = comparison["expected_sha256"]
        actual_digest = comparison["actual_sha256"]
        unless comparison["expected_source"] == "kubernetes_external"
          errors << "#{label} Kubernetes oracle comparison #{index} expected source must be external Kubernetes"
        end
        unless comparison["actual_source"] == "rubernetes"
          errors << "#{label} Kubernetes oracle comparison #{index} actual source must be Rubernetes"
        end
        unless valid_digest?(expected_digest) && valid_digest?(actual_digest)
          errors << "#{label} Kubernetes oracle comparison #{index} must record both observable SHA-256 digests"
        end
        if valid_digest?(expected_digest) && valid_digest?(actual_digest) && expected_digest != actual_digest
          errors << "#{label} Kubernetes oracle comparison #{index} observable digests differ"
        end
        operation = expected_by_id[identifier]
        if label == "API" && operation
          errors << "#{label} Kubernetes oracle comparison #{index} expected digest is not bound to the API operation" unless
            expected_digest == operation["expected_sha256"]
          errors << "#{label} Kubernetes oracle comparison #{index} actual digest is not bound to the API operation" unless
            actual_digest == operation["actual_sha256"]
        end
        identifier if non_empty_string?(identifier)
      end
      return if comparison_ids.uniq.length == comparison_ids.length && comparison_ids.sort == expected_ids.sort

      errors << "#{label} Kubernetes oracle comparison inventory differs from the report inventory"
    end

    def validate_api_execution_evidence(oracle, operations, errors)
      records = oracle["container_execution"]
      unless records.is_a?(Array) && !records.empty?
        errors << "API Kubernetes oracle raw container execution is required"
        return
      end
      records.each_with_index do |record, index|
        unless record.is_a?(Hash) && record.keys.sort == %w[argv exit_status sequence stderr stdout]
          errors << "API Kubernetes oracle container execution #{index} is malformed"
          next
        end
        errors << "API Kubernetes oracle container execution #{index} sequence is invalid" unless record["sequence"] == index
        errors << "API Kubernetes oracle container execution #{index} argv is invalid" unless
          record["argv"].is_a?(Array) && record["argv"].all?(String)
        errors << "API Kubernetes oracle container execution #{index} raw stdout/stderr are required" unless
          record["stdout"].is_a?(String) && record["stderr"].is_a?(String)
        errors << "API Kubernetes oracle container execution #{index} exit status is invalid" unless integer?(record["exit_status"])
      end

      execution_digest = canonical_document_digest(records)
      errors << "API Kubernetes oracle container execution SHA-256 is invalid" unless valid_digest?(oracle["container_execution_sha256"])
      errors << "API Kubernetes oracle container execution digest does not match raw execution" unless
        oracle["container_execution_sha256"] == execution_digest
      validate_pinned_container_execution(records, errors)

      source_files = %w[tools/milestones/m1_api_probe.rb tools/milestones/m1_kubernetes_oracle.rb].map do |relative|
        path = File.join(PROJECT_ROOT, relative)
        {"path" => relative, "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
      end
      runner_material = {
        "source_files" => source_files,
        "pinned_images" => {"kube_apiserver" => KUBE_APISERVER_IMAGE, "etcd" => ETCD_IMAGE},
        "container_execution_sha256" => execution_digest
      }
      errors << "API Kubernetes oracle runner material differs from the executed probe" unless oracle["runner_material"] == runner_material
      errors << "API Kubernetes oracle runner SHA-256 is not bound to source, images, and execution" unless
        oracle["runner_sha256"] == canonical_document_digest(runner_material)
      errors << "API Kubernetes oracle kube-apiserver image is not pinned" unless oracle["kube_apiserver_image"] == KUBE_APISERVER_IMAGE
      errors << "API Kubernetes oracle etcd image is not pinned" unless oracle["etcd_image"] == ETCD_IMAGE

      stream = oracle["request_stream"]
      unless stream.is_a?(Array)
        errors << "API Kubernetes oracle exact request stream is required"
        return
      end
      stream.each_with_index do |record, index|
        unless record.is_a?(Hash) && record.keys.sort == %w[request request_sha256 sequence target]
          errors << "API Kubernetes oracle request stream entry #{index} is malformed"
          next
        end
        errors << "API Kubernetes oracle request stream entry #{index} sequence is invalid" unless record["sequence"] == index
        errors << "API Kubernetes oracle request stream entry #{index} target is invalid" unless
          %w[rubernetes kubernetes_external].include?(record["target"])
        errors << "API Kubernetes oracle request stream entry #{index} digest is invalid" unless valid_digest?(record["request_sha256"])
        if record["request"].is_a?(Hash) && valid_digest?(record["request_sha256"])
          errors << "API Kubernetes oracle request stream entry #{index} digest does not match request" unless
            record["request_sha256"] == canonical_document_digest(record["request"])
        else
          errors << "API Kubernetes oracle request stream entry #{index} request preimage is required"
        end
      end
      expected_stream = expected_api_request_stream(operations)
      errors << "API Kubernetes oracle request stream differs from the exact probe inventory" unless stream == expected_stream
      stream_digest = canonical_document_digest(stream)
      errors << "API Kubernetes oracle request stream SHA-256 is invalid" unless valid_digest?(oracle["request_stream_sha256"])
      unless oracle["request_stream_sha256"] == stream_digest
        errors << "API Kubernetes oracle request stream digest does not match its preimage"
      end
      unless oracle["request_seed_sha256"] == stream_digest
        errors << "API Kubernetes oracle request seed is not the exact request stream digest"
      end
    rescue Errno::ENOENT => error
      errors << "API Kubernetes oracle runner source is unavailable: #{error.message}"
    end

    def validate_pinned_container_execution(records, errors)
      [KUBE_APISERVER_IMAGE, ETCD_IMAGE].each do |image|
        inspect_argv = ["docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"]
        inspections = records.select { |record| record.is_a?(Hash) && record["argv"] == inspect_argv }
        errors << "API Kubernetes oracle must inspect pinned image #{image} exactly once" unless inspections.one?
        next unless inspections.one?

        inspection = inspections.first
        valid_output = begin
          inspection["exit_status"] == 0 && Array(JSON.parse(inspection["stdout"])).include?(image)
        rescue JSON::ParserError, TypeError
          false
        end
        errors << "API Kubernetes oracle pinned image inspection output is invalid for #{image}" unless valid_output
        runs = records.select do |record|
          argv = record.is_a?(Hash) ? record["argv"] : nil
          argv.is_a?(Array) && argv.first(2) == %w[docker run] && argv.include?(image) && record["exit_status"] == 0
        end
        errors << "API Kubernetes oracle must run pinned image #{image} exactly once" unless runs.one?
      end
      required_commands = {
        "isolated network creation" => ->(argv) { argv.first(3) == %w[docker network create] },
        "etcd health check" => ->(argv) { argv.first(2) == %w[docker exec] && argv.include?("endpoint") && argv.include?("health") },
        "kube-apiserver port lookup" => ->(argv) { argv.first(2) == %w[docker port] && argv.last == "6443/tcp" }
      }
      required_commands.each do |label, predicate|
        errors << "API Kubernetes oracle container execution lacks #{label}" unless records.any? do |record|
          record.is_a?(Hash) && record["exit_status"] == 0 && record["argv"].is_a?(Array) && predicate.call(record["argv"])
        end
      end
    end

    def expected_api_request_stream(operations)
      sequence = 0
      stream = []
      append_pair = lambda do |request|
        %w[rubernetes kubernetes_external].each do |target|
          stream << request_stream_entry(sequence, target, request)
          sequence += 1
        end
      end
      pinned_discovery_endpoint_inventory.each do |entry|
        append_pair.call(api_request("GET", entry.fetch("path")))
      end
      append_pair.call(api_request(
        "POST", "/api/v1/namespaces",
        body: {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => API_NAMESPACE}}
      ))
      operations_by_id = Array(operations).to_h do |operation|
        [operation.is_a?(Hash) ? operation["id"] : nil, operation]
      end
      REQUIRED_API_OPERATION_INVENTORY.each do |inventory|
        if inventory.fetch("id") == "eviction-invalid-delete-options"
          # Eviction fixtures: the namespace's default service account (the
          # isolated kube-apiserver runs ServiceAccount admission) and the pod.
          append_pair.call(api_request(
            "POST", "/api/v1/namespaces/#{API_NAMESPACE}/serviceaccounts",
            body: {"apiVersion" => "v1", "kind" => "ServiceAccount", "metadata" => {"name" => "default", "namespace" => API_NAMESPACE}}
          ))
          append_pair.call(api_request(
            "POST", "/api/v1/namespaces/#{API_NAMESPACE}/pods",
            body: {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "m1-evict", "namespace" => API_NAMESPACE},
                   "spec" => {"containers" => [{"name" => "m1", "image" => "m1.example.com/pause:1"}]}}
          ))
        end
        if inventory.fetch("id") == "watch"
          operation = operations_by_id["watch"]
          actual_rv = operation.is_a?(Hash) ? operation.dig("resource_version_observation", "actual", "start_resourceVersion") : nil
          expected_rv = operation.is_a?(Hash) ? operation.dig("resource_version_observation", "expected", "start_resourceVersion") : nil
          request = inventory.fetch("request")
          actual_request = request.merge("query" => request.fetch("query").merge("resourceVersion" => actual_rv.to_s))
          expected_request = request.merge("query" => request.fetch("query").merge("resourceVersion" => expected_rv.to_s))
          stream << request_stream_entry(sequence, "rubernetes", actual_request)
          sequence += 1
          stream << request_stream_entry(sequence, "kubernetes_external", expected_request)
          sequence += 1
          next
        end
        append_pair.call(inventory.fetch("request"))
      end
      stream
    end

    def api_request(method, path, body: nil, query: {}, headers: {})
      {
        "method" => method,
        "path" => path,
        "query" => query,
        "headers" => {"user-agent" => API_USER_AGENT}.merge(headers),
        "body" => body
      }
    end

    def request_stream_entry(sequence, target, request)
      request = JSON.parse(JSON.generate(request))
      {
        "sequence" => sequence, "target" => target, "request" => request,
        "request_sha256" => canonical_document_digest(request)
      }
    end

    def validate_semantic_oracle(document, expected_count, expected_items, errors)
      label = "roundtrip semantic Kubernetes oracle"
      oracle = document["semantic_oracle"]
      unless oracle.is_a?(Hash)
        errors << "#{label} evidence is missing"
        return
      end
      validate_oracle_provenance(oracle, errors, label, expected_kind: KUBERNETES_SEMANTICS_ORACLE_KIND)
      errors << "#{label} was not executed" unless oracle["executed"] == true
      errors << "#{label} Kubernetes version must be #{KUBERNETES_VERSION}" unless oracle["kubernetes_version"] == KUBERNETES_VERSION
      unless oracle["source_commit"] == KUBERNETES_SOURCE_COMMIT
        errors << "#{label} Kubernetes source commit must be #{KUBERNETES_SOURCE_COMMIT}"
      end
      source_identity = oracle.dig("provenance", "source")
      unless non_empty_string?(oracle["source_root"]) && source_identity.is_a?(Hash) && oracle["source_root"] == source_identity["root"]
        errors << "#{label} source root must match provenance"
      end
      errors << "#{label} source checkout must be clean" unless oracle["source_tree_clean"] == true
      unless integer?(oracle["comparison_count"]) && oracle["comparison_count"] == expected_count
        errors << "#{label} comparison count must match the report inventory"
      end
      unless integer?(oracle["missing_comparison_count"]) && oracle["missing_comparison_count"].zero?
        errors << "#{label} missing comparison count must be zero"
      end
      errors << "#{label} runner SHA-256 is required" unless valid_digest?(oracle["runner_sha256"])
      errors << "#{label} request seed SHA-256 is required" unless valid_digest?(oracle["request_seed_sha256"])
      validate_semantic_validation_criterion(oracle, expected_count, expected_items, errors, label)
      comparisons = oracle["comparisons"]
      unless comparisons.is_a?(Array)
        errors << "#{label} comparisons are required"
        return
      end
      errors << "#{label} comparison entries must match comparison_count" unless comparisons.length == oracle["comparison_count"]
      expected_ids = Array(expected_items).filter_map do |item|
        item.is_a?(Hash) ? (item["id"] || item["name"]) : item
      end
      comparison_ids = comparisons.filter_map.with_index do |comparison, index|
        unless comparison.is_a?(Hash)
          errors << "#{label} comparison #{index} must be an object"
          next
        end
        identifier = comparison["id"] || comparison["name"]
        errors << "#{label} comparison #{index} has no identifier" unless non_empty_string?(identifier)
        errors << "#{label} comparison #{index} did not pass" unless comparison["passed"] == true
        errors << "#{label} comparison #{index} recorded a helper error" if non_empty_string?(comparison["external_error"])
        attempts = comparison["attempt_count"] || comparison["attempts"]
        errors << "#{label} comparison #{index} must run exactly once" unless attempts == 1
        json_expected_digest = comparison["json_expected_sha256"]
        json_actual_digest = comparison["json_actual_sha256"]
        unless comparison["json_expected_source"] == "kubernetes_external"
          errors << "#{label} comparison #{index} JSON expected source must be external Kubernetes"
        end
        unless comparison["json_actual_source"] == "rubernetes"
          errors << "#{label} comparison #{index} JSON actual source must be Rubernetes"
        end
        unless valid_digest?(json_expected_digest) && valid_digest?(json_actual_digest)
          errors << "#{label} comparison #{index} JSON must record expected and actual SHA-256 digests"
        end
        if valid_digest?(json_expected_digest) && valid_digest?(json_actual_digest) && json_expected_digest != json_actual_digest
          errors << "#{label} comparison #{index} JSON observable digests differ"
        end
        json_dimension = comparison["json"]
        if json_dimension.is_a?(Hash)
          validate_semantic_dimension(json_dimension, errors, "#{label} comparison #{index} JSON", require_applicability: true)
          errors << "#{label} comparison #{index} JSON top-level digest/source fields do not match the dimension record" unless
            comparison["json_expected_sha256"] == json_dimension["expected_sha256"] &&
            comparison["json_actual_sha256"] == json_dimension["actual_sha256"] &&
            comparison["json_expected_source"] == json_dimension["expected_source"] &&
            comparison["json_actual_source"] == json_dimension["actual_source"]
          %w[raw_sha256 canonical_sha256 unknown_raw_sha256 unknown_canonical_sha256].each do |digest_name|
            expected_observation = json_dimension.dig("expected_observation", digest_name)
            actual_observation = json_dimension.dig("actual_observation", digest_name)
            unless valid_digest?(expected_observation) && valid_digest?(actual_observation)
              errors << "#{label} comparison #{index} JSON #{digest_name} must record external and local digests"
            end
          end
        else
          errors << "#{label} comparison #{index} JSON dimension is required"
        end
        %w[defaulting validation].each do |dimension|
          expected_digest = comparison["#{dimension}_expected_sha256"]
          actual_digest = comparison["#{dimension}_actual_sha256"]
          unless comparison["#{dimension}_expected_source"] == "kubernetes_external"
            errors << "#{label} comparison #{index} #{dimension} expected source must be external Kubernetes"
          end
          unless comparison["#{dimension}_actual_source"] == "rubernetes"
            errors << "#{label} comparison #{index} #{dimension} actual source must be Rubernetes"
          end
          unless valid_digest?(expected_digest) && valid_digest?(actual_digest)
            errors << "#{label} comparison #{index} #{dimension} must record expected and actual SHA-256 digests"
          end
          if valid_digest?(expected_digest) && valid_digest?(actual_digest) && expected_digest != actual_digest
            errors << "#{label} comparison #{index} #{dimension} observable digests differ"
          end
          applicable = comparison["#{dimension}_applicable"]
          dimension_record = comparison[dimension]
          if dimension_record.is_a?(Hash)
            validate_semantic_dimension(dimension_record, errors, "#{label} comparison #{index} #{dimension}", require_applicability: true)
            errors << "#{label} comparison #{index} #{dimension} top-level digest/source fields do not match the dimension record" unless
              comparison["#{dimension}_expected_sha256"] == dimension_record["expected_sha256"] &&
              comparison["#{dimension}_actual_sha256"] == dimension_record["actual_sha256"] &&
              comparison["#{dimension}_expected_source"] == dimension_record["expected_source"] &&
              comparison["#{dimension}_actual_source"] == dimension_record["actual_source"]
            if dimension == "defaulting" && applicable == true
              expected_observation = dimension_record["expected_observation"]
              actual_observation = dimension_record["actual_observation"]
              unless expected_observation.is_a?(Hash) && actual_observation.is_a?(Hash)
                errors << "#{label} comparison #{index} defaulting observations are required"
              end
              if expected_observation.is_a?(Hash) && actual_observation.is_a?(Hash)
                errors << "#{label} comparison #{index} defaulting scheme registration must be recorded" unless [true,
                                                                                                                 false].include?(expected_observation["scheme_registered"])
                %w[before_sha256 after_sha256].each do |digest_name|
                  unless valid_digest?(expected_observation[digest_name]) && valid_digest?(actual_observation[digest_name])
                    errors << "#{label} comparison #{index} defaulting #{digest_name} must be recorded for both sources"
                  end
                end
              end
            end
          else
            errors << "#{label} comparison #{index} #{dimension} dimension is required"
          end
          errors << "#{label} comparison #{index} #{dimension} applicability must be boolean" unless [true, false].include?(applicable)
          if (applicable == false) && !non_empty_string?(dimension_record && dimension_record["reason"])
            errors << "#{label} comparison #{index} #{dimension} N/A reason is required"
          end
        end
        identifier if non_empty_string?(identifier)
      end
      return if comparison_ids.uniq.length == comparison_ids.length && comparison_ids.sort == expected_ids.sort

      errors << "#{label} comparison inventory differs from the report inventory"
    end

    VALIDATION_LEDGER_MODES = %w[strategy constructor handler list rest_endpoint response].freeze

    # Every generated type must be validated through an executable upstream
    # path: a REST strategy (with source-backed collaborators), a REST handler
    # validation function, the item owner of a list envelope, or, for request
    # and response types the apiserver never validates on create/update, the
    # API differential operations against the isolated kube-apiserver.
    def validate_validation_ledger_modes(ledger, errors, label)
      differential = api_differential_operations
      ledger.each_with_index do |entry, index|
        next unless entry.is_a?(Hash)

        errors << "#{label} ledger entry #{index} must be applicable" unless entry["applicable"] == true
        mode = entry["mode"]
        unless VALIDATION_LEDGER_MODES.include?(mode)
          errors << "#{label} ledger entry #{index} mode #{mode.inspect} is not an executable validation path"
        end
        collaborators = entry["collaborators"]
        if mode == "constructor" && collaborators.is_a?(Array) && !collaborators.empty?
          collaborators.each do |collaborator|
            unless collaborator.is_a?(Hash) && non_empty_string?(collaborator["implementation"]) && non_empty_string?(collaborator["source_path"]) && non_empty_string?(collaborator["expression"])
              errors << "#{label} ledger entry #{index} collaborator provenance is incomplete"
            end
          end
        end
        next unless %w[rest_endpoint response].include?(mode) || entry.dig("evidence", "report") == "api-differential"

        evidence = entry["evidence"]
        operations = evidence.is_a?(Hash) ? Array(evidence["operations"]) : []
        if operations.empty? || evidence["report"] != "api-differential"
          errors << "#{label} ledger entry #{index} (#{entry["id"]}) must reference API differential operations"
          next
        end
        if differential.nil?
          errors << "#{label} ledger entry #{index} (#{entry["id"]}) references the API differential, which is missing from this bundle"
          next
        end
        operations.each do |operation|
          record = differential[operation]
          unless record.is_a?(Hash) && record["passed"] == true
            errors << "#{label} ledger entry #{index} (#{entry["id"]}) references API differential operation #{operation.inspect}, which was not executed or did not pass"
          end
        end
      end
    end

    # Comparison and discovery-surface records of the api-differential report
    # in the bundle being evaluated, keyed by operation id.
    def api_differential_evidenced?(comparison)
      %w[rest_endpoint response].include?(comparison["mode"]) || comparison.dig("evidence", "report") == "api-differential"
    end

    def validate_api_differential_reference(comparison, errors, label)
      evidence = comparison["evidence"]
      operations = evidence.is_a?(Hash) ? Array(evidence["operations"]) : []
      if operations.empty? || evidence["report"] != "api-differential"
        errors << "#{label} must reference API differential operations"
        return
      end
      differential = api_differential_operations
      if differential.nil?
        errors << "#{label} references the API differential, which is missing from this bundle"
        return
      end
      operations.each do |operation|
        record = differential[operation]
        unless record.is_a?(Hash) && record["passed"] == true
          errors << "#{label} references API differential operation #{operation.inspect}, which was not executed or did not pass"
        end
      end
    end

    def api_differential_operations
      return @api_differential_operations if defined?(@api_differential_operations) && !@api_differential_operations.nil?
      return nil unless defined?(@evidence_directory) && @evidence_directory

      path = REPORTS.fetch("api", {}).fetch(:names, %w[api-differential.json]).map do |name|
        ::File.join(@evidence_directory, name)
      end.find { |candidate| ::File.file?(candidate) }
      return nil unless path

      document = JSON.parse(::File.binread(path), max_nesting: 256)
      index = {}
      # The API probe reports its executed requests under "operations";
      # older reports used "comparisons".
      (Array(document["operations"]) + Array(document["comparisons"])).each { |record| index[record["id"]] = record if record.is_a?(Hash) }
      Array(document.dig("api_surface", "discovery_endpoints")).each do |record|
        index[record["id"] || record["path"]] = record if record.is_a?(Hash)
      end
      @api_differential_operations = index
    rescue JSON::ParserError, Errno::ENOENT, Errno::EACCES
      nil
    end

    def validate_semantic_validation_criterion(oracle, expected_count, expected_items, errors, label)
      criterion = oracle["validation_criterion"]
      unless criterion.is_a?(Hash)
        errors << "#{label} validation applicability criterion is required"
        return
      end
      status = criterion["status"]
      errors << "#{label} validation applicability criterion status is invalid" unless %w[COMPLETE INCOMPLETE].include?(status)
      applicable_count = criterion["applicable_count"]
      not_applicable_count = criterion["not_applicable_count"]
      unless integer?(applicable_count) && integer?(not_applicable_count) && applicable_count >= 0 && not_applicable_count >= 0 &&
             applicable_count + not_applicable_count == expected_count
        errors << "#{label} validation applicability counts must partition the report inventory"
      end
      expected_status = integer?(not_applicable_count) && not_applicable_count.zero? ? "COMPLETE" : "INCOMPLETE"
      errors << "#{label} validation applicability status does not match its N/A count" unless status == expected_status
      errors << "#{label} validation criterion remains INCOMPLETE" unless status == "COMPLETE"
      comparisons = oracle["comparisons"]
      if comparisons.is_a?(Array) && comparisons.all?(Hash)
        observed_applicable_count = comparisons.count { |comparison| comparison["validation_applicable"] == true }
        observed_not_applicable_count = comparisons.count { |comparison| comparison["validation_applicable"] == false }
        errors << "#{label} validation applicability counts do not match comparison records" unless
          applicable_count == observed_applicable_count && not_applicable_count == observed_not_applicable_count
      end

      ledger = criterion["ledger"]
      unless ledger.is_a?(Array) && ledger.length == expected_count
        errors << "#{label} validation applicability ledger must contain one entry per type"
        return
      end
      validate_validation_ledger_modes(ledger, errors, label)
      expected_ids = Array(expected_items).filter_map do |item|
        item.is_a?(Hash) ? (item["id"] || item["name"]) : item
      end
      comparison_by_id = if comparisons.is_a?(Array)
                           comparisons.each_with_object({}) do |comparison, index|
                             index[comparison["id"] || comparison["name"]] = comparison if comparison.is_a?(Hash)
                           end
                         else
                           {}
                         end
      ledger_ids = ledger.filter_map.with_index do |entry, index|
        unless entry.is_a?(Hash)
          errors << "#{label} validation applicability ledger entry #{index} must be an object"
          next
        end
        id = entry["id"] || entry["name"]
        errors << "#{label} validation applicability ledger entry #{index} has no identifier" unless non_empty_string?(id)
        applicable = entry["applicable"]
        errors << "#{label} validation applicability ledger entry #{index} applicability must be boolean" unless [true,
                                                                                                                  false].include?(applicable)
        if (applicable == false) && !non_empty_string?(entry["reason"])
          errors << "#{label} validation applicability ledger entry #{index} N/A reason is required"
        end
        comparison = comparison_by_id[id]
        if comparison
          unless comparison["validation_applicable"] == applicable
            errors << "#{label} validation applicability ledger entry #{index} does not match its comparison applicability"
          end
          errors << "#{label} validation applicability ledger entry #{index} reason does not match its comparison" unless entry["reason"] == comparison.dig(
            "validation", "reason"
          )
        end
        source_paths = entry["source_paths"]
        errors << "#{label} validation applicability ledger entry #{index} source paths must be a non-empty array" unless
          source_paths.is_a?(Array) && !source_paths.empty? && source_paths.all? { |path| non_empty_string?(path) }
        id if non_empty_string?(id)
      end
      return if ledger_ids.uniq.length == ledger_ids.length && ledger_ids.sort == expected_ids.sort

      errors << "#{label} validation applicability ledger inventory differs from the report inventory"
    end

    def validate_validation_oracle(document, expected_count, expected_items, errors)
      label = "roundtrip REST validation Kubernetes oracle"
      oracle = document["validation_oracle"]
      unless oracle.is_a?(Hash)
        errors << "#{label} evidence is missing"
        return
      end
      validate_oracle_provenance(oracle, errors, label, expected_kind: KUBERNETES_SEMANTICS_ORACLE_KIND)
      errors << "#{label} was not executed" unless oracle["executed"] == true
      errors << "#{label} Kubernetes version must be #{KUBERNETES_VERSION}" unless oracle["kubernetes_version"] == KUBERNETES_VERSION
      unless oracle["source_commit"] == KUBERNETES_SOURCE_COMMIT
        errors << "#{label} Kubernetes source commit must be #{KUBERNETES_SOURCE_COMMIT}"
      end
      errors << "#{label} source root must match provenance" unless non_empty_string?(oracle["source_root"]) && oracle.dig("provenance",
                                                                                                                           "source", "root") == oracle["source_root"]
      errors << "#{label} source checkout must be clean" unless oracle["source_tree_clean"] == true
      unless integer?(oracle["comparison_count"]) && oracle["comparison_count"] == expected_count
        errors << "#{label} comparison count must match the report inventory"
      end
      unless integer?(oracle["missing_comparison_count"]) && oracle["missing_comparison_count"].zero?
        errors << "#{label} missing comparison count must be zero"
      end
      errors << "#{label} runner SHA-256 is required" unless valid_digest?(oracle["runner_sha256"])
      errors << "#{label} request seed SHA-256 is required" unless valid_digest?(oracle["request_seed_sha256"])
      errors << "#{label} validation criterion digest is required" unless valid_digest?(oracle["validation_criterion_sha256"])

      semantic = document["semantic_oracle"]
      criterion = semantic.is_a?(Hash) ? semantic["validation_criterion"] : nil
      if criterion.is_a?(Hash) && valid_digest?(oracle["validation_criterion_sha256"]) && oracle["validation_criterion_sha256"] != canonical_document_digest(criterion)
        errors << "#{label} validation criterion digest does not match semantic evidence"
      end

      comparisons = oracle["comparisons"]
      unless comparisons.is_a?(Array) && comparisons.length == expected_count
        errors << "#{label} comparison entries must match comparison_count"
        return
      end
      expected_ids = Array(expected_items).filter_map { |item| item.is_a?(Hash) ? (item["id"] || item["name"]) : item }
      comparison_ids = comparisons.filter_map.with_index do |comparison, index|
        unless comparison.is_a?(Hash)
          errors << "#{label} comparison #{index} must be an object"
          next
        end
        id = comparison["id"] || comparison["name"]
        errors << "#{label} comparison #{index} has no identifier" unless non_empty_string?(id)
        errors << "#{label} comparison #{index} did not complete" unless comparison["passed"] == true
        applicable = comparison["applicable"]
        errors << "#{label} comparison #{index} applicability must be boolean" unless [true, false].include?(applicable)
        if applicable == true
          errors << "#{label} comparison #{index} owner schema is required" unless non_empty_string?(comparison["owner_schema"])
          path = comparison["target_path"]
          errors << "#{label} comparison #{index} target path must be an array" unless path.is_a?(Array)
          unless valid_digest?(comparison["operation_observation_sha256"])
            errors << "#{label} comparison #{index} operation observation digest is required"
          end
          if api_differential_evidenced?(comparison)
            # Request/response types the apiserver never validates on
            # create/update are proven by the API differential operations
            # they reference, not by REST strategy calls.
            validate_api_differential_reference(comparison, errors, "#{label} comparison #{index}")
          else
            validate_validation_operations(comparison, errors, "#{label} comparison #{index}")
          end
        else
          errors << "#{label} comparison #{index} N/A reason is required" unless non_empty_string?(comparison["reason"])
          errors << "#{label} comparison #{index} N/A result must not carry operations" if comparison.key?("operations")
        end
        source_paths = comparison["source_paths"]
        errors << "#{label} comparison #{index} source paths must be a non-empty array of paths" unless
          source_paths.is_a?(Array) && !source_paths.empty? && source_paths.all? { |path| non_empty_string?(path) }
        id if non_empty_string?(id)
      end
      unless comparison_ids.uniq.length == comparison_ids.length && comparison_ids.sort == expected_ids.sort
        errors << "#{label} comparison inventory differs from the report inventory"
      end

      catalog = oracle["error_catalog"]
      unless catalog.is_a?(Hash) && catalog.all? do |digest, entries|
               valid_digest?(digest) && entries.is_a?(Array) && entries.all? do |entry|
                 entry.is_a?(Hash) && %w[type field detail].all? { |key| entry[key].is_a?(String) }
               end
             end
        errors << "#{label} error catalog must contain digest-keyed error records"
      end
      if catalog.is_a?(Hash)
        referenced_catalog = {}
        comparisons.each_with_index do |comparison, _index|
          next unless comparison.is_a?(Hash) && comparison["applicable"] == true

          operations = comparison["operations"]
          next unless operations.is_a?(Hash)

          REQUIRED_VALIDATION_OPERATIONS.each do |operation_name|
            operation = operations[operation_name]
            next unless operation.is_a?(Hash)

            digest = operation["errors_sha256"]
            entries = operation["errors"]
            next unless valid_digest?(digest) && entries.is_a?(Array)

            referenced_catalog[digest] = entries
          end
        end
        unless catalog.keys.sort == referenced_catalog.keys.sort
          errors << "#{label} error catalog keys must exactly match operation error digests"
        end
        referenced_catalog.each do |digest, entries|
          errors << "#{label} error catalog entry #{digest} does not match operation errors" unless catalog[digest] == entries
        end
      end
      ruby_catalog = oracle["rubernetes_error_catalog"]
      return unless ruby_catalog

      unless ruby_catalog.is_a?(Hash) && ruby_catalog.all? do |digest, entries|
               valid_digest?(digest) && entries.is_a?(Array) && entries.all? do |entry|
                 entry.is_a?(Hash) && %w[type field detail].all? { |key| entry[key].is_a?(String) }
               end
             end
        errors << "#{label} Rubernetes error catalog must contain digest-keyed error records"
      end
    end

    def validate_validation_operations(comparison, errors, label)
      operations = comparison["operations"]
      unless operations.is_a?(Hash)
        errors << "#{label} operations must be an object"
        return
      end
      unless operations.keys.map(&:to_s).sort == REQUIRED_VALIDATION_OPERATIONS.sort
        errors << "#{label} operations must contain exactly #{REQUIRED_VALIDATION_OPERATIONS.join(", ")}"
      end

      observations = []
      all_expectations_match = true
      REQUIRED_VALIDATION_OPERATIONS.each do |operation_name|
        operation = operations[operation_name]
        unless operation.is_a?(Hash)
          errors << "#{label} #{operation_name} operation must be an object"
          all_expectations_match = false
          next
        end

        observations << operation
        operation_matches = validate_validation_operation(operation, errors, "#{label} #{operation_name}")
        all_expectations_match &&= operation_matches
      end
      if observations.length == REQUIRED_VALIDATION_OPERATIONS.length
        expected_digest = canonical_document_digest(observations)
        errors << "#{label} operation observation digest does not match raw operations" unless
          comparison["operation_observation_sha256"] == expected_digest
      end

      comparison_error = comparison["error"]
      errors << "#{label} top-level error must be null or an empty string" unless comparison_error.nil? || comparison_error == ""
      expected_passed = (comparison_error.nil? || comparison_error == "") && all_expectations_match
      errors << "#{label} passed must bind to completed operations and expectation matches" unless comparison["passed"] == expected_passed
    end

    def validate_validation_operation(operation, errors, label)
      expected_keys = %w[
        accepted completed error expected_accepted expectation_matches errors
        error_count errors_sha256 field_paths
      ]
      errors << "#{label} has an unexpected operation shape" unless operation.keys.map(&:to_s).sort == expected_keys.sort
      errors << "#{label} did not complete" unless operation["completed"] == true
      errors << "#{label} accepted must be boolean" unless [true, false].include?(operation["accepted"])
      errors << "#{label} expected_accepted must be boolean" unless [true, false].include?(operation["expected_accepted"])
      errors << "#{label} expectation_matches must be boolean" unless [true, false].include?(operation["expectation_matches"])
      errors << "#{label} error must be null or a string" unless operation["error"].nil? || operation["error"].is_a?(String)

      entries = operation["errors"]
      unless entries.is_a?(Array) && entries.all? do |entry|
               entry.is_a?(Hash) && entry.keys.map(&:to_s).sort == %w[detail field type] &&
               %w[type field detail].all? { |key| entry[key].is_a?(String) }
             end
        errors << "#{label} errors must contain only typed field error records"
        entries = []
      end
      errors << "#{label} error_count does not match raw errors" unless operation["error_count"] == entries.length
      expected_fields = entries.map { |entry| entry.fetch("field") }.uniq.sort
      errors << "#{label} field_paths do not match raw errors" unless operation["field_paths"] == expected_fields
      expected_errors_digest = canonical_document_digest(entries)
      errors << "#{label} errors_sha256 does not match raw errors" unless
        valid_digest?(operation["errors_sha256"]) && operation["errors_sha256"] == expected_errors_digest

      error_text = operation["error"].to_s
      accepted = operation["accepted"]
      expected_accepted = operation["expected_accepted"]
      semantic_acceptance = if expected_accepted == true
                              accepted == true && entries.empty? && error_text.empty?
                            elsif expected_accepted == false
                              accepted == false && !entries.empty? && error_text.empty?
                            else
                              false
                            end
      computed_match = operation["completed"] == true && accepted == expected_accepted && semantic_acceptance
      errors << "#{label} expectation_matches is not bound to accepted/error semantics" unless
        operation["expectation_matches"] == computed_match
      computed_match
    end

    def validate_unknown_field_mismatch_packet(document, expected_count, expected_items, errors)
      label = "roundtrip unknown-field mismatch packet"
      packet = document["unknown_field_mismatch_packet"]
      unless packet.is_a?(Hash)
        errors << "#{label} is required"
        return
      end
      errors << "#{label} must record execution" unless packet["executed"] == true
      errors << "#{label} comparison count must match the report inventory" unless packet["comparison_count"] == expected_count
      mismatch_count = packet["mismatch_count"]
      non_comparable_count = packet["non_comparable_count"]
      unless integer?(mismatch_count) && integer?(non_comparable_count) && mismatch_count >= 0 && non_comparable_count >= 0 && mismatch_count + non_comparable_count <= expected_count
        errors << "#{label} counts must be non-negative and partition no more than the report inventory"
      end
      expected_ids = Array(expected_items).filter_map { |item| item.is_a?(Hash) ? (item["id"] || item["name"]) : item }
      mismatches = packet["by_type"]
      unless mismatches.is_a?(Array) && mismatches.length == mismatch_count
        errors << "#{label} by-type mismatch entries must match mismatch_count"
        mismatches = []
      end
      mismatch_ids = mismatches.filter_map.with_index do |entry, index|
        unless entry.is_a?(Hash)
          errors << "#{label} mismatch entry #{index} must be an object"
          next
        end
        id = entry["id"]
        errors << "#{label} mismatch entry #{index} has no identifier" unless non_empty_string?(id)
        errors << "#{label} mismatch entry #{index} field is required" unless non_empty_string?(entry["field"])
        %w[kubernetes_preserved rubernetes_preserved].each do |key|
          errors << "#{label} mismatch entry #{index} #{key} must be boolean" unless [true, false].include?(entry[key])
        end
        %w[raw_sha256 kubernetes_canonical_sha256 rubernetes_canonical_sha256].each do |key|
          errors << "#{label} mismatch entry #{index} #{key} must be a digest" unless valid_digest?(entry[key])
        end
        id if non_empty_string?(id)
      end
      unless mismatch_ids.uniq.length == mismatch_ids.length && (mismatch_ids - expected_ids).empty?
        errors << "#{label} mismatch inventory contains duplicate or unknown identifiers"
      end

      non_comparable = packet["non_comparable_by_type"]
      unless non_comparable.is_a?(Array) && non_comparable.length == non_comparable_count
        errors << "#{label} non-comparable entries must match non_comparable_count"
        non_comparable = []
      end
      non_comparable_ids = non_comparable.filter_map.with_index do |entry, index|
        unless entry.is_a?(Hash)
          errors << "#{label} non-comparable entry #{index} must be an object"
          next
        end
        id = entry["id"]
        errors << "#{label} non-comparable entry #{index} has no identifier" unless non_empty_string?(id)
        errors << "#{label} non-comparable entry #{index} field is required" unless non_empty_string?(entry["field"])
        errors << "#{label} non-comparable entry #{index} reason is required" unless non_empty_string?(entry["reason"])
        id if non_empty_string?(id)
      end
      errors << "#{label} non-comparable inventory contains duplicate, unknown, or overlapping identifiers" unless
        non_comparable_ids.uniq.length == non_comparable_ids.length && (non_comparable_ids - expected_ids).empty? && (non_comparable_ids & mismatch_ids).empty?

      groups = packet["groups"]
      errors << "#{label} groups must be an array" unless groups.is_a?(Array)
      fix = packet["production_codec_fix_packet"]
      unless fix.is_a?(Hash) && fix["not_applied"] == true && fix["target_files"].is_a?(Array) && fix["target_files"].all? do |path|
        non_empty_string?(path)
      end
        errors << "#{label} production codec fix packet must be explicit and not applied"
      end
      return unless integer?(mismatch_count) && mismatch_count.positive?

      return if fix.is_a?(Hash) && fix["status"] == "REQUIRED"

      errors << "#{label} must mark the production codec fix REQUIRED while mismatches remain"
    end

    def validate_semantic_dimension(dimension, errors, label, require_applicability: false)
      if require_applicability
        applicable = dimension["applicable"]
        errors << "#{label} applicability must be boolean" unless [true, false].include?(applicable)
      end
      errors << "#{label} expected source must be external Kubernetes" unless dimension["expected_source"] == "kubernetes_external"
      errors << "#{label} actual source must be Rubernetes" unless dimension["actual_source"] == "rubernetes"
      expected_digest = dimension["expected_sha256"]
      actual_digest = dimension["actual_sha256"]
      unless valid_digest?(expected_digest) && valid_digest?(actual_digest)
        errors << "#{label} must record expected and actual SHA-256 digests"
      end
      if valid_digest?(expected_digest) && valid_digest?(actual_digest) && expected_digest != actual_digest
        errors << "#{label} observable digests differ"
      end
      errors << "#{label} must record a matching semantic result" unless dimension["matches"] == true
      unless dimension["expected"].is_a?(Hash) && dimension["actual"].is_a?(Hash)
        errors << "#{label} expected and actual observations are required"
      end
      return unless dimension["applicable"] == false

      reason = dimension["reason"]
      errors << "#{label} N/A reason is required" unless non_empty_string?(reason)
      expected = dimension["expected"]
      actual = dimension["actual"]
      unless expected.is_a?(Hash) && expected["applicable"] == false &&
             actual.is_a?(Hash) && actual["applicable"] == false
        errors << "#{label} N/A observations must be marked not applicable"
      end
    end

    def validate_oracle_provenance(oracle, errors, label, expected_kind:)
      provenance = oracle["provenance"]
      unless provenance.is_a?(Hash)
        errors << "#{label} provenance is required"
        return
      end
      errors << "#{label} provenance kind must be #{expected_kind}" unless provenance["kind"] == expected_kind
      errors << "#{label} provenance mode must be external" unless provenance["mode"] == "external"
      errors << "#{label} provenance must not be a self-comparison" unless provenance["self_comparison"] == false
      errors << "#{label} provenance implementation is required" unless non_empty_string?(provenance["implementation"])
      source = provenance["source"]
      unless source.is_a?(Hash)
        errors << "#{label} provenance source identity is required"
        return
      end
      errors << "#{label} provenance Kubernetes version must be #{KUBERNETES_VERSION}" unless source["version"] == KUBERNETES_VERSION
      unless source["commit"] == KUBERNETES_SOURCE_COMMIT
        errors << "#{label} provenance Kubernetes source commit must be #{KUBERNETES_SOURCE_COMMIT}"
      end
      errors << "#{label} provenance Kubernetes source tag must be #{KUBERNETES_VERSION}" unless source["tag"] == KUBERNETES_VERSION
      if [KUBERNETES_PROTOBUF_ORACLE_KIND, KUBERNETES_SEMANTICS_ORACLE_KIND].include?(expected_kind)
        errors << "#{label} provenance source root is required" unless non_empty_string?(source["root"])
        errors << "#{label} provenance source checkout must be clean" unless source["tree_clean"] == true
      else
        errors << "#{label} provenance image identity is required" unless non_empty_string?(source["apiserver_image"])
        errors << "#{label} provenance etcd image identity is required" unless non_empty_string?(source["etcd_image"])
        errors << "#{label} provenance network isolation must be true" unless source["network_isolated"] == true
      end
      unless valid_digest?(provenance["runner_sha256"]) && provenance["runner_sha256"] == oracle["runner_sha256"]
        errors << "#{label} provenance runner SHA-256 must match oracle"
      end
      unless valid_digest?(provenance["request_seed_sha256"]) && provenance["request_seed_sha256"] == oracle["request_seed_sha256"]
        errors << "#{label} provenance request seed SHA-256 must match oracle"
      end
      errors << "#{label} provenance SHA-256 is required" unless valid_digest?(provenance["provenance_sha256"])
      return unless valid_digest?(provenance["provenance_sha256"])

      expected = canonical_document_digest(provenance, excluded_keys: ["provenance_sha256"])
      errors << "#{label} provenance SHA-256 does not match canonical content" unless provenance["provenance_sha256"] == expected
    end

    def validate_protobuf_unsupported_inventory(document, errors)
      unsupported = document["protobuf_unsupported_types"]
      unless unsupported.is_a?(Array) && unsupported.length == 1
        errors << "roundtrip protobuf unsupported inventory must contain exactly one entry"
        return
      end

      entry = unsupported.first
      unless entry.is_a?(Hash) && entry["id"] == "io.k8s.apimachinery.pkg.version.Info" &&
             non_empty_string?(entry["reason"])
        errors << "roundtrip protobuf unsupported inventory must record the pinned upstream Info exception"
      end
    end

    def validate_kubectl(document, errors)
      operation_count = required_integer(document, %w[operation_count total_count], errors, "kubectl operation count")
      errors << "kubectl operation count must equal #{REQUIRED_OPERATIONS.length}" unless operation_count == REQUIRED_OPERATIONS.length
      operations = document["operations"] || document["results"]
      unless operations.is_a?(Array)
        errors << "kubectl transcript operations are missing"
        return
      end
      names = operations.map do |operation|
        operation.is_a?(Hash) ? (operation["operation"] || operation["name"]) : nil
      end
      errors << "kubectl transcript operation count does not match operations" unless operation_count == operations.length
      REQUIRED_OPERATIONS.each do |required_operation|
        errors << "kubectl #{required_operation} operation is missing" unless names.count(required_operation) == 1
      end
      errors << "kubectl transcript contains an unknown or duplicate operation" unless names.all? do |name|
        non_empty_string?(name)
      end && names.sort == REQUIRED_OPERATIONS.sort
      operations.each_with_index do |operation, index|
        unless operation.is_a?(Hash)
          errors << "kubectl operation #{index} must be an object"
          next
        end
        expected_exit = operation.key?("expected_exit_status") ? operation["expected_exit_status"] : 0
        errors << "kubectl operation #{index} did not pass" unless operation["exit_status"] == expected_exit && operation["passed"] == true
        name = operation["operation"] || operation["name"]
        command = Array(operation["command"])
        if name == "apply"
          errors << "kubectl apply must run strict client-side validation" if command.include?("--validate=false") || command.any? do |part|
            part.to_s.start_with?("--validate=") && part != "--validate=strict"
          end
        elsif name == "apply-invalid"
          unless expected_exit == 1 && operation["stderr"].to_s.include?("unknown field")
            errors << "kubectl apply-invalid must be rejected by client-side validation"
          end
        end
        errors << "kubectl operation #{index} has no name" unless non_empty_string?(operation["operation"] || operation["name"])
        attempt_count = operation["attempt_count"] || operation["attempts"]
        errors << "kubectl operation #{index} must run exactly once" unless attempt_count == 1
      end
      check_zero(document, %w[failure_count failures], errors, "kubectl failure count")
      check_zero(document, %w[unexpected_skip_count unexpected_skips], errors, "kubectl unexpected skip count")
      check_zero(document, %w[unclassified_count unclassified], errors, "kubectl unclassified count")
    end

    def validate_result_counts(manifest, artifacts, subjects, errors)
      counts = manifest["result_counts"]
      return unless counts.is_a?(Hash)

      expected_counts = {
        "commands" => manifest.fetch("commands", []).length,
        "artifacts" => artifacts.length,
        "subjects" => subjects.length,
        "command_failures" => manifest.fetch("commands", []).count { |command| command["exit_status"] != 0 },
        "reports" => REPORTS.length,
        "source_files" => manifest["input_file_count"]
      }
      expected_counts.each do |key, expected|
        errors << "result_counts #{key} is missing or invalid" unless integer?(counts[key])
        errors << "result_counts #{key} is incorrect" if integer?(counts[key]) && counts[key] != expected
      end
    end

    def required_integer(document, keys, errors, label)
      present = keys.select { |key| document.key?(key) }
      candidate = present.empty? ? nil : document[present.first]
      errors << "#{label} is missing or invalid" unless integer?(candidate) && candidate >= 0
      errors << "#{label} aliases disagree" unless present.all? { |key| document[key] == candidate }
      candidate if integer?(candidate) && candidate >= 0
    end

    def check_zero(document, keys, errors, label)
      present = keys.select { |key| document.key?(key) }
      return if !present.empty? && present.all? { |key| integer?(document[key]) && document[key].zero? }

      errors << "#{label} must be zero"
    end

    def value(document, keys)
      keys.each do |key|
        return document[key] if document.key?(key)
      end
      nil
    end

    def identity?(value)
      value.is_a?(Hash) && valid_digest?(value["sha256"]) && positive_integer?(value["file_count"])
    end

    def report_passed?(document)
      document["passed"] == true || %w[PASS PASSED COMPLETE].include?(document["status"])
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
  end
end

if $PROGRAM_NAME == __FILE__
  manifest_path = ARGV.fetch(0) { abort "Usage: m1_gate.rb PATH/manifest.json" }
  output = M1Gate.evaluate(manifest_path)
  puts(JSON.pretty_generate(output))
  exit(output.fetch("passed") ? 0 : 1)
end
