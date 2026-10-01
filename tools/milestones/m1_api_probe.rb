#!/usr/bin/env ruby
# frozen_string_literal: true

# Run one deterministic ConfigMap request sequence against the in-process
# Rubernetes API and an isolated, digest-pinned Kubernetes v1.36.2 oracle.

require "digest"
require "json"
require_relative "m1_probe_support"
require_relative "m1_kubernetes_oracle"
require_relative "m1_gate"

module M1APIDifferential
  REVIEW_TOKEN = M1KubernetesOracle::REVIEW_TOKEN
  USER_AGENT = "rubernetes-m1-oracle-probe/1"
  NAMESPACE = "m1-oracle"
  COLLECTION_PATH = "/api/v1/namespaces/#{NAMESPACE}/configmaps".freeze
  # Only transport-generated or hop-by-hop headers may be omitted from the
  # semantic comparison.  This is intentionally a closed, machine-readable
  # policy: a newly observed header is compared and therefore cannot be hidden
  # by adding a wildcard or a broad prefix.
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
  # These schemas remain part of the 321/153 compile-time corpus, but the
  # upstream v1.36.2 default API profile does not serve these compiled API
  # versions. Evidence
  # must record that absence explicitly; treating a 404 as a successful 200
  # comparison would make the surface report forgeable.
  DEFAULT_PROFILE = "kubernetes-v1.36.2-default"
  DEFAULT_FEATURE_GATES = {
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
  }.freeze
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
  class RecordingClient
    def initialize(client, target:, stream:)
      @client = client
      @target = target
      @stream = stream
    end

    def request(method:, path:, body: nil, query: nil, headers: {})
      request = M1APIDifferential.request_observation(
        method: method, path: path, body: body, query: query, headers: headers
      )
      @stream << {
        "sequence" => @stream.length,
        "target" => @target,
        "request" => request,
        "request_sha256" => M1Gate.canonical_document_digest(request)
      }
      @client.request(method: method, path: path, body: body, query: query, headers: headers)
    end
  end

  module_function

  def call_pair(rubernetes, oracle, method:, path:, body: nil, query: nil, headers: {})
    request_headers = {"User-Agent" => USER_AGENT}.merge(headers)
    rubernetes_response = rubernetes.request(
      method: method,
      path: path,
      body: clone_payload(body),
      query: query&.dup,
      headers: request_headers.dup
    )
    oracle_response = oracle.request(
      method: method,
      path: path,
      body: clone_payload(body),
      query: query&.dup,
      headers: request_headers.dup
    )
    [rubernetes_response, oracle_response]
  end

  def clone_payload(value)
    return nil if value.nil?
    return value.dup if value.is_a?(String)

    JSON.parse(JSON.generate(value))
  end

  def response_category(oracle_response, watch: false, initial_watch: false)
    return :initial_watch if initial_watch
    return :watch if watch
    return :status if oracle_response.body.is_a?(Hash) && oracle_response.body["kind"] == "Status"

    :resource
  end

  def body_signature(response, category, policy: nil)
    case category
    when :status
      M1KubernetesOracle.status_signature(response.body)
    when :watch
      M1KubernetesOracle.watch_signature(response.body)
    when :initial_watch
      M1KubernetesOracle.watch_signature(initial_watch_events(response.body))
    else
      M1KubernetesOracle.canonical_resource(apply_body_policy(response.body, policy))
    end
  end

  # The legacy componentstatus endpoint reports the live health of the
  # scheduler, controller manager and etcd of the serving host.  The two
  # servers run in different environments, so the health observation itself
  # (condition status/message/error) is an environment fact, not an API
  # contract; the inventory, names and condition types are compared exactly.
  COMPONENT_STATUS_POLICY = {
    "conditions[].status" => "<environment-health>",
    "conditions[].message" => "<environment-health>",
    "conditions[].error" => "<environment-health>",
    "items" => "sorted by metadata.name (kube-apiserver enumerates a map)"
  }.freeze

  def body_policy_document
    {"component_status" => COMPONENT_STATUS_POLICY}
  end

  def apply_body_policy(body, policy)
    return body unless policy == :component_status && body.is_a?(Hash)

    normalize_component = lambda do |component|
      next component unless component.is_a?(Hash)

      component.merge(
        "conditions" => Array(component["conditions"]).map do |condition|
          next condition unless condition.is_a?(Hash)

          normalized = condition.dup
          %w[status message error].each { |key| normalized[key] = "<environment-health>" if normalized.key?(key) }
          normalized
        end
      )
    end
    if body.key?("items")
      # kube-apiserver enumerates its component servers from a map, so the
      # list order is not part of the contract; compare the sorted inventory.
      items = Array(body["items"]).map { |item| normalize_component.call(item) }
      body.merge("items" => items.sort_by { |item| item.is_a?(Hash) ? item.dig("metadata", "name").to_s : "" })
    else
      normalize_component.call(body)
    end
  end

  def ownership_signature(response, category)
    case category
    when :watch, :initial_watch
      events = if category == :initial_watch
                 initial_watch_events(response.body)
               elsif response.body.is_a?(Hash)
                 [response.body]
               else
                 Array(response.body)
               end
      events.map { |event| M1KubernetesOracle.ownership_signature(event.is_a?(Hash) ? event["object"] : nil) }
    when :resource
      M1KubernetesOracle.ownership_signature(response.body)
    else
      []
    end
  end

  # Kubernetes may emit additional ordinary BOOKMARK events at any cadence once
  # bookmarks are allowed. The initial-events-end bookmark is the deterministic
  # part of this contract and is therefore the only bookmark compared here.
  def initial_watch_events(value)
    events = value.is_a?(Hash) ? [value] : Array(value)
    events.reject do |event|
      event.is_a?(Hash) && event["type"] == "BOOKMARK" &&
        event.dig("object", "metadata", "annotations", "k8s.io/initial-events-end") != "true"
    end
  end

  def header_policy
    HEADER_EXCLUSION_ALLOWLIST.transform_values(&:dup)
  end

  def normalized_headers(response)
    headers = response.respond_to?(:headers) ? response.headers : {}
    Hash(headers || {}).each_with_object({}) do |(raw_name, raw_value), normalized|
      name = raw_name.to_s.downcase
      value = if raw_value.is_a?(Array)
                raw_value.join(", ")
              else
                raw_value.to_s
              end
      normalized[name] = value
    end
  end

  def header_observation(response)
    all = normalized_headers(response)
    excluded = all.keys.select { |name| HEADER_EXCLUSION_ALLOWLIST.key?(name) }.sort
    compared = all.reject { |name, _value| HEADER_EXCLUSION_ALLOWLIST.key?(name) }
    {
      "all" => all,
      "compared" => compared,
      "excluded" => excluded,
      "all_sha256" => M1Gate.canonical_document_digest(all),
      "compared_sha256" => M1Gate.canonical_document_digest(compared)
    }
  end

  def header_signature(response)
    header_observation(response).fetch("compared")
  end

  def observable(response, category:, causality: nil, policy: nil)
    result = {
      "status" => response.status,
      "headers" => header_signature(response),
      "body" => body_signature(response, category, policy: policy),
      "ownership" => ownership_signature(response, category)
    }
    result["resourceVersion_causality"] = causality_signature(causality) if causality
    result
  end

  def digest(value)
    Digest::SHA256.hexdigest(JSON.generate(value))
  end

  def request_observation(method:, path:, body: nil, query: nil, headers: {})
    {
      "method" => method.to_s.upcase,
      "path" => path.to_s,
      "query" => Hash(query || {}).transform_keys(&:to_s).transform_values(&:to_s),
      "headers" => normalized_headers(Struct.new(:headers).new({"User-Agent" => USER_AGENT}.merge(headers))),
      "body" => clone_payload(body)
    }
  end

  def operation(id, method:, path:, rubernetes:, oracle:, request:, defaulting: false, validation: false,
                watch: false, initial_watch: false, rubernetes_causality: nil, oracle_causality: nil,
                body_policy: nil)
    category = response_category(oracle, watch: watch, initial_watch: initial_watch)
    rubernetes_body = body_signature(rubernetes, category, policy: body_policy)
    oracle_body = body_signature(oracle, category, policy: body_policy)
    rubernetes_ownership = ownership_signature(rubernetes, category)
    oracle_ownership = ownership_signature(oracle, category)
    status_matches = rubernetes.status == oracle.status
    header_matches = header_signature(rubernetes) == header_signature(oracle)
    body_matches = rubernetes_body == oracle_body
    ownership_matches = rubernetes_ownership == oracle_ownership
    watch_operation = watch || initial_watch
    causality_matches = if watch_operation
                          rubernetes_causality.is_a?(Hash) && oracle_causality.is_a?(Hash) &&
                            rubernetes_causality["valid"] == true && oracle_causality["valid"] == true
                        else
                          true
                        end
    status_body_matches = category == :status ? body_matches : true
    defaulting_matches = defaulting ? body_matches : true
    validation_matches = validation ? status_body_matches : true
    watch_matches = watch_operation ? body_matches && ownership_matches && causality_matches : true
    expected_observable = observable(oracle, category: category, causality: oracle_causality, policy: body_policy)
    actual_observable = observable(rubernetes, category: category, causality: rubernetes_causality, policy: body_policy)
    expected_sha256 = M1Gate.canonical_document_digest(expected_observable)
    actual_sha256 = M1Gate.canonical_document_digest(actual_observable)
    passed = expected_sha256 == actual_sha256 && causality_matches
    dimensions = {
      "status" => status_matches,
      "headers" => header_matches,
      "body" => body_matches,
      "status_body" => status_body_matches,
      "defaulting" => defaulting_matches,
      "validation" => validation_matches,
      "ownership" => ownership_matches,
      "watch" => watch_matches,
      "resourceVersion_causality" => causality_matches
    }
    {
      "id" => id,
      "method" => method,
      "path" => path,
      "body_policy" => body_policy&.to_s,
      "request" => request,
      "request_sha256" => M1Gate.canonical_document_digest(request),
      "oracle_status" => oracle.status,
      "rubernetes_status" => rubernetes.status,
      "status_matches" => status_matches,
      "header_matches" => header_matches,
      "body_matches" => body_matches,
      "status_body_matches" => status_body_matches,
      "defaulting_matches" => defaulting_matches,
      "validation_matches" => validation_matches,
      "ownership_matches" => ownership_matches,
      "watch_matches" => watch_matches,
      "resource_version_causality_matches" => causality_matches,
      "expected_sha256" => expected_sha256,
      "actual_sha256" => actual_sha256,
      "header_observation" => {
        "expected" => header_observation(oracle),
        "actual" => header_observation(rubernetes)
      },
      "resource_version_observation" => if watch_operation
                                          {
                                            "expected" => oracle_causality,
                                            "actual" => rubernetes_causality,
                                            "expected_sha256" => M1Gate.canonical_document_digest(oracle_causality),
                                            "actual_sha256" => M1Gate.canonical_document_digest(rubernetes_causality)
                                          }
                                        end,
      "attempt_count" => 1,
      "differences" => dimensions.reject { |_name, matches| matches }.keys,
      # Keep the complete observable packets in the report.  A digest without
      # its preimage lets a producer claim equality by writing the same
      # arbitrary SHA-256 on both sides.
      "oracle_observable" => expected_observable,
      "rubernetes_observable" => actual_observable,
      "passed" => passed
    }
  end

  def resource_version(response)
    value = response.body.is_a?(Hash) ? response.body.dig("metadata", "resourceVersion") : nil
    Integer(value, 10)
  rescue ArgumentError, TypeError
    nil
  end

  def positive_resource_version(value)
    parsed = Integer(value, 10)
    parsed.positive? ? parsed : nil
  rescue ArgumentError, TypeError
    nil
  end

  def initial_watch_causality(response)
    events = initial_watch_events(response.body)
    records = events.map do |event|
      {
        "type" => event.is_a?(Hash) ? event["type"].to_s : "",
        "resourceVersion" => event.is_a?(Hash) ? event.dig("object", "metadata", "resourceVersion").to_s : "",
        "initial_events_end" => event.is_a?(Hash) &&
          event.dig("object", "metadata", "annotations", "k8s.io/initial-events-end") == "true"
      }
    end
    bookmark_indices = records.each_index.select { |index| records[index]["initial_events_end"] }
    bookmark_index = bookmark_indices.one? ? bookmark_indices.first : nil
    list_version = bookmark_index && positive_resource_version(records[bookmark_index]["resourceVersion"])
    initial_records = records.reject { |record| record["initial_events_end"] }
    event_versions = initial_records.map { |record| positive_resource_version(record["resourceVersion"]) }
    valid = response.status == 200 && bookmark_index == records.length - 1 && !initial_records.empty? &&
            initial_records.all? { |record| record["type"] == "ADDED" } && list_version &&
            event_versions.all? && event_versions.all? { |version| version <= list_version }
    {
      "mode" => "initial-watch",
      "response_status" => response.status,
      "events" => records,
      "list_resourceVersion" => bookmark_index ? records[bookmark_index]["resourceVersion"] : "",
      "valid" => !!valid
    }
  end

  def causality_signature(trace)
    return nil unless trace.is_a?(Hash)

    records = Array(trace["events"])
    case trace["mode"]
    when "initial-watch"
      bookmark_indices = records.each_index.select { |index| records[index].is_a?(Hash) && records[index]["initial_events_end"] == true }
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
      event_versions = records.map { |record| positive_resource_version(record.is_a?(Hash) ? record["resourceVersion"] : nil) }
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

  def causal_watch(force_response, patch_response, watch_response)
    force_version = resource_version(force_response)
    patch_version = resource_version(patch_response)
    events = watch_response.body.is_a?(Hash) ? [watch_response.body] : Array(watch_response.body)
    records = events.map do |event|
      {
        "type" => event.is_a?(Hash) ? event["type"].to_s : "",
        "resourceVersion" => event.is_a?(Hash) ? event.dig("object", "metadata", "resourceVersion").to_s : ""
      }
    end
    event_versions = records.map { |record| positive_resource_version(record["resourceVersion"]) }
    valid = watch_response.status == 200 && force_version && patch_version && patch_version > force_version &&
            records.length == 1 && records.first["type"] == "MODIFIED" && event_versions == [patch_version]
    {
      "mode" => "watch",
      "response_status" => watch_response.status,
      "start_resourceVersion" => force_version.to_s,
      "mutation_resourceVersion" => patch_version.to_s,
      "events" => records,
      "valid" => !!valid
    }
  end

  def runner_source_files
    [__FILE__, File.join(__dir__, "m1_kubernetes_oracle.rb")].map do |path|
      {
        "path" => path.delete_prefix("#{ROOT}/"),
        "sha256" => Digest::SHA256.file(path).hexdigest,
        "bytes" => File.size(path)
      }
    end
  end

  def runner_material(container_execution_sha256:)
    {
      "source_files" => runner_source_files,
      "pinned_images" => {
        "kube_apiserver" => M1KubernetesOracle::KUBE_APISERVER_IMAGE,
        "etcd" => M1KubernetesOracle::ETCD_IMAGE
      },
      "container_execution_sha256" => container_execution_sha256
    }
  end

  def runner_sha256(container_execution_sha256:)
    M1Gate.canonical_document_digest(runner_material(container_execution_sha256: container_execution_sha256))
  end

  def request_seed_sha256(request_stream)
    M1Gate.canonical_document_digest(request_stream)
  end

  SURFACE_FIELDS = %w[
    group version resource kind scope plural singular verbs subresources
    shortNames categories listKind schema_contract_present
  ].freeze

  def canonical_discovery_value(value)
    case value
    when Hash
      normalized = value.keys.map(&:to_s).uniq.sort.each_with_object({}) do |key, result|
        # These fields are wire metadata rather than the discovery contract:
        # apiVersion is negotiated by the serializer, storageVersionHash is
        # explicitly unstable across storage layouts, and the legacy /api
        # server-address list is deployment-specific.  Surface rows below
        # still compare every group/version/resource field.
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

  def discovery_endpoint_digest(value)
    digest(canonical_discovery_value(value))
  end

  def default_off_discovery_body(path)
    ROUTER_NOT_FOUND_DISCOVERY_PATHS.include?(path) ? DISCOVERY_NOT_FOUND_BODY : DISCOVERY_STATUS_NOT_FOUND_BODY
  end

  def default_profile_discovery_value(path, value)
    canonical = canonical_discovery_value(value)
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

    if canonical["versions"].is_a?(Array) && path.to_s.start_with?("/apis/")
      group = path.to_s.split("/")[2]
      versions = canonical.fetch("versions").reject do |version|
        DEFAULT_OFF_DISCOVERY_PATHS.include?("/apis/#{group}/#{version["version"]}")
      end
      preferred = canonical["preferredVersion"]
      preferred = versions.first unless versions.any?(preferred)
      return canonical.merge("versions" => versions, "preferredVersion" => preferred)
    end

    canonical
  end

  def discovery_rows_from_body(body, path:, expected_ids:)
    return [] unless body.is_a?(Hash) && body["resources"].is_a?(Array)

    group, version = M1ProbeSupport.discovery_group_version(path)
    return [] unless group && version

    raw_resources = body.fetch("resources")
    rows = []
    raw_resources.each do |entry|
      name = entry.fetch("name").to_s
      parent = name.split("/", 2).first
      siblings = raw_resources.filter_map do |candidate|
        candidate_name = candidate.fetch("name").to_s
        candidate_name.delete_prefix("#{parent}/") if candidate_name.start_with?("#{parent}/")
      end
      base = M1ProbeSupport.discovery_surface_fields(
        entry,
        group: group,
        version: version,
        subresources: siblings
      )
      rows << base
      override_group = entry["group"]
      override_version = entry["version"] || version
      next unless override_group

      override = M1ProbeSupport.discovery_surface_fields(
        entry,
        group: override_group,
        version: override_version,
        subresources: siblings
      )
      rows << override if expected_ids.key?(M1ProbeSupport.surface_identifier(override))
    end
    rows
  end

  def comparable_surface_fields(row)
    return nil unless row.is_a?(Hash)

    row.slice(*SURFACE_FIELDS).tap do |fields|
      fields["verbs"] = Array(fields["verbs"]).map(&:to_s).sort
      %w[subresources shortNames categories].each do |key|
        fields[key] = Array(fields[key]).map(&:to_s).sort
      end
      fields["schema_contract_present"] = false unless fields.key?("schema_contract_present")
    end
  end

  def surface_digest(row)
    M1Gate.canonical_document_digest(comparable_surface_fields(row))
  end

  def surface_presence_fields(row)
    fields = comparable_surface_fields(row)
    return nil unless fields

    fields.merge("schema_contract_present" => false)
  end

  def default_off_gvr?(identifier)
    DEFAULT_OFF_GVR_IDS.include?(identifier.to_s)
  end

  def default_off_gvk?(identifier)
    DEFAULT_OFF_GVK_IDS.include?(identifier.to_s)
  end

  def default_off_surface?(identifier)
    default_off_gvr?(identifier) || default_off_gvk?(identifier)
  end

  def surface_matrix_row(identifier, expected:, oracle:, rubernetes:, runtime:)
    direct = runtime || expected || oracle || rubernetes || {
      "group" => "", "version" => "", "resource" => "", "kind" => "", "scope" => "",
      "plural" => "", "singular" => "", "verbs" => [], "subresources" => [],
      "shortNames" => [], "categories" => [], "listKind" => "",
      "schema_contract_present" => false
    }
    expected_fields = surface_presence_fields(expected)
    oracle_fields = surface_presence_fields(oracle)
    rubernetes_fields = surface_presence_fields(rubernetes)
    contract_present = runtime.is_a?(Hash) && runtime["schema_contract_present"] == true
    disabled = default_off_gvr?(identifier)
    matches = if disabled
                expected_fields && oracle.nil? && rubernetes.nil?
              else
                expected_fields && oracle_fields && rubernetes_fields &&
                  expected_fields == oracle_fields && expected_fields == rubernetes_fields
              end
    direct_fields = comparable_surface_fields(direct)
    direct_fields["schema_contract_present"] = contract_present
    {
      "id" => identifier,
      "attempt_count" => 1,
      "passed" => matches && contract_present,
      "availability" => disabled ? "not_served_default" : "served",
      "availability_reason" => disabled ? DEFAULT_OFF_REASON : nil,
      "expected" => expected_fields,
      "oracle" => {
        "present" => !oracle.nil?,
        "fields" => oracle_fields,
        "sha256" => oracle && surface_digest(oracle)
      },
      "rubernetes" => {
        "present" => !rubernetes.nil?,
        "fields" => rubernetes_fields,
        "sha256" => rubernetes && surface_digest(rubernetes)
      }
    }.merge(direct_fields)
  end

  def gvk_matrix_rows(registry_document, expected_rows:, oracle_rows:, rubernetes_rows:, runtime_rows:)
    expected_by_gvk = Hash.new { |hash, key| hash[key] = [] }
    oracle_by_gvk = Hash.new { |hash, key| hash[key] = [] }
    rubernetes_by_gvk = Hash.new { |hash, key| hash[key] = [] }
    [expected_rows, oracle_rows, rubernetes_rows].each_with_index do |rows, index|
      target = [expected_by_gvk, oracle_by_gvk, rubernetes_by_gvk].fetch(index)
      Array(rows).each do |row|
        key = M1ProbeSupport.identifier(row.fetch("group", ""), row.fetch("version"), row.fetch("kind"))
        target[key] << row
        if row["listKind"].to_s != ""
          list_key = M1ProbeSupport.identifier(row.fetch("group", ""), row.fetch("version"), row.fetch("listKind"))
          target[list_key] << list_gvk_surface_row(row)
        end
      end
    end
    runtime_by_gvk = Array(registry_document.fetch("gvks")).to_h do |entry|
      [M1ProbeSupport.gvk_identifier(entry), entry]
    end
    type_index = Array(registry_document.fetch("types")).to_h { |entry| [entry.fetch("schema"), entry] }
    runtime_rows_by_gvk = Array(runtime_rows).group_by do |row|
      M1ProbeSupport.identifier(row.fetch("group", ""), row.fetch("version"), row.fetch("kind"))
    end
    list_aliases = Array(runtime_rows).filter_map do |row|
      next if row["listKind"].to_s.empty?

      [
        M1ProbeSupport.identifier(row.fetch("group", ""), row.fetch("version"), row.fetch("listKind")),
        list_gvk_surface_row(row)
      ]
    end
    list_aliases.each do |list_key, row|
      runtime_rows_by_gvk[list_key] ||= []
      runtime_rows_by_gvk[list_key] << row
    end

    runtime_by_gvk.sort.map do |identifier, entry|
      expected = expected_by_gvk.fetch(identifier, []).first
      oracle = oracle_by_gvk.fetch(identifier, []).first
      rubernetes = rubernetes_by_gvk.fetch(identifier, []).first
      runtime = runtime_rows_by_gvk.fetch(identifier, []).first
      schema_present = M1ProbeSupport.schema_contract_present?(entry["schema"], type_index: type_index)
      direct = runtime || expected || oracle || rubernetes || {
        "group" => entry.fetch("group", ""), "version" => entry.fetch("version"),
        "resource" => "", "kind" => entry.fetch("kind"), "scope" => "",
        "plural" => "", "singular" => "", "verbs" => [], "subresources" => [],
        "shortNames" => [], "categories" => [], "listKind" => "",
        "schema_contract_present" => schema_present
      }
      direct = comparable_surface_fields(direct)
      direct["group"] = entry.fetch("group", "").to_s
      direct["version"] = entry.fetch("version").to_s
      direct["kind"] = entry.fetch("kind").to_s
      direct["schema_contract_present"] = schema_present
      direct["schema_contract_applicable"] = entry["schema"].is_a?(String) && !entry["schema"].empty?
      expected_present = !expected.nil?
      oracle_present = !oracle.nil?
      rubernetes_present = !rubernetes.nil?
      oracle_observation = {
        "present" => oracle_present,
        "fields" => surface_presence_fields(oracle),
        "sha256" => oracle && surface_digest(oracle)
      }
      rubernetes_observation = {
        "present" => rubernetes_present,
        "fields" => surface_presence_fields(rubernetes),
        "sha256" => rubernetes && surface_digest(rubernetes)
      }
      surface_matches = if expected_present
                          expected_fields = surface_presence_fields(expected)
                          oracle_fields = surface_presence_fields(oracle)
                          rubernetes_fields = surface_presence_fields(rubernetes)
                          if default_off_gvk?(identifier)
                            expected_fields && oracle.nil? && rubernetes.nil?
                          else
                            expected_fields && expected_fields == oracle_fields && expected_fields == rubernetes_fields
                          end
                        else
                          oracle.nil? && rubernetes.nil?
                        end
      disabled = default_off_gvk?(identifier)
      {
        "id" => identifier,
        "attempt_count" => 1,
        "passed" => surface_matches &&
          (disabled ? !oracle_present && !rubernetes_present : expected_present == oracle_present && expected_present == rubernetes_present) &&
          (!direct.fetch("schema_contract_applicable", true) || schema_present),
        "availability" => disabled ? "not_served_default" : "served",
        "availability_reason" => disabled ? DEFAULT_OFF_REASON : nil,
        "expected_present" => expected_present,
        "oracle_present" => oracle_present,
        "rubernetes_present" => rubernetes_present,
        "expected" => surface_presence_fields(expected),
        "oracle" => oracle_observation,
        "rubernetes" => rubernetes_observation
      }.merge(direct)
    end
  end

  def list_gvk_surface_row(row)
    row.merge(
      "kind" => row.fetch("listKind"),
      "listKind" => "",
      "singular" => "",
      "subresources" => [],
      "shortNames" => [],
      "categories" => []
    )
  end

  def api_surface(rubernetes, oracle, registry_document)
    expected_ids = Array(registry_document.fetch("gvrs", [])).map { |entry| entry.fetch("identifier") }.to_h { |id| [id, true] }
    expected_rows = M1ProbeSupport.canonical_discovery_surface
    runtime_rows = M1ProbeSupport.runtime_surface_entries(registry_document)
    expected_by_id = expected_rows.to_h { |row| [M1ProbeSupport.surface_identifier(row), row] }
    runtime_by_id = runtime_rows.to_h { |row| [M1ProbeSupport.surface_identifier(row), row] }
    oracle_occurrences = Hash.new { |hash, key| hash[key] = [] }
    rubernetes_occurrences = Hash.new { |hash, key| hash[key] = [] }
    endpoints = []
    M1ProbeSupport.canonical_discovery_documents.each do |document|
      path = document.fetch("path")
      rubernetes_response = rubernetes.request(
        method: "GET", path: path, headers: {"User-Agent" => USER_AGENT}
      )
      oracle_response = oracle.request(
        method: "GET", path: path, headers: {"User-Agent" => USER_AGENT}
      )
      default_off_endpoint = DEFAULT_OFF_DISCOVERY_PATHS.include?(path)
      expected_body = if default_off_endpoint
                        canonical_discovery_value(default_off_discovery_body(path))
                      else
                        default_profile_discovery_value(path, document.fetch("body"))
                      end
      expected_digest = digest(expected_body)
      rubernetes_digest = discovery_endpoint_digest(rubernetes_response.body)
      oracle_digest = discovery_endpoint_digest(oracle_response.body)
      oracle_body = canonical_discovery_value(oracle_response.body)
      rubernetes_body = canonical_discovery_value(rubernetes_response.body)
      oracle_headers = header_observation(oracle_response)
      rubernetes_headers = header_observation(rubernetes_response)
      header_matches = oracle_headers.fetch("compared") == rubernetes_headers.fetch("compared")
      expected_status = default_off_endpoint ? 404 : 200
      endpoint_passed = oracle_response.status == expected_status && rubernetes_response.status == expected_status &&
                        expected_digest == oracle_digest && expected_digest == rubernetes_digest && header_matches
      endpoints << {
        "id" => path,
        "path" => path,
        "source_path" => document.fetch("source_path"),
        "attempt_count" => 1,
        "availability" => default_off_endpoint ? "not_served_default" : "served",
        "availability_reason" => default_off_endpoint ? DEFAULT_OFF_REASON : nil,
        "oracle_status" => oracle_response.status,
        "rubernetes_status" => rubernetes_response.status,
        "expected_source" => "pinned_kubernetes_discovery",
        "oracle_source" => "kubernetes_external",
        "rubernetes_source" => "rubernetes",
        "comparison_scope" => "full_semantic",
        "expected_sha256" => expected_digest,
        "oracle_sha256" => oracle_digest,
        "rubernetes_sha256" => rubernetes_digest,
        "expected_body" => expected_body,
        "oracle_body" => oracle_body,
        "rubernetes_body" => rubernetes_body,
        "header_matches" => header_matches,
        "header_observation" => {
          "expected" => oracle_headers,
          "actual" => rubernetes_headers
        },
        "passed" => endpoint_passed
      }
      discovery_rows_from_body(oracle_response.body, path: path, expected_ids: expected_ids).each do |row|
        oracle_occurrences[M1ProbeSupport.surface_identifier(row)] << row
      end
      discovery_rows_from_body(rubernetes_response.body, path: path, expected_ids: expected_ids).each do |row|
        rubernetes_occurrences[M1ProbeSupport.surface_identifier(row)] << row
      end
    end
    oracle_rows = oracle_occurrences.values.flatten
    rubernetes_rows = rubernetes_occurrences.values.flatten
    gvr_matrix = expected_ids.keys.sort.map do |identifier|
      surface_matrix_row(
        identifier,
        expected: expected_by_id[identifier],
        oracle: oracle_occurrences[identifier].first,
        rubernetes: rubernetes_occurrences[identifier].first,
        runtime: runtime_by_id[identifier]
      )
    end
    gvk_matrix = gvk_matrix_rows(
      registry_document,
      expected_rows: expected_rows,
      oracle_rows: oracle_rows,
      rubernetes_rows: rubernetes_rows,
      runtime_rows: runtime_rows
    )
    gvr_missing_oracle = gvr_matrix.count { |row| row.fetch("oracle").fetch("present") == false && !default_off_gvr?(row.fetch("id")) }
    gvr_missing_rubernetes = gvr_matrix.count do |row|
      row.fetch("rubernetes").fetch("present") == false && !default_off_gvr?(row.fetch("id"))
    end
    gvr_duplicates = oracle_occurrences.values.sum { |rows| [rows.length - 1, 0].max } +
                     rubernetes_occurrences.values.sum { |rows| [rows.length - 1, 0].max }
    gvk_missing_oracle = gvk_matrix.count do |row|
      row.fetch("expected_present") && !default_off_gvk?(row.fetch("id")) && !row.fetch("oracle_present")
    end
    gvk_missing_rubernetes = gvk_matrix.count do |row|
      row.fetch("expected_present") && !default_off_gvk?(row.fetch("id")) && !row.fetch("rubernetes_present")
    end
    expected_gvk_ids = Array(registry_document.fetch("gvks")).map { |entry| M1ProbeSupport.gvk_identifier(entry) }.to_h { |id| [id, true] }
    oracle_gvk_ids = oracle_rows.flat_map do |row|
      ids = [M1ProbeSupport.identifier(row.fetch("group", ""), row.fetch("version"), row.fetch("kind"))]
      ids << M1ProbeSupport.identifier(row.fetch("group", ""), row.fetch("version"), row.fetch("listKind")) if row["listKind"].to_s != ""
      ids
    end.to_h { |id| [id, true] }
    rubernetes_gvk_ids = rubernetes_rows.flat_map do |row|
      ids = [M1ProbeSupport.identifier(row.fetch("group", ""), row.fetch("version"), row.fetch("kind"))]
      ids << M1ProbeSupport.identifier(row.fetch("group", ""), row.fetch("version"), row.fetch("listKind")) if row["listKind"].to_s != ""
      ids
    end.to_h { |id| [id, true] }
    unexpected_count = (oracle_occurrences.keys - expected_ids.keys).length +
                       (rubernetes_occurrences.keys - expected_ids.keys).length +
                       (oracle_gvk_ids.keys - expected_gvk_ids.keys).length +
                       (rubernetes_gvk_ids.keys - expected_gvk_ids.keys).length
    endpoint_failures = endpoints.count { |entry| !entry.fetch("passed") }
    matrix_failures = gvr_matrix.count { |entry| !entry.fetch("passed") } + gvk_matrix.count { |entry| !entry.fetch("passed") }
    {
      "registry_gvk_count" => Array(registry_document.fetch("gvks")).length,
      "registry_gvr_count" => expected_ids.length,
      "discovery_endpoint_count" => endpoints.length,
      "feature_profile" => {
        "name" => DEFAULT_PROFILE,
        "feature_gates" => DEFAULT_FEATURE_GATES,
        "default_off_gvr_ids" => DEFAULT_OFF_GVR_IDS,
        "default_off_gvk_ids" => DEFAULT_OFF_GVK_IDS,
        "default_off_discovery_paths" => DEFAULT_OFF_DISCOVERY_PATHS,
        "reason" => DEFAULT_OFF_REASON
      },
      "discovery_endpoints" => endpoints,
      "gvk_matrix" => gvk_matrix,
      "gvr_matrix" => gvr_matrix,
      "oracle_missing_count" => gvr_missing_oracle + gvk_missing_oracle,
      "rubernetes_missing_count" => gvr_missing_rubernetes + gvk_missing_rubernetes,
      "duplicate_count" => gvr_duplicates,
      "unexpected_count" => unexpected_count,
      "endpoint_difference_count" => endpoint_failures,
      "difference_count" => endpoint_failures + matrix_failures + unexpected_count,
      "schema_contract_missing_count" => gvr_matrix.count { |entry| !entry.fetch("schema_contract_present") } +
        gvk_matrix.count { |entry| entry.fetch("schema_contract_applicable", true) && !entry.fetch("schema_contract_present") },
      "registry_gvk_ids" => gvk_matrix.map { |entry| entry.fetch("id") },
      "registry_gvr_ids" => expected_ids.keys.sort,
      "passed" => endpoints.all? { |entry| entry.fetch("passed") } &&
        gvr_matrix.all? { |entry| entry.fetch("passed") } &&
        gvk_matrix.all? { |entry| entry.fetch("passed") } &&
        gvr_missing_oracle.zero? && gvr_missing_rubernetes.zero? &&
        gvk_missing_oracle.zero? && gvk_missing_rubernetes.zero? &&
        gvr_duplicates.zero? && unexpected_count.zero?
    }
  end

  def execute(rubernetes, oracle)
    operations = []
    namespace_body = {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => NAMESPACE}}
    rubernetes_namespace, oracle_namespace = call_pair(
      rubernetes, oracle, method: "POST", path: "/api/v1/namespaces", body: namespace_body
    )
    unless rubernetes_namespace.status == 201 && oracle_namespace.status == 201
      raise M1KubernetesOracle::Error,
            "namespace fixture creation failed (Rubernetes #{rubernetes_namespace.status}, oracle #{oracle_namespace.status})"
    end

    created_body = {"metadata" => {"name" => "m1-created"}}
    rubernetes_created, oracle_created = call_pair(
      rubernetes, oracle, method: "POST", path: COLLECTION_PATH, body: created_body
    )
    operations << operation(
      "create-defaulting", method: "POST", path: COLLECTION_PATH,
                           rubernetes: rubernetes_created, oracle: oracle_created, defaulting: true,
                           request: request_observation(method: "POST", path: COLLECTION_PATH, body: created_body)
    )

    rubernetes_get, oracle_get = call_pair(
      rubernetes, oracle, method: "GET", path: "#{COLLECTION_PATH}/m1-created"
    )
    operations << operation(
      "get", method: "GET", path: "#{COLLECTION_PATH}/m1-created",
             rubernetes: rubernetes_get, oracle: oracle_get,
             request: request_observation(method: "GET", path: "#{COLLECTION_PATH}/m1-created")
    )

    # The collection response is the executable evidence for ListMeta
    # (resourceVersion, continue, remainingItemCount) and the list envelope.
    rubernetes_list, oracle_list = call_pair(rubernetes, oracle, method: "GET", path: COLLECTION_PATH)
    operations << operation(
      "list", method: "GET", path: COLLECTION_PATH,
              rubernetes: rubernetes_list, oracle: oracle_list,
              request: request_observation(method: "GET", path: COLLECTION_PATH)
    )

    rubernetes_duplicate, oracle_duplicate = call_pair(
      rubernetes, oracle, method: "POST", path: COLLECTION_PATH, body: created_body
    )
    operations << operation(
      "duplicate-create-status", method: "POST", path: COLLECTION_PATH,
                                 rubernetes: rubernetes_duplicate, oracle: oracle_duplicate,
                                 request: request_observation(method: "POST", path: COLLECTION_PATH, body: created_body)
    )

    invalid_body = {"apiVersion" => "v1", "kind" => "ConfigMap", "data" => {"key" => "value"}}
    rubernetes_invalid, oracle_invalid = call_pair(
      rubernetes, oracle, method: "POST", path: COLLECTION_PATH, body: invalid_body
    )
    operations << operation(
      "validation-status", method: "POST", path: COLLECTION_PATH,
                           rubernetes: rubernetes_invalid, oracle: oracle_invalid, validation: true,
                           request: request_observation(method: "POST", path: COLLECTION_PATH, body: invalid_body)
    )

    initial_validation_query = {"watch" => "true", "sendInitialEvents" => "true"}
    rubernetes_initial_invalid, oracle_initial_invalid = call_pair(
      rubernetes, oracle, method: "GET", path: COLLECTION_PATH, query: initial_validation_query
    )
    operations << operation(
      "initial-watch-validation-status", method: "GET",
                                         path: "#{COLLECTION_PATH}?watch=true&sendInitialEvents=true",
                                         rubernetes: rubernetes_initial_invalid, oracle: oracle_initial_invalid, validation: true,
                                         request: request_observation(method: "GET", path: COLLECTION_PATH, query: initial_validation_query)
    )

    apply_path = "#{COLLECTION_PATH}/m1-applied"
    apply_body = {
      "apiVersion" => "v1", "kind" => "ConfigMap",
      "metadata" => {"name" => "m1-applied"}, "data" => {"owned" => "one"}
    }
    apply_headers = {"Content-Type" => "application/apply-patch+yaml"}
    rubernetes_applied, oracle_applied = call_pair(
      rubernetes, oracle, method: "PATCH", path: apply_path, body: apply_body,
                          query: {"fieldManager" => "manager-one"}, headers: apply_headers
    )
    operations << operation(
      "apply-create", method: "PATCH", path: "#{apply_path}?fieldManager=manager-one",
                      rubernetes: rubernetes_applied, oracle: oracle_applied,
                      request: request_observation(method: "PATCH", path: apply_path, body: apply_body,
                                                   query: {"fieldManager" => "manager-one"}, headers: apply_headers)
    )

    conflicting_body = clone_payload(apply_body)
    conflicting_body["data"]["owned"] = "two"
    rubernetes_conflict, oracle_conflict = call_pair(
      rubernetes, oracle, method: "PATCH", path: apply_path, body: conflicting_body,
                          query: {"fieldManager" => "manager-two"}, headers: apply_headers
    )
    operations << operation(
      "apply-conflict-status", method: "PATCH", path: "#{apply_path}?fieldManager=manager-two",
                               rubernetes: rubernetes_conflict, oracle: oracle_conflict,
                               request: request_observation(method: "PATCH", path: apply_path, body: conflicting_body,
                                                            query: {"fieldManager" => "manager-two"}, headers: apply_headers)
    )

    rubernetes_force, oracle_force = call_pair(
      rubernetes, oracle, method: "PATCH", path: apply_path, body: conflicting_body,
                          query: {"fieldManager" => "manager-two", "force" => "true"}, headers: apply_headers
    )
    operations << operation(
      "apply-force", method: "PATCH", path: "#{apply_path}?fieldManager=manager-two&force=true",
                     rubernetes: rubernetes_force, oracle: oracle_force,
                     request: request_observation(method: "PATCH", path: apply_path, body: conflicting_body,
                                                  query: {"fieldManager" => "manager-two", "force" => "true"}, headers: apply_headers)
    )

    merge_body = {"data" => {"watch" => "ready"}}
    merge_headers = {"Content-Type" => "application/merge-patch+json"}
    rubernetes_patch, oracle_patch = call_pair(
      rubernetes, oracle, method: "PATCH", path: apply_path, body: merge_body, headers: merge_headers
    )
    operations << operation(
      "merge-patch", method: "PATCH", path: apply_path,
                     rubernetes: rubernetes_patch, oracle: oracle_patch,
                     request: request_observation(method: "PATCH", path: apply_path, body: merge_body, headers: merge_headers)
    )

    initial_watch_query = {
      "watch" => "true",
      "sendInitialEvents" => "true",
      "allowWatchBookmarks" => "true",
      "resourceVersionMatch" => "NotOlderThan",
      "resourceVersion" => "0",
      "timeoutSeconds" => "1"
    }
    rubernetes_initial_watch, oracle_initial_watch = call_pair(
      rubernetes, oracle, method: "GET", path: COLLECTION_PATH, query: initial_watch_query
    )
    initial_watch_path = "#{COLLECTION_PATH}?watch=true&sendInitialEvents=true&allowWatchBookmarks=true&" \
                         "resourceVersionMatch=NotOlderThan&resourceVersion=0&timeoutSeconds=1"
    operations << operation(
      "initial-watch", method: "GET",
                       path: "#{COLLECTION_PATH}?watch=true&sendInitialEvents=true&allowWatchBookmarks=true&resourceVersionMatch=NotOlderThan&resourceVersion=0&timeoutSeconds=1",
                       rubernetes: rubernetes_initial_watch, oracle: oracle_initial_watch, initial_watch: true,
                       rubernetes_causality: initial_watch_causality(rubernetes_initial_watch),
                       oracle_causality: initial_watch_causality(oracle_initial_watch),
                       request: request_observation(method: "GET", path: COLLECTION_PATH, query: initial_watch_query)
    )

    rubernetes_watch = rubernetes.request(
      method: "GET", path: COLLECTION_PATH,
      query: {"watch" => "true", "resourceVersion" => resource_version(rubernetes_force).to_s, "timeoutSeconds" => "1"},
      headers: {"User-Agent" => USER_AGENT}
    )
    oracle_watch = oracle.request(
      method: "GET", path: COLLECTION_PATH,
      query: {"watch" => "true", "resourceVersion" => resource_version(oracle_force).to_s, "timeoutSeconds" => "1"},
      headers: {"User-Agent" => USER_AGENT}
    )
    rubernetes_causality = causal_watch(rubernetes_force, rubernetes_patch, rubernetes_watch)
    oracle_causality = causal_watch(oracle_force, oracle_patch, oracle_watch)
    operations << operation(
      "watch", method: "GET",
               path: "#{COLLECTION_PATH}?watch=true&resourceVersion=<per-target>&timeoutSeconds=1",
               rubernetes: rubernetes_watch, oracle: oracle_watch, watch: true,
               rubernetes_causality: rubernetes_causality, oracle_causality: oracle_causality,
               request: request_observation(
                 method: "GET", path: COLLECTION_PATH,
                 query: {"watch" => "true", "resourceVersion" => "<per-target>", "timeoutSeconds" => "1"}
               )
    )

    rubernetes_delete, oracle_delete = call_pair(
      rubernetes, oracle, method: "DELETE", path: "#{COLLECTION_PATH}/m1-created"
    )
    operations << operation(
      "delete", method: "DELETE", path: "#{COLLECTION_PATH}/m1-created",
                rubernetes: rubernetes_delete, oracle: oracle_delete,
                request: request_observation(method: "DELETE", path: "#{COLLECTION_PATH}/m1-created")
    )

    rubernetes_missing, oracle_missing = call_pair(
      rubernetes, oracle, method: "GET", path: "#{COLLECTION_PATH}/m1-created"
    )
    operations << operation(
      "not-found-status", method: "GET", path: "#{COLLECTION_PATH}/m1-created",
                          rubernetes: rubernetes_missing, oracle: oracle_missing,
                          request: request_observation(method: "GET", path: "#{COLLECTION_PATH}/m1-created")
    )
    operations.concat(execute_virtual_resources(rubernetes, oracle))
    operations
  end

  # REST handlers without storage: token/subject reviews, pod eviction and
  # the legacy component status endpoint.  Every request is sent to both
  # servers with the same deterministic body.
  def execute_virtual_resources(rubernetes, oracle)
    operations = []
    token_review_path = "/apis/authentication.k8s.io/v1/tokenreviews"
    review_body = {"apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenReview", "spec" => {"token" => REVIEW_TOKEN}}
    rubernetes_review, oracle_review = call_pair(rubernetes, oracle, method: "POST", path: token_review_path, body: review_body)
    operations << operation(
      "tokenreview-create", method: "POST", path: token_review_path,
                            rubernetes: rubernetes_review, oracle: oracle_review,
                            request: request_observation(method: "POST", path: token_review_path, body: review_body)
    )

    missing_token_body = {"apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenReview", "spec" => {}}
    rubernetes_missing_token, oracle_missing_token = call_pair(rubernetes, oracle, method: "POST", path: token_review_path,
                                                                                   body: missing_token_body)
    operations << operation(
      "tokenreview-missing-token", method: "POST", path: token_review_path,
                                   rubernetes: rubernetes_missing_token, oracle: oracle_missing_token,
                                   request: request_observation(method: "POST", path: token_review_path, body: missing_token_body)
    )

    self_review_path = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
    self_review_body = {"apiVersion" => "authentication.k8s.io/v1", "kind" => "SelfSubjectReview"}
    rubernetes_self, oracle_self = call_pair(rubernetes, oracle, method: "POST", path: self_review_path, body: self_review_body)
    operations << operation(
      "selfsubjectreview-create", method: "POST", path: self_review_path,
                                  rubernetes: rubernetes_self, oracle: oracle_self,
                                  request: request_observation(method: "POST", path: self_review_path, body: self_review_body)
    )

    rules_path = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"
    rules_body = {"apiVersion" => "authorization.k8s.io/v1", "kind" => "SelfSubjectRulesReview", "spec" => {"namespace" => NAMESPACE}}
    rubernetes_rules, oracle_rules = call_pair(rubernetes, oracle, method: "POST", path: rules_path, body: rules_body)
    operations << operation(
      "selfsubjectrulesreview-create", method: "POST", path: rules_path,
                                       rubernetes: rubernetes_rules, oracle: oracle_rules,
                                       request: request_observation(method: "POST", path: rules_path, body: rules_body)
    )

    missing_namespace_body = {"apiVersion" => "authorization.k8s.io/v1", "kind" => "SelfSubjectRulesReview", "spec" => {}}
    rubernetes_no_namespace, oracle_no_namespace = call_pair(rubernetes, oracle, method: "POST", path: rules_path,
                                                                                 body: missing_namespace_body)
    operations << operation(
      "selfsubjectrulesreview-missing-namespace", method: "POST", path: rules_path,
                                                  rubernetes: rubernetes_no_namespace, oracle: oracle_no_namespace,
                                                  request: request_observation(method: "POST", path: rules_path, body: missing_namespace_body)
    )

    # Eviction needs a stored pod; the isolated kube-apiserver runs the
    # ServiceAccount admission plugin, which requires the namespace's default
    # service account.  Neither fixture request is a compared operation.
    service_account_body = {"apiVersion" => "v1", "kind" => "ServiceAccount", "metadata" => {"name" => "default", "namespace" => NAMESPACE}}
    rubernetes_account, oracle_account = call_pair(rubernetes, oracle, method: "POST",
                                                                       path: "/api/v1/namespaces/#{NAMESPACE}/serviceaccounts", body: service_account_body)
    unless rubernetes_account.status == 201 && oracle_account.status == 201
      raise M1KubernetesOracle::Error,
            "service account fixture creation failed (Rubernetes #{rubernetes_account.status}, oracle #{oracle_account.status})"
    end
    pod_body = {
      "apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "m1-evict", "namespace" => NAMESPACE},
      "spec" => {"containers" => [{"name" => "m1", "image" => "m1.example.com/pause:1"}]}
    }
    rubernetes_pod, oracle_pod = call_pair(rubernetes, oracle, method: "POST", path: "/api/v1/namespaces/#{NAMESPACE}/pods", body: pod_body)
    unless rubernetes_pod.status == 201 && oracle_pod.status == 201
      raise M1KubernetesOracle::Error,
            "pod fixture creation failed (Rubernetes #{rubernetes_pod.status}, oracle #{oracle_pod.status})"
    end

    eviction_path = "/api/v1/namespaces/#{NAMESPACE}/pods/m1-evict/eviction"
    invalid_eviction = {
      "apiVersion" => "policy/v1", "kind" => "Eviction", "metadata" => {"name" => "m1-evict", "namespace" => NAMESPACE},
      "deleteOptions" => {"propagationPolicy" => "Invalid"}
    }
    rubernetes_invalid_eviction, oracle_invalid_eviction = call_pair(rubernetes, oracle, method: "POST", path: eviction_path,
                                                                                         body: invalid_eviction)
    operations << operation(
      "eviction-invalid-delete-options", method: "POST", path: eviction_path,
                                         rubernetes: rubernetes_invalid_eviction, oracle: oracle_invalid_eviction, validation: true,
                                         request: request_observation(method: "POST", path: eviction_path, body: invalid_eviction)
    )

    eviction_body = {"apiVersion" => "policy/v1", "kind" => "Eviction", "metadata" => {"name" => "m1-evict", "namespace" => NAMESPACE}}
    rubernetes_eviction, oracle_eviction = call_pair(rubernetes, oracle, method: "POST", path: eviction_path, body: eviction_body)
    operations << operation(
      "eviction-create", method: "POST", path: eviction_path,
                         rubernetes: rubernetes_eviction, oracle: oracle_eviction,
                         request: request_observation(method: "POST", path: eviction_path, body: eviction_body)
    )

    list_path = "/api/v1/componentstatuses"
    rubernetes_components, oracle_components = call_pair(rubernetes, oracle, method: "GET", path: list_path)
    operations << operation(
      "componentstatus-list", method: "GET", path: list_path,
                              rubernetes: rubernetes_components, oracle: oracle_components, body_policy: :component_status,
                              request: request_observation(method: "GET", path: list_path)
    )

    get_path = "#{list_path}/etcd-0"
    rubernetes_component, oracle_component = call_pair(rubernetes, oracle, method: "GET", path: get_path)
    operations << operation(
      "componentstatus-get", method: "GET", path: get_path,
                             rubernetes: rubernetes_component, oracle: oracle_component, body_policy: :component_status,
                             request: request_observation(method: "GET", path: get_path)
    )
    operations
  end
end

M1ProbeSupport.run_probe("m1_api_differential") do |_current, input|
  server, _store, registry_document = M1ProbeSupport.build_api_server
  raise M1KubernetesOracle::Error, "generated registry GVK inventory must contain exactly 321 entries" unless Array(registry_document["gvks"]).length == 321

  rubernetes_client = M1KubernetesOracle::InProcessClient.new(server)
  M1KubernetesOracle::DockerCluster.new.with_client do |oracle, evidence|
    request_stream = []
    rubernetes = M1APIDifferential::RecordingClient.new(
      rubernetes_client, target: "rubernetes", stream: request_stream
    )
    oracle = M1APIDifferential::RecordingClient.new(
      oracle, target: "kubernetes_external", stream: request_stream
    )
    surface = M1APIDifferential.api_surface(rubernetes, oracle, registry_document)
    operations = M1APIDifferential.execute(rubernetes, oracle)
    raise M1KubernetesOracle::Error, "oracle differential produced no comparisons" if operations.empty?

    failed = operations.reject { |operation| operation.fetch("passed") }
    comparisons = operations.map do |operation|
      {
        "id" => operation.fetch("id"),
        "attempt_count" => 1,
        "passed" => operation.fetch("passed"),
        "expected_source" => "kubernetes_external",
        "actual_source" => "rubernetes",
        "expected_sha256" => operation.fetch("expected_sha256"),
        "actual_sha256" => operation.fetch("actual_sha256")
      }
    end
    container_execution_sha256 = M1Gate.canonical_document_digest(evidence.fetch("container_execution"))
    runner_material = M1APIDifferential.runner_material(
      container_execution_sha256: container_execution_sha256
    )
    request_stream_sha256 = M1APIDifferential.request_seed_sha256(request_stream)
    oracle_evidence = evidence.merge(
      "container_execution_sha256" => container_execution_sha256,
      "runner_material" => runner_material,
      "runner_sha256" => M1APIDifferential.runner_sha256(
        container_execution_sha256: container_execution_sha256
      ),
      "request_stream" => request_stream,
      "request_stream_sha256" => request_stream_sha256,
      "request_seed_sha256" => request_stream_sha256,
      "request_sequence" => "configmap-v1",
      "comparison_count" => operations.length,
      "missing_comparison_count" => 0,
      "comparisons" => comparisons
    )
    provenance = {
      "kind" => M1Gate::KUBERNETES_API_ORACLE_KIND,
      "mode" => "external",
      "self_comparison" => false,
      "implementation" => "isolated Kubernetes kube-apiserver and etcd",
      "source" => {
        "version" => oracle_evidence.fetch("kubernetes_version"),
        "commit" => oracle_evidence.fetch("source_commit"),
        "tag" => M1Gate::KUBERNETES_VERSION,
        "apiserver_image" => oracle_evidence.fetch("kube_apiserver_image"),
        "etcd_image" => oracle_evidence.fetch("etcd_image"),
        "network_isolated" => true
      },
      "runner_sha256" => oracle_evidence.fetch("runner_sha256"),
      "request_seed_sha256" => oracle_evidence.fetch("request_seed_sha256")
    }
    provenance["provenance_sha256"] = M1Gate.canonical_document_digest(provenance)
    oracle_evidence["provenance"] = provenance
    failure_count = failed.length + surface.fetch("difference_count")
    {
      "operation_count" => operations.length,
      "passed_count" => operations.length - failed.length,
      "operations" => operations,
      "header_policy" => M1APIDifferential.header_policy,
      "header_policy_sha256" => M1Gate.canonical_document_digest(M1APIDifferential.header_policy),
      "body_policy" => M1APIDifferential.body_policy_document,
      "body_policy_sha256" => M1Gate.canonical_document_digest(M1APIDifferential.body_policy_document),
      "api_surface" => surface,
      "oracle" => oracle_evidence,
      "self_check_difference_count" => 0,
      "difference_count" => failure_count,
      "oracle_difference_count" => failed.length + surface.fetch("oracle_missing_count") + surface.fetch("difference_count"),
      "status_mismatch_count" => operations.count { |operation| !operation.fetch("status_matches") },
      "header_mismatch_count" => operations.count { |operation| !operation.fetch("header_matches") },
      "status_body_mismatch_count" => operations.count { |operation| !operation.fetch("status_body_matches") },
      "defaulting_mismatch_count" => operations.count { |operation| !operation.fetch("defaulting_matches") },
      "validation_mismatch_count" => operations.count { |operation| !operation.fetch("validation_matches") },
      "ownership_mismatch_count" => operations.count { |operation| !operation.fetch("ownership_matches") },
      "watch_failure_count" => operations.count { |operation| !operation.fetch("watch_matches") },
      "unclassified_count" => 0,
      "failure_count" => failure_count,
      "passed" => input.fetch("stable") && failure_count.zero? && surface.fetch("passed")
    }
  end
end
