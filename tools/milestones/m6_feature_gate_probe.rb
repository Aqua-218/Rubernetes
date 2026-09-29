#!/usr/bin/env ruby
# frozen_string_literal: true

# M6 exit criterion 2: the served API surface under the default feature-gate
# profile and under the enabled profiles (AllBeta, alpha API gates) is
# identical to the pinned kube-apiserver's discovery documents captured
# under the same profiles (schema/kubernetes/v1.36.2-defaults/bootstrap/
# discovery-*.json, dumped by tools/schema/import_kubernetes_bootstrap.rb).

require_relative "m6_probe_support"

module M6FeatureGateProbe
  ALPHA_API_GATES = %w[MutatingAdmissionPolicy ClusterTrustBundle PodCertificateRequest CoordinatedLeaderElection
                       MultiCIDRServiceAllocator DynamicResourceAllocation GenericWorkload VolumeAttributesClass StorageVersionMigrator].freeze

  module_function

  def corpus_gates
    JSON.parse(File.read(File.join(M6ProbeSupport::DEFAULTS, "features.json"))).fetch("gates")
  end

  def profile_gates(name)
    gates = corpus_gates
    case name
    when "default" then {}
    when "all-beta" then gates.select { |_gate, info| info["stage"] == "Beta" && !info["lock_to_default"] }.to_h { |gate, _| [gate, true] }
    when "alpha-apis" then ALPHA_API_GATES.to_h { |gate| [gate, true] }
    end
  end

  def normalize_resource_list(document)
    return nil unless document.is_a?(Hash) && document["kind"] == "APIResourceList"

    document.fetch("resources", []).map do |resource|
      {"name" => resource["name"], "namespaced" => resource["namespaced"], "kind" => resource["kind"], "verbs" => Array(resource["verbs"]).sort,
       "shortNames" => Array(resource["shortNames"]).sort, "categories" => Array(resource["categories"]).sort, "singularName" => resource["singularName"].to_s}
    end.sort_by { |resource| resource["name"] }
  end

  def served_documents(service, oracle)
    documents = {}
    oracle.each_key do |path|
      next if path.end_with?("(aggregated)")

      response = M6ProbeSupport.request(service, "GET", path, token: "admin-token")
      documents[path] = response.status == 200 ? response.body : {"status" => response.status}
    end
    documents
  end

  def compare_profile(name)
    oracle = M6ProbeSupport.corpus_discovery(name)
    # The alpha-apis oracle run also passed --runtime-config=api/all=true.
    service = M6ProbeSupport.build_service(feature_gates: profile_gates(name), runtime_config: name == "alpha-apis" ? {"api/all" => true} : {})
    served = served_documents(service, oracle)
    differences = []
    oracle_groups = oracle["/apis"]["groups"].map { |group| group["name"] }.sort
    served_groups = served["/apis"].is_a?(Hash) ? served["/apis"]["groups"].map { |group| group["name"] }.sort : []
    differences << {"path" => "/apis", "missing_groups" => oracle_groups - served_groups, "extra_groups" => served_groups - oracle_groups} unless oracle_groups == served_groups
    oracle["/apis"]["groups"].each do |group|
      served_group = served["/apis"]["groups"].find { |candidate| candidate["name"] == group["name"] } if served["/apis"].is_a?(Hash)
      next if served_group.nil?

      oracle_versions = group["versions"].map { |version| version["groupVersion"] }
      served_versions = served_group["versions"].map { |version| version["groupVersion"] }
      differences << {"path" => "/apis/#{group["name"]}", "oracle_versions" => oracle_versions, "served_versions" => served_versions} unless oracle_versions == served_versions
      differences << {"path" => "/apis/#{group["name"]}", "field" => "preferredVersion", "oracle" => group["preferredVersion"], "served" => served_group["preferredVersion"]} unless group["preferredVersion"] == served_group["preferredVersion"]
    end
    oracle.each do |path, document|
      next if path == "/apis" || path == "/api" || path.end_with?("(aggregated)")

      expected = normalize_resource_list(document)
      actual = normalize_resource_list(served[path])
      next if expected == actual

      differences << {"path" => path, "missing" => (expected || []) - (actual || []), "extra" => (actual || []) - (expected || [])}
    end
    {"id" => "profile-#{name}", "gates_enabled" => profile_gates(name).length, "documents_compared" => oracle.length - 1,
     "differences" => differences.first(40), "difference_count" => differences.length, "passed" => differences.empty?}
  end

  def run
    started_at = M6ProbeSupport.now
    cases = %w[default all-beta alpha-apis].map { |profile| compare_profile(profile) }
    gates = corpus_gates
    cases << {"id" => "gate_corpus", "gate_count" => gates.length, "stages" => gates.values.map { |info| info["stage"] }.tally, "passed" => gates.length >= 200}
    M6ProbeSupport.emit(M6ProbeSupport.report(
      kind: "m6_feature_gate_matrix", measurement_level: "differentially_tested", started_at: started_at, cases: cases,
      extra: {"profiles" => {"default" => [], "all-beta" => ["AllBeta=true"], "alpha-apis" => ALPHA_API_GATES + ["runtime-config=api/all=true"]},
              "sources" => M5ProbeSupport.source_files(%w[schema/kubernetes/v1.36.2-defaults/features.json schema/kubernetes/v1.36.2-defaults/bootstrap/manifest.json lib/rubernetes/api/server.rb])}
    ))
  end
end

M6FeatureGateProbe.run if $PROGRAM_NAME == __FILE__
