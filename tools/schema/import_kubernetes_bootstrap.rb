#!/usr/bin/env ruby
# frozen_string_literal: true

# Dump the objects a pinned kube-apiserver v1.36.2 bootstraps at start
# (API Priority and Fairness FlowSchemas / PriorityLevelConfigurations, RBAC
# bootstrap ClusterRoles / Bindings, kube-system Roles / RoleBindings, system
# namespaces) plus the discovery documents served under the default
# feature-gate profile and under the all-enabled profile.  The oracle is the
# same Docker cluster the M1 differential uses; the dump is written to
# schema/kubernetes/v1.36.2-defaults/bootstrap/ with the image digests recorded.
#
# Usage: ruby tools/schema/import_kubernetes_bootstrap.rb

require "digest"
require "fileutils"
require "json"

require_relative "../milestones/m1_kubernetes_oracle"

module KubernetesBootstrapImporter
  ROOT = File.expand_path("../..", __dir__)
  OUTPUT = File.join(ROOT, "schema/kubernetes/v1.36.2-defaults/bootstrap")
  DUMPS = {
    "flowschemas.json" => "/apis/flowcontrol.apiserver.k8s.io/v1/flowschemas",
    "prioritylevelconfigurations.json" => "/apis/flowcontrol.apiserver.k8s.io/v1/prioritylevelconfigurations",
    "clusterroles.json" => "/apis/rbac.authorization.k8s.io/v1/clusterroles",
    "clusterrolebindings.json" => "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
    "roles.json" => "/apis/rbac.authorization.k8s.io/v1/roles",
    "rolebindings.json" => "/apis/rbac.authorization.k8s.io/v1/rolebindings",
    "namespaces.json" => "/api/v1/namespaces"
  }.freeze
  VOLATILE_METADATA = %w[uid resourceVersion creationTimestamp managedFields generation].freeze

  module_function

  def strip(object)
    return object unless object.is_a?(Hash)

    copy = object.dup
    copy["metadata"] = copy["metadata"].reject { |key, _| VOLATILE_METADATA.include?(key) } if copy["metadata"].is_a?(Hash)
    if copy["items"].is_a?(Array)
      copy["items"] = copy["items"].map { |item| strip(item) }
      copy.delete("metadata")
    end
    copy
  end

  def fetch_all(client, path)
    response = client.request(method: :get, path: path)
    raise "GET #{path} failed: #{response.status}" unless response.status.between?(200, 299)

    strip(response.body)
  end

  def discovery(client)
    documents = {}
    %w[/api /apis].each { |path| documents[path] = client.request(method: :get, path: path).body }
    aggregated = client.request(method: :get, path: "/apis",
                                headers: {"accept" => "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList"})
    documents["/apis(aggregated)"] = aggregated.body
    groups = documents["/apis"].fetch("groups", []).flat_map do |group|
      group.fetch("versions", []).map do |version|
        version.fetch("groupVersion")
      end
    end
    (["v1"] + groups).each do |group_version|
      path = group_version == "v1" ? "/api/v1" : "/apis/#{group_version}"
      documents[path] = client.request(method: :get, path: path).body
    end
    documents
  end

  def run
    FileUtils.mkdir_p(OUTPUT)
    # AllAlpha=true is not a runnable standalone kube-apiserver profile
    # (StorageVersionAPI makes the priority-class post-start hook wait for a
    # storage-version manager that only exists in a full control plane), so
    # the enabled profile is AllBeta plus every alpha gate that changes the
    # served API surface, which is exactly what the feature-gate matrix needs.
    alpha_api_gates = %w[MutatingAdmissionPolicy ClusterTrustBundle PodCertificateRequest CoordinatedLeaderElection
                         MultiCIDRServiceAllocator DynamicResourceAllocation GenericWorkload VolumeAttributesClass
                         StorageVersionMigrator]
    profiles = {
      "default" => [],
      # RBAC bootstrap roles are only installed when the RBAC authorizer is
      # enabled; the oracle token user is in system:masters so it can read them.
      "rbac" => ["--authorization-mode=Node,RBAC"],
      "all-beta" => ["--feature-gates=AllBeta=true"],
      "alpha-apis" => ["--feature-gates=#{alpha_api_gates.map { |gate| "#{gate}=true" }.join(",")}", "--runtime-config=api/all=true"]
    }
    manifest = {"schema_version" => 1, "oracle" => {"kube_apiserver_image" => M1KubernetesOracle::KUBE_APISERVER_IMAGE,
                                                    "etcd_image" => M1KubernetesOracle::ETCD_IMAGE}, "profiles" => profiles, "files" => {}}
    profiles.each do |profile, extra|
      cluster = M1KubernetesOracle::DockerCluster.new(extra_api_args: extra)
      cluster.with_client do |client, evidence|
        manifest["oracle"]["version"] ||= evidence["version"] if evidence.is_a?(Hash)
        if profile == "default"
          # Bootstrap objects appear shortly after start; poll until the
          # suggested FlowSchemas are present.
          wait_for(client, DUMPS.fetch("flowschemas.json"), 11)
          DUMPS.each do |file, path|
            next if file.include?("role")

            write(file, fetch_all(client, path), manifest)
          end
        elsif profile == "rbac"
          wait_for(client, DUMPS.fetch("clusterroles.json"), 60)
          DUMPS.select { |file, _| file.include?("role") }.each do |file, path|
            write(file, fetch_all(client, path), manifest)
          end
        end
        write("discovery-#{profile}.json", discovery(client), manifest) unless profile == "rbac"
      end
    end
    File.write(File.join(OUTPUT, "manifest.json"), JSON.pretty_generate(manifest) << "\n")
    puts JSON.pretty_generate(manifest["files"].transform_values { |entry| entry["items"] })
  end

  def wait_for(client, path, minimum)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 90
    loop do
      document = fetch_all(client, path)
      if document["items"].length >= minimum
        sleep 2
        return
      end
      raise "#{path} was not bootstrapped (#{document["items"].length} < #{minimum})" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.5
    end
  end

  def write(file, document, manifest)
    path = File.join(OUTPUT, file)
    File.write(path, JSON.pretty_generate(document) << "\n")
    manifest["files"][file] = {"sha256" => Digest::SHA256.file(path).hexdigest, "items" => document.is_a?(Hash) && document["items"].is_a?(Array) ? document["items"].length : document.length}
  end
end

KubernetesBootstrapImporter.run if $PROGRAM_NAME == __FILE__
