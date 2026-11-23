#!/usr/bin/env ruby
# frozen_string_literal: true

# Builds test/compatibility/api/selection-ledger.json from the real Ginkgo
# dry-run inventory of the pinned upstream e2e suite
# (spec/verification/kubernetes-compatibility.md#k3).
#
# Every spec is classified exactly once into required / platform-inapplicable /
# provider-private / implementation-internal.  Per the spec, [LinuxOnly],
# [Disruptive], [Slow], [Serial], [Flaky] and [Feature:*] are NOT grounds for
# exclusion, and neither is "unimplemented", "fails", "times out" or "hard to
# set up" — so no rule here may reference those.

require "json"
require "optparse"
require "time"

require_relative "k3_internal_contract_index"
require_relative "k3_local_volume_contract_index"
require_relative "k3_csi_contract_index"

module Conformance
  module SelectionLedger
    ROOT = File.expand_path("../..", __dir__)

    # A driver that only exists inside a specific cloud account or on vendor
    # hardware.  Matching is on the upstream [Driver: x] / provider tag.
    PROVIDER_DRIVERS = %w[
      vsphere gcepd aws azure-disk azure-file gluster ceph rbd cinder
      azurefile azuredisk gcp-localssd windows-gcepd csi-hostpath-provider
    ].freeze
    PROVIDER_TAGS = [
      "[Driver: vsphere]", "[Driver: gcepd]", "[Driver: aws]", "[Driver: azure-disk]",
      "[Driver: azure-file]", "[Driver: gluster]", "[Driver: ceph]", "[Driver: rbd]",
      "[Driver: cinder]", "[Driver: azurefile]", "[Driver: azuredisk]",
      "[Feature:Windows]", "[Feature:GKE", "[Feature:GCE", "[Feature:EKS",
      "[Feature:vsphere", "[Feature:CloudProvider", "[Feature:IngressGCE",
      "[Feature:NetworkPolicy:CloudProvider"
    ].freeze

    # Non-Linux platforms the contract does not cover.
    PLATFORM_TAGS = ["[WindowsOnly]", "[Feature:WindowsHostProcessContainers]",
                     "[Feature:Windows]", "[sig-windows]"].freeze

    # These tests require a particular process or deployment layout. The
    # neighboring public APIs and node proxy endpoints remain required.
    INTERNAL_FILES = {
      "test/e2e/apimachinery/apiserver_identity.go" => "restarts kube-apiserver by SSH on a GCE control-plane host",
      "test/e2e/apimachinery/etcd_failure.go" => "disrupts an etcd process or its transport by SSH on a control-plane host",
      "test/e2e/node/kubelet_perf.go" => "profiles the kubelet and runtime system containers by their upstream names"
    }.freeze
    COMPONENT_METRICS = [
      "should grab all metrics from a Scheduler.",
      "should grab all metrics from a ControllerManager."
    ].freeze
    GCE_PROXY_MIGRATION = "test/e2e/cloud/gcp/network/kube_proxy_migration.go"
    GCE_PD_CSI = "[Driver: pd.csi.storage.gke.io]"
    GCE_LOCAL_SSD = "[Driver: local] [LocalVolumeType: gce-localssd-scsi-fs]"

    module_function

    def run(argv = ARGV)
      options = {inventory: nil, output: File.join(ROOT, "test/compatibility/api/selection-ledger.json")}
      OptionParser.new do |parser|
        parser.on("--inventory PATH", "Ginkgo --ginkgo.json-report output") { |v| options[:inventory] = v }
        parser.on("--output PATH") { |v| options[:output] = v }
      end.parse!(argv)
      raise ArgumentError, "--inventory is required" if options[:inventory].nil?

      specs = load_specs(options[:inventory])
      tests = specs.map { |spec| classify(spec) }
      counts = tests.group_by { |entry| entry.fetch("classification") }.transform_values(&:length)
      ledger = {
        "schema_version" => 1,
        "kind" => "k3_selection_ledger",
        "generated_at" => Time.now.utc.iso8601,
        "source" => {
          "kubernetes_tag" => "v1.36.2",
          "inventory" => "ginkgo --dry-run over the pinned test/e2e binary",
          "spec_count" => tests.length
        },
        "counts" => counts,
        "unclassified" => tests.count { |entry| entry["classification"].nil? },
        "unlinked_external_contracts" =>
          tests.count { |entry| entry["external_contract"] == true && entry["replacement_test"].to_s.empty? },
        "tests" => tests
      }
      File.write(options[:output], "#{JSON.pretty_generate(ledger)}\n")
      puts JSON.pretty_generate(ledger.reject { |key, _| key == "tests" })
      ledger.fetch("unclassified").zero? && ledger.fetch("unlinked_external_contracts").zero? ? 0 : 1
    end

    def load_specs(path)
      JSON.parse(File.read(path)).flat_map { |suite| suite["SpecReports"] || [] }
        .select { |spec| spec["LeafNodeType"] == "It" }
    end

    def spec_name(spec)
      (Array(spec["ContainerHierarchyTexts"]) + [spec["LeafNodeText"].to_s]).reject(&:empty?).join(" ")
    end

    def classify(spec)
      name = spec_name(spec)
      file = (spec["LeafNodeLocation"] || {})["FileName"].to_s
        .sub(%r{\A(?:.*/kubernetes-v1\.36\.2/|k8s\.io/kubernetes/)}, "")
      labels = (Array(spec["ContainerHierarchyLabels"]).flatten + Array(spec["LeafNodeLabels"])).compact.uniq
      classification, reason, external =
        if PLATFORM_TAGS.any? { |tag| name.include?(tag) } || labels.any? { |label| label.to_s.downcase.include?("windows") }
          ["platform-inapplicable", "asserts a non-Linux platform only", false]
        elsif file == GCE_PROXY_MIGRATION
          ["provider-private", "requires GCE upgrades that switch kube-proxy static Pods and DaemonSets", true]
        elsif (provider = storage_provider_reason(file, name))
          ["provider-private", provider, true]
        elsif PROVIDER_TAGS.any? { |tag| name.include?(tag) }
          ["provider-private", "requires a specific cloud account, vendor hardware or provider-private API", true]
        elsif (internal = internal_reason(file, spec["LeafNodeText"]))
          ["implementation-internal", internal, true]
        else
          ["required", "exercises a public Linux cluster API or externally observable behaviour", false]
        end
      replacement_index, replacement_case = replacement_for(classification, name, file)
      {
        "id" => name,
        "file" => file,
        "labels" => labels,
        "classification" => classification,
        "reason" => reason,
        "external_contract" => external,
        "replacement_test" => replacement_case && replacement_index::RUNNER,
        "reviewer" => "tools/conformance/build_selection_ledger.rb"
      }.tap { |entry| entry["replacement_case"] = replacement_case if replacement_case }
    end

    def replacement_for(classification, name, file)
      case classification
      when "implementation-internal"
        [K3InternalContractIndex, K3InternalContractIndex::CASES[name]]
      when "provider-private"
        [K3LocalVolumeContractIndex, K3CSIContractIndex].each do |index|
          replacement = index.case_for(name, file)
          return [index, replacement] if replacement
        end
        nil
      end
    end

    def storage_provider_reason(file, name)
      return unless file.start_with?("test/e2e/storage/testsuites/")

      # drivers/csi.go SkipUnsupportedTest only accepts gce and PrepareTest
      # deploys the GCE PD CSI driver with provider credentials.
      return "requires the GCE provider and its Persistent Disk CSI driver credentials" if name.include?(GCE_PD_CSI)

      # drivers/in_tree.go PrepareTest checks for actual local SSDs mounted
      # under /mnt/disks/by-uuid/google-local-ssds-scsi-fs.
      "requires a mounted Google local SCSI SSD filesystem on the node" if name.include?(GCE_LOCAL_SSD)
    end

    def internal_reason(file, leaf)
      return INTERNAL_FILES.fetch(file) if INTERNAL_FILES.key?(file)
      return unless file == "test/e2e/instrumentation/monitoring/metrics_grabber.go" && COMPONENT_METRICS.include?(leaf)

      "locates and proxies metrics from an upstream-named control-plane Pod"
    end
  end
end

exit(Conformance::SelectionLedger.run) if $PROGRAM_NAME == __FILE__
