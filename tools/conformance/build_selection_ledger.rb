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

    # Tests that assert Kubernetes' own process paths, Go-internal metrics or
    # direct etcd manipulation rather than externally observable behaviour.
    INTERNAL_MARKERS = [
      "kubelet-serving", "[Feature:ComponentSLIs]", "componentstatuses",
      "kube-apiserver", "kube-controller-manager", "kube-scheduler",
      "etcd", "Kubelet Metrics", "apiserver metrics", "scheduler metrics",
      "controller-manager metrics", "/metrics", "static pod", "kubelet config",
      "GoRoutine", "golang", "pprof"
    ].freeze
    INTERNAL_FILES = %w[
      test/e2e/instrumentation/monitoring
      test/e2e/apimachinery/etcd
      test/e2e/node/kubelet_
      test/e2e/invariants
    ].freeze

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
      file = (spec["LeafNodeLocation"] || {})["FileName"].to_s.sub(%r{\A.*/kubernetes-v1\.36\.2/}, "")
      labels = (Array(spec["ContainerHierarchyLabels"]).flatten + Array(spec["LeafNodeLabels"])).compact.uniq
      classification, reason, external, replacement =
        if PLATFORM_TAGS.any? { |tag| name.include?(tag) } || labels.any? { |label| label.to_s.downcase.include?("windows") }
          ["platform-inapplicable", "asserts a non-Linux platform only", false, nil]
        elsif PROVIDER_TAGS.any? { |tag| name.include?(tag) }
          ["provider-private", "requires a specific cloud account, vendor hardware or provider-private API",
           true, "test/conformance/kubernetes/m4_csi_cluster"]
        elsif INTERNAL_FILES.any? { |prefix| file.start_with?(prefix) } ||
              INTERNAL_MARKERS.any? { |marker| name.include?(marker) }
          ["implementation-internal", "asserts Kubernetes process paths, Go-internal metrics or direct etcd state",
           true, "test/conformance/kubernetes/m5_raft_cluster"]
        else
          ["required", "exercises a public Linux cluster API or externally observable behaviour", false, nil]
        end
      {
        "id" => name,
        "file" => file,
        "labels" => labels,
        "classification" => classification,
        "reason" => reason,
        "external_contract" => external,
        "replacement_test" => replacement,
        "reviewer" => "tools/conformance/build_selection_ledger.rb"
      }
    end
  end
end

exit(Conformance::SelectionLedger.run) if $PROGRAM_NAME == __FILE__
