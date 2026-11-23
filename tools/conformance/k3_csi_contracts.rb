#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "yaml"
require_relative "k3_csi_contract_index"
require_relative "k3_csi_fixture"
require_relative "k3_csi_restart_contracts"
require_relative "k3_junit"

module Conformance
  class K3CSIContracts
    I = K3CSIContractIndex

    def initialize(source:, reports:, binary:, case_ids: nil)
      @source = source
      @reports = File.expand_path(reports)
      @binary = binary
      @case_ids = case_ids
    end

    def run(cases)
      raise ArgumentError, "select distinct, known CSI storage contracts" if cases.empty? || cases.uniq != cases || (cases - I::CONTRACTS.keys).any?

      profiles = cases.group_by { |key| profile_for(key) }
      runs = profiles.map do |filesystem, selected|
        directory = profiles.one? ? @reports : File.join(@reports, filesystem)
        run_profile(selected, directory, filesystem)
      rescue K7ClusterDriver::Unsupported => error
        results = selected.flat_map do |key|
          replacement = "#{I.external_for(key)} #{I.patterned_suffix(key)}"
          contract_results(key, replacement, []).map { |result| result.merge("reason" => error.message) }
        end
        {"passed" => false, "results" => results, "report" => nil}
      end
      return runs.first if runs.one?

      {"passed" => runs.all? { |run| run.fetch("passed") }, "results" => runs.flat_map { |run| run.fetch("results") },
       "reports" => runs.filter_map { |run| run.fetch("report") },
       "report_artifacts" => runs.flat_map { |run| run.fetch("report_artifacts", []) }}
    end

    private

    def profile_for(key)
      filesystem = key[/\Acsi-(ext3|ext4|xfs)-/, 1]
      return filesystem if filesystem
      return key.start_with?("csi-nfs-") ? "nfs-node" : "node" if K3CSIRestartContracts::CASES.key?(key)
      return "nfs" if key.start_with?("csi-nfs-")
      return "rbd" if key.start_with?("csi-rbd-")
      return "raw-stress" if key == "csi-raw-volume-stress"
      return "topology" if key.start_with?("csi-topology-")

      "default"
    end

    def run_profile(cases, directory, profile)
      FileUtils.mkdir_p(directory)
      return run_node_profile(cases, directory, nfs: profile == "nfs-node") if %w[node nfs-node].include?(profile)

      report = File.join(directory, "ginkgo.json")
      if [report, "#{report}.gz"].any? { |path| File.exist?(path) || File.symlink?(path) } ||
         !Dir.glob(K3JUnit::REPORTS, base: directory).empty?
        raise "CSI reports already exist in: #{directory}"
      end

      snapshots = cases.any? { |key| I.patterned_suffix(key).include?("[Feature:VolumeSnapshotDataSource]") }
      expansion = cases.any? { |key| I::FILES.fetch(key).end_with?("/volume_expand.go") || key.end_with?("-expansion") }
      fixture = K3CSIFixture.new(@source, directory)
      setup = lambda do |storage_class, node|
        definition = write_driver_definition(directory, storage_class, node, snapshots: snapshots, expansion: expansion, profile: profile, cases: cases)
        log = File.join(directory, "e2e.log")
        status = system(@binary, "--provider=skeleton", "--kubeconfig=#{ENV.fetch("KUBECONFIG")}",
                        "--kubectl-path=#{K7ClusterDriver::KUBECTL}", "--storage.testdriver=#{definition}",
                        "--ginkgo.focus=#{focus(cases)}", "--ginkgo.no-color", "--ginkgo.json-report=#{report}",
                        "--report-dir=#{directory}", out: log, err: %i[child out])
        summarize(cases, report, status)
      end
      return fixture.with_topology_driver(&setup) if profile == "topology"
      return fixture.with_nfs_driver(&setup) if profile == "nfs"
      return fixture.with_rbd_driver(mount_options: cases.include?("csi-rbd-mount-options"), &setup) if profile == "rbd"
      return fixture.with_driver(filesystem: "ext4", backing_capacity: 64 * (1024**3), &setup) if profile == "raw-stress"

      filesystem = profile if K3CSIFixture::FILESYSTEM_FORMATTERS.key?(profile)
      fixture.with_driver(snapshots: snapshots, expansion: expansion, filesystem: filesystem, &setup)
    end

    def summarize(cases, report, status)
      directory = File.dirname(report)
      bytes = File.binread(report) if File.file?(report)
      suites = bytes ? JSON.parse(bytes) : []
      results = case_results(cases, suites)
      verify_rejected_block_provision(results, directory) if cases.include?("csi-nfs-block-provision-denied")
      ginkgo = record_ginkgo(report, bytes, suites) if bytes
      junit = K3JUnit.archive_completed(directory)
      if junit
        junit = {"path" => junit.fetch("path"), "sha256" => junit.fetch("sha256"),
                 "uncompressed_sha256" => junit.fetch("xml_sha256"), "uncompressed_bytes" => junit.fetch("xml_bytes")}
      end
      {"passed" => status == true && results.all? { |result| result.fetch("passed") }, "results" => results,
       "report" => ginkgo&.fetch("path") || report, "report_artifacts" => [ginkgo, junit].compact}
    end

    def record_ginkgo(report, bytes, suites)
      complete = suites.one? && [true, false].include?(suites.first["SuiteSucceeded"])
      artifact = complete ? ReportArchive.retain(report, bytes: bytes) : ReportArchive.artifact_for(report)
      artifact.merge("path" => File.expand_path(artifact.fetch("path"), Lock::ROOT))
    end

    def run_node_profile(cases, directory, nfs:)
      report = File.join(directory, "node-observations.json")
      raise "the CSI node observation report already exists: #{report}" if File.exist?(report)

      fixture = K3CSIFixture.new(@source, directory)
      setup = lambda do |storage_class, node|
        driver = K3CSIRestartContracts.new(storage_class, node, nfs: nfs)
        observations = cases.to_h do |key|
          evidence = driver.run(**K3CSIRestartContracts::CASES.fetch(key))
          [key, evidence.merge("state" => "passed")]
        rescue StandardError => error
          [key, {"state" => "failed", "reason" => error.message}]
        end
        File.write(report, JSON.pretty_generate(observations))
        results = cases.flat_map do |key|
          contract_results(key, I.patterned_suffix(key), [observations.fetch(key).fetch("state")])
        end
        {"passed" => results.all? { |result| result.fetch("passed") }, "results" => results, "report" => report}
      end
      nfs ? fixture.with_nfs_driver(select_node: true, &setup) : fixture.with_driver(&setup)
    end

    def write_driver_definition(directory, storage_class, node, snapshots:, expansion:, profile:, cases:)
      path = File.join(directory, "testdriver.yml")
      nfs = profile == "nfs"
      names, driver = case profile
                      when "nfs" then [%w[persistence multipods RWX], K3CSINFSFixture::NFS_DRIVER]
                      when "rbd" then [%w[block persistence], I::RBD_DRIVER]
                      else [%w[block persistence exec fsGroup multipods multiplePVsSameID readWriteOncePod], K3CSIFixture::DRIVER]
                      end
      capabilities = names.to_h { |name| [name, true] }
      minimum_size = nfs ? "1Gi" : "5Gi"
      data = {"StorageClass" => {"FromExistingClassName" => storage_class},
              "DriverInfo" => {"Name" => driver, "MaxFileSize" => 104_857_600, "SupportedSizeRange" => {"Min" => minimum_size},
                               "RequiredAccessModes" => ["ReadWriteOnce"], "Capabilities" => capabilities}}
      data.fetch("DriverInfo")["StressTestOptions"] = {"NumPods" => 10, "NumRestarts" => 10} if cases.intersect?(%w[csi-volume-stress csi-raw-volume-stress])
      if cases.any? { |key| key.start_with?("csi-snapshot-stress-") }
        data.fetch("DriverInfo")["VolumeSnapshotStressTestOptions"] = {"NumPods" => 20, "NumSnapshots" => 2}
      end
      data["NodeSelectors"] = {"kubernetes.io/hostname" => node} if node
      data.fetch("DriverInfo")["SupportedFsType"] = {profile => {}} if K3CSIFixture::FILESYSTEM_FORMATTERS.key?(profile)
      if profile == "rbd"
        info = data.fetch("DriverInfo")
        info["SupportedFsType"] = {"" => {}, "ext4" => {}}
        info["SupportedMountOption"] = K3CSIRBDFixture::MOUNT_OPTIONS.to_h { |mode| [mode, {}] } if cases.include?("csi-rbd-mount-options")
      end
      if profile == "topology"
        data.fetch("DriverInfo")["TopologyKeys"] = [K3CSITopologyFixture::TOPOLOGY_KEY]
        capabilities["topology"] = true
      end
      if snapshots
        data["SnapshotClass"] = {"FromName" => true}
        capabilities["snapshotDataSource"] = true
      end
      if expansion
        capabilities["controllerExpansion"] = true
        %w[nodeExpansion offlineExpansion onlineExpansion].each { |name| capabilities[name] = true } unless nfs
      end
      File.write(path, YAML.dump(data))
      path
    end

    def focus(cases)
      specs = cases.map do |key|
        Regexp.escape("Kubernetes e2e suite #{I.external_for(key)} #{I.patterned_suffix(key)}").gsub("\\ ", " ")
      end
      "\\A(#{specs.join("|")})\\z"
    end

    def case_results(cases, suites)
      specs = suites.flat_map { |suite| suite.fetch("SpecReports") }.select { |spec| spec["LeafNodeType"] == "It" }
      cases.flat_map do |key|
        suffix = I.patterned_suffix(key)
        file = I::FILES.fetch(key)
        replacement = "#{I.external_for(key)} #{suffix}"
        matches = specs.select { |spec| spec_name(spec) == replacement && source_file(spec) == file }
        contract_results(key, replacement, matches.map { |spec| spec["State"] })
      end
    end

    def verify_rejected_block_provision(results, directory)
      # The stock assertion permits a claim that stayed Pending without
      # reaching the driver. Require the pinned driver's own RPC error too.
      error = "GRPC error: rpc error: code = InvalidArgument desc = block volume capability not supported"
      received = Dir.glob(File.join(directory, "worker-*-nfsplugin.log")).any? do |path|
        File.foreach(path).any? { |line| line.include?(error) }
      end
      return if received

      results.each do |result|
        next unless result["replacement_case"] == "csi-nfs-block-provision-denied"

        result.merge!("passed" => false, "reason" => "NFS CSI did not observe an unsupported Block request")
      end
    end

    def contract_results(key, replacement, states)
      ids = I::CASES.filter_map { |id, mapped| id if mapped == key && (@case_ids.nil? || @case_ids.include?(id)) }
      ids.map do |id|
        {"id" => id, "file" => I::FILES.fetch(key), "replacement_case" => key, "replacement_name" => replacement,
         "passed" => states == ["passed"], "states" => states}
      end
    end

    def spec_name(spec)
      (spec.fetch("ContainerHierarchyTexts") + [spec.fetch("LeafNodeText")]).reject(&:empty?).join(" ")
    end

    def source_file(spec)
      spec.dig("LeafNodeLocation", "FileName").to_s.sub(%r{\A(?:.*/kubernetes-v1\.36\.2/|k8s\.io/kubernetes/)}, "")
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    runner = Conformance::K3CSIContracts.new(source: ENV.fetch("RUBERNETES_KUBERNETES_SOURCE"),
                                             reports: ENV.fetch("RUBERNETES_K3_CSI_REPORTS"),
                                             binary: ENV.fetch("RUBERNETES_K3_E2E_BINARY"),
                                             case_ids: JSON.parse(ENV.fetch("RUBERNETES_K3_CSI_CASE_IDS", "null")))
    result = runner.run(ARGV)
    puts JSON.generate(result)
    exit(result.fetch("passed") ? 0 : 1)
  rescue StandardError => error
    warn "K3 CSI storage fixture: #{error.class}: #{error.message}"
    exit 2
  end
end
