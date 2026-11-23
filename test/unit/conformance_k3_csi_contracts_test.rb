# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/conformance/k3_csi_contracts"
require_relative "../../tools/milestones/m8_k3_replacements"

class ConformanceK3CSIContractsTest < Minitest::Test
  INDEX = Conformance::K3CSIContractIndex
  EXECUTION = "csi-store-data"

  def test_only_one_passing_result_from_the_same_upstream_case_counts
    good = spec

    assert result_for(good).fetch("passed")
    refute result_for(good.merge("State" => "skipped")).fetch("passed")
    refute result_for(good, good).fetch("passed")
    refute result_for(good.merge("LeafNodeLocation" => {"FileName" => "different/volumes.go"})).fetch("passed")
  end

  def test_topology_result_is_shared_only_by_explicit_origins
    key = "csi-topology-immediate-allowed"
    suffix = INDEX.patterned_suffix(key)
    source = INDEX::FILES.fetch(key)
    azure_disk = "[sig-storage] In-tree Volumes [Driver: azure-disk] #{suffix}"
    azure_file = "[sig-storage] In-tree Volumes [Driver: azure-file] #{suffix}"

    assert_equal key, INDEX.case_for(azure_disk, source)
    assert_nil INDEX.case_for(azure_disk, "different/topology.go")
    assert_nil INDEX.case_for(azure_file, source)
  end

  def test_network_filesystem_contract_matches_only_azure_file
    key = "csi-nfs-cross-node-concurrent"
    suffix = INDEX.patterned_suffix(key)
    source = INDEX::FILES.fetch(key)
    azure_file = "[sig-storage] In-tree Volumes [Driver: azure-file] #{suffix}"
    azure_disk = "[sig-storage] In-tree Volumes [Driver: azure-disk] #{suffix}"

    assert_equal key, INDEX.case_for(azure_file, source)
    assert_nil INDEX.case_for(azure_disk, source)
    assert_equal INDEX::EXTERNAL_NFS, INDEX.external_for(key)
  end

  def test_cross_node_block_backed_filesystem_contract_requires_the_matching_source
    key = "csi-rbd-cross-node-filesystem"
    suffix = INDEX.patterned_suffix(key)
    source = INDEX::FILES.fetch(key)
    cinder = "[sig-storage] In-tree Volumes [Driver: cinder] #{suffix}"
    azure_file = "[sig-storage] In-tree Volumes [Driver: azure-file] #{suffix}"

    assert_equal key, INDEX.case_for(cinder, source)
    assert_nil INDEX.case_for(cinder, "different/multivolume.go")
    refute_equal key, INDEX.case_for(azure_file, source)
    assert_equal INDEX::EXTERNAL_RBD, INDEX.external_for(key)
  end

  def test_azure_file_subpath_uses_the_same_stock_spec_on_the_nfs_driver
    key = "csi-nfs-subpath-deleted"
    suffix = INDEX.patterned_suffix(key)
    source = INDEX::FILES.fetch(key)

    assert_equal INDEX.patterned_suffix("csi-subpath-deleted"), suffix
    assert_equal key, INDEX.case_for("[sig-storage] In-tree Volumes [Driver: azure-file] #{suffix}", source)
    assert_equal "csi-subpath-deleted", INDEX.case_for("[sig-storage] In-tree Volumes [Driver: azure-disk] #{suffix}", source)
    assert_equal INDEX::EXTERNAL_NFS, INDEX.external_for(key)
  end

  def test_nfs_recovery_uses_node_observations_with_the_network_driver
    runner = Conformance::K3CSIContracts.new(source: ".", reports: ".", binary: "unused")

    assert_equal "nfs-node", runner.send(:profile_for, "csi-nfs-subpath-delete-during-restart")
    assert_equal "nfs", runner.send(:profile_for, "csi-nfs-subpath-deleted")
    assert_equal "node", runner.send(:profile_for, "csi-subpath-delete-during-restart")
  end

  def test_pending_block_claim_requires_rejection_observed_at_the_nfs_driver
    runner = Conformance::K3CSIContracts.new(source: ".", reports: ".", binary: "unused")
    result = {"replacement_case" => "csi-nfs-block-provision-denied", "passed" => true}
    Dir.mktmpdir do |directory|
      check = result.dup
      runner.send(:verify_rejected_block_provision, [check], directory)

      refute check.fetch("passed")

      File.write(File.join(directory, "worker-0-nfsplugin.log"),
                 "GRPC error: rpc error: code = InvalidArgument desc = block volume capability not supported\n")
      runner.send(:verify_rejected_block_provision, [result], directory)

      assert result.fetch("passed")
    end
  end

  def test_completed_csi_reports_preserve_original_bytes_and_record_the_archive
    with_reports do |directory, report, originals|
      runner = Conformance::K3CSIContracts.new(source: ".", reports: directory, binary: "unused")
      result = runner.send(:summarize, [EXECUTION], report, true)

      assert result.fetch("passed")
      assert_equal "#{report}.gz", result.fetch("report")
      assert_equal 2, result.fetch("report_artifacts").size
      result.fetch("report_artifacts").each do |artifact|
        path = artifact.fetch("path")
        original = originals.fetch(path.delete_suffix(".gz"))

        assert_equal Digest::SHA256.file(path).hexdigest, artifact.fetch("sha256")
        assert_equal original.bytesize, artifact.fetch("uncompressed_bytes")
        assert_equal Digest::SHA256.hexdigest(original), artifact.fetch("uncompressed_sha256")
        assert_equal original, Conformance::ReportArchive.read(path, alternate: false)
        refute_path_exists path.delete_suffix(".gz")
      end
    end
  end

  def test_m8_csi_reads_only_the_single_attested_representation
    with_reports do |directory, report, originals|
      root = File.expand_path("../..", directory)
      entries = [Conformance::ReportArchive.artifact_for(report)]
      records = {"artifacts" => entries}
      verifier = M8K3Replacements.new([], nil, lambda do |path, unique_format:|
        raise "CSI report selection must identify one original" unless unique_format

        Conformance::ArchivedArtifact.verify_format!(records, records, root, "k3/#{path}")
      end)
      historical = verifier.send(:csi_reports, {"passed" => true, "report" => report})
      runner = Conformance::K3CSIContracts.new(source: ".", reports: directory, binary: "unused")
      archived = runner.send(:summarize, [EXECUTION], report, true)
      archived_path = archived.fetch("report")
      entries.replace(archived.fetch("report_artifacts"))

      assert_equal historical, verifier.send(:csi_reports, archived)

      invalid_metadata = JSON.parse(JSON.generate(archived))
      invalid_metadata.fetch("report_artifacts").first["uncompressed_sha256"] = "0" * 64
      assert_raises(Conformance::ReportArchive::Error) { verifier.send(:csi_reports, invalid_metadata) }

      File.binwrite(report, originals.fetch(report))
      entries.push(Conformance::ReportArchive.artifact_for(report))
      assert_raises(Conformance::ArchivedArtifact::Invalid) { verifier.send(:csi_reports, archived) }

      entries.pop
      File.unlink(archived_path)
      assert_raises(Conformance::ArchivedArtifact::Missing) { verifier.send(:csi_reports, archived) }
    end
  end

  private

  def with_reports
    Dir.mktmpdir do |root|
      directory = File.join(root, "k3", "csi-replacements")
      FileUtils.mkdir_p(directory)
      report = File.join(directory, "ginkgo.json")
      junit = File.join(directory, "junit_01.xml")
      originals = {report => JSON.generate([{"SuiteSucceeded" => true, "SpecReports" => [spec]}]),
                   junit => '<testsuites><testsuite name="fixture"/></testsuites>'}
      originals.each { |path, bytes| File.binwrite(path, bytes) }
      yield directory, report, originals
    end
  end

  def spec
    {"LeafNodeType" => "It", "State" => "passed", "ContainerHierarchyTexts" => [INDEX::EXTERNAL, "[Testpattern: #{INDEX::DEFAULT_PATTERN}]", ""],
     "LeafNodeText" => INDEX::CONTRACTS.fetch(EXECUTION)[1],
     "LeafNodeLocation" => {"FileName" => "k8s.io/kubernetes/#{INDEX::FILES.fetch(EXECUTION)}"}}
  end

  def result_for(*specs)
    checker = Conformance::K3CSIContracts.new(source: ".", reports: ".", binary: "unused")
    checker.send(:case_results, [EXECUTION], [{"SpecReports" => specs}]).first
  end
end
