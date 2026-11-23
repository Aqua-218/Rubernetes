# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/conformance/k3_observations"

class ConformanceK3ObservationsTest < Minitest::Test
  Observations = Conformance::K3Observations
  K3 = Conformance::Lanes::K3
  JUnit = Conformance::K3JUnit
  TAG = "v1.36.2"
  ID = "[sig-example] accepts a < b & c > d"
  VERSIONED_ID = "#{ID} [KubeletMinVersion:1.36]".freeze

  def test_lane_metadata_keeps_the_exact_junit_id_and_provenance
    with_lane_artifacts do |paths, command|
      File.write(paths.fetch(:command), JSON.generate("command" => command))
      records, rejected = observe(paths)

      assert_empty rejected
      assert_equal [{"outcome" => "passed", "junit" => paths.fetch(:junit), "selection" => paths.fetch(:selection),
                     "command" => paths.fetch(:command), "provenance" => paths.fetch(:selection)}], records.fetch(ID)
    end
  end

  def test_extra_focus_flag_rejects_the_execution
    with_lane_artifacts do |paths, command|
      File.write(paths.fetch(:command), JSON.generate("command" => command + ["--ginkgo.focus=.*"]))
      records, rejected = observe(paths)

      assert_empty records
      assert_equal paths.fetch(:command), rejected.fetch(0).fetch("path")
    end
  end

  def test_pinned_junit_component_annotation_matches_its_exact_ledger_id
    annotated = "#{VERSIONED_ID} [kubelet: [>=1.36]]"
    with_lane_artifacts(id: VERSIONED_ID, report_ids: [annotated]) do |paths, command|
      File.write(paths.fetch(:command), JSON.generate("command" => command))
      records, rejected = observe(paths)

      assert_empty rejected
      assert_equal "passed", records.fetch(VERSIONED_ID).fetch(0).fetch("outcome")
      assert K3.junit_chunk(paths.fetch(:junit), [VERSIONED_ID]).fetch("complete")
    end
  end

  def test_other_annotations_or_versions_are_unexpected
    mismatched = "#{VERSIONED_ID} [kubelet: [>=1.35]]"
    undeclared = "#{ID} [kubelet: [>=1.36]]"
    unrelated = "#{VERSIONED_ID} [apiserver: [>=1.36]]"
    with_lane_artifacts(id: VERSIONED_ID, report_ids: [mismatched, undeclared, unrelated]) do |paths, command|
      File.write(paths.fetch(:command), JSON.generate("command" => command))
      records, rejected = observe(paths)
      totals = K3.junit_chunk(paths.fetch(:junit), [VERSIONED_ID])

      assert_empty records
      assert_includes rejected.fetch(0).fetch("detail"), "unexpected execution"
      assert_equal [mismatched, undeclared, unrelated], totals.fetch("unexpected_executions")
      refute totals.fetch("complete")
    end
  end

  def test_version_annotation_cannot_hide_a_duplicate
    annotated = "#{VERSIONED_ID} [kubelet: [>=1.36]]"
    with_lane_artifacts(id: VERSIONED_ID, report_ids: [VERSIONED_ID, annotated]) do |paths, command|
      File.write(paths.fetch(:command), JSON.generate("command" => command))
      records, rejected = observe(paths)
      totals = K3.junit_chunk(paths.fetch(:junit), [VERSIONED_ID])

      assert_empty rejected
      assert_equal "duplicate", records.fetch(VERSIONED_ID).fetch(0).fetch("outcome")
      assert_equal [VERSIONED_ID], totals.fetch("missing_failed_or_duplicate")
      refute totals.fetch("complete")
    end
  end

  def test_archiving_preserves_xml_bytes_verdict_and_provenance
    with_lane_artifacts do |paths, command|
      xml = paths.fetch(:junit)
      bytes = File.binread(xml).gsub("\n", "\r\n") + "<!-- 東京 • -->\r\n".b
      File.binwrite(xml, bytes)
      before = K3.junit_totals(paths.fetch(:root), [[ID]])
      report = JUnit.archive_completed(File.dirname(xml))
      archive = report.fetch("path")
      executions = [{"command" => command, "junit_report" => report}]
      File.write(paths.fetch(:command), JSON.generate(executions.first))
      records, rejected = observe(paths)

      refute_path_exists xml
      assert_equal "#{xml}.gz", archive
      assert_equal Digest::SHA256.hexdigest(bytes), report.fetch("xml_sha256")
      assert_equal bytes, JUnit.read(xml), "a reader that discovered the XML before publication can still read it"
      assert_equal report, JUnit.archive_completed(File.dirname(xml)), "a completed archive may be retried"
      assert_equal before, K3.junit_totals(paths.fetch(:root), [[ID]], executions: executions)
      assert_empty rejected
      assert_equal "passed", records.fetch(ID).fetch(0).fetch("outcome")
      assert_equal archive, records.fetch(ID).fetch(0).fetch("junit")
    end
  end

  def test_two_formats_count_once_only_if_their_contents_match
    with_lane_artifacts do |paths, command|
      xml = paths.fetch(:junit)
      dir = File.dirname(xml)
      bytes = File.binread(xml)
      archive = JUnit.archive_completed(dir).fetch("path")
      File.binwrite(xml, bytes)

      assert_equal [archive], JUnit.paths(dir)

      File.open(xml, "ab") { |file| file.write("\n") }
      File.write(paths.fetch(:command), JSON.generate("command" => command))
      records, rejected = observe(paths)

      assert_equal 2, JUnit.paths(dir).length
      assert_nil JUnit.archive_completed(dir)
      assert_empty records
      assert_includes rejected.fetch(0).fetch("detail"), "expected one raw Ginkgo JUnit report"
      assert_equal 0, K3.junit_totals(paths.fetch(:root), [[ID]]).fetch("reports")
    end
  end

  def test_diagnostic_family_metadata_binds_a_compressed_report_to_its_xml_digest
    with_lane_artifacts do |paths, command|
      root = paths.fetch(:root)
      File.unlink(paths.fetch(:selection))
      File.write(File.join(root, "selection.json"), JSON.generate([ID]))
      File.write(File.join(root, "command.json"), JSON.generate(command.drop(4)))
      report = JUnit.archive_completed(File.dirname(paths.fetch(:junit)))
      report["xml_sha256"] = "1" * 64
      family = {"kubernetes_tag" => TAG, "binary_sha256" => "sample",
                "suite_results" => [{"suite" => File.basename(root), "archived_junit" => report}]}
      File.write(File.join(root, "family-results.json"), JSON.generate(family))
      records, rejected = observe(paths)

      assert_empty records
      assert_includes rejected.fetch(0).fetch("detail"), "checksum differs"
    end
  end

  def test_two_archivers_publish_one_logical_report
    with_lane_artifacts do |paths, _command|
      xml = paths.fetch(:junit)
      raw = File.binread(xml)
      directory = File.dirname(xml)
      ready = Queue.new
      start = Queue.new
      writers = Array.new(2) do
        Thread.new do
          ready << true
          start.pop
          JUnit.archive_completed(directory)
        end
      end
      2.times { ready.pop(timeout: 2) }
      2.times { start << true }
      reports = writers.map(&:value)

      assert_equal ["#{xml}.gz"], JUnit.paths(directory)
      assert_equal [Digest::SHA256.hexdigest(raw)], reports.map { |report| report.fetch("xml_sha256") }.uniq
      assert_equal raw, JUnit.read(xml)
      refute_path_exists xml
    end
  end

  def test_wrong_recorded_digest_or_corrupt_archive_cannot_supply_a_pass
    with_lane_artifacts do |paths, command|
      report = JUnit.archive_completed(File.dirname(paths.fetch(:junit)))
      execution = {"command" => command, "junit_report" => report.merge("xml_sha256" => "0" * 64)}
      File.write(paths.fetch(:command), JSON.generate(execution))
      records, rejected = observe(paths)

      assert_empty records
      assert_includes rejected.fetch(0).fetch("detail"), "checksum differs"
      assert_equal 0, K3.junit_totals(paths.fetch(:root), [[ID]], executions: [execution]).fetch("passed")

      File.write(paths.fetch(:command), JSON.generate("command" => command))
      archive = report.fetch("path")
      original = File.binread(archive)
      corrupt = original.dup
      corrupt.setbyte(-8, corrupt.getbyte(-8) ^ 0xff)
      File.binwrite(archive, corrupt)
      records, rejected = observe(paths)

      assert_empty records
      assert_includes rejected.fetch(0).fetch("detail"), "invalid JUnit gzip report"

      File.binwrite(archive, original + "unexpected trailing bytes")
      records, rejected = observe(paths)

      assert_empty records
      assert_includes rejected.fetch(0).fetch("detail"), "unexpected data after the JUnit gzip stream"
      assert_equal 0, K3.junit_totals(paths.fetch(:root), [[ID]]).fetch("passed")
    end
  end

  def test_truncated_xml_is_preserved_and_never_counted
    with_lane_artifacts do |paths, command|
      xml = paths.fetch(:junit)
      bytes = File.binread(xml).sub(%r{</testsuites>\s*\z}, "")
      File.binwrite(xml, bytes)
      File.write(paths.fetch(:command), JSON.generate("command" => command))
      records, rejected = observe(paths)

      assert_nil JUnit.archive_completed(File.dirname(xml))
      assert_equal bytes, File.binread(xml)
      assert_empty records
      assert_equal 1, rejected.length
      assert_equal 0, K3.junit_totals(paths.fetch(:root), [[ID]]).fetch("passed")
    end
  end

  private

  def with_lane_artifacts(id: ID, report_ids: [id])
    Dir.mktmpdir("k3-observation") do |root|
      binary = File.join(root, "e2e.test")
      report_dir = File.join(root, "chunk-000")
      FileUtils.mkdir_p(report_dir)
      paths = {root: root, binary: binary, junit: File.join(report_dir, "junit_01.xml"),
               selection: File.join(root, "upstream-selection.json"), command: File.join(root, "e2e-command-000.json")}
      File.write(paths.fetch(:selection), JSON.generate("kubernetes_tag" => TAG, "binary_path" => binary,
                                                        "binary_sha256" => "sample", "chunks" => [[id]]))
      testcases = report_ids.map do |report_id|
        %(<testcase name="[It] #{REXML::Text.normalize(report_id)}" status="passed"/>)
      end
      File.write(paths.fetch(:junit), <<~XML)
        <testsuites><testsuite>
          <properties><property name="SuiteSucceeded" value="true"/></properties>
          #{testcases.join("\n")}
          <testcase name="[It] different spec" status="skipped"><skipped/></testcase>
        </testsuite></testsuites>
      XML
      yield paths, ["ip", "netns", "exec", "test-fixture", binary, "--provider=skeleton",
                    "--ginkgo.focus=#{K3.focus_pattern([id])}", "--report-dir=#{report_dir}"]
    end
  end

  def observe(paths)
    records = Hash.new { |results, id| results[id] = [] }
    rejected = []
    Observations.observe_fixture(paths.fetch(:root), tag: TAG, binary: paths.fetch(:binary), digest: "sample",
                                                     records: records, rejected: rejected)
    [records, rejected]
  end
end
