# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/conformance/lanes"
require "tmpdir"

class ConformanceK4NodeConformanceTest < Minitest::Test
  K4 = Conformance::Lanes::K4
  Evidence = Conformance::K4Evidence

  def test_selected_cases_and_suite_hooks_must_pass
    expected = suite(spec("volume"), spec("resource", "skipped"))
    actual = suite(spec("volume"), spec("resource", "skipped"))

    assert K4.compare(expected, actual).fetch("complete")
    refute K4.compare(expected, actual.merge("SuiteSucceeded" => false)).fetch("complete")
  end

  def test_unexpected_execution_and_skipped_selected_cases_fail_coverage
    expected = suite(spec("volume"), spec("resource", "skipped"))
    actual = suite(spec("volume", "skipped"), spec("resource"))
    result = K4.compare(expected, actual)

    refute result.fetch("complete")
    assert_equal 1, result.fetch("selected")
    assert_equal 0, result.fetch("passed")
    assert_equal ["skipped"], result.fetch("missing_failed_or_skipped").first.fetch("states")
    assert_equal "Node tests resource", result.fetch("unexpected_executions").first.fetch("name")
  end

  def test_missing_and_duplicate_selected_cases_fail_coverage
    expected = suite(spec("volume"))

    refute K4.compare(expected, suite).fetch("complete")
    refute K4.compare(expected, suite(spec("volume"), spec("volume"))).fetch("complete")
  end

  def test_node_runtime_probes_use_the_configured_cri_endpoint
    connection = {"dns_domain" => "cluster.local", "endpoint" => "https://localhost:6443", "name" => "worker-0",
                  "token" => "test-token", "kubectl" => "/tools/kubectl"}
    endpoint = "unix:///run/custom-cri.sock"

    assert_includes K4.node_arguments(connection.merge("runtime_endpoint" => endpoint), "/reports"), "--container-runtime-endpoint=#{endpoint}"
    assert_includes K4.node_arguments(connection.merge("runtime_endpoint" => ""), "/reports"), "--container-runtime-endpoint="
  end

  def test_completed_suite_archives_exact_reports_and_redacted_execution_records
    inventory = suite_json(dry_run: true)
    report = suite_json(dry_run: false)
    junit = junit_xml
    reports = {K4::INVENTORY => inventory, K4::REPORT => report, K4::JUNIT => junit, "junit_01.xml" => junit}
    Dir.mktmpdir do |directory|
      result = run_suite_fixture(directory, reports)

      assert result.fetch("passed")
      assert_equal 1, result.dig("coverage", "passed")
      reports.each do |name, bytes|
        assert_archive(result, directory, name, bytes)
      end
      execution_artifacts = %w[inventory-execution.json execution.json] + Conformance::K4RRO::OBSERVATIONS
      execution_artifacts.each do |name|
        bytes = Evidence.read(File.join(directory, name))

        assert_archive(result, directory, name, bytes)

        capture = JSON.parse(bytes)

        assert_equal "stdout [redacted] �", capture.fetch("stdout")
        assert_equal "stderr [redacted]", capture.fetch("stderr")
        assert_includes capture.fetch("command"), "--bearer-token=[redacted]" unless Conformance::K4RRO::OBSERVATIONS.include?(name)
      end

      assert_equal JSON.parse(inventory).first, K4.load_suite(directory, K4::INVENTORY, dry_run: true)
      assert_equal JSON.parse(report).first, K4.load_suite(directory, K4::REPORT, dry_run: false)
    end
  end

  def test_malformed_reports_remain_available_for_diagnosis
    Dir.mktmpdir do |directory|
      malformed_json = "[{\"SuiteDescription\":"
      result = run_suite_fixture(directory, {K4::INVENTORY => suite_json(dry_run: true), K4::REPORT => malformed_json})

      refute result.fetch("passed")
      assert_equal "upstream Node Conformance execution did not produce a valid report", result.fetch("reason")
      assert_equal malformed_json, Evidence.read(File.join(directory, K4::REPORT))
      refute_path_exists File.join(directory, "#{K4::REPORT}.gz")
    end

    Dir.mktmpdir do |directory|
      malformed_xml = "<testsuites><testsuite>"
      reports = {K4::INVENTORY => suite_json(dry_run: true), K4::REPORT => suite_json(dry_run: false), K4::JUNIT => malformed_xml}
      result = run_suite_fixture(directory, reports)

      refute result.fetch("passed")
      assert_equal "stock Node Conformance JUnit does not match the execution", result.fetch("reason")
      assert_equal malformed_xml, Evidence.read(File.join(directory, K4::JUNIT))
      refute_path_exists File.join(directory, "#{K4::JUNIT}.gz")
    end
  end

  def test_historical_raw_report_and_conflicting_archive_keep_distinct_bytes
    Dir.mktmpdir do |directory|
      raw = File.join(directory, K4::INVENTORY)
      bytes = suite_json(dry_run: true)
      digest = Digest::SHA256.hexdigest(bytes)
      File.binwrite(raw, bytes)

      assert_equal JSON.parse(bytes).first, K4.load_suite(directory, K4::INVENTORY, dry_run: true)
      assert_equal bytes, Evidence.read("#{raw}.gz", sha256: digest)
      assert_raises(Evidence::Error) { Evidence.read(raw, sha256: "0" * 64) }

      invalid_archive = "#{raw}.gz"
      File.binwrite(invalid_archive, "invalid gzip")
      artifact = Evidence.retain(raw, bytes: bytes)

      assert_equal raw, artifact.fetch("path")
      assert_equal digest, artifact.fetch("sha256")
      assert_equal bytes, Evidence.read(raw, sha256: digest)
      assert_equal "invalid gzip", File.binread(invalid_archive)
      assert_raises(Evidence::Error) { Evidence.read(invalid_archive) }
      assert_empty Dir.glob(File.join(directory, ".report-*.pending"))
    end
  end

  private

  def assert_archive(result, directory, name, bytes)
    path = File.join(directory, "#{name}.gz")
    artifact = result.fetch("artifacts").find { |entry| entry.fetch("path") == path }

    refute_nil artifact, name
    assert_equal Digest::SHA256.file(path).hexdigest, artifact.fetch("sha256")
    assert_equal Digest::SHA256.hexdigest(bytes), artifact.fetch("uncompressed_sha256")
    assert_equal bytes.bytesize, artifact.fetch("uncompressed_bytes")
    assert_equal bytes, Evidence.read(File.join(directory, name), sha256: artifact.fetch("uncompressed_sha256"))
    refute_path_exists File.join(directory, name)
  end

  def run_suite_fixture(directory, reports)
    connection = {"dns_domain" => "cluster.local", "endpoint" => "https://localhost:6443", "name" => "worker-0",
                  "token" => "unit-t0ken", "kubectl" => "/tools/kubectl", "node" => {}}
    kubeconfig = "/fixture/kubeconfig"
    capture = lambda do |command, env:, timeout:|
      assert_equal({"KUBECONFIG" => kubeconfig}, env)
      if timeout
        assert_equal 30, timeout
        assert_equal ["/tools/kubectl", "--kubeconfig=#{kubeconfig}", "--server=https://localhost:6443", "get", "--raw", "/api/v1/nodes"], command
      else
        assert_includes command, "--bearer-token=#{connection.fetch("token")}"
        files = if command.include?("--dry-run")
                  reports.slice(K4::INVENTORY)
                else
                  assert_includes command, "--junit-report=#{File.join(directory, K4::JUNIT)}"
                  reports.except(K4::INVENTORY)
                end
        files.each { |name, bytes| File.binwrite(File.join(directory, name), bytes) }
      end
      {"command" => command, "exit_status" => 0, "stdout" => +"stdout unit-t0ken \xff".b, "stderr" => +"stderr unit-t0ken"}
    end
    Conformance::Lanes.stub(:capture, capture) do
      K4.stub(:pinned_inventory?, true) do
        K4.run_suite("/tools/e2e_node.test", build: {}, connection: connection, kubeconfig: kubeconfig, directory: directory)
      end
    end
  end

  def suite_json(dry_run:)
    config = {"LabelFilter" => K4::LABEL, "DryRun" => dry_run, "RandomSeed" => 1, "FailOnEmpty" => true,
              "FailFast" => false, "FlakeAttempts" => 0, "MustPassRepeatedly" => 0, "SemVerFilter" => ""}
    entry = spec("volume").merge("NumAttempts" => dry_run ? 0 : 1)
    document = suite(entry).merge("SuiteDescription" => "E2eNode Suite", "SuiteHasProgrammaticFocus" => false, "SuiteConfig" => config)
    " \n#{JSON.pretty_generate([document])}\n".b
  end

  def junit_xml
    <<~XML.b
      <testsuites><testsuite name="E2eNode Suite"><properties>
        <property name="SuiteSucceeded" value="true"/>
        <property name="SuiteHasProgrammaticFocus" value="false"/>
        <property name="LabelFilter" value="NodeConformance"/>
        <property name="DryRun" value="false"/>
        <property name="RandomSeed" value="1"/>
      </properties><testcase name="[It] Node tests volume" status="passed"/></testsuite></testsuites>
    XML
  end

  def spec(name, state = "passed")
    {"LeafNodeType" => "It", "LeafNodeText" => name, "ContainerHierarchyTexts" => ["Node tests"],
     "LeafNodeLocation" => {"FileName" => "one_test.go", "LineNumber" => 42}, "State" => state, "NumAttempts" => state == "passed" ? 1 : 0}
  end

  def suite(*specs)
    {"SuiteSucceeded" => true, "SpecReports" => specs}
  end
end
