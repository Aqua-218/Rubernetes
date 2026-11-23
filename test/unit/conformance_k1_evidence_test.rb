# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/conformance/k1_evidence"
require_relative "../../tools/conformance/k1_ginkgo_report"
require "tempfile"

class ConformanceK1EvidenceTest < Minitest::Test
  Evidence = Conformance::K1Evidence
  GinkgoReport = Conformance::K1GinkgoReport
  CODENAMES = ["[sig-api-machinery] list A & B [Conformance]", "[sig-node] start a Pod [Conformance]"].freeze
  PROPERTIES = {
    "SuiteSucceeded" => "true", "SuiteHasProgrammaticFocus" => "false",
    "FocusStrings" => Evidence::FOCUS, "SkipStrings" => "", "FocusFiles" => "", "SkipFiles" => "",
    "LabelFilter" => "", "SemVerFilter" => "", "FlakeAttempts" => "0", "DryRun" => "false", "ParallelTotal" => "1"
  }.freeze

  def test_joins_only_selected_specs_by_exact_decoded_codename
    cases = [*CODENAMES.map { |name| ["[It] #{name}", "passed"] },
             ["[It] a spec outside the Conformance focus", "skipped"], ["[ReportBeforeSuite]", "passed"], ["[ReportBeforeSuite]", "passed"]]

    summary, joined = junit(cases)

    assert_equal({"selected" => 2, "passed" => 2, "failed" => 0, "skipped" => 0, "flaked" => 0},
                 summary.slice("selected", "passed", "failed", "skipped", "flaked"))
    assert_equal 1, summary["unselected"]
    assert_equal 2, summary["suite_hooks"]
    assert summary["suite_passed"]
    assert summary["execution_properties_match"]
    assert_empty joined["unmatched_codenames"]
    assert_empty joined["duplicate_codenames"]
    assert_empty joined["unexpected_codenames"]
  end

  def test_reports_outcomes_config_and_bad_codenames_independently
    unexpected = "[sig-node] overlapping text: #{CODENAMES.last}"
    cases = [["[It] #{CODENAMES.first}", "skipped"], ["[It] #{CODENAMES.first}", "panicked", "error"],
             ["[It] #{unexpected}", "passed"], ["[It] an unselected test ran", "passed"], ["[AfterSuite]", "failed", "failure"]]

    summary, joined = junit(cases, properties: {"DryRun" => "true"}, stdout: "[FLAKEY TEST - TOOK 2 ATTEMPTS TO PASS]")

    assert_equal({"selected" => 3, "passed" => 1, "failed" => 1, "skipped" => 1, "flaked" => 1},
                 summary.slice("selected", "passed", "failed", "skipped", "flaked"))
    refute summary["suite_passed"]
    refute summary["execution_properties_match"]
    assert_equal ["[AfterSuite]"], summary["setup_teardown_failures"]
    assert_equal ["[It] an unselected test ran"], summary["unexpected_executions"]
    assert_equal [CODENAMES.first], joined["duplicate_codenames"]
    assert_equal [CODENAMES.last], joined["unmatched_codenames"]
    assert_equal [unexpected], joined["unexpected_codenames"]
  end

  def test_joins_gzip_with_original_junit_and_checks_original_bytes
    _, _, original = junit(CODENAMES.map { |name| ["[It] #{name}", "passed"] }, properties: {"RandomSeed" => "90210"})
    raw = JSON.pretty_generate([ginkgo_suite])

    with_ginkgo_archive(raw) do |path|
      result = GinkgoReport.join(path, original, expected: 2)

      assert result["passed"]
      assert_equal Digest::SHA256.hexdigest(raw), result["raw_sha256"]
      assert_equal raw.bytesize, result["raw_bytes"]

      mismatched = GinkgoReport.join(path, original.merge("random_seed" => "10"), expected: 2)

      refute mismatched["passed"]
      refute mismatched["random_seed_match"]
    end
  end

  def test_rejects_pending_selected_specs_and_multiple_attempts
    _, _, original = junit(CODENAMES.map { |name| ["[It] #{name}", "passed"] }, properties: {"RandomSeed" => "90210"})
    suite = ginkgo_suite
    suite.fetch("SpecReports").fetch(0)["State"] = "pending"
    suite.fetch("SpecReports").fetch(1)["NumAttempts"] = 2

    with_ginkgo_archive(JSON.generate([suite])) do |path|
      result = GinkgoReport.join(path, original, expected: 2)

      refute result["passed"]
      refute result["junit_cases_match"]
      assert_equal({"pending" => 1, "passed" => 1}, result["outcomes"])
      assert_equal [CODENAMES.last], result["unexpected_attempts"]
    end
  end

  private

  def ginkgo_suite
    config = PROPERTIES.except("SuiteSucceeded", "SuiteHasProgrammaticFocus").merge(
      "FocusStrings" => [Evidence::FOCUS], "SkipStrings" => nil, "FocusFiles" => nil, "SkipFiles" => nil,
      "DryRun" => false, "ParallelTotal" => 1, "FlakeAttempts" => 0, "RandomSeed" => 90_210
    )
    specs = CODENAMES.map do |codename|
      container, leaf = codename.split(" ", 2)
      {"ContainerHierarchyTexts" => [container], "LeafNodeText" => leaf, "LeafNodeType" => "It",
       "State" => "passed", "NumAttempts" => 1}
    end
    {"SuiteConfig" => config, "SuiteSucceeded" => true, "SuiteHasProgrammaticFocus" => false, "SpecReports" => specs}
  end

  def with_ginkgo_archive(raw)
    Tempfile.create(["upstream-ginkgo", ".json.gz"]) do |file|
      Zlib::GzipWriter.open(file.path) { |writer| writer.write(raw) }
      yield file.path
    end
  end

  def junit(cases, properties: {}, stdout: "")
    report = REXML::Document.new
    suite = report.add_element("testsuites").add_element("testsuite", {"tests" => cases.length.to_s})
    property_list = suite.add_element("properties")
    PROPERTIES.merge(properties).each do |name, value|
      property_list.add_element("property", {"name" => name, "value" => value})
    end
    cases.each do |name, status, child|
      entry = suite.add_element("testcase", {"name" => name, "status" => status})
      entry.add_element(child) if child
    end
    Tempfile.create(["k1-junit", ".xml"]) do |file|
      report.write(file)
      file.flush
      Evidence.junit(file.path, codenames: CODENAMES, stdout: stdout)
    end
  end
end
