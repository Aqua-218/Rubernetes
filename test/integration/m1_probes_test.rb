# frozen_string_literal: true

require "json"
require "open3"
require "rbconfig"
require_relative "../test_helper"
require_relative "../../tools/milestones/m1_gate"
require_relative "../../tools/milestones/m1_kubernetes_validation_oracle"

class M1ProbesTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  KUBERNETES_SOURCE_ROOT = "/tmp/kubernetes-v1.36.2"
  REGISTRY_PATH = File.join(ROOT, "generated/schema/registry.json")

  def test_corpus_and_generation_probes_report_real_pinned_inputs
    corpus, _stderr, corpus_status = run_probe("corpus")

    assert_predicate corpus_status, :success?, corpus.fetch("errors").join("\n")
    assert_equal true, corpus.fetch("passed")
    assert_equal [321, 321], [corpus.dig("gvk", "expected_count"), corpus.dig("gvk", "registered_count")]
    assert_equal [153, 153], [corpus.dig("gvr", "expected_count"), corpus.dig("gvr", "registered_count")]

    generation, _stderr, generation_status = run_probe("generation")

    assert_equal generation.fetch("passed"), generation_status.success?
    assert_equal 2, generation.fetch("runs").length
    assert_equal 0, generation.fetch("byte_diff_count")
    assert_equal generation.fetch("canonical_differences").length, generation.fetch("canonical_diff_count")
    if generation.fetch("passed")
      assert_equal 0, generation.fetch("canonical_diff_count")
    else
      assert_operator generation.fetch("canonical_diff_count"), :>, 0
      assert_operator generation.fetch("failure_count"), :>, 0
    end
  end

  def test_roundtrip_probe_reports_a_complete_validation_criterion
    report, _stderr, status = run_probe("roundtrip")

    assert_predicate status, :success?, report.fetch("errors").join("\n")
    assert_equal true, report.fetch("passed")
    assert_equal 311, report.fetch("gvk_count")
    assert_equal 770, report.fetch("case_count")
    assert_equal 770, report.fetch("protobuf_supported_count")
    assert_equal(["io.k8s.apimachinery.pkg.version.Info"],
                 report.fetch("protobuf_unsupported_types").map { |entry| entry.fetch("id") })
    %w[json_roundtrip_failures protobuf_roundtrip_failures unknown_field_failures defaulting_failures validation_failures].each do |key|
      assert_equal 0, report.fetch(key), key
    end
    %w[json_roundtrip protobuf_roundtrip unknown_field defaulting validation].each do |key|
      assert_equal 770, report.fetch("cases").count { |entry| entry.fetch(key) }, key
    end
    assert_equal true, report.dig("oracle", "executed")
    assert_equal 770, report.dig("oracle", "comparison_count")
    assert_equal 0, report.dig("oracle", "missing_comparison_count")
    assert_equal 770, report.dig("oracle", "comparisons").length
    assert_equal 0, report.fetch("oracle_difference_count")
    assert_equal 0, report.fetch("semantic_difference_count")

    validation = report.fetch("validation_oracle")

    assert_equal true, validation.fetch("executed")
    assert_equal 770, validation.fetch("comparison_count")
    assert_equal 0, validation.fetch("missing_comparison_count")
    comparisons = validation.fetch("comparisons")

    assert_equal 770, comparisons.length
    assert_equal(770, comparisons.count { |entry| entry.fetch("applicable") })
    assert_equal(770, comparisons.count { |entry| entry.fetch("passed") })
    # Every executable path is one of the source-backed validation modes.
    modes = comparisons.map { |entry| entry.fetch("mode") }.tally

    assert_equal %w[constructor handler list response rest_endpoint strategy], modes.keys.sort

    criterion = report.dig("semantic_oracle", "validation_criterion")

    assert_equal "COMPLETE", criterion.fetch("status")
    assert_equal 770, criterion.fetch("applicable_count")
    assert_equal 0, criterion.fetch("not_applicable_count")
    assert_equal M1Gate.canonical_document_digest(criterion), validation.fetch("validation_criterion_sha256")
    assert_equal validation_criterion_ledger, criterion
  end

  def test_api_probe_matches_the_real_kubernetes_oracle
    report, _stderr, status = run_probe("api")

    assert_predicate status, :success?, report.fetch("errors").join("\n")
    assert_equal true, report.fetch("passed")
    assert_equal report.fetch("operations").count { |operation| operation.fetch("passed") },
                 report.fetch("passed_count")
    assert_equal 0, report.fetch("self_check_difference_count")
    assert_equal true, report.dig("oracle", "executed")
    assert_equal "v1.36.2", report.dig("oracle", "kubernetes_version")
    assert_equal report.fetch("operation_count"), report.dig("oracle", "comparison_count")
    assert_equal 0, report.dig("oracle", "missing_comparison_count")
    assert_equal report.fetch("operation_count"), report.dig("oracle", "comparisons").length
    failed_count = report.fetch("operations").count { |operation| !operation.fetch("passed") }

    assert_equal 0, failed_count
    surface = report.fetch("api_surface")

    assert_equal 321, surface.fetch("registry_gvk_count")
    assert_equal 153, surface.fetch("registry_gvr_count")
    assert_equal 60, surface.fetch("discovery_endpoint_count")
    assert_equal 321, surface.fetch("gvk_matrix").length
    assert_equal 153, surface.fetch("gvr_matrix").length
    assert_equal 60, surface.fetch("discovery_endpoints").length
    %w[oracle_missing_count rubernetes_missing_count duplicate_count unexpected_count difference_count
       schema_contract_missing_count].each do |key|
      assert_equal 0, surface.fetch(key), key
    end
    assert_equal true, surface.fetch("passed")
    assert(surface.fetch("discovery_endpoints").all? { |entry| entry.fetch("attempt_count") == 1 })
    assert(report.fetch("header_policy").key?("date"))
    assert(report.fetch("header_policy").key?("audit-id"))
    assert(report.fetch("operations").all? { |operation| operation.fetch("header_observation").key?("expected") })
    assert_equal failed_count, report.fetch("difference_count")
    assert_equal failed_count, report.fetch("oracle_difference_count")
  end

  def test_official_kubectl_probe_passes_all_required_operations_once
    report, _stderr, status = run_probe("kubectl")

    assert_predicate status, :success?, report.fetch("errors").join("\n")
    assert_equal true, report.fetch("passed")
    assert_equal M1Gate::REQUIRED_OPERATIONS.sort,
                 report.fetch("operations").map { |operation| operation.fetch("operation") }.sort
    assert(report.fetch("operations").all? { |operation| operation.fetch("attempt_count") == 1 })
    assert(report.fetch("operations").all? { |operation| operation.fetch("exit_status") == operation.fetch("expected_exit_status", 0) })
    apply = report.fetch("operations").find { |operation| operation.fetch("operation") == "apply" }

    refute_includes apply.fetch("command"), "--validate=false"
    assert_equal report.fetch("expected_kubectl_sha256"), report.fetch("kubectl_sha256")
  end

  def test_probe_rejects_a_changed_input_identity_before_execution
    report, _stderr, status = run_probe(
      "corpus",
      "RUBERNETES_M1_INPUT_SHA256" => "0" * 64,
      "RUBERNETES_M1_INPUT_FILE_COUNT" => "1"
    )

    refute_predicate status, :success?
    assert_equal false, report.fetch("passed")
    assert_equal false, report.fetch("input_stable")
    assert_includes report.fetch("errors"), "source input changed before probe execution"
  end

  private

  def run_probe(name, environment = {})
    path = File.join(ROOT, "tools/milestones/m1_#{name}_probe.rb")
    stdout, stderr, status = Open3.capture3(environment, RbConfig.ruby, path, chdir: ROOT)
    [JSON.parse(stdout), stderr, status]
  end

  def validation_criterion_ledger
    types = JSON.parse(File.read(REGISTRY_PATH)).fetch("types").reject do |type|
      type.fetch("schema") == "io.k8s.apimachinery.pkg.version.Info"
    end
    mappings = M1KubernetesValidationOracle.map_types(source_root: KUBERNETES_SOURCE_ROOT, types: types)
    applicable_count = mappings.count { |mapping| mapping.fetch("applicable") }
    not_applicable_count = mappings.count { |mapping| !mapping.fetch("applicable") }
    {
      "status" => not_applicable_count.zero? ? "COMPLETE" : "INCOMPLETE",
      "applicable_count" => applicable_count,
      "not_applicable_count" => not_applicable_count,
      "ledger" => mappings.sort_by { |mapping| mapping.fetch("target_schema") }.map do |mapping|
        {
          "id" => mapping.fetch("target_schema"),
          "applicable" => mapping.fetch("applicable"),
          "mode" => mapping["validation_mode"],
          "owner_schema" => mapping["owner_schema"],
          "evidence" => mapping["evidence"],
          "collaborators" => Array(mapping["collaborators"]),
          "reason" => mapping["reason"],
          "source_paths" => Array(mapping["source_paths"])
        }
      end
    }
  end
end
