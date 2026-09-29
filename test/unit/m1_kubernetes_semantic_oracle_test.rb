# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/milestones/m1_kubernetes_semantic_oracle"

class M1KubernetesSemanticOracleTest < Minitest::Test
  SOURCE_ROOT = "/tmp/rubernetes-k8s-source-v1.36.2"

  def test_source_pin_and_provenance_kind_are_exact
    assert_equal("v1.36.2", M1KubernetesSemanticOracle::KUBERNETES_VERSION)
    assert_equal(
      "24e2b02af5543d7910c2bb074c7264df5a8f0467",
      M1KubernetesSemanticOracle::SOURCE_COMMIT
    )
    assert_equal(
      "kubernetes_api_semantics",
      M1Gate::KUBERNETES_SEMANTICS_ORACLE_KIND
    )
  end

  def test_validation_applicability_ledger_is_anchored_to_generated_source
    network_policy = M1KubernetesSemanticOracle.validation_registration(
      source_root: SOURCE_ROOT,
      go_package: "k8s.io/api/extensions/v1beta1",
      go_type: "NetworkPolicy"
    )
    assert_equal(true, network_policy.fetch("applicable"))
    assert(network_policy.fetch("source_paths").any? { |path| path.end_with?("zz_generated.validations.go") })

    deployment = M1KubernetesSemanticOracle.validation_registration(
      source_root: SOURCE_ROOT,
      go_package: "k8s.io/api/apps/v1",
      go_type: "Deployment"
    )
    assert_equal(false, deployment.fetch("applicable"))
    assert_match(/upstream source has no zz_generated\.validations\.go|does not register Deployment/, deployment.fetch("reason"))
  end

  def test_request_normalization_rejects_invalid_json_and_duplicate_ids
    request = valid_request
    assert_raises(M1KubernetesSemanticOracle::OracleError) do
      M1KubernetesSemanticOracle.normalize_requests([request.merge("raw_json" => "not-json")])
    end
    assert_raises(M1KubernetesSemanticOracle::OracleError) do
      M1KubernetesSemanticOracle.normalize_requests([request, request])
    end
  end

  def test_go_runner_records_external_json_defaulting_and_validation_observations
    skip("pinned Kubernetes source checkout is unavailable") unless File.directory?(SOURCE_ROOT)

    report = M1KubernetesSemanticOracle.compare(source_root: SOURCE_ROOT, requests: [valid_request])
    assert_equal(true, report.fetch("executed"))
    assert_equal(1, report.fetch("comparison_count"))
    assert_equal(M1Gate::KUBERNETES_SEMANTICS_ORACLE_KIND, report.dig("provenance", "kind"))
    comparison = report.fetch("comparisons").fetch(0)
    assert_equal(true, comparison.dig("json", "accepted"))
    assert_equal(false, comparison.dig("json", "unknown", "field_preserved"))
    assert_equal(true, comparison.dig("defaulting", "applicable"))
    assert_equal(false, comparison.dig("validation", "applicable"))
    assert_match(/no zz_generated\.validations\.go|does not register/, comparison.dig("validation", "reason"))
    assert_equal("INCOMPLETE", report.dig("validation_criterion", "status"))
    assert_equal(1, report.dig("validation_criterion", "not_applicable_count"))
    assert_equal(comparison.fetch("id"), report.dig("validation_criterion", "ledger", 0, "id"))
  end

  private

  def valid_request
    {
      "id" => "io.k8s.api.apps.v1.Deployment",
      "go_package" => "k8s.io/api/apps/v1",
      "go_type" => "Deployment",
      "raw_json" => "{}",
      "unknown_json" => '{"m1FutureField":{"value":1}}',
      "missing_json" => "{}",
      "validation_applicable" => false,
      "validation_reason" => "upstream source has no zz_generated.validations.go for k8s.io/api/apps/v1.Deployment; scanned package source"
    }
  end
end
