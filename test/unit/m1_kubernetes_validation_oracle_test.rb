# frozen_string_literal: true

require "json"

require_relative "../test_helper"
require_relative "../../tools/milestones/m1_kubernetes_validation_oracle"

class M1KubernetesValidationOracleTest < Minitest::Test
  SOURCE_ROOT = "/tmp/kubernetes-v1.36.2"
  REGISTRY_PATH = File.expand_path("../../generated/schema/registry.json", __dir__)

  def test_resource_graph_maps_all_supported_types_with_a_source_anchored_ledger
    skip("pinned Kubernetes source checkout is unavailable") unless File.directory?(SOURCE_ROOT)

    types = supported_types
    mappings = M1KubernetesValidationOracle.map_types(source_root: SOURCE_ROOT, types: types)

    assert_equal(770, mappings.length)
    assert_equal(770, mappings.count { |mapping| mapping.fetch("applicable") })
    assert_equal(0, mappings.count { |mapping| !mapping.fetch("applicable") })
    assert_equal(%w[constructor handler list response rest_endpoint strategy],
                 mappings.map { |mapping| mapping.fetch("validation_mode") }.uniq.sort)

    # Strategies with collaborators are constructed from source-backed
    # upstream implementations and the ledger names each one.
    constructor = mappings.find { |mapping| mapping.fetch("target_schema") == "io.k8s.api.admissionregistration.v1.MutatingAdmissionPolicy" }
    assert_equal("constructor", constructor.fetch("validation_mode"))
    assert_equal(true, constructor.fetch("constructor_safe"))
    assert_equal(%w[authorizer resourceResolver], constructor.fetch("collaborators").map { |entry| entry.fetch("name") }.sort)
    assert(constructor.fetch("collaborators").all? { |entry| entry.fetch("source_path").end_with?(".go") })

    response = mappings.find { |mapping| mapping.fetch("target_schema") == "io.k8s.apimachinery.pkg.apis.meta.v1.WatchEvent" }
    assert_equal("response", response.fetch("validation_mode"))
    assert_equal("api-differential", response.dig("evidence", "report"))
    assert_includes(response.dig("evidence", "operations"), "watch")

    list = mappings.find { |mapping| mapping.fetch("target_schema") == "io.k8s.api.core.v1.ConfigMapList" }
    assert_equal("list", list.fetch("validation_mode"))
    assert_equal("io.k8s.api.core.v1.ConfigMap", list.fetch("item_schema"))
    assert_equal("strategy", list.fetch("item_mode"))

    token_request_spec = mappings.find { |mapping| mapping.fetch("target_schema") == "io.k8s.api.authentication.v1.TokenRequestSpec" }
    assert_equal("handler", token_request_spec.fetch("validation_mode"))
    assert_equal("io.k8s.api.authentication.v1.TokenRequest", token_request_spec.fetch("owner_schema"))
    assert_equal([{"field" => "spec", "container" => "object"}], token_request_spec.fetch("target_path"))

    events = mappings.find { |mapping| mapping.fetch("target_schema") == "io.k8s.api.events.v1.Event" }
    assert_equal("strategy", events.fetch("validation_mode"))
    assert_equal("k8s.io/kubernetes/pkg/apis/events/v1", events.fetch("version_import"))
  end

  def test_direct_strategy_runner_records_owner_operations_and_field_paths
    skip("pinned Kubernetes source checkout is unavailable") unless File.directory?(SOURCE_ROOT)

    mapping = M1KubernetesValidationOracle.map_types(
      source_root: SOURCE_ROOT,
      types: supported_types
    ).find { |entry| entry.fetch("target_schema") == "io.k8s.api.apps.v1.Deployment" }
    fixture = JSON.generate(
      "apiVersion" => "apps/v1",
      "kind" => "Deployment",
      "metadata" => {"name" => "m1-validation", "namespace" => "default"},
      "spec" => {
        "selector" => {"matchLabels" => {"app" => "m1"}},
        "template" => {
          "metadata" => {"labels" => {"app" => "m1"}},
          "spec" => {"containers" => [{"name" => "app", "image" => "example.invalid/m1:latest"}]}
        }
      }
    )
    invalid_fixture = JSON.generate(
      "apiVersion" => "apps/v1",
      "kind" => "Deployment",
      "metadata" => {"name" => "m1-invalid", "namespace" => "default"},
      "spec" => {}
    )
    missing_fixture = JSON.generate("apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"namespace" => "default"})
    update_fixture = JSON.generate(JSON.parse(fixture).merge("metadata" => {"name" => "m1-validation", "namespace" => "default", "resourceVersion" => "1"}))
    report = M1KubernetesValidationOracle.compare(
      source_root: SOURCE_ROOT,
      requests: [{
        "id" => mapping.fetch("target_schema"),
        "validation_mapping" => mapping,
        "fixture_json" => fixture,
        "invalid_fixture_json" => invalid_fixture,
        "missing_fixture_json" => missing_fixture,
        "update_fixture_json" => update_fixture,
        "validation_expectations" => {"create" => true, "invalid" => false, "missing" => false, "update" => true}
      }]
    )

    assert_equal(true, report.fetch("executed"))
    assert_equal(1, report.fetch("comparison_count"))
    comparison = report.fetch("comparisons").fetch(0)
    assert_equal(true, comparison.fetch("applicable"))
    assert_equal(true, comparison.fetch("passed"))
    assert_equal(mapping.fetch("owner_schema"), comparison.fetch("owner_schema"))
    assert_equal(mapping.fetch("source_paths"), comparison.fetch("source_paths"))
    %w[create invalid update missing].each do |operation|
      assert_kind_of(Hash, comparison.fetch(operation))
    end
    assert_equal(true, comparison.dig("create", "accepted"))
    assert_equal(false, comparison.dig("invalid", "accepted"))
    assert_equal(false, comparison.dig("missing", "accepted"))
    assert_equal(true, comparison.dig("update", "accepted"))
    assert(comparison.dig("invalid", "errors").any?)
  end

  def test_evidence_modes_pass_through_the_runner_without_fixtures
    skip("pinned Kubernetes source checkout is unavailable") unless File.directory?(SOURCE_ROOT)

    mappings = M1KubernetesValidationOracle.map_types(source_root: SOURCE_ROOT, types: supported_types)
    ids = [
      "io.k8s.apimachinery.pkg.apis.meta.v1.WatchEvent",
      "io.k8s.api.authentication.v1.TokenReview"
    ]
    requests = ids.map do |id|
      mapping = mappings.find { |entry| entry.fetch("target_schema") == id }
      {
        "id" => id,
        "validation_mapping" => mapping,
        "validation_reason" => "",
        "validation_source_paths" => mapping.fetch("source_paths"),
        "fixture_json" => "{}",
        "invalid_fixture_json" => "{}",
        "missing_fixture_json" => "{}",
        "update_fixture_json" => "{}"
      }
    end
    report = M1KubernetesValidationOracle.compare(source_root: SOURCE_ROOT, requests: requests)

    assert_equal(true, report.fetch("executed"))
    assert_equal(ids.length, report.fetch("comparison_count"))
    assert_equal("COMPLETE", report.dig("validation_criterion", "status"))
    report.fetch("comparisons").each do |comparison|
      assert_equal(true, comparison.fetch("applicable"))
      assert_equal(true, comparison.fetch("passed"))
      assert_includes(%w[response rest_endpoint], comparison.fetch("mode"))
      assert_equal("api-differential", comparison.dig("evidence", "report"))
      refute_empty(comparison.dig("evidence", "operations"))
    end
    ledger = report.dig("validation_criterion", "ledger")
    assert_equal(ids.sort, ledger.map { |entry| entry.fetch("id") }.sort)
    assert(ledger.all? { |entry| entry.fetch("applicable") && %w[response rest_endpoint].include?(entry.fetch("mode")) })
  end

  def test_normalization_accepts_source_anchored_validation_requests
    valid_fixture = %q({"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingAdmissionPolicy"})
    invalid_fixture = %q({"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingAdmissionPolicy","metadata":{"name":7}})
    missing_fixture = %q({"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingAdmissionPolicy","metadata":{}})
    update_fixture = %q({"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingAdmissionPolicy","metadata":{"name":"m1","resourceVersion":"1"}})
    request = {
      "id" => "io.k8s.api.admissionregistration.v1.MutatingAdmissionPolicy",
      "validation_mapping" => {
        "applicable" => false,
        "validation_mode" => "protocol",
        "source_paths" => ["pkg/registry/admissionregistration/mutatingadmissionpolicy/strategy.go"]
      },
      "validation_reason" => "upstream constructor collaborators are not source-backed safe",
      "validation_source_paths" => ["pkg/registry/admissionregistration/mutatingadmissionpolicy/strategy.go"],
      "fixture_json" => valid_fixture,
      "invalid_fixture_json" => invalid_fixture,
      "missing_fixture_json" => missing_fixture,
      "update_fixture_json" => update_fixture
    }
    assert_nil(M1KubernetesValidationOracle.normalize_requests([request]).fetch(0).fetch("validation_mapping"))
  end

  def test_normalization_rejects_unsafe_constructor_collaborators
    valid_fixture = %q({"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingAdmissionPolicy"})
    invalid_fixture = %q({"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingAdmissionPolicy","metadata":{"name":7}})
    missing_fixture = %q({"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingAdmissionPolicy","metadata":{}})
    update_fixture = %q({"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingAdmissionPolicy","metadata":{"name":"m1","resourceVersion":"1"}})
    request = {
      "id" => "io.k8s.api.admissionregistration.v1.MutatingAdmissionPolicy",
      "validation_mapping" => {
        "applicable" => true,
        "validation_mode" => "constructor",
        "constructor_safe" => false,
        "source_paths" => ["pkg/registry/admissionregistration/mutatingadmissionpolicy/strategy.go"]
      },
      "validation_reason" => "",
      "validation_source_paths" => ["pkg/registry/admissionregistration/mutatingadmissionpolicy/strategy.go"],
      "fixture_json" => valid_fixture,
      "invalid_fixture_json" => invalid_fixture,
      "missing_fixture_json" => missing_fixture,
      "update_fixture_json" => update_fixture
    }
    assert_raises(M1KubernetesValidationOracle::OracleError) do
      M1KubernetesValidationOracle.normalize_requests([request])
    end
  end

  private

  def supported_types
    document = JSON.parse(File.read(REGISTRY_PATH))
    document.fetch("types").reject { |type| type.fetch("schema") == "io.k8s.apimachinery.pkg.version.Info" }
  end
end
