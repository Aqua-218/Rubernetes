# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)
require "rubernetes/api"

class APITopologySpreadValidationTest < Minitest::Test
  API = Rubernetes::API
  PODS = "/api/v1/namespaces/default/pods"
  DEPLOYMENTS = "/apis/apps/v1/namespaces/default/deployments"
  CONSTRAINT = {"maxSkew" => 1, "topologyKey" => "rack", "whenUnsatisfiable" => "DoNotSchedule"}.freeze
  MATCH_KEYS = "MatchLabelKeysInPodTopologySpread"
  SELECTOR_MERGE = "MatchLabelKeysInPodTopologySpreadSelectorMerge"

  def test_compound_pod_selector_errors_follow_kubernetes_order
    entry = {"topologyKey" => "", "whenUnsatisfiable" => "ScheduleAnyway", "minDomains" => 0, "nodeTaintsPolicy" => "unknown",
             "matchLabelKeys" => ["bad key"], "labelSelector" => {"matchExpressions" => [{"key" => "tier", "operator" => "In"}]}}
    response = post(server, PODS, pod(entry))

    assert_equal 422, response.status
    fields = response.body.dig("details", "causes").map { |cause| cause.fetch("field").delete_prefix("spec.topologySpreadConstraints[0].") }

    assert_equal %w[maxSkew topologyKey minDomains minDomains nodeTaintsPolicy matchLabelKeys[0] labelSelector.matchExpressions[0].values], fields
    causes = response.body.dig("details", "causes")

    assert_equal "Invalid value: 0: must be greater than zero", causes.first.fetch("message")
    assert_equal "Required value: can not be empty", causes[1].fetch("message")
  end

  def test_duplicate_tuples_are_reported_on_earlier_workload_constraints
    labels = {"tier" => "web"}
    template = {"metadata" => {"labels" => labels}, "spec" => pod(CONSTRAINT, CONSTRAINT, CONSTRAINT).fetch("spec")}
    deployment = {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"name" => "duplicate"},
                  "spec" => {"selector" => {"matchLabels" => labels}, "template" => template}}
    response = post(server, DEPLOYMENTS, deployment)

    assert_equal 422, response.status
    causes = response.body.dig("details", "causes")
    expected = [0, 1].map do |index|
      {"field" => "spec.template.spec.topologySpreadConstraints[#{index}].{topologyKey, whenUnsatisfiable}",
       "reason" => "FieldValueDuplicate", "message" => 'Duplicate value: "{rack, DoNotSchedule}"'}
    end

    assert_equal expected, causes
  end

  def test_dropping_match_label_keys_and_the_legacy_selector_are_independent
    entry = CONSTRAINT.merge("matchLabelKeys" => ["tier"], "labelSelector" => {"matchLabels" => {"tier" => "web"}})
    current = post(server, PODS, pod(entry))
    legacy = post(server(gates: {SELECTOR_MERGE => false}), PODS, pod(entry))
    disabled = post(server(gates: {MATCH_KEYS => false, SELECTOR_MERGE => false}), PODS, pod(entry))

    assert_equal [422, 422, 201], [current.status, legacy.status, disabled.status]
    assert_equal "spec.topologySpreadConstraints[0][0]", current.body.dig("details", "causes", 0, "field")
    assert_equal "spec.topologySpreadConstraints[0].matchLabelKeys[0]", legacy.body.dig("details", "causes", 0, "field")
    assert_equal entry.except("matchLabelKeys"), disabled.body.dig("spec", "topologySpreadConstraints", 0)
  end

  def test_existing_merged_pod_can_be_updated_after_selector_merge_is_disabled
    store = API::MemoryStore.new
    entry = CONSTRAINT.merge("matchLabelKeys" => ["tier"], "labelSelector" => {})
    created = post(server(store: store), PODS, pod(entry))
    legacy = server(store: store, gates: {SELECTOR_MERGE => false})
    updated = legacy.call(method: "PATCH", path: "#{PODS}/spread?fieldValidation=Strict", headers: {"Content-Type" => "application/merge-patch+json"},
                          body: {"metadata" => {"labels" => {"tier" => "backend"}}})

    assert_equal [201, 200], [created.status, updated.status]
    expected = [{"key" => "tier", "operator" => "In", "values" => ["web"]}]

    assert_equal expected, created.body.dig("spec", "topologySpreadConstraints", 0, "labelSelector", "matchExpressions")
    assert_equal expected, updated.body.dig("spec", "topologySpreadConstraints", 0, "labelSelector", "matchExpressions")
  end

  private

  def pod(*constraints)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "spread", "labels" => {"tier" => "web"}},
     "spec" => {"containers" => [{"name" => "main", "image" => "busybox"}], "topologySpreadConstraints" => constraints}}
  end

  def server(store: API::MemoryStore.new, gates: {})
    resources = [
      API::Resource.new(group: "", version: "v1", resource: "pods", kind: "Pod", scope: :namespaced,
                        schema: Rubernetes::Generated.definition_for("io.k8s.api.core.v1.Pod")),
      API::Resource.new(group: "apps", version: "v1", resource: "deployments", kind: "Deployment", scope: :namespaced,
                        schema: Rubernetes::Generated.definition_for("io.k8s.api.apps.v1.Deployment"))
    ]
    API::Server.new(registry: API::Registry.new(resources: resources, defaults: false), store: store, feature_gates: gates)
  end

  def post(api, path, body)
    api.call(method: "POST", path: "#{path}?fieldValidation=Strict", headers: {"Content-Type" => "application/json"}, body: JSON.generate(body))
  end
end
