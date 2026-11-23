# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class WorkloadSelectorValidationTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator
  TEMPLATE_LABELS = "spec.template.metadata.labels"

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = Rubernetes::API::Server.new(registry: registry)
  end

  def test_label_requirements_are_conjunctive_and_check_presence
    selector = {
      "matchLabels" => {"tier" => ""},
      "matchExpressions" => [requirement("stage", "In", "prod", ""),
                             requirement("rollout", "NotIn", "old"),
                             requirement("zone", "Exists"),
                             requirement("legacy", "DoesNotExist")]
    }
    labels = {"tier" => "", "stage" => "", "zone" => ""}

    assert_equal 201, create("Deployment", selector, labels).status
    bad_labels = [labels.except("tier"), labels.except("stage"), labels.except("zone"),
                  labels.merge("rollout" => "old"), labels.merge("legacy" => "")]
    bad_labels.each do |invalid|
      response = create("Deployment", selector, invalid)

      assert_equal 422, response.status
      assert_equal [TEMPLATE_LABELS], cause_fields(response)
    end
  end

  def test_template_label_error_distinguishes_omitted_and_empty_maps
    selector = {"matchLabels" => {"tier" => "web"}}
    [nil, {}].each do |labels|
      response = create("Deployment", selector, labels)

      assert_equal [{"reason" => "FieldValueInvalid", "field" => TEMPLATE_LABELS,
                     "message" => "Invalid value: #{JSON.generate(labels)}: `selector` does not match template `labels`"}],
                   causes(response)
    end
  end

  def test_omitted_empty_and_invalid_selectors_have_distinct_causes
    %w[Deployment ReplicaSet StatefulSet DaemonSet].each do |kind|
      missing = create(kind, nil, {})
      missing_fields = kind == "DaemonSet" ? [TEMPLATE_LABELS] : ["spec.selector", TEMPLATE_LABELS]

      assert_equal missing_fields, cause_fields(missing)

      empty = create(kind, {"matchLabels" => {}, "matchExpressions" => []}, {})
      upstream_name = kind == "ReplicaSet" ? "deployment" : kind.downcase

      assert_equal [{"reason" => "FieldValueInvalid", "field" => "spec.selector",
                     "message" => "Invalid value: {}: empty selector is invalid for #{upstream_name}"}], causes(empty)

      invalid = create(kind, {"matchExpressions" => [requirement("tier", "Invalid")]}, {})
      expected = ["spec.selector.matchExpressions[0].operator"]
      expected << "spec.selector" unless kind == "DaemonSet"

      assert_equal expected, cause_fields(invalid)
    end
  end

  def test_malformed_selector_hides_secondary_template_errors_except_for_daemon_sets
    selector = {"matchExpressions" => [requirement("tier", "Invalid")]}
    %w[Deployment ReplicaSet StatefulSet DaemonSet].each do |kind|
      expected = ["spec.selector.matchExpressions[0].operator"]
      expected << (kind == "DaemonSet" ? "spec.template.spec.containers" : "spec.selector")

      assert_equal expected, cause_fields(create(kind, selector, nil, "template" => nil))
    end
  end

  def test_replication_controller_selector_is_a_label_map
    selector = {"matchLabels" => "literal", "matchExpressions" => "", "tier" => "web"}

    assert_equal 201, create("ReplicationController", selector, selector).status
    assert_equal [TEMPLATE_LABELS], cause_fields(create("ReplicationController", selector, selector.except("matchExpressions")))
    assert_equal 201, create("ReplicationController", nil, {"tier" => "web"}).status
    assert_equal ["spec.selector"], cause_fields(create("ReplicationController", nil, {}))
  end

  def test_empty_replication_controller_template_is_checked_as_a_value
    expected = [TEMPLATE_LABELS, "spec.template.spec.containers"]
    response = create("ReplicationController", {"tier" => "web"}, nil, "template" => {})

    assert_equal expected, cause_fields(response)
  end

  def test_nested_claim_selector_keeps_its_own_rules
    claim = {"metadata" => {"name" => "data"},
             "spec" => {"selector" => {}, "accessModes" => ["ReadWriteOnce"],
                        "resources" => {"requests" => {"storage" => "1Gi"}}}}
    volumes = {"volumeClaimTemplates" => [claim]}
    selector = {"matchLabels" => {"tier" => "web"}}

    assert_equal 201, create("StatefulSet", selector, {"tier" => "web"}, volumes).status

    claim["spec"]["selector"] = {"matchExpressions" => [requirement("disk", "In")]}
    invalid_claim = create("StatefulSet", selector, {"tier" => "web"}, volumes)

    assert_equal ["spec.volumeClaimTemplates[0].spec.selector.matchExpressions[0].values"],
                 cause_fields(invalid_claim)
  end

  def test_daemon_set_update_preserves_legacy_invalid_expression_value
    selector = {"matchExpressions" => [requirement("tier", "In", "bad value")]}
    object = {"spec" => {"selector" => selector, "template" => {"spec" => {}}}}

    assert_equal ["spec.selector.matchExpressions[0].values[0]"],
                 Validator.selector_errors(object, "DaemonSet").map(&:kubernetes_field)
    assert_empty Validator.selector_errors(object, "DaemonSet", old: object)
  end

  private

  def requirement(key, operator, *values)
    {"key" => key, "operator" => operator, "values" => values}
  end

  def create(kind, selector, labels, spec_fields = {})
    core = kind == "ReplicationController"
    template = {"spec" => {"containers" => [{"name" => "main", "image" => "example/app"}]}}
    template["metadata"] = {"labels" => labels} if labels
    spec = {"template" => template}.merge(spec_fields)
    spec["selector"] = selector unless selector.nil?
    spec["serviceName"] = "app" if kind == "StatefulSet"
    body = {"apiVersion" => core ? "v1" : "apps/v1", "kind" => kind, "metadata" => {"name" => "sample"}, "spec" => spec}
    base = core ? "/api/v1" : "/apis/apps/v1"
    identity = {"username" => "admin", "groups" => ["system:masters"]}
    request = Rubernetes::API::Request.new(
      method: "POST", path: "#{base}/namespaces/default/#{kind.downcase}s?dryRun=All",
      headers: {"content-type" => "application/json"}, identity: identity, body: JSON.generate(body)
    )
    @server.call(request)
  end

  def causes(response)
    response.body.dig("details", "causes")
  end

  def cause_fields(response)
    causes(response).map { |cause| cause.fetch("field") }
  end
end
