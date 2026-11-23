# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)

class NetworkPolicyValidationTest < Minitest::Test
  def test_valid_ranges_named_ports_and_all_ports_are_accepted
    spec = {"policyTypes" => %w[Ingress Egress],
            "ingress" => [{"ports" => [{"port" => 443, "endPort" => 443}, {"port" => "https", "protocol" => "TCP"}, {}]}],
            "egress" => [{"ports" => [{"protocol" => "SCTP", "port" => 1, "endPort" => 65_535}, {"protocol" => "UDP"}]}]}

    assert_empty causes(spec)
  end

  def test_end_port_requires_a_numeric_start_and_an_inclusive_range
    spec = {"egress" => [{"ports" => [{"endPort" => 1000}, {"port" => "https", "endPort" => 1000}, {"port" => 9000, "endPort" => 8000}]}]}

    assert_equal [
      ["spec.egress[0].ports[0].endPort", "FieldValueInvalid", "Invalid value: 1000: may not be specified when `port` is not specified"],
      ["spec.egress[0].ports[1].endPort", "FieldValueInvalid", "Invalid value: 1000: may not be specified when `port` is non-numeric"],
      ["spec.egress[0].ports[2].endPort", "FieldValueInvalid", "Invalid value: 9000: must be greater than or equal to `port`"]
    ], causes(spec)
  end

  def test_protocol_number_and_name_errors_match_the_api_fields
    spec = {"ingress" => [{"ports" => [{"protocol" => "ICMP", "port" => 0}, {"port" => 80, "endPort" => 65_536}, {"port" => "443"}]}]}

    assert_equal [
      ["spec.ingress[0].ports[0].protocol", "FieldValueNotSupported", 'Unsupported value: "ICMP": supported values: "TCP", "UDP", "SCTP"'],
      ["spec.ingress[0].ports[0].port", "FieldValueInvalid", "Invalid value: 0: must be between 1 and 65535, inclusive"],
      ["spec.ingress[0].ports[1].endPort", "FieldValueInvalid", "Invalid value: 65536: must be between 1 and 65535, inclusive"],
      ["spec.ingress[0].ports[2].port", "FieldValueInvalid", 'Invalid value: "443": must contain at least one letter (a-z)']
    ], causes(spec)
  end

  def test_ingress_and_egress_require_peers_and_disallow_ip_blocks_with_selectors
    spec = {"ingress" => [{"from" => [{}]}],
            "egress" => [{"to" => [{"namespaceSelector" => {}, "ipBlock" => {"cidr" => "10.0.0.0/8"}}]}]}

    assert_equal [
      ["spec.ingress[0].from[0]", "FieldValueRequired", "Required value: must specify a peer"],
      ["spec.egress[0].to[0]", "FieldValueForbidden", "Forbidden: may not specify both ipBlock and another peer"]
    ], causes(spec)
    assert_empty causes({"ingress" => [{"from" => [{"podSelector" => {}, "namespaceSelector" => {}}]}]})
  end

  def test_policy_types_length_is_checked_before_individual_values
    assert_equal [
      ["spec.policyTypes", "FieldValueInvalid", 'Invalid value: ["Ingress","Egress","Other"]: may not specify more than two policyTypes']
    ], causes({"policyTypes" => %w[Ingress Egress Other]})
    assert_equal [
      ["spec.policyTypes[1]", "FieldValueNotSupported", 'Unsupported value: "Other": supported values: "Ingress", "Egress"']
    ], causes({"policyTypes" => %w[Ingress Other]})
    assert_empty causes({"policyTypes" => %w[Ingress Ingress]})
  end

  def test_updates_preserve_compatibility_for_old_selector_expression_values
    selector = {"matchExpressions" => [{"key" => "team", "operator" => "In", "values" => ["bad value"]}]}
    spec = {"podSelector" => selector, "egress" => [{"to" => [{"namespaceSelector" => selector}]}]}

    assert_equal %w[spec.podSelector.matchExpressions[0].values[0] spec.egress[0].to[0].namespaceSelector.matchExpressions[0].values[0]],
                 causes(spec).map(&:first)
    assert_empty causes(spec, old: object({"podSelector" => selector}))

    invalid_map = spec.merge("podSelector" => {"matchLabels" => {"app" => "bad value"}})
    field, reason, message = causes(invalid_map, old: object({"podSelector" => selector})).fetch(0)

    assert_equal ["spec.podSelector.matchLabels", "FieldValueInvalid"], [field, reason]
    assert_match(/\AInvalid value: "bad value": /, message)
  end

  private

  def object(spec)
    {"apiVersion" => "networking.k8s.io/v1", "kind" => "NetworkPolicy", "metadata" => {"name" => "policy", "namespace" => "default"},
     "spec" => {"podSelector" => {}}.merge(spec)}
  end

  def causes(spec, old: nil)
    definition = Rubernetes::Generated.definition_for("io.k8s.api.networking.v1.NetworkPolicy")
    desired = object(spec)
    definition.validator.errors(desired, operation: old ? :update : :create, old: old).map do |issue|
      issue.to_cause(desired).values_at("field", "reason", "message")
    end
  end
end
