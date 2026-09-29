# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/schema"

# StrictIPCIDRValidation (Beta, on in v1.36): legacy IP and CIDR fields
# refuse leading zeros, IPv4-mapped IPv6 addresses and CIDRs with host bits,
# while values the old object held stay valid (util/validation/ip.go).
class StrictIPCIDRValidationTest < Minitest::Test
  V = Rubernetes::Schema::KubernetesValidator

  def messages(issues)
    issues.map { |issue| "#{issue.path.join(".")}: #{issue.message}" }
  end

  def test_ip_rules
    assert_empty V.legacy_ip_messages("10.1.2.3")
    assert_empty V.legacy_ip_messages("2001:db8::1")
    assert_equal ["must not have leading 0s"], V.legacy_ip_messages("010.1.2.3")
    assert_equal ["must not be an IPv4-mapped IPv6 address"], V.legacy_ip_messages("::ffff:1.2.3.4")
    assert_equal [V::INVALID_IP], V.legacy_ip_messages("300.1.2.3")
    assert_equal [V::INVALID_IP], V.legacy_ip_messages("fe80::1%eth0")
    assert_equal [V::INVALID_IP], V.legacy_ip_messages("")
    assert_empty V.legacy_ip_messages("010.1.2.3", ["010.1.2.3"])
  end

  def test_cidr_rules
    assert_empty V.legacy_cidr_messages("10.0.0.0/8")
    assert_empty V.legacy_cidr_messages("2001:db8::/64")
    assert_equal ["must not have bits set beyond the prefix length"], V.legacy_cidr_messages("10.0.0.1/8")
    assert_equal ["must not have leading 0s in IP or prefix length"], V.legacy_cidr_messages("10.0.0.0/08")
    assert_equal ["must not have leading 0s in IP or prefix length"], V.legacy_cidr_messages("010.0.0.0/8")
    assert_equal ["must not have an IPv4-mapped IPv6 address"], V.legacy_cidr_messages("::ffff:10.0.0.0/104")
    assert_equal [V::INVALID_CIDR], V.legacy_cidr_messages("10.0.0.0")
    assert_equal [V::INVALID_CIDR], V.legacy_cidr_messages("10.0.0.0/33")
    assert_empty V.legacy_cidr_messages("10.0.0.1/8", ["10.0.0.1/8"])
  end

  def service(spec, annotations: nil)
    metadata = {"name" => "s", "namespace" => "default"}
    metadata["annotations"] = annotations if annotations
    {"metadata" => metadata, "spec" => {"ports" => [{"port" => 80}]}.merge(spec)}
  end

  def test_service_fields_and_the_old_object_allowance
    bad = service({"clusterIPs" => ["010.0.0.10"], "externalIPs" => ["::ffff:1.2.3.4"], "type" => "LoadBalancer",
                   "loadBalancerSourceRanges" => [" 10.0.0.1/8 "]})
    assert_equal ["spec.clusterIPs.0: must not have leading 0s", "spec.externalIPs.0: must not be an IPv4-mapped IPv6 address",
                  "spec.loadBalancerSourceRanges.0: must not have bits set beyond the prefix length"],
                 messages(V.ip_field_errors(bad, "Service", nil))
    assert_empty V.ip_field_errors(bad, "Service", bad)
    assert_empty V.ip_field_errors(service({"clusterIPs" => ["None"]}), "Service", nil)
    annotated = service({"type" => "ClusterIP"}, annotations: {V::LB_SOURCE_RANGES => "10.0.0.0/8, 10.0.0.1/8"})
    assert_equal ["metadata.annotations.#{V::LB_SOURCE_RANGES}: may only be used when `type` is 'LoadBalancer'",
                  "metadata.annotations.#{V::LB_SOURCE_RANGES}: must not have bits set beyond the prefix length"],
                 messages(V.ip_field_errors(annotated, "Service", nil))
    status = service({}).merge("status" => {"loadBalancer" => {"ingress" => [{"ip" => "010.1.1.1"}, {"hostname" => "lb.example"}]}})
    # Status is validated on update only (PrepareForCreate resets it).
    assert_empty V.ip_field_errors(status, "Service", nil)
    assert_equal ["status.loadBalancer.ingress.0.ip: must not have leading 0s"], messages(V.ip_field_errors(status, "Service", service({})))
  end

  def test_pod_template_node_and_endpoint_slice_fields
    pod = {"spec" => {"dnsConfig" => {"nameservers" => ["8.8.8.8", "08.8.8.8"]}},
           "status" => {"podIPs" => [{"ip" => "010.244.0.5"}], "hostIPs" => [{"ip" => "10.0.0.1"}]}}
    assert_equal ["spec.dnsConfig.nameservers.1: must not have leading 0s"], messages(V.ip_field_errors(pod, "Pod", nil))
    assert_equal ["spec.dnsConfig.nameservers.1: must not have leading 0s", "status.podIPs.0.ip: must not have leading 0s"],
                 messages(V.ip_field_errors(pod, "Pod", {"spec" => {}}))
    assert_equal ["spec.dnsConfig.nameservers.1: must not have leading 0s"], messages(V.ip_field_errors(pod, "Pod", pod))
    deployment = {"spec" => {"template" => {"spec" => {"dnsConfig" => {"nameservers" => ["::ffff:8.8.8.8"]}}}}}
    assert_equal ["spec.template.spec.dnsConfig.nameservers.0: must not be an IPv4-mapped IPv6 address"],
                 messages(V.ip_field_errors(deployment, "Deployment", nil))
    node = {"spec" => {"podCIDRs" => ["10.244.1.0/24", "10.244.2.1/24"]}}
    assert_equal ["spec.podCIDRs.1: must not have bits set beyond the prefix length"], messages(V.ip_field_errors(node, "Node", nil))
    slice = {"addressType" => "IPv4", "endpoints" => [{"addresses" => ["10.0.0.1", "010.0.0.2", "2001:db8::1"]}]}
    assert_equal ["endpoints.0.addresses.1: must not have leading 0s", "endpoints.0.addresses: must be an IPv4 address"],
                 messages(V.ip_field_errors(slice, "EndpointSlice", nil))
  end

  def policy(block)
    {"spec" => {"podSelector" => {}, "ingress" => [{"from" => [{"ipBlock" => block}]}]}}
  end

  def test_ip_block_cidr_except_subset_and_old_allowance
    assert_empty V.network_policy_errors(policy({"cidr" => "10.0.0.0/8", "except" => ["10.1.0.0/16"]}))
    errors = messages(V.network_policy_errors(policy({"cidr" => "10.0.0.1/8", "except" => ["10.0.0.0/8", "11.0.0.0/16", "10.2.0.1/16"]})))
    path = "spec.ingress.0.from.0.ipBlock"
    assert_includes errors, "#{path}.cidr: must not have bits set beyond the prefix length"
    assert_includes errors, "#{path}.except.0: must be a strict subset of `cidr`"
    assert_includes errors, "#{path}.except.1: must be a strict subset of `cidr`"
    assert_includes errors, "#{path}.except.2: must not have bits set beyond the prefix length"
    old = policy({"cidr" => "10.0.0.1/8"})
    assert_empty V.network_policy_errors(old, :update, old)
    assert_equal ["#{path}.cidr: "], messages(V.network_policy_errors(policy({"cidr" => ""})))
  end

  # Through the generated Service definition's validator, i.e. the same
  # dispatch every create and update takes.
  def test_the_service_validator_refuses_a_strictly_invalid_external_ip
    require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)
    definition = Rubernetes::Generated.definition_for("io.k8s.api.core.v1.Service")
    object = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "web", "namespace" => "default"},
              "spec" => {"ports" => [{"port" => 80}], "externalIPs" => ["010.1.2.3"]}}
    issues = definition.validator.errors(object, operation: :create)
    issue = issues.find { |candidate| candidate.kubernetes_field == "spec.externalIPs[0]" }
    refute_nil issue, issues.map(&:kubernetes_field).inspect
    assert_equal "must not have leading 0s", issue.message
    assert_empty definition.validator.errors(object, operation: :update, old: object).select { |candidate| candidate.kubernetes_field.start_with?("spec.externalIPs") }
  end
end
