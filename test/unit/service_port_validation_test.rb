# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# Core ServicePort validation accepts fields that receive API defaults later.
class ServicePortValidationTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def service(ports)
    {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "s", "namespace" => "ns"},
     "spec" => {"type" => "ClusterIP", "ports" => ports}}
  end

  def errors(ports)
    Validator.send(:service_errors, service(ports))
  end

  def test_a_single_unnamed_port_is_fine
    assert_empty errors([{"port" => 80, "protocol" => "TCP"}])
  end

  def test_two_ports_each_need_a_name
    refute_empty errors([{"port" => 80, "protocol" => "TCP"}, {"port" => 443, "protocol" => "TCP"}])
  end

  def test_two_named_ports_are_fine
    assert_empty errors([{"name" => "http", "port" => 80, "protocol" => "TCP"},
                         {"name" => "https", "port" => 443, "protocol" => "TCP"}])
  end

  def test_duplicate_port_names_are_rejected
    issues = errors([{"name" => "http", "port" => 80, "protocol" => "TCP"},
                     {"name" => "http", "port" => 8080, "protocol" => "TCP"}])

    refute_empty issues
    assert(issues.any? { |i| i.path.last == "name" })
  end

  def test_an_out_of_range_port_is_rejected
    refute_empty errors([{"port" => 0, "protocol" => "TCP"}])
    refute_empty errors([{"port" => 70_000, "protocol" => "TCP"}])
  end

  def test_an_empty_protocol_and_target_port_can_be_defaulted
    assert_empty errors([{"port" => 80, "protocol" => "", "targetPort" => 0}])
  end

  def test_a_single_explicitly_empty_name_can_be_omitted
    assert_empty errors([{"name" => "", "port" => 80, "protocol" => "TCP"}])
    issues = errors([{"name" => "one", "port" => 80}, {"name" => "", "port" => 81}])

    assert_equal([["spec.ports[1].name", :required]], issues.map { |issue| [issue.kubernetes_field, issue.code] })
  end
end
