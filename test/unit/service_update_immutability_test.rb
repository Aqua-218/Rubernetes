# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# validateUpgradeDowngradeClusterIPs: a Service's clusterIP may not change once
# set.  Nothing enforced it, so an update could move a live Service to a
# different address while every client kept using the old one.
class ServiceUpdateImmutabilityTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def service(spec_extra = {})
    {"apiVersion" => "v1", "kind" => "Service",
     "metadata" => {"name" => "svc", "namespace" => "ns"},
     "spec" => {"type" => "ClusterIP", "clusterIP" => "10.96.0.10",
                "clusterIPs" => ["10.96.0.10"],
                "ports" => [{"port" => 80, "protocol" => "TCP"}]}.merge(spec_extra)}
  end

  def errors(new_service, old_service, operation: :update)
    Validator.send(:service_update_errors, new_service, old_service, operation)
  end

  def test_an_unchanged_service_is_accepted
    assert_empty errors(service, service)
  end

  def test_the_cluster_ip_may_not_change
    refute_empty errors(service("clusterIP" => "10.96.0.11", "clusterIPs" => ["10.96.0.11"]), service)
  end

  def test_an_omitted_cluster_ip_keeps_the_allocation
    bare = service
    bare["spec"].delete("clusterIP")
    bare["spec"].delete("clusterIPs")

    assert_empty errors(bare, service)
  end

  def test_the_port_may_change
    assert_empty errors(service("ports" => [{"port" => 8080, "protocol" => "TCP"}]), service)
  end

  def test_a_move_to_external_name_is_allowed
    external = service("type" => "ExternalName", "externalName" => "example.com")
    external["spec"].delete("clusterIP")
    external["spec"].delete("clusterIPs")

    assert_empty errors(external, service)
  end

  def test_a_create_is_never_restricted
    assert_empty errors(service("clusterIP" => "10.96.0.99"), service, operation: :create)
  end
end
