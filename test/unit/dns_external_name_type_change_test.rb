# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"

# "[sig-network] DNS should provide DNS for ExternalName services" turns an
# ExternalName Service into a ClusterIP one and expects its A record to be the
# new ClusterIP.  The Service keeps spec.externalName across the change, and
# the resolver answered the CNAME whenever externalName was set instead of
# only for type ExternalName, as CoreDNS does.
class DnsExternalNameTypeChangeTest < Minitest::Test
  NAME = "dns-test-service-3.apps.svc.cluster.local"

  def service(spec)
    {"metadata" => {"name" => "dns-test-service-3", "namespace" => "apps"}, "spec" => spec}
  end

  def test_a_service_changed_to_cluster_ip_answers_its_cluster_ip
    resolver = Rubernetes::Network::DNS::Resolver.new
    resolver.add_service(service("type" => "ExternalName", "externalName" => "foo.example.com"))
    assert_equal "foo.example.com", resolver.resolve(NAME, type: "CNAME").first.data

    resolver.update_service(service("type" => "ClusterIP", "externalName" => "foo.example.com",
                                    "clusterIP" => "10.96.12.34", "clusterIPs" => ["10.96.12.34"],
                                    "ports" => [{"port" => 80, "name" => "http", "protocol" => "TCP"}]))

    records = resolver.resolve(NAME, type: "A").records
    assert_equal [["A", "10.96.12.34"]], records.map { |record| [record.type, record.data] }
  end
end
