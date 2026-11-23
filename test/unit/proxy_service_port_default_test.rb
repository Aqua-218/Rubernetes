# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"
require "rubernetes/schema"

# SetDefaults_ServicePort: an unset targetPort means "the same as port".
# intstr's zero value is the integer 0, so an omitted targetPort is stored as 0
# unless it is defaulted -- and a Service port of 0 is not a port at all.
#
# A StatefulSet's headless governing Service declares `port: 80` and no
# targetPort, so every one of them was stored with targetPort 0; kube-proxy
# then refused the whole Service list over it and every Service created after
# the first such one was unreachable -- its ClusterIP answered nothing.
class ProxyServicePortDefaultTest < Minitest::Test
  Proxy = Rubernetes::Proxy

  def port_from(entry)
    Proxy::Service.port_from(entry)
  end

  def test_an_omitted_target_port_is_the_service_port
    assert_equal(80, port_from("port" => 80).target_port)
  end

  # The stored zero means the same thing: it is what an omitted intstr looks
  # like on the wire.
  def test_a_zero_target_port_is_the_service_port
    assert_equal(80, port_from("port" => 80, "targetPort" => 0).target_port)
  end

  def test_an_explicit_target_port_is_kept
    assert_equal(8080, port_from("port" => 80, "targetPort" => 8080).target_port)
  end

  def test_a_named_target_port_is_kept
    assert_equal("http", port_from("port" => 80, "targetPort" => "http").target_port)
  end

  # A headless governing Service is the exact shape that broke it.
  def test_a_headless_governing_service_is_usable
    service = Proxy::Service.new(
      name: "test", namespace: "statefulset-1", cluster_ip: "None",
      ports: [{"name" => "http", "port" => 80}]
    )

    assert_equal(80, service.ports.first.target_port)
  end

  def test_only_advertised_vip_mode_load_balancer_addresses_become_proxy_frontends
    object = {"metadata" => {"name" => "web", "namespace" => "default"},
              "spec" => {"type" => "LoadBalancer", "clusterIP" => "10.96.0.5", "loadBalancerIP" => "198.51.100.2",
                         "ports" => [{"port" => 80}]}}

    assert_empty Proxy::Service.new(object).load_balancer_ips

    object["status"] = {"loadBalancer" => {"ingress" => [{"ip" => "198.51.100.3", "ipMode" => "Proxy"},
                                                         {"ip" => "198.51.100.4"}, {"ip" => "198.51.100.5", "ipMode" => "VIP"}]}}

    assert_equal %w[198.51.100.4 198.51.100.5], Proxy::Service.new(object).load_balancer_ips
  end
end
