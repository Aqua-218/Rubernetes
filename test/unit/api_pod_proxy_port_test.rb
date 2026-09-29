# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# A pod proxy URL without a port goes to the first port declared by the first
# container that declares one (pkg/registry/core/pod/strategy.go
# ResourceLocation); ":80" is only the fallback.  "[sig-node] PreStop should
# call prestop when killing a pod" reads pods/server/proxy/read from an agnhost
# listening on 8080.
class APIPodProxyPortTest < Minitest::Test
  def server = Rubernetes::API::Server.allocate

  def pod(*containers) = {"spec" => {"containers" => containers}}

  def test_defaults_to_the_first_declared_port
    value = pod({"name" => "a"}, {"name" => "b", "ports" => [{"containerPort" => 8080}, {"containerPort" => 9090}]})
    assert_equal 8080, server.send(:resolve_pod_port, value, nil)
    assert_equal 8080, server.send(:resolve_pod_port, value, "")
  end

  def test_falls_back_to_80_and_honours_explicit_ports
    assert_equal 80, server.send(:resolve_pod_port, pod({"name" => "a"}), nil)
    value = pod({"name" => "a", "ports" => [{"name" => "http", "containerPort" => 8080}]})
    assert_equal 9000, server.send(:resolve_pod_port, value, "9000")
    assert_equal 8080, server.send(:resolve_pod_port, value, "http")
  end
end
