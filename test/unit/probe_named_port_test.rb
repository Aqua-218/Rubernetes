# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# The in-sandbox probe connector receives the probe definition verbatim; a
# named port ("healthcheck") must be resolved to the container port number
# before it gets there.  cert-manager's webhook and every image that names its
# health port failed liveness on each period and restarted forever.
class ProbeNamedPortTest < Minitest::Test
  class Runtime
    attr_reader :definitions

    def initialize = @definitions = []

    def http_get(_container_id, definition, timeout:, context: nil)
      @definitions << definition
      {"status" => 200, "success" => true}
    end

    def tcp_socket(_container_id, definition, timeout:, context: nil)
      @definitions << definition
      {"connected" => true, "success" => true}
    end
  end

  def test_named_http_and_tcp_ports_reach_the_connector_as_numbers
    runtime = Runtime.new
    manager = Rubernetes::Node::ProbeManager.new(runtime: runtime)
    context = {"host" => "10.0.0.7", "ports" => [{"name" => "healthcheck", "containerPort" => 6080, "protocol" => "TCP"}]}

    assert_predicate manager.check("c", {"httpGet" => {"path" => "/healthz", "port" => "healthcheck"}}, context: context), :success?
    assert_predicate manager.check("c", {"tcpSocket" => {"port" => "healthcheck"}}, context: context), :success?
    assert_predicate manager.check("c", {"httpGet" => {"path" => "/healthz", "port" => 6080}}, context: context), :success?

    assert_equal([6080, 6080, 6080], runtime.definitions.map { |definition| definition["port"] })
    assert_equal "/healthz", runtime.definitions.first["path"], "the rest of the definition is passed through"
  end

  def test_an_undefined_named_port_is_a_probe_failure_with_a_reason
    manager = Rubernetes::Node::ProbeManager.new(runtime: Runtime.new)
    result = manager.check("c", {"httpGet" => {"port" => "missing"}}, context: {"host" => "10.0.0.7", "ports" => []})

    refute_predicate result, :success?
    assert_match(/named probe port "missing" is not defined/, result.message.to_s)
  end
end
