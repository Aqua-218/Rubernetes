# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/bootstrap"

class ServiceV1FieldsTest < Minitest::Test
  API = Rubernetes::API
  COLLECTION = "/api/v1/namespaces/team/services"
  PORTS = [{"port" => 80}].freeze

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = API::Server.new(registry: registry, store: API::MemoryStore.new, service_cidrs: ["10.96.0.0/24"])
    request("POST", "/api/v1/namespaces", {"metadata" => {"name" => "team"}})
  end

  def test_empty_service_fields_take_kubernetes_defaults_before_validation
    status, result = create("empty", {"type" => "", "sessionAffinity" => "", "sessionAffinityConfig" => {"clientIP" => {"timeoutSeconds" => 0}},
                                      "ports" => [{"port" => 80, "name" => "", "protocol" => "", "targetPort" => ""}]})

    assert_equal 201, status
    spec = result.fetch("spec")

    assert_equal %w[ClusterIP None], spec.values_at("type", "sessionAffinity")
    refute spec.key?("sessionAffinityConfig")
    assert_equal [{"port" => 80, "protocol" => "TCP", "targetPort" => 80}], spec.fetch("ports")
  end

  def test_generated_service_accepts_input_that_can_be_defaulted_by_the_api
    definition = Rubernetes::Generated.definition_for("io.k8s.api.core.v1.Service")
    raw = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "typed", "namespace" => "team"},
           "spec" => {"type" => "", "sessionAffinity" => "", "ports" => [{"port" => 80, "name" => "", "protocol" => "", "targetPort" => 0}]}}
    object = definition.value_class.new(raw)

    assert_empty definition.validator.errors(object, operation: :create)
    assert_equal raw.fetch("spec"), object.to_h.fetch("spec")
  end

  def test_default_and_boundary_client_ip_timeouts_and_affinity_changes
    status, result = create("affinity", {"sessionAffinity" => "ClientIP", "sessionAffinityConfig" => {"clientIP" => {}}})

    assert_equal 201, status
    assert_equal 10_800, result.dig("spec", "sessionAffinityConfig", "clientIP", "timeoutSeconds")
    status, result = patch("affinity", {"sessionAffinityConfig" => {"clientIP" => {"timeoutSeconds" => 86_400}}})

    assert_equal 200, status
    assert_equal 86_400, result.dig("spec", "sessionAffinityConfig", "clientIP", "timeoutSeconds")
    [0, -1, 86_401].each do |timeout|
      status, result = patch("affinity", {"sessionAffinityConfig" => {"clientIP" => {"timeoutSeconds" => timeout}}})

      assert_equal 422, status
      assert_equal [["spec.sessionAffinityConfig.clientIP.timeoutSeconds", "FieldValueInvalid",
                     "Invalid value: #{timeout}: must be greater than 0 and less than 86400"]], causes(result)
    end
    status, result = patch("affinity", {"sessionAffinity" => ""})

    assert_equal 200, status
    assert_equal "None", result.dig("spec", "sessionAffinity")
    refute result.fetch("spec").key?("sessionAffinityConfig")
  end

  def test_external_name_keeps_fqdn_and_type_changes_are_compatible
    status, result = create("alias", {"type" => "ExternalName", "externalName" => "backend.example.", "ports" => []})

    assert_equal 201, status
    assert_equal "backend.example.", result.dig("spec", "externalName")
    refute result.fetch("spec").key?("ports")
    status, result = patch("alias", {"type" => "ClusterIP", "ports" => PORTS})

    assert_equal 200, status
    assert_equal "ClusterIP", result.dig("spec", "type")
    status, result = patch("alias", {"type" => "ExternalName", "externalName" => "next.example."})

    assert_equal 200, status
    assert_equal "next.example.", result.dig("spec", "externalName")
    status, result = patch("alias", {"externalName" => "example.."})

    assert_equal 422, status
    assert_match(/\AInvalid value: "example\.": a lowercase RFC 1123 subdomain/, causes(result).dig(0, 2))
    status, result = patch("alias", {"externalName" => "."})

    assert_equal 422, status
    assert_equal [["spec.externalName", "FieldValueRequired", "Required value"]], causes(result)
    status, result = create("headless", {"clusterIP" => "None", "ports" => []})

    assert_equal 201, status
    refute result.fetch("spec").key?("ports")
  end

  def test_preflight_reports_all_invalid_service_fields_in_kubernetes_order
    status, result = create("invalid", {"type" => "Unexpected", "sessionAffinity" => "Unexpected", "trafficDistribution" => "",
                                        "ports" => [{"name" => "bad.name", "port" => 0, "protocol" => "tcp",
                                                     "targetPort" => "123", "appProtocol" => "wrong/prefix/name"}]})

    assert_equal 422, status
    assert_equal %w[spec.ports[0].name spec.ports[0].port spec.ports[0].protocol spec.ports[0].targetPort
                    spec.ports[0].appProtocol spec.sessionAffinity spec.type spec.trafficDistribution], causes(result).map(&:first)
    assert_equal ["spec.ports[0].name", "FieldValueInvalid", 'Invalid value: "bad.name": must not contain dots'], causes(result).first
    assert_match(/supported values: "PreferClose", "PreferSameZone", "PreferSameNode"\z/, causes(result).last.last)
  end

  def test_duplicate_port_error_uses_the_pair_key_after_defaulting_protocol
    status, result = create("pair", {"ports" => [{"name" => "first", "port" => 80}, {"name" => "second", "port" => 80, "protocol" => ""}]})

    assert_equal 422, status
    value = '{"Name":"","Protocol":"TCP","AppProtocol":null,"Port":80,"TargetPort":0,"NodePort":0}'

    assert_equal [["spec.ports[1]", "FieldValueDuplicate", "Duplicate value: #{value}"]], causes(result)
  end

  private

  def request(method, path, body, type = "application/json")
    response = @server.call(API::Request.new(method: method, path: path, headers: {"content-type" => type}, body: JSON.generate(body),
                                             identity: {"username" => "admin", "groups" => ["system:masters"]}))
    [response.status, response.body.is_a?(String) ? JSON.parse(response.body) : response.body]
  end

  def create(name, spec)
    request("POST", COLLECTION, {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => name}, "spec" => {"ports" => PORTS}.merge(spec)})
  end

  def patch(name, spec) = request("PATCH", "#{COLLECTION}/#{name}", {"spec" => spec}, "application/merge-patch+json")

  def causes(status) = status.dig("details", "causes").map { |cause| cause.values_at("field", "reason", "message") }
end
