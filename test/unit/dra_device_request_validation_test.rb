# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class DRADeviceRequestValidationTest < Minitest::Test
  API = Rubernetes::API
  LEGACY_CLAIMS = "/apis/resource.k8s.io/v1beta1/namespaces/default/resourceclaims"
  STABLE_CLAIMS = "/apis/resource.k8s.io/v1/namespaces/default/resourceclaims"

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = API::Server.new(registry: registry, runtime_config: {"resource.k8s.io/v1beta1" => true})
  end

  def test_v1beta1_go_client_zero_value_keeps_prioritized_alternatives
    created = request("POST", LEGACY_CLAIMS, claim(device_class: ""))

    assert_equal 201, created.status, created.body.inspect
    assert_equal "", created.body.dig("spec", "devices", "requests", 0, "deviceClassName")

    stable = request("GET", "#{STABLE_CLAIMS}/example-claim")
    device_request = stable.body.dig("spec", "devices", "requests", 0)

    assert_equal 200, stable.status, stable.body.inspect
    assert_nil device_request["exactly"]
    assert_equal(%w[large small], device_request.fetch("firstAvailable").map { |item| item.fetch("name") })
  end

  def test_v1beta1_still_rejects_both_an_exact_request_and_alternatives
    rejected = request("POST", LEGACY_CLAIMS, claim(device_class: "example-class"))

    assert_equal 422, rejected.status, rejected.body.inspect
    cause = rejected.body.dig("details", "causes", 0)

    assert_equal "spec.devices.requests[0]", cause.fetch("field")
    assert_includes cause.fetch("message"), "multiple fields are set"
  end

  def test_constraint_attributes_use_c_identifiers_after_the_dns_domain
    created = request("POST", STABLE_CLAIMS, constrained_claim("example.com/pcieRoot_1"))

    assert_equal 201, created.status, created.body.inspect
    assert_equal "example.com/pcieRoot_1", created.body.dig("spec", "devices", "constraints", 0, "matchAttribute")

    rejected = request("POST", STABLE_CLAIMS, constrained_claim("example.com/pcie-root", name: "invalid-constraint-claim"))

    assert_equal 422, rejected.status, rejected.body.inspect
    assert_equal "spec.devices.constraints[0].matchAttribute", rejected.body.dig("details", "causes", 0, "field")
  end

  private

  def claim(device_class:)
    alternatives = {"name" => "gpu", "deviceClassName" => device_class,
                    "firstAvailable" => [{"name" => "large", "deviceClassName" => "example-class", "count" => 2},
                                         {"name" => "small", "deviceClassName" => "example-class", "count" => 1}]}
    {"apiVersion" => "resource.k8s.io/v1beta1", "kind" => "ResourceClaim", "metadata" => {"name" => "example-claim"},
     "spec" => {"devices" => {"requests" => [alternatives]}}}
  end

  def constrained_claim(attribute, name: "constraint-claim")
    {"apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceClaim", "metadata" => {"name" => name},
     "spec" => {"devices" => {"requests" => [{"name" => "gpu", "exactly" => {"deviceClassName" => "example-class"}}],
                              "constraints" => [{"requests" => ["gpu"], "matchAttribute" => attribute}]}}}
  end

  def request(method, path, body = nil)
    @server.call(API::Request.new(method: method, path: path, body: body))
  end
end
