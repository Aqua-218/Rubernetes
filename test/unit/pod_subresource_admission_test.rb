# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/admission_policy_harness"
require "rubernetes/bootstrap"

class PodSubresourceAdmissionTest < Minitest::Test
  include AdmissionPolicyHarness

  PODS = "/api/v1/namespaces/team/pods"
  CONFIGURATIONS = "admissionregistration.k8s.io"

  def setup
    super
    @reviews = []
    @context.put("serviceaccounts", "team", "default", {"metadata" => {"name" => "default"}})
    @context.put("mutatingwebhookconfigurations", nil, "binding", configuration("binding", %w[pods/binding bindings]), group: CONFIGURATIONS)
    @context.put("validatingwebhookconfigurations", nil, "eviction", configuration("eviction", %w[pods/eviction]), group: CONFIGURATIONS)
    client = method(:admission_review)
    factories = A::Registry.factories
    plugins = %w[ServiceAccount DefaultTolerationSeconds RuntimeClass].map { |name| factories.fetch(name).call(@context, {}) }
    %w[MutatingAdmissionWebhook ValidatingAdmissionWebhook].each { |name| plugins << factories.fetch(name).call(@context, {"client" => client}) }
    security = S::Pipeline.new(admission: A::Chain.new(plugins: plugins))
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = Rubernetes::API::Server.new(registry: registry, security: security)
    call("POST", PODS, {"metadata" => {"name" => "pending"}, "spec" => {"containers" => [{"name" => "main", "image" => "test"}]}})
  end

  def configuration(name, resources)
    {"metadata" => {"name" => name}, "webhooks" => [{"name" => "#{name}.example.test", "sideEffects" => "NoneOnDryRun", "admissionReviewVersions" => ["v1"],
                                                     "rules" => [{"apiGroups" => [""], "apiVersions" => ["v1"], "operations" => ["CREATE"],
                                                                  "resources" => resources}], "clientConfig" => {"url" => "https://#{name}.example.test/"}}]}
  end

  def admission_review(config, review, timeout_seconds:)
    request = review.fetch("request")
    @reviews << request
    response = {"uid" => request.fetch("uid"), "allowed" => true}
    if config.fetch("url").include?("binding")
      patch = [{"op" => "replace", "path" => "/target/name", "value" => "admitted-node"}]
      response["patchType"] = "JSONPatch"
      response["patch"] = [JSON.generate(patch)].pack("m0")
    end
    [200, {"response" => response}]
  end

  def call(method, path, body = nil)
    @server.call(method: method, path: path, body: body, headers: {"Content-Type" => "application/json"},
                 identity: {"username" => "admin", "groups" => ["system:masters"]})
  end

  def test_virtual_creates_report_the_payload_kind_and_request_resource
    binding = {"metadata" => {"name" => "pending"}, "target" => {"kind" => "Node", "name" => "worker"}}
    eviction = {"metadata" => {"name" => "pending"}}
    [["#{PODS}/pending/binding", binding, "", "Binding", "pods", "binding"],
     ["/api/v1/namespaces/team/bindings", binding, "", "Binding", "bindings", nil],
     ["#{PODS}/pending/eviction", eviction, "policy", "Eviction", "pods", "eviction"]].each do |path, body, group, kind, resource, subresource|
      response = call("POST", "#{path}?dryRun=All", body)

      assert_equal 201, response.status, response.body.inspect
      review = @reviews.shift

      assert_equal({"group" => group, "version" => "v1", "kind" => kind}, review.fetch("kind"))
      assert_equal({"group" => "", "version" => "v1", "resource" => resource}, review.fetch("resource"))
      assert_equal review.values_at("kind", "resource"), review.values_at("requestKind", "requestResource")
      assert_equal [subresource, subresource], review.values_at("subResource", "requestSubResource")
      assert_equal ["CREATE", true, ["All"]], [review["operation"], review["dryRun"], review.dig("options", "dryRun")]
      refute review.fetch("object").key?("spec"), "Pod-only plugins must leave the subresource payload alone"
      assert_nil call("GET", "#{PODS}/pending").body.dig("spec", "nodeName")
    end
    assert_equal 201, call("POST", "#{PODS}/pending/binding", binding).status
    assert_equal "admitted-node", call("GET", "#{PODS}/pending").body.dig("spec", "nodeName")
  end
end
