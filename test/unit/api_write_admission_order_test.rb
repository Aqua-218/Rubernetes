# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/admission_policy_harness"
require "rubernetes/bootstrap"

class APIWriteAdmissionOrderTest < Minitest::Test
  include AdmissionPolicyHarness

  CONTROLLERS = "/api/v1/namespaces/team/replicationcontrollers"
  RESOURCE = "#{CONTROLLERS}/example".freeze
  CONFIG_GROUP = "admissionregistration.k8s.io"
  MERGE_PATCH = "application/merge-patch+json"
  APPLY_PATCH = "application/apply-patch+yaml"

  def setup
    super
    @reviews = []
    @mutation = {}
    install_hook("mutating", "mutate")
    install_hook("validating", "check")
    plugins = %w[MutatingAdmissionWebhook ValidatingAdmissionWebhook].map do |name|
      A::Registry.factories.fetch(name).call(@context, {"client" => method(:admission_review)})
    end
    security = S::Pipeline.new(admission: A::Chain.new(plugins: plugins))
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = Rubernetes::API::Server.new(registry: registry, security: security)
  end

  def test_repaired_create_and_apply_leave_webhook_fields_without_client_ownership
    @mutation["mutate"] = replicas_patch(0) + [{"op" => "add", "path" => "/metadata/labels/webhook.example~1added", "value" => "yes"}]
    patch_preview = call("PATCH", RESOURCE, controller(-1), format: APPLY_PATCH, dry_run: true)
    created = call("POST", CONTROLLERS, controller(-1))

    [patch_preview, created].each do |response|
      assert_equal 201, response.status, response.body.inspect
      assert_equal 0, response.body.dig("spec", "replicas")
      assert_equal "yes", response.body.dig("metadata", "labels", "webhook.example/added")
      refute response.body.dig("metadata", "managedFields", 0, "fieldsV1", "f:metadata", "f:labels", "f:webhook.example/added")
    end
    assert_equal([-1, 0, -1, 0], @reviews.map { |_, request| request.dig("object", "spec", "replicas") })
    assert_equal([true, true, false, false], @reviews.map { |_, request| request["dryRun"] })
  end

  def test_repaired_put_and_merge_patch_and_rejected_mutations
    original = call("POST", CONTROLLERS, controller(1)).body
    put = controller(-1)
    put["metadata"]["resourceVersion"] = original.dig("metadata", "resourceVersion")
    @mutation["mutate"] = replicas_patch(2)

    assert_equal 2, call("PUT", RESOURCE, put).body.dig("spec", "replicas")
    preview = call("PATCH", RESOURCE, {"spec" => {"replicas" => -1}}, format: MERGE_PATCH, dry_run: true)

    assert_equal 200, preview.status, preview.body.inspect
    assert_equal 2, preview.body.dig("spec", "replicas")
    @mutation["mutate"] = replicas_patch(-1)
    @reviews.clear
    rejected = call("PATCH", RESOURCE, {"spec" => {"replicas" => 3}}, format: MERGE_PATCH)

    assert_equal 422, rejected.status
    assert_equal "spec.replicas", rejected.body.dig("details", "causes", 0, "field")
    assert_equal ["mutate"], @reviews.map(&:first)
    assert_equal 2, call("GET", RESOURCE).body.dig("spec", "replicas")
  end

  def test_wire_types_are_checked_at_request_and_webhook_decoding
    @mutation["mutate"] = replicas_patch(0)
    rejected = call("POST", CONTROLLERS, controller("invalid"))

    assert_equal 400, rejected.status
    assert_match(/ReplicationControllerSpec\.spec\.replicas of type int32/, rejected.body.fetch("message"))
    assert_empty @reviews

    @mutation["mutate"] = replicas_patch("invalid")
    rejected = call("POST", CONTROLLERS, controller(0))

    assert_equal 500, rejected.status
    assert_equal "InternalError", rejected.body.fetch("reason")
    assert_equal ["mutate"], @reviews.map(&:first)
    assert_equal 404, call("GET", RESOURCE).status
  end

  def test_webhooks_receive_defaults_from_the_previous_patch
    install_hook("mutating", "next")
    patch = {"op" => "add", "path" => "/spec/template/spec/containers/-", "value" => {"name" => "sidecar", "image" => "example:v1"}}
    @mutation["mutate"] = [patch]

    assert_equal 201, call("POST", CONTROLLERS, controller(0)).status
    second_request = @reviews.find { |hook, _| hook == "next" }.last
    sidecar = second_request.dig("object", "spec", "template", "spec", "containers", 1)

    assert_equal "IfNotPresent", sidecar.fetch("imagePullPolicy")
    assert_equal "File", sidecar.fetch("terminationMessagePolicy")
  end

  private

  def call(method, path, body = nil, format: "application/json", dry_run: false)
    query = {"fieldManager" => "writer"}
    query["dryRun"] = "All" if dry_run
    @server.call(method: method, path: path, body: body, query: query, headers: {"content-type" => format},
                 identity: {"username" => "admin", "groups" => ["system:masters"]})
  end

  def controller(replicas)
    {"apiVersion" => "v1", "kind" => "ReplicationController",
     "metadata" => {"name" => "example", "namespace" => "team", "labels" => {"app" => "fixture"}},
     "spec" => {"replicas" => replicas, "selector" => {"app" => "fixture"},
                "template" => {"metadata" => {"labels" => {"app" => "fixture"}},
                               "spec" => {"containers" => [{"name" => "main", "image" => "example:v1"}]}}}}
  end

  def install_hook(phase, name)
    hook = {"name" => "#{name}.example.test", "sideEffects" => "None", "admissionReviewVersions" => ["v1"],
            "rules" => [{"apiGroups" => [""], "apiVersions" => ["v1"], "operations" => %w[CREATE UPDATE],
                         "resources" => ["replicationcontrollers"]}], "clientConfig" => {"url" => "https://example.test/#{name}"}}
    @context.put("#{phase}webhookconfigurations", nil, name, {"metadata" => {"name" => name}, "webhooks" => [hook]}, group: CONFIG_GROUP)
  end

  def admission_review(config, review, timeout_seconds:)
    request = review.fetch("request")
    hook = config.fetch("url").split("/").last
    @reviews << [hook, request]
    response = {"uid" => request.fetch("uid"), "allowed" => true}
    if (patch = @mutation[hook])
      response["patchType"] = "JSONPatch"
      response["patch"] = [JSON.generate(patch)].pack("m0")
    end
    [200, {"response" => response}]
  end

  def replicas_patch(value) = [{"op" => "replace", "path" => "/spec/replicas", "value" => value}]
end
