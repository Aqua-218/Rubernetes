# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class DeploymentHelmSSATest < Minitest::Test
  PATH = "/apis/apps/v1/namespaces/default/deployments/nats-box"
  RESOURCES_FIELD = %w[f:spec f:template f:spec f:containers] + ['k:{"name":"nats-box"}', "f:resources"]

  def test_apply_and_controller_annotation_do_not_transfer_empty_container_resources
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @api = Rubernetes::API::Server.new(registry: registry)
    manifest = {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"name" => "nats-box"},
                "spec" => {"selector" => {"matchLabels" => {"app" => "nats-box"}},
                           "template" => {"metadata" => {"labels" => {"app" => "nats-box"}},
                                          "spec" => {"containers" => [{"name" => "nats-box", "image" => "busybox", "resources" => nil}]}}}}
    created = patch(manifest, "helm", "application/apply-patch+yaml")

    assert_equal 201, created.status, created.body.inspect
    assert_equal({}, created.body.dig("spec", "template", "spec", "containers", 0, "resources"))

    controller = patch({"metadata" => {"annotations" => {"deployment.kubernetes.io/revision" => "1"}}},
                       "kube-controller-manager", "application/merge-patch+json")

    assert_equal 200, controller.status, controller.body.inspect
    owners = controller.body.dig("metadata", "managedFields").filter_map do |entry|
      entry["manager"] unless entry.dig("fieldsV1", *RESOURCES_FIELD).nil?
    end

    assert_equal ["helm"], owners

    upgraded = patch(manifest, "helm", "application/apply-patch+yaml")

    assert_equal 200, upgraded.status, upgraded.body.inspect
  end

  private

  def patch(object, manager, content_type)
    @api.call(Rubernetes::API::Request.new(method: "PATCH", path: PATH, query: {"fieldManager" => manager},
                                           headers: {"content-type" => content_type}, body: JSON.generate(object)))
  end
end
