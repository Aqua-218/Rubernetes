# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)
require "rubernetes/api"

class PodServiceAccountOwnershipTest < Minitest::Test
  API = Rubernetes::API
  PODS = "/api/v1/namespaces/default/pods"
  DEPLOYMENTS = "/apis/apps/v1/namespaces/default/deployments"
  ACCOUNT_FIELDS = %w[serviceAccount serviceAccountName].freeze

  def setup
    resources = [
      API::Resource.new(group: "", version: "v1", resource: "pods", kind: "Pod", scope: :namespaced,
                        schema: Rubernetes::Generated.definition_for("io.k8s.api.core.v1.Pod")),
      API::Resource.new(group: "apps", version: "v1", resource: "deployments", kind: "Deployment", scope: :namespaced,
                        schema: Rubernetes::Generated.definition_for("io.k8s.api.apps.v1.Deployment"))
    ]
    @api = API::Server.new(registry: API::Registry.new(resources: resources, defaults: false), store: API::MemoryStore.new)
  end

  def test_admission_default_does_not_become_the_create_managers_field
    [{}, {"serviceAccount" => "", "serviceAccountName" => nil}].each_with_index do |selection, index|
      name = "omitted-#{index}"
      created = write("POST", PODS, pod(name, selection))
      read = @api.call(method: "GET", path: "#{PODS}/#{name}")

      assert_equal [201, 200], [created.status, read.status]
      [created.body, read.body].each do |body|
        assert_equal({"serviceAccount" => "default", "serviceAccountName" => "default"}, account(body))
        assert_empty owned_account_fields(body, "writer")
      end
    end
  end

  def test_ordinary_update_uses_the_equivalent_legacy_alias
    created = write("POST", PODS, pod("explicit", "serviceAccount" => "ignored", "serviceAccountName" => "alpha"))
    replacement = pod("explicit", "serviceAccount" => "alpha")
    replacement["metadata"]["resourceVersion"] = created.body.dig("metadata", "resourceVersion")
    updated = write("PUT", "#{PODS}/explicit", replacement, manager: "updater")

    assert_equal [201, 200], [created.status, updated.status]
    assert_equal({"serviceAccount" => "alpha", "serviceAccountName" => "alpha"}, account(updated.body))
    assert_equal %w[f:serviceAccount f:serviceAccountName], owned_account_fields(updated.body, "writer")
    assert_empty owned_account_fields(updated.body, "updater")
  end

  def test_apply_force_does_not_change_the_effective_service_account
    ACCOUNT_FIELDS.each do |field|
      name = field.downcase
      created = write("PATCH", "#{PODS}/#{name}", pod(name, field => "alpha"), apply: true)
      conflict = write("PATCH", "#{PODS}/#{name}", pod(name, field => "beta"), manager: "taker", apply: true)
      forced = write("PATCH", "#{PODS}/#{name}", pod(name, field => "beta"), manager: "taker", apply: true, force: true)
      live = @api.call(method: "GET", path: "#{PODS}/#{name}")

      assert_equal [201, 409], [created.status, conflict.status]
      assert_equal ["f:#{field}"], owned_account_fields(created.body, "writer")
      assert_equal(field == "serviceAccount" ? 200 : 422, forced.status)
      assert_equal({"serviceAccount" => "alpha", "serviceAccountName" => "alpha"}, account(live.body))
    end
  end

  def test_empty_template_account_is_omitted_without_defaulting_it
    labels = {"app" => "test"}
    template = {"metadata" => {"labels" => labels}, "spec" => pod("unused", "serviceAccount" => "", "serviceAccountName" => "").fetch("spec")}
    deployment = {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"name" => "example"},
                  "spec" => {"selector" => {"matchLabels" => labels}, "template" => template}}
    created = write("POST", DEPLOYMENTS, deployment)

    assert_equal 201, created.status
    assert_empty created.body.dig("spec", "template", "spec").slice(*ACCOUNT_FIELDS)
  end

  private

  def pod(name, fields)
    spec = {"containers" => [{"name" => "main", "image" => "busybox"}]}.merge(fields)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name}, "spec" => spec}
  end

  def account(body) = body.fetch("spec").slice(*ACCOUNT_FIELDS)

  def owned_account_fields(body, manager)
    entry = body.dig("metadata", "managedFields")&.find { |item| item["manager"] == manager }
    (entry&.dig("fieldsV1", "f:spec") || {}).keys.grep(/\Af:serviceAccount/).sort
  end

  def write(method, path, body, manager: "writer", apply: false, force: false)
    headers = {"Content-Type" => apply ? "application/apply-patch+yaml" : "application/json"}
    query = {"fieldManager" => manager, "fieldValidation" => "Strict"}
    query["force"] = "true" if force
    @api.call(method: method, path: path, query: query, headers: headers, body: JSON.generate(body))
  end
end
