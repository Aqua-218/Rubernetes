# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)
require "rubernetes/api"

class HostnameOverrideAPITest < Minitest::Test
  API = Rubernetes::API
  PODS = "/api/v1/namespaces/default/pods"
  JOBS = "/apis/batch/v1/namespaces/default/jobs"
  GATE = "HostnameOverride"

  def test_default_gate_rejects_invalid_or_conflicting_hostnames
    api = server
    [
      ["Not-RFC1123", {}, "FieldValueInvalid", "RFC 1123 subdomain"],
      ["", {}, "FieldValueInvalid", "RFC 1123 subdomain"],
      ["a" * 65, {}, "FieldValueTooLong", "64 bytes"],
      ["valid.example", {"hostNetwork" => true}, "FieldValueForbidden", "hostNetwork"],
      ["valid.example", {"setHostnameAsFQDN" => true}, "FieldValueForbidden", "setHostnameAsFQDN"]
    ].each do |hostname, other, reason, expected|
      response = request(api, "POST", PODS, pod("invalid", hostname, other))

      assert_equal 422, response.status, response.body.inspect
      cause = response.body.dig("details", "causes").find { |entry| entry["field"] == "spec.hostnameOverride" }

      assert_equal reason, cause.fetch("reason")
      assert_includes cause.fetch("message"), expected
    end

    valid = request(api, "POST", PODS, pod("valid", "a" * 64, "setHostnameAsFQDN" => false))

    assert_equal 201, valid.status, valid.body.inspect
    assert_equal "a" * 64, valid.body.dig("spec", "hostnameOverride")
  end

  def test_disabled_gate_drops_new_values_and_keeps_a_stored_value
    store = API::MemoryStore.new
    enabled = server(store: store)
    disabled = server({GATE => false}, store: store)

    assert_equal 201, request(enabled, "POST", PODS, pod("stored", "old.host")).status

    created = request(disabled, "POST", PODS, pod("new", "Not-RFC1123", "hostNetwork" => true))
    patched = request(disabled, "PATCH", "#{PODS}/stored", "metadata" => {"labels" => {"keep" => "yes"}})

    assert_equal 201, created.status, created.body.inspect
    refute created.body.fetch("spec").key?("hostnameOverride")
    assert_equal 200, patched.status, patched.body.inspect
    assert_equal "old.host", patched.body.dig("spec", "hostnameOverride")
  end

  def test_job_template_validates_the_same_field
    spec = pod("test", "Not-RFC1123").fetch("spec").merge("restartPolicy" => "Never")
    object = {"apiVersion" => "batch/v1", "kind" => "Job", "metadata" => {"name" => "job"},
              "spec" => {"template" => {"spec" => spec}}}
    rejected = request(server, "POST", JOBS, object)

    assert_equal 422, rejected.status, rejected.body.inspect
    assert_includes rejected.body.dig("details", "causes").map { |cause| cause.fetch("field") }, "spec.template.spec.hostnameOverride"
  end

  private

  def server(gates = {}, store: API::MemoryStore.new)
    definitions = [["", "pods", "Pod", "core"], ["batch", "jobs", "Job", "batch"]].map do |group, resource, kind, package|
      API::Resource.new(group: group, version: "v1", resource: resource, kind: kind, scope: :namespaced,
                        schema: Rubernetes::Generated.definition_for("io.k8s.api.#{package}.v1.#{kind}"))
    end
    API::Server.new(registry: API::Registry.new(resources: definitions, defaults: false), store: store, feature_gates: gates)
  end

  def request(api, method, path, body)
    headers = method == "PATCH" ? {"Content-Type" => "application/merge-patch+json"} : {}
    api.call(API::Request.new(method: method, path: path, headers: headers, body: body))
  end

  def pod(name, hostname, other = {})
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name},
     "spec" => {"containers" => [{"name" => "workload", "image" => "busybox"}], "hostnameOverride" => hostname}.merge(other)}
  end
end
