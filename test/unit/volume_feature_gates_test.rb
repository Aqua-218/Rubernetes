# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)
require "rubernetes/api"
require "rubernetes/controller"

class VolumeFeatureGatesTest < Minitest::Test
  API = Rubernetes::API
  CLAIMS = "/api/v1/namespaces/default/persistentvolumeclaims"
  VOLUMES = "/api/v1/persistentvolumes"
  CROSS_NAMESPACE = "CrossNamespaceVolumeDataSource"
  MUTABLE_AFFINITY = "MutablePVNodeAffinity"
  UNUSED_SINCE = "PersistentVolumeClaimUnusedSinceTime"

  def test_cross_namespace_reference_is_pruned_or_retained_at_write_time
    origin = {"kind" => "PersistentVolumeClaim", "name" => "source", "namespace" => "origin"}
    disabled = request(server, "POST", CLAIMS, claim("a", "dataSourceRef" => origin))
    enabled_api = server({CROSS_NAMESPACE => true})
    enabled = request(enabled_api, "POST", CLAIMS, claim("a", "dataSourceRef" => origin))
    source_on_wire = origin.merge("apiGroup" => nil)

    assert_equal 201, disabled.status, disabled.body.inspect
    refute disabled.body.fetch("spec").key?("dataSourceRef")
    assert_equal 201, enabled.status, enabled.body.inspect
    assert_equal source_on_wire, enabled.body.dig("spec", "dataSourceRef")
    refute enabled.body.fetch("spec").key?("dataSource")
    disabled_api_with_claim = server({}, store: enabled_api.instance_variable_get(:@store).store)

    updated = request(disabled_api_with_claim, "PATCH", "#{CLAIMS}/a", "metadata" => {"labels" => {"a" => "b"}})

    assert_equal 200, updated.status, updated.body.inspect
    assert_equal source_on_wire, updated.body.dig("spec", "dataSourceRef")
  end

  def test_local_source_normalization_and_namespaced_source_errors
    api = server({CROSS_NAMESPACE => true})
    origin = {"kind" => "PersistentVolumeClaim", "name" => "source"}
    local = request(api, "POST", CLAIMS, claim("local", "dataSource" => origin))

    assert_equal 201, local.status, local.body.inspect
    assert_equal origin.merge("apiGroup" => nil), local.body.dig("spec", "dataSourceRef")
    invalid = request(api, "POST", CLAIMS, claim("invalid", "dataSourceRef" => origin.merge("namespace" => "a.b")))

    assert_equal 422, invalid.status
    assert_includes invalid.body.dig("details", "causes").map { |cause| cause["field"] }, "spec.dataSourceRef.namespace"
    both = request(api, "POST", CLAIMS, claim("both", "dataSource" => origin, "dataSourceRef" => origin.merge("namespace" => "origin")))

    assert_equal 422, both.status
  end

  def test_node_affinity_changes_still_validate_and_label_upgrade_is_compatible
    old_affinity = affinity("failure-domain.beta.kubernetes.io/zone", "west")
    ga_affinity = affinity("topology.kubernetes.io/zone", "west")
    new_affinity = affinity("topology.kubernetes.io/zone", "east")
    disabled = server

    assert_equal 201, request(disabled, "POST", VOLUMES, volume(old_affinity)).status
    assert_equal 200, patch_affinity(disabled, ga_affinity).status
    forbidden = patch_affinity(disabled, new_affinity)

    assert_equal 422, forbidden.status
    assert_includes forbidden.body.dig("details", "causes").map { |cause| cause["field"] }, "nodeAffinity"
    assert_equal 422, patch_affinity(disabled, nil).status

    enabled = server({MUTABLE_AFFINITY => true})

    assert_equal 201, request(enabled, "POST", VOLUMES, volume(old_affinity)).status
    assert_equal 200, patch_affinity(enabled, new_affinity).status
    invalid = patch_affinity(enabled, affinity("topology.kubernetes.io/zone", "east", "Bogus"))

    assert_equal 422, invalid.status
    assert_equal 200, patch_affinity(enabled, nil).status
  end

  def test_unused_condition_transitions_and_keeps_other_conditions
    controller = Rubernetes::Controller::PersistentVolumeClaimProtectionController.new
    other = {"type" => "Resizing", "status" => "True"}
    pvc = claim("a").merge("status" => {"phase" => "Bound", "conditions" => [other]})
    options = {feature_gates: {UNUSED_SINCE => true}, now: Time.utc(2026, 1, 1)}
    unused = controller.plan(pvc, pods: [], **options).operations.first

    assert_equal :status_update, unused.action
    assert_equal [other, {"type" => "Unused", "status" => "True", "reason" => "NoPodsUsingPVC",
                          "message" => "No pods are currently referencing this PVC", "lastTransitionTime" => "2026-01-01T00:00:00Z"}],
                 unused.patch["conditions"]
    pvc["metadata"]["finalizers"] = ["kubernetes.io/pvc-protection"]
    pvc["status"] = unused.patch

    assert_empty controller.plan(pvc, pods: [], **options).operations
    pod = {"kind" => "Pod", "metadata" => {"namespace" => "default", "name" => "consumer"},
           "spec" => {"volumes" => [{"persistentVolumeClaim" => {"claimName" => "a"}}]}}
    used = controller.plan(pvc, pods: [pod], **options.merge(now: Time.utc(2026, 1, 2))).operations.first

    assert_equal "False", used.patch.dig("conditions", 1, "status")
    assert_equal "2026-01-02T00:00:00Z", used.patch.dig("conditions", 1, "lastTransitionTime")
    pvc["status"] = used.patch
    pod["status"] = {"phase" => "Succeeded"}

    assert_equal "True", controller.plan(pvc, pods: [pod], **options).operations.first.patch.dig("conditions", 1, "status")
    assert_empty controller.plan(pvc, pods: [pod]).operations
  end

  private

  def server(gates = {}, store: API::MemoryStore.new)
    resources = [["persistentvolumeclaims", "PersistentVolumeClaim", :namespaced],
                 ["persistentvolumes", "PersistentVolume", :cluster]].map do |resource, kind, scope|
      API::Resource.new(group: "", version: "v1", resource: resource, kind: kind, scope: scope,
                        schema: Rubernetes::Generated.definition_for("io.k8s.api.core.v1.#{kind}"))
    end
    registry = API::Registry.new(resources: resources, defaults: false)
    API::Server.new(registry: registry, store: store, feature_gates: gates)
  end

  def request(api, method, path, body = nil)
    headers = method == "PATCH" ? {"Content-Type" => "application/merge-patch+json"} : {}
    api.call(API::Request.new(method: method, path: path, headers: headers, body: body))
  end

  def patch_affinity(api, value)
    request(api, "PATCH", "#{VOLUMES}/pv", "spec" => {"nodeAffinity" => value})
  end

  def claim(name, sources = {})
    {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim", "metadata" => {"name" => name, "namespace" => "default"},
     "spec" => {"resources" => {"requests" => {"storage" => "1Gi"}}, "accessModes" => ["ReadWriteOnce"]}.merge(sources)}
  end

  def affinity(key, value, operator = "In")
    {"required" => {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => key, "operator" => operator, "values" => [value]}]}]}}
  end

  def volume(node_affinity)
    {"metadata" => {"name" => "pv"}, "spec" => {"capacity" => {"storage" => "1Gi"}, "accessModes" => ["ReadWriteOnce"],
                                                "hostPath" => {"path" => "/volumes/test"}, "nodeAffinity" => node_affinity}}
  end
end
