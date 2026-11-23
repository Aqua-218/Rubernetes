# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"
require "rubernetes/schema"

# ValidateDaemonSetSpecUpdate / ValidateDeploymentUpdate /
# ValidateReplicaSetUpdate make the selector immutable
# (pkg/apis/apps/validation/validation.go:403,712,767), a ControllerRevision's
# data is immutable (line 366), and a StatefulSet accepts changes only to a
# named set of spec fields (line 268).  None of it was enforced.
class WorkloadUpdateRulesTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def workload(kind, spec)
    {"apiVersion" => "apps/v1", "kind" => kind, "metadata" => {"name" => "w", "namespace" => "ns"},
     "spec" => spec}
  end

  def selector_spec(selector = {"matchLabels" => {"app" => "demo"}})
    {"replicas" => 1, "selector" => selector,
     "template" => {"metadata" => {"labels" => {"app" => "demo"}},
                    "spec" => {"containers" => [{"name" => "c", "image" => "img"}]}}}
  end

  def immutable_errors(new_object, old_object, kind)
    Validator.send(:immutable_field_errors, new_object, old_object, kind, :update)
  end

  %w[Deployment ReplicaSet DaemonSet].each do |kind|
    define_method(:"test_#{kind.downcase}_selector_is_immutable") do
      old = workload(kind, selector_spec)
      changed = workload(kind, selector_spec("matchLabels" => {"app" => "other"}))

      refute_empty immutable_errors(changed, old, kind)
      assert_empty immutable_errors(workload(kind, selector_spec.merge("replicas" => 3)), old, kind)
    end
  end

  def test_controller_revision_data_is_immutable
    old = {"apiVersion" => "apps/v1", "kind" => "ControllerRevision", "data" => {"a" => 1}, "revision" => 1}
    changed = {"apiVersion" => "apps/v1", "kind" => "ControllerRevision", "data" => {"a" => 2}, "revision" => 1}

    refute_empty immutable_errors(changed, old, "ControllerRevision")
  end

  def test_daemonset_template_generation_is_managed_by_the_api
    key = "deprecated.daemonset.template.generation"
    path = "/apis/apps/v1/namespaces/ns/daemonsets"
    daemon = workload("DaemonSet", selector_spec.except("replicas"))
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    server = Rubernetes::API::Server.new(registry: registry)
    created = workload_request(server, "POST", path, daemon)

    assert_equal 201, created.status, created.body.inspect
    assert_equal [1, "1"], daemonset_generations(created.body, key)

    metadata_patch = {"metadata" => {"annotations" => {key => "99"}}, "spec" => {"minReadySeconds" => 1}}
    changed = workload_request(server, "PATCH", "#{path}/w", metadata_patch)

    assert_equal 200, changed.status, changed.body.inspect
    assert_equal [2, "1"], daemonset_generations(changed.body, key)

    template = {"spec" => {"containers" => [{"name" => "c", "image" => "img:2"}]}}
    updated = workload_request(server, "PATCH", "#{path}/w", {"spec" => {"template" => template}})

    assert_equal 200, updated.status, updated.body.inspect
    assert_equal [3, "2"], daemonset_generations(updated.body, key)
  end

  def test_pod_resize_rejects_a_strategic_order_only_patch
    path = "/api/v1/namespaces/ns/pods"
    containers = %w[one two].map do |name|
      {"name" => name, "image" => "busybox", "resources" => {"requests" => {"cpu" => "100m"}}}
    end
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    server = Rubernetes::API::Server.new(registry: registry)
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "resizable"}, "spec" => {"containers" => containers}}
    created = workload_request(server, "POST", path, pod)

    assert_equal 201, created.status, created.body.inspect

    order = [{"name" => "two"}, {"name" => "one"}]
    result = workload_request(server, "PATCH", "#{path}/resizable/resize", {"spec" => {"$setElementOrder/containers" => order}})

    assert_equal 422, result.status, result.body.inspect

    fields = result.body.dig("details", "causes").map { |cause| cause.fetch("field") }

    assert_equal %w[spec.containers[0].name spec.containers[1].name], fields
    assert_equal created.body, workload_request(server, "GET", "#{path}/resizable", nil).body
  end

  def workload_request(server, method, path, body)
    content_type = method == "PATCH" ? "application/strategic-merge-patch+json" : "application/json"
    identity = {"username" => "admin", "groups" => ["system:masters"]}
    request = Rubernetes::API::Request.new(
      method: method, path: path, headers: {"content-type" => content_type},
      identity: identity, body: JSON.generate(body)
    )
    server.call(request)
  end

  def daemonset_generations(object, key)
    [object.dig("metadata", "generation"), object.dig("metadata", "annotations", key)]
  end

  def stateful_errors(new_object, old_object, operation: :update)
    Validator.send(:stateful_set_update_errors, new_object, old_object, operation)
  end

  def stateful(spec_extra = {})
    workload("StatefulSet", selector_spec.merge("serviceName" => "svc",
                                                "podManagementPolicy" => "OrderedReady").merge(spec_extra))
  end

  def test_statefulset_replicas_may_change
    assert_empty stateful_errors(stateful("replicas" => 5), stateful)
  end

  def test_statefulset_template_may_change
    changed = stateful
    changed["spec"]["template"]["spec"]["containers"][0]["image"] = "img:2"

    assert_empty stateful_errors(changed, stateful)
  end

  def test_statefulset_service_name_may_not_change
    refute_empty stateful_errors(stateful("serviceName" => "other"), stateful)
  end

  def test_statefulset_pod_management_policy_may_not_change
    refute_empty stateful_errors(stateful("podManagementPolicy" => "Parallel"), stateful)
  end

  def test_a_create_is_never_restricted
    assert_empty stateful_errors(stateful("serviceName" => "other"), stateful, operation: :create)
  end
end
