# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller/infrastructure_storage"

class InfrastructureStorageControllerTest < Minitest::Test
  Controller = Rubernetes::Controller

  def test_taint_eviction_respects_noexecute_toleration_deadline
    node = node("node-a", taints: [{"key" => "node.kubernetes.io/unreachable", "effect" => "NoExecute",
                                    "timeAdded" => "2026-01-01T00:00:00Z"}])
    immediate = pod("immediate", node: "node-a")
    delayed = pod("delayed", node: "node-a",
                             tolerations: [{"key" => "node.kubernetes.io/unreachable", "effect" => "NoExecute",
                                            "tolerationSeconds" => 60}])
    controller = Controller::TaintEvictionController.new(clock: -> { Time.utc(2026, 1, 1, 0, 0, 30) })

    before_deadline = controller.plan(node, pods: [immediate, delayed])

    assert_equal ["immediate"], deleted_names(before_deadline)
    assert_equal "TaintManagerEviction", before_deadline.events.first.fetch("reason")

    after_deadline = controller.plan(node, pods: [delayed], now: Time.utc(2026, 1, 1, 0, 1))

    assert_equal ["delayed"], deleted_names(after_deadline)
  end

  def test_device_taint_eviction_uses_device_taint_source_and_deadline
    node = node("node-a")
    device_taint = {"key" => "resource.kubernetes.io/gpu", "effect" => "NoExecute",
                    "timeAdded" => "2026-01-01T00:00:00Z"}
    pod_value = pod("gpu", node: "node-a",
                           tolerations: [{"key" => "resource.kubernetes.io/gpu", "effect" => "NoExecute",
                                          "tolerationSeconds" => 120}])
    controller = Controller::DeviceTaintEvictionController.new

    assert_empty deleted_names(controller.plan(node, pods: [pod_value], device_taints: [device_taint],
                                                     now: Time.utc(2026, 1, 1, 0, 1)))
    result = controller.plan(node, pods: [pod_value], device_taints: [device_taint],
                                   now: Time.utc(2026, 1, 1, 0, 2))

    assert_equal ["gpu"], deleted_names(result)
  end

  def test_cloud_controllers_only_mutate_their_owned_surfaces
    provider = Class.new do
      attr_reader :load_balancers, :routes

      def initialize
        @load_balancers = []
        @routes = []
      end

      def ensure_load_balancer(service, nodes)
        @load_balancers << [service.fetch("metadata").fetch("name"), nodes.map { |node| node.fetch("metadata").fetch("name") }]
        {"ingress" => [{"ip" => "198.51.100.10"}]}
      end

      def ensure_route(node, route)
        @routes << [node.fetch("metadata").fetch("name"), route.fetch("destination")]
      end
    end.new
    service = service("web", type: "LoadBalancer")
    ignored = service("external", type: "LoadBalancer", load_balancer_class: "example.com/external")
    node_value = node("node-a", provider_id: "cloud://node-a", pod_cidr: "10.244.0.0/24")
    controller = Controller::ServiceLBController.new(provider: provider)
    result = controller.plan(service, nodes: [node_value])

    assert_equal [{"ip" => "198.51.100.10"}], result.status.dig("loadBalancer", "ingress")
    assert_equal [["web", ["node-a"]]], provider.load_balancers
    assert_empty controller.plan(ignored, nodes: [node_value]).operations

    route_result = Controller::NodeRouteController.new(provider: provider).plan(node_value)

    assert_equal(["10.244.0.0/24"], route_result.status.fetch("routes").map { |route| route.fetch("destination") })
    assert_equal [["node-a", "10.244.0.0/24"]], provider.routes
  end

  def test_persistent_volume_binding_requires_class_access_mode_and_capacity
    claim = pvc("claim", storage_class: "fast", access_modes: ["ReadWriteOnce"], request: "10Gi")
    wrong_class = pv("wrong-class", storage_class: "slow", access_modes: ["ReadWriteOnce"], capacity: "20Gi")
    wrong_mode = pv("wrong-mode", storage_class: "fast", access_modes: ["ReadOnlyMany"], capacity: "20Gi")
    too_small = pv("too-small", storage_class: "fast", access_modes: ["ReadWriteOnce"], capacity: "5Gi")
    matching = pv("matching", storage_class: "fast", access_modes: ["ReadWriteOnce"], capacity: "20Gi")
    result = Controller::PersistentVolumeBinderController.new.plan(claim,
                                                                   persistent_volumes: [wrong_class, wrong_mode, too_small, matching])

    # bind: the volume's claimRef (update) and phase (status), then the
    # claim's volumeName and annotations (update) and phase (status).
    actions = result.operations.map { |operation| [operation.action, operation.resource.kind, operation.object.dig("metadata", "name")] }

    assert_equal [[:update, "PersistentVolume", "matching"], [:status_update, "PersistentVolume", "matching"],
                  [:update, "PersistentVolumeClaim", "claim"], [:status_update, "PersistentVolumeClaim", "claim"]], actions
    volume_update, volume_status, claim_update, claim_status = result.operations

    assert_equal "claim", volume_update.object.dig("spec", "claimRef", "name")
    assert_equal "yes", volume_update.object.dig("metadata", "annotations", "pv.kubernetes.io/bound-by-controller")
    assert_equal "Bound", volume_status.patch["phase"]
    assert_equal "matching", claim_update.object.dig("spec", "volumeName")
    assert_equal({"pv.kubernetes.io/bind-completed" => "yes", "pv.kubernetes.io/bound-by-controller" => "yes"},
                 claim_update.object.dig("metadata", "annotations"))
    assert_equal "Bound", claim_status.patch["phase"]
    assert_equal({"storage" => "20Gi"}, claim_status.patch["capacity"])
    assert_empty result.events, "binding records no event"
  end

  def test_attach_detach_refuses_a_second_node_for_a_single_node_volume
    volume = pv("data", capacity: "20Gi", csi_driver: "example.csi")
    claim = pvc("claim", volume_name: "data", storage_class: "")
    pod_value = pod("consumer", node: "node-b",
                                volumes: [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "claim"}}])
    existing = volume_attachment("data", node_name: "node-a", attacher: "example.csi", attached: true)
    managed = %w[node-a node-b].map do |name|
      {"apiVersion" => "v1", "kind" => "Node",
       "metadata" => {"name" => name, "annotations" => {"volumes.kubernetes.io/controller-managed-attach-detach" => "true"}},
       "status" => {"volumesInUse" => ["kubernetes.io/csi/example.csi^"]}}
    end
    result = Controller::PersistentVolumeAttachDetachController.new.plan(volume, pods: [pod_value], claims: [claim],
                                                                                 attachments: [existing], nodes: managed)

    assert_empty result.creates
    assert_empty result.operations.reject { |operation| operation.action == :status_merge }, "node-a still has it mounted: no detach yet"
    assert_equal([["FailedAttachVolume", "Multi-Attach error for volume \"data\" Volume is already exclusively attached to one node " \
                                         "and can't be attached to another"]],
                 result.events.map { |event| event.values_at("reason", "message") })
  end

  def test_expander_updates_capacity_and_filesystem_pending_status
    claim = pvc("claim", storage_class: "fast", volume_name: "data", request: "20Gi")
    claim["status"] = {"phase" => "Bound", "capacity" => {"storage" => "10Gi"}}
    volume = pv("data", storage_class: "fast", capacity: "20Gi")
    result = Controller::PersistentVolumeExpanderController.new.plan(
      claim, persistent_volume: volume,
             storage_class: {"apiVersion" => "storage.k8s.io/v1", "kind" => "StorageClass",
                             "metadata" => {"name" => "fast"}, "spec" => {"allowVolumeExpansion" => true}}
    )

    status_update = result.operations.find { |operation| operation.action == :status_update }

    assert_equal "20Gi", status_update.patch.dig("capacity", "storage")
    assert_equal "FileSystemResizePending", result.status.fetch("conditions").last.fetch("type")
    assert_equal "VolumeResizeSuccessful", result.events.first.fetch("reason")
  end

  def test_cluster_role_aggregation_is_owned_and_idempotent
    target = cluster_role("admin", aggregation_rule: [{"matchLabels" => {"rbac.example/aggregate" => "true"}}],
                                   rules: [{"apiGroups" => [""], "resources" => ["pods"], "verbs" => ["get"]}])
    source_a = cluster_role("source-a", labels: {"rbac.example/aggregate" => "true"},
                                        rules: [{"apiGroups" => [""], "resources" => ["pods"], "verbs" => ["get"]}])
    source_b = cluster_role("source-b", labels: {"rbac.example/aggregate" => "true"},
                                        rules: [{"apiGroups" => [""], "resources" => ["deployments"], "verbs" => ["list"]}])
    controller = Controller::ClusterRoleAggregationController.new
    first = controller.plan(target, roles: [target, source_b, source_a])
    candidate = first.operations.first.object
    second = controller.plan(candidate, roles: [candidate, source_b, source_a])

    assert_equal 2, candidate.fetch("rules").length
    assert_equal %w[deployments pods], candidate.fetch("rules").map { |rule| rule.fetch("resources").first }.sort
    assert_empty second.operations
    assert_equal "ClusterRoleAggregated", first.events.first.fetch("reason")
  end

  def test_factory_exposes_pinned_metadata_and_concrete_implementations
    factory = Controller::InfrastructureStorageControllerFactory

    assert_equal "v1.36.2", factory::VERSION
    assert_equal factory::NAMES.sort, factory::IMPLEMENTATIONS.keys.sort
    factory.definitions.each do |definition|
      refute_nil definition.implementation
      assert_operator definition.implementation, :<=, Controller::BaseController
      definition.validate!
    end
  end

  private

  def deleted_names(result)
    result.deletes.map { |operation| operation.object.fetch("metadata").fetch("name") }
  end

  def node(name, taints: [], provider_id: nil, pod_cidr: nil)
    spec = {}
    spec["taints"] = taints unless taints.empty?
    spec["providerID"] = provider_id if provider_id
    spec["podCIDR"] = pod_cidr if pod_cidr
    {"apiVersion" => "v1", "kind" => "Node",
     "metadata" => {"name" => name, "uid" => "uid-#{name}"}, "spec" => spec, "status" => {}}
  end

  def pod(name, node:, tolerations: [], volumes: [])
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"},
     "spec" => {"nodeName" => node, "tolerations" => tolerations, "volumes" => volumes},
     "status" => {"phase" => "Running"}}
  end

  def service(name, type:, load_balancer_class: nil)
    spec = {"type" => type}
    spec["loadBalancerClass"] = load_balancer_class if load_balancer_class
    {"apiVersion" => "v1", "kind" => "Service",
     "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"},
     "spec" => spec, "status" => {}}
  end

  def pvc(name, storage_class:, access_modes: ["ReadWriteOnce"], request: "1Gi", volume_name: nil)
    spec = {"storageClassName" => storage_class, "accessModes" => access_modes,
            "resources" => {"requests" => {"storage" => request}}}
    spec["volumeName"] = volume_name if volume_name
    {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim",
     "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"},
     "spec" => spec, "status" => {}}
  end

  def pv(name, storage_class: "", access_modes: ["ReadWriteOnce"], capacity: "1Gi", csi_driver: nil)
    spec = {"storageClassName" => storage_class, "accessModes" => access_modes,
            "capacity" => {"storage" => capacity}}
    spec["csi"] = {"driver" => csi_driver} if csi_driver
    {"apiVersion" => "v1", "kind" => "PersistentVolume",
     "metadata" => {"name" => name, "uid" => "uid-#{name}"}, "spec" => spec,
     "status" => {"phase" => "Available"}}
  end

  def volume_attachment(volume_name, node_name:, attacher:, attached:)
    {"apiVersion" => "storage.k8s.io/v1", "kind" => "VolumeAttachment",
     "metadata" => {"name" => "va-#{node_name}"},
     "spec" => {"attacher" => attacher, "nodeName" => node_name,
                "source" => {"persistentVolumeName" => volume_name}},
     "status" => {"attached" => attached}}
  end

  def cluster_role(name, labels: {}, aggregation_rule: nil, rules: [])
    value = {"apiVersion" => "rbac.authorization.k8s.io/v1", "kind" => "ClusterRole",
             "metadata" => {"name" => name, "uid" => "uid-#{name}", "labels" => labels},
             "rules" => rules}
    value["aggregationRule"] = {"clusterRoleSelectors" => aggregation_rule} if aggregation_rule
    value
  end
end
