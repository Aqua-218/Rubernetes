# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/observability/metrics"

# The controller-manager series wired on 2026-09-27: node IPAM cidrsets,
# ResourceClaim creation, device taint eviction, attach/detach forced
# detaches and volume states, retroactive default StorageClass assignment
# and PersistentVolume operation errors -- each recorded once the operation
# the controller planned was applied (Operation#notify), as upstream counts
# after its API call returned.
class ControllerManagerMetricsExtrasTest < Minitest::Test
  Controller = Rubernetes::Controller

  def setup
    @registry = Rubernetes::Observability::Metrics.new(apiserver: false, process: false, component: "kube-controller-manager")
    Controller.metrics = @registry
  end

  def teardown = Controller.metrics = nil

  def value(series)
    line = @registry.render.lines.find { |text| text.start_with?("#{series} ") }
    line&.then { |text| text.split.last.to_f }
  end

  def node(name, annotations: {}, spec: {})
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "uid" => "uid-#{name}", "annotations" => annotations},
     "spec" => spec}
  end

  def test_node_ipam_cidrset
    nodes = [node("a", spec: {"podCIDR" => "10.244.0.0/24", "podCIDRs" => ["10.244.0.0/24"]}), node("b")]
    controller = Controller::NodeIPAMController.new
    result = controller.plan(nodes[1], nodes: nodes, cluster_cidr: "10.244.0.0/22", node_cidr_mask_size: 24)

    assert_equal ["10.244.1.0/24"], result.operations.first.object.dig("spec", "podCIDRs")
    labels = '{clusterCIDR="10.244.0.0/22"}'

    assert_equal 4, value("node_ipam_controller_cirdset_max_cidrs#{labels}")
    assert_nil value("node_ipam_controller_cidrset_cidrs_allocations_total#{labels}"), "not before the Node update"

    result.operations.first.notify(true)

    assert_equal 1, value("node_ipam_controller_cidrset_cidrs_allocations_total#{labels}")
    # 10.244.0.0/24 was taken: one candidate tried before the free one.
    assert_equal 1, value("node_ipam_controller_cidrset_allocation_tries_per_request_sum#{labels}")
    assert_in_delta(0.5, value("node_ipam_controller_cidrset_usage_cidrs#{labels}"))

    controller.plan(nodes[1], nodes: nodes, cluster_cidr: "10.244.0.0/22", node_cidr_mask_size: 24).operations.first.notify(false,
                                                                                                                            RuntimeError.new("conflict"))

    assert_equal 2, value("node_ipam_controller_cidrset_cidrs_allocations_total#{labels}")
    assert_equal 1, value("node_ipam_controller_cidrset_cidrs_releases_total#{labels}")
    assert_in_delta(0.25, value("node_ipam_controller_cidrset_usage_cidrs#{labels}"))
  end

  def test_resource_claim_creates_and_claim_labels
    template = {"apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceClaimTemplate", "metadata" => {"name" => "gpu", "namespace" => "ns"},
                "spec" => {"spec" => {"devices" => {"requests" => [{"name" => "r", "exactly" => {"deviceClassName" => "gpu", "adminAccess" => true}}]}}}}
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "pod-uid"},
           "spec" => {"resourceClaims" => [{"name" => "gpu", "resourceClaimTemplateName" => "gpu"}], "containers" => []}}
    controller = Controller::ResourceClaimController.new(name: "resourceclaim-controller")
    create = controller.plan(pod, claims: [], templates: [template]).operations.find(&:create?)
    create.notify(true)
    create.notify(false, RuntimeError.new("quota"))

    assert_equal 1, value('resourceclaim_controller_creates_total{admin_access="true",status="success"}')
    assert_equal 1, value('resourceclaim_controller_creates_total{admin_access="true",status="failure"}')

    claim = create.object

    assert_equal({"allocated" => "false", "admin_access" => "true", "source" => "resource_claim_template"},
                 Controller::ResourceClaimController.claim_metric_labels(claim))
    extended = {"metadata" => {"annotations" => {"resource.kubernetes.io/extended-resource-claim" => "true"}},
                "status" => {"allocation" => {}}}

    assert_equal({"allocated" => "true", "admin_access" => "false", "source" => "extended_resource"},
                 Controller::ResourceClaimController.claim_metric_labels(extended))
  end

  def test_device_taint_eviction_deletions
    taint = {"key" => "resource.kubernetes.io/gpu", "effect" => "NoExecute", "timeAdded" => "2026-01-01T00:00:00Z"}
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "gpu", "namespace" => "ns", "uid" => "u"},
           "spec" => {"nodeName" => "a", "containers" => [{"name" => "c"}],
                      "tolerations" => [{"key" => "resource.kubernetes.io/gpu", "effect" => "NoExecute", "tolerationSeconds" => 60}]},
           "status" => {"phase" => "Running"}}
    clock = -> { Time.utc(2026, 1, 1, 0, 1, 30) }
    controller = Controller::DeviceTaintEvictionController.new(clock: clock)
    delete = controller.plan(node("a"), pods: [pod], device_taints: [taint], now: clock.call).operations.find do |operation|
      operation.action == :delete
    end
    delete.notify(true)

    assert_equal 1, value("device_taint_eviction_controller_pod_deletions_total")
    # The effect began at timeAdded + 60 s; the delete went through 30 s later.
    assert_equal 30, value("device_taint_eviction_controller_pod_deletion_duration_seconds_sum")
    delete.notify(false, RuntimeError.new("gone"))

    assert_equal 1, value("device_taint_eviction_controller_pod_deletions_total")
  end

  MANAGED = {"volumes.kubernetes.io/controller-managed-attach-detach" => "true"}.freeze

  def pv(name, driver)
    {"apiVersion" => "v1", "kind" => "PersistentVolume", "metadata" => {"name" => name},
     "spec" => {"csi" => {"driver" => driver, "volumeHandle" => name}, "accessModes" => ["ReadWriteOnce"]}}
  end

  def pvc(name, volume)
    {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim", "metadata" => {"name" => name, "namespace" => "ns"},
     "spec" => {"volumeName" => volume}}
  end

  def consumer(name, node_name, claim, extra: [])
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "ns", "uid" => name},
     "spec" => {"nodeName" => node_name, "volumes" => [{"name" => "v", "persistentVolumeClaim" => {"claimName" => claim}}] + extra},
     "status" => {"phase" => "Running"}}
  end

  def attachment(volume, node_name, attached: true)
    {"apiVersion" => "storage.k8s.io/v1", "kind" => "VolumeAttachment", "metadata" => {"name" => "va-#{volume}-#{node_name}"},
     "spec" => {"attacher" => "example.csi", "nodeName" => node_name, "source" => {"persistentVolumeName" => volume}},
     "status" => {"attached" => attached}}
  end

  def test_attach_detach_forced_detach_and_volume_states
    volume = pv("data", "example.csi")
    busy = node("a", annotations: MANAGED).merge("status" => {"volumesInUse" => ["kubernetes.io/csi/example.csi^data"]})
    now = Time.utc(2026, 1, 1)
    clock = -> { now }
    controller = Controller::PersistentVolumeAttachDetachController.new(clock: clock)

    assert_empty(controller.plan(volume, pods: [], claims: [], attachments: [attachment("data", "a")], nodes: [busy], csi_drivers: [])
      .operations.select { |operation| operation.action == :delete })
    now += 6 * 60
    detach = controller.plan(volume, pods: [], claims: [], attachments: [attachment("data", "a")], nodes: [busy], csi_drivers: [])
      .operations.find { |operation| operation.action == :delete }
    detach.notify(true)

    assert_equal 1, value('attach_detach_controller_attachdetach_controller_forced_detaches{reason="timeout"}')

    counts = Controller::PersistentVolumeAttachDetachController.state_counts(
      pods: [consumer("p1", "a", "c1", extra: [{"name" => "cm", "configMap" => {"name" => "x"}}]), consumer("p2", "b", "c2")],
      claims: [pvc("c1", "data"), pvc("c2", "other")], volumes: [volume, pv("other", "other.csi")],
      nodes: [node("a", annotations: MANAGED), node("b")], attachments: [attachment("data", "a"), attachment("other", "b", attached: false)],
      drivers: []
    )

    assert_equal({["a", "kubernetes.io/csi:example.csi"] => 1, ["b", "kubernetes.io/csi:other.csi"] => 1}, counts[:in_use])
    # Only node a leaves attach/detach to the controller.
    assert_equal({["kubernetes.io/csi:example.csi", "desired_state_of_world"] => 1, ["kubernetes.io/csi:example.csi", "actual_state_of_world"] => 1},
                 counts[:totals])
  end

  def storage_class(name, provisioner, default: false)
    {"apiVersion" => "storage.k8s.io/v1", "kind" => "StorageClass",
     "metadata" => {"name" => name, "annotations" => default ? {"storageclass.kubernetes.io/is-default-class" => "true"} : {}},
     "provisioner" => provisioner, "volumeBindingMode" => "Immediate"}
  end

  def claim(name, klass: nil)
    spec = {"accessModes" => ["ReadWriteOnce"], "resources" => {"requests" => {"storage" => "1Gi"}}}
    spec["storageClassName"] = klass if klass
    {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim", "metadata" => {"name" => name, "namespace" => "ns", "uid" => "uid-#{name}"},
     "spec" => spec, "status" => {"phase" => "Pending"}}
  end

  def test_retroactive_default_storage_class
    controller = Controller::PersistentVolumeBinderController.new
    classes = [storage_class("standard", "example.csi", default: true)]
    unclassed = claim("old")
    assign = controller.plan(unclassed, persistent_volumes: [], claims: [unclassed], storage_classes: classes, pods: [])
      .operations.find { |operation| operation.object&.dig("spec", "storageClassName") == "standard" }
    assign.notify(true)
    assign.notify(false, RuntimeError.new("conflict"))

    assert_equal 2, value("retroactive_storageclass_total")
    assert_equal 1, value("retroactive_storageclass_errors_total")
  end

  def test_volume_operation_errors
    controller = Controller::PersistentVolumeBinderController.new(host_path_deleter: ->(_path) { raise Errno::EACCES, "/tmp/x" })
    classes = [storage_class("fast", "example.csi")]
    pending = claim("new", klass: "fast")
    annotate = controller.plan(pending, persistent_volumes: [], claims: [pending], storage_classes: classes, pods: [])
      .operations.find do |operation|
      operation.object&.dig("metadata", "annotations",
                            "volume.kubernetes.io/storage-provisioner")
    end
    annotate.notify(false, RuntimeError.new("conflict"))

    assert_equal 1, value('volume_operation_errors_total{operation_name="provision",plugin_name="example.csi"}')

    released = lambda do |name, provisioner, spec|
      {"apiVersion" => "v1", "kind" => "PersistentVolume",
       "metadata" => {"name" => name, "annotations" => {"pv.kubernetes.io/provisioned-by" => provisioner}},
       "spec" => spec.merge("persistentVolumeReclaimPolicy" => "Delete", "capacity" => {"storage" => "1Gi"}, "accessModes" => ["ReadWriteOnce"],
                            "claimRef" => {"kind" => "PersistentVolumeClaim", "namespace" => "ns", "name" => "gone", "uid" => "gone-uid"}),
       "status" => {"phase" => "Released"}}
    end
    # The first sync adds the in-tree deletion finalizer; the next deletes.
    sync = lambda do |volume|
      update = controller.plan(volume, persistent_volumes: [volume], claims: [], storage_classes: [], pods: []).operations.find do |o|
        o.action == :update
      end
      volume = update.object if update
      controller.plan(volume, persistent_volumes: [volume], claims: [], storage_classes: [], pods: [])
    end
    sync.call(released.call("host", "kubernetes.io/host-path", {"hostPath" => {"path" => "/tmp/x"}}))

    assert_equal 1, value('volume_operation_errors_total{operation_name="delete",plugin_name="kubernetes.io/host-path"}')
    # An in-tree provisioner with no deleter here (and no CSI migration).
    sync.call(released.call("nfs", "kubernetes.io/nfs", {"nfs" => {"server" => "s", "path" => "/e"}}))

    assert_equal 1, value('volume_operation_errors_total{operation_name="delete",plugin_name="N/A"}')
  end

  def test_stale_sync_skips_are_not_registered
    text = @registry.render

    %w[daemonset job replicaset statefulset].each { |kind| refute_includes text, "#{kind}_controller_stale_sync_skips_total" }
    # volume_operation_total_errors: ALPHA, deprecated in 1.36.0, hidden.
    refute_includes text, "volume_operation_total_errors"
    assert_match(/^hidden_metrics_total 1$/, text)
  end
end
