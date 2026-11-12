# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# kube-controller-manager --enable-hostpath-provisioner: the in-tree hostPath
# plugin provisions a claim's volume as a directory under /tmp/hostpath_pv
# (pkg/volume/hostpath, pv_controller.go provisionClaimOperation).  Off, a
# kubernetes.io/ provisioner has no plugin, as before.
class PVHostPathProvisionerTest < Minitest::Test
  Controller = Rubernetes::Controller
  PLUGIN = "kubernetes.io/host-path"

  def storage_class(**fields)
    {"apiVersion" => "storage.k8s.io/v1", "kind" => "StorageClass", "metadata" => {"name" => "standard"}, "provisioner" => PLUGIN,
     "reclaimPolicy" => "Delete", "volumeBindingMode" => "Immediate"}.merge(fields.transform_keys(&:to_s))
  end

  def claim(**spec)
    {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim",
     "metadata" => {"name" => "data", "namespace" => "shop", "uid" => "claim-uid", "resourceVersion" => "7"},
     "spec" => {"accessModes" => ["ReadWriteOnce"], "resources" => {"requests" => {"storage" => "1Gi"}}, "storageClassName" => "standard",
                "volumeMode" => "Filesystem"}.merge(spec.transform_keys(&:to_s)),
     "status" => {"phase" => "Pending"}}
  end

  def setup
    @made = []
    @removed = []
    @controller = Controller::PersistentVolumeBinderController.new(host_path_provisioner: ->(path) { @made << path },
                                                                   host_path_deleter: ->(path) { @removed << path })
  end

  def plan(claim, volumes: [], classes: [storage_class], enabled: true)
    @controller.plan(claim, persistent_volumes: volumes, claims: [claim], storage_classes: classes, pods: [],
                            enable_hostpath_provisioner: enabled)
  end

  def created_volume(result) = result.operations.find { |operation| operation.action == :create }&.object
  def reasons(result) = result.events.map { |event| "#{event["type"]} #{event["reason"]}" }

  def test_a_claim_gets_a_directory_and_a_volume_bound_to_it
    result = plan(claim)
    volume = created_volume(result)

    assert_equal 1, @made.length
    assert_match(%r{\A/tmp/hostpath_pv/[0-9a-f-]{36}\z}, @made.first)
    assert_equal "pvc-claim-uid", volume.dig("metadata", "name")
    assert_equal({"path" => @made.first}, volume.dig("spec", "hostPath"))
    assert_equal({"storage" => "1Gi"}, volume.dig("spec", "capacity"))
    assert_equal ["ReadWriteOnce"], volume.dig("spec", "accessModes")
    assert_equal "standard", volume.dig("spec", "storageClassName")
    assert_equal({"kind" => "PersistentVolumeClaim", "namespace" => "shop", "name" => "data", "uid" => "claim-uid", "apiVersion" => "v1",
                  "resourceVersion" => "7"}, volume.dig("spec", "claimRef"))
    assert_equal({"kubernetes.io/createdby" => "hostpath-dynamic-provisioner", "pv.kubernetes.io/bound-by-controller" => "yes",
                  "pv.kubernetes.io/provisioned-by" => PLUGIN}, volume.dig("metadata", "annotations"))
    assert_equal ["kubernetes.io/pv-controller"], volume.dig("metadata", "finalizers"), "a Delete volume is protected until its directory is gone"
    assert_equal ["Normal ProvisioningSucceeded"], reasons(result)
    assert_equal "Successfully provisioned volume pvc-claim-uid using kubernetes.io/host-path", result.events.first.fetch("message")
  end

  def test_the_claim_is_marked_with_its_provisioner
    annotated = plan(claim).operations.find { |operation| operation.action == :update }.object

    assert_equal({"volume.kubernetes.io/storage-provisioner" => PLUGIN, "volume.beta.kubernetes.io/storage-provisioner" => PLUGIN},
                 annotated.dig("metadata", "annotations"))
  end

  def test_without_the_flag_the_plugin_does_not_provision
    result = plan(claim, enabled: false)

    assert_empty @made
    assert_nil created_volume(result)
    assert_equal ["Warning ProvisioningFailed"], reasons(result)
    assert_equal "no provisionable volume plugin matched", result.events.first.fetch("message")
  end

  def test_a_retained_volume_has_no_deletion_finalizer_and_a_claim_without_modes_gets_the_plugins
    volume = created_volume(plan(claim(accessModes: []), classes: [storage_class(reclaimPolicy: "Retain")]))

    assert_equal "Retain", volume.dig("spec", "persistentVolumeReclaimPolicy")
    refute volume.fetch("metadata").key?("finalizers")
    assert_equal ["ReadWriteOnce"], volume.dig("spec", "accessModes")
  end

  # Until the new volume shows up in the cache, the claim is synced again.
  def test_a_claim_whose_volume_exists_is_not_provisioned_twice
    existing = {"apiVersion" => "v1", "kind" => "PersistentVolume", "metadata" => {"name" => "pvc-claim-uid"},
                "spec" => {"capacity" => {"storage" => "1Gi"}, "accessModes" => ["ReadWriteOnce"], "storageClassName" => "other",
                           "hostPath" => {"path" => "/tmp/hostpath_pv/x"}}, "status" => {"phase" => "Pending"}}
    result = plan(claim, volumes: [existing])

    assert_empty @made
    assert_nil created_volume(result)
  end

  def test_what_the_plugin_cannot_provision_is_refused_with_upstreams_words
    block = plan(claim(volumeMode: "Block"))
    mount = plan(claim, classes: [storage_class(mountOptions: %w[noatime ro])])
    source = plan(claim(dataSource: {"kind" => "VolumeSnapshot", "name" => "s"}))

    assert_empty @made
    assert_equal 'Failed to provision volume with StorageClass "standard": kubernetes.io/host-path does not support block volume provisioning',
                 block.events.first.fetch("message")
    assert_equal 'Mount options are not supported by the provisioner but StorageClass "standard" has mount options [noatime ro]',
                 mount.events.first.fetch("message")
    assert_equal 'plugin "kubernetes.io/host-path" is not a CSI plugin. Only CSI plugin can provision a claim with a datasource',
                 source.events.first.fetch("message")
    [block, mount, source].each { |result| assert_nil created_volume(result) }
  end

  def test_a_directory_that_cannot_be_made_fails_the_claim_and_asks_the_scheduler_again
    controller = Controller::PersistentVolumeBinderController.new(host_path_provisioner: ->(_path) { raise Errno::EROFS, "/tmp" })
    waiting = claim
    waiting["metadata"]["annotations"] = {"volume.kubernetes.io/selected-node" => "worker-0"}
    result = controller.plan(waiting, persistent_volumes: [], claims: [waiting], storage_classes: [storage_class], pods: [],
                                      enable_hostpath_provisioner: true)
    rescheduled = result.operations.map(&:object).find { |object| !object.dig("metadata", "annotations").key?("volume.kubernetes.io/selected-node") }

    assert_match(/\AFailed to provision volume with StorageClass "standard": Read-only file system/, result.events.first.fetch("message"))
    refute_nil rescheduled, "the selected node is taken off the claim"
  end

  # pv_controller_base.go deleteClaim: the volume of a deleted claim is
  # synced, or it would stay Bound to a claim that is gone.
  def test_a_claim_event_also_queues_the_volume_the_claim_names
    specs = Controller::InfrastructureStorageControllerFactory.watch_specs("persistentvolume-binder-controller")
    bound = claim(volumeName: "pvc-claim-uid")
    keys = specs.select { |spec| spec.resource.kind == "PersistentVolumeClaim" && spec.route == :self }.map { |spec| spec.queue_key.call(bound) }

    assert_equal ["pvc-claim-uid"], keys
    assert_nil specs.find { |spec| spec.resource.kind == "PersistentVolumeClaim" && spec.route == :self }.queue_key.call(claim)
  end

  # The API refused the volume, or another pass had created it already.
  def test_a_volume_that_was_not_stored_leaves_no_directory
    create = plan(claim).operations.find { |operation| operation.action == :create }
    create.notify(false, RuntimeError.new("already exists"))

    assert_equal @made, @removed

    @removed.clear
    plan(claim).operations.find { |operation| operation.action == :create }.notify(true)

    assert_empty @removed
  end
end
