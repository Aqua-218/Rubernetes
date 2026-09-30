# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller/protection_publication"
require "rubernetes/schema"

class M3ProtectionPublicationControllerTest < Minitest::Test
  Controller = Rubernetes::Controller
  Support = Controller::ProtectionPublicationSupport

  def test_factory_exposes_nine_concrete_pinned_definitions
    factory = Controller::ProtectionPublicationControllerFactory

    assert_equal "v1.36.2", factory::VERSION
    assert_equal factory::NAMES.sort, factory::IMPLEMENTATIONS.keys.sort
    assert_equal "ttl-after-finished-controller", factory.metadata("ttl-after-finished-controller").fetch("name")
    assert_equal factory::NAMES.sort, factory.definitions.map(&:name).sort
    factory.definitions.each do |definition|
      refute_nil definition.implementation
      assert_operator definition.implementation, :<=, Controller::BaseController
      definition.validate!
      entry = Controller::BuiltinControllerCorpus.fetch(definition.name)

      assert_equal entry.sync_targets, definition.sync_targets
      assert_equal entry.status_fields, definition.status_fields
      assert_equal entry.events, definition.events
    end
  end

  def test_batch4_descriptors_match_pinned_catalog_and_registry_validation
    catalog = Rubernetes::Schema::Catalog.default
    corpus = Controller::BuiltinControllerCorpus

    pod_group = corpus.descriptors_for("PodGroup").first

    assert_equal ["scheduling.k8s.io", "v1alpha2", "PodGroup"], pod_group.gvk
    assert_equal ["scheduling.k8s.io", "v1alpha2", "podgroups"], pod_group.gvr
    assert catalog.find_gvk(group: pod_group.group, version: pod_group.version, kind: pod_group.kind)
    refute catalog.find_gvk("scheduling.k8s.io/v1/PodGroup")
    assert_equal ["GenericWorkload"], corpus.fetch("podgroup-protection-controller").feature_gates

    trust_bundles = corpus.descriptors_for("ClusterTrustBundle")

    assert_equal %w[v1beta1 v1alpha1], trust_bundles.map(&:version)
    trust_bundles.each do |descriptor|
      assert catalog.find_gvk(group: descriptor.group, version: descriptor.version, kind: descriptor.kind)
    end
    refute catalog.find_gvk("certificates.k8s.io/v1/ClusterTrustBundle")
    assert_includes corpus.fetch("kube-apiserver-serving-clustertrustbundle-publisher-controller").startup_conditions,
                    "ClusterTrustBundle API served"

    registry = Controller::ControllerRegistry.new(schema_registry: catalog)
    Controller::ProtectionPublicationControllerFactory.register!(registry)

    pod_group_definition = registry.fetch("podgroup-protection-controller")

    assert_equal pod_group.gvk, pod_group_definition.kind.gvk
    trust_bundle_definition = registry.fetch("kube-apiserver-serving-clustertrustbundle-publisher-controller")

    assert_equal trust_bundles.first.gvk, trust_bundle_definition.kind.gvk
  end

  def test_pvc_protection_adds_finalizer_and_removes_only_after_safe_usage_snapshot
    pvc = pvc_object("claim")
    added = Controller::PersistentVolumeClaimProtectionController.new.plan(pvc)

    assert_equal [:update], added.operations.map(&:action)
    assert_equal [Support::PVC_PROTECTION_FINALIZER], added.updates.first.object.dig("metadata", "finalizers")

    deleting = pvc.merge("metadata" => pvc.fetch("metadata").merge(
      "deletionTimestamp" => "2026-01-01T00:00:00Z",
      "finalizers" => [Support::PVC_PROTECTION_FINALIZER]
    ))
    pod = pod_object("consumer", node_name: "node-a",
                                 volumes: [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "claim"}}])
    controller = Controller::PersistentVolumeClaimProtectionController.new

    assert_empty controller.plan(deleting, pods: [pod]).operations
    assert_empty controller.plan(deleting).operations
    removed = controller.plan(deleting, pods: [])

    assert_equal [], removed.updates.first.object.dig("metadata", "finalizers")
    assert_empty controller.plan(removed.updates.first.object, pods: []).operations
  end

  def test_pvc_protection_matches_owned_ephemeral_pvcs_and_allows_shutdown_pods
    pod = pod_object("consumer", node_name: "node-a", volumes: [{"name" => "scratch", "ephemeral" => {}}])
    pvc = pvc_object("consumer-scratch").merge(
      "metadata" => pvc_object("consumer-scratch").fetch("metadata").merge(
        "ownerReferences" => [Controller::Support.owner_reference(pod)]
      )
    )
    deleting = pvc.merge("metadata" => pvc.fetch("metadata").merge(
      "deletionTimestamp" => "2026-01-01T00:00:00Z",
      "finalizers" => [Support::PVC_PROTECTION_FINALIZER]
    ))
    controller = Controller::PersistentVolumeClaimProtectionController.new

    assert_empty controller.plan(deleting, pods: [pod]).operations

    shutdown = pod.merge("metadata" => pod.fetch("metadata").merge(
      "deletionTimestamp" => "2026-01-01T00:00:00Z",
      "deletionGracePeriodSeconds" => 0
    ))

    assert_equal :update, controller.plan(deleting, pods: [shutdown]).operations.first.action
  end

  def test_pv_and_vac_protection_apply_finalizers_and_block_used_deletes
    pv = pv_object("volume", phase: "Available")
    pv_controller = Controller::PersistentVolumeProtectionController.new

    assert_equal [Support::PV_PROTECTION_FINALIZER], pv_controller.plan(pv).updates.first.object.dig("metadata", "finalizers")
    deleting_pv = pv.merge("metadata" => pv.fetch("metadata").merge(
      "deletionTimestamp" => "2026-01-01T00:00:00Z",
      "finalizers" => [Support::PV_PROTECTION_FINALIZER]
    ))

    assert_equal :update, pv_controller.plan(deleting_pv).operations.first.action
    bound_pv = deleting_pv.merge("status" => {"phase" => "Bound"})

    assert_empty pv_controller.plan(bound_pv).operations

    vac = vac_object("fast")
    vac_controller = Controller::VolumeAttributesClassProtectionController.new

    assert_equal [Support::VAC_PROTECTION_FINALIZER], vac_controller.plan(vac).updates.first.object.dig("metadata", "finalizers")
    deleting_vac = vac.merge("metadata" => vac.fetch("metadata").merge(
      "deletionTimestamp" => "2026-01-01T00:00:00Z",
      "finalizers" => [Support::VAC_PROTECTION_FINALIZER]
    ))
    used_pvc = pvc_object("claim").merge("spec" => {"volumeAttributesClassName" => "fast"})

    assert_empty vac_controller.plan(deleting_vac, pvs: [], pvcs: [used_pvc]).operations
    removed = vac_controller.plan(deleting_vac, pvs: [], pvcs: [])

    assert_equal [], removed.updates.first.object.dig("metadata", "finalizers")
  end

  def test_podgroup_protection_removes_admission_finalizer_only_when_no_active_pods_remain
    pod_group = pod_group_object("batch")
    deleting = pod_group.merge("metadata" => pod_group.fetch("metadata").merge(
      "deletionTimestamp" => "2026-01-01T00:00:00Z",
      "finalizers" => [Support::POD_GROUP_PROTECTION_FINALIZER]
    ))
    active = pod_object("active", volumes: []).merge(
      "spec" => {"schedulingGroup" => {"podGroupName" => "batch"}},
      "status" => {"phase" => "Running"}
    )
    terminal = active.merge("status" => {"phase" => "Succeeded"})
    controller = Controller::PodGroupProtectionController.new

    assert_empty controller.plan(deleting, pods: [active]).operations
    assert_equal :update, controller.plan(deleting, pods: [terminal]).operations.first.action
    refute_predicate controller.plan(pod_group), :changed?
  end

  def test_ttl_after_finished_rechecks_fresh_uid_and_is_idempotent
    now = Time.utc(2026, 1, 1)
    job = job_object(ttl: 10, finished_at: now - 20)
    controller = Controller::TTLAfterFinishedController.new

    assert_equal :delete, controller.plan(job, now: now).operations.first.action
    changed = job.merge("spec" => {"ttlSecondsAfterFinished" => 100})

    assert_empty controller.plan(job, fresh: changed, now: now).operations
    active = job.merge("status" => {})

    assert_empty controller.plan(active, now: now).operations
    assert_empty controller.plan(job, now: now - 25).operations
  end

  def test_root_ca_publisher_creates_repairs_and_replays_configmaps
    namespace = namespace_object("team-a")
    controller = Controller::RootCACertificatePublisherController.new(root_ca: "CA-1")
    first = controller.plan(namespace, namespaces: [namespace], config_maps: [])
    create = first.creates.first

    assert_equal Support::ROOT_CA_CONFIG_MAP_NAME, create.object.dig("metadata", "name")
    assert_equal "CA-1", create.object.dig("data", "ca.crt")
    assert_equal Support::ROOT_CA_DESCRIPTION, create.object.dig("metadata", "annotations", Support::ROOT_CA_DESCRIPTION_ANNOTATION)
    assert_empty controller.plan(namespace, namespaces: [namespace], config_maps: [create.object]).operations

    stale = create.object.merge("data" => {"ca.crt" => "old"},
                                "metadata" => create.object.fetch("metadata").merge("annotations" => {}))
    repaired = controller.plan(namespace, namespaces: [namespace], config_maps: [stale])

    assert_equal :update, repaired.operations.first.action
    terminating = namespace.merge("metadata" => namespace.fetch("metadata").merge("deletionTimestamp" => "now"))

    assert_empty controller.plan(terminating, namespaces: [terminating], config_maps: []).operations
  end

  def test_cluster_trust_bundle_publisher_uses_pinned_name_and_removes_stale_signer_bundles
    controller = Controller::KubeAPIServerServingClusterTrustBundlePublisherController.new(ca_bundle: "CA")
    expected_name = Controller::KubeAPIServerServingClusterTrustBundlePublisherController.construct_bundle_name(
      Support::CLUSTER_TRUST_BUNDLE_SIGNER, "CA"
    )
    stale = cluster_trust_bundle("stale", signer: Support::CLUSTER_TRUST_BUNDLE_SIGNER, trust_bundle: "old")
    first = controller.plan(nil, trust_bundles: [stale])

    assert_equal %i[create delete], first.operations.map(&:action)
    assert_equal expected_name, first.creates.first.object.dig("metadata", "name")
    assert_equal "CA", first.creates.first.object.dig("spec", "trustBundle")
    current = first.creates.first.object

    assert_empty controller.plan(current, trust_bundles: [current], ca_bundle: "CA").operations
  end

  def test_ephemeral_volume_controller_creates_owned_pvcs_and_rejects_name_reuse
    pod = pod_object("worker", volumes: [{
                       "name" => "scratch",
                       "ephemeral" => {"volumeClaimTemplate" => {
                         "metadata" => {"labels" => {"purpose" => "scratch"}},
                         "spec" => {"accessModes" => ["ReadWriteOnce"]}
                       }}
                     }])
    controller = Controller::EphemeralVolumeController.new
    first = controller.plan(pod, pvcs: [])
    pvc = first.creates.first.object

    assert_equal "worker-scratch", pvc.dig("metadata", "name")
    assert_equal "worker", pvc.dig("metadata", "ownerReferences", 0, "name")
    assert_equal "worker-uid", pvc.dig("metadata", "ownerReferences", 0, "uid")
    assert_empty controller.plan(pod, pvcs: [pvc]).operations
    assert_raises(Controller::StoreError) do
      controller.plan(pod, pvcs: [pvc.merge("metadata" => pvc.fetch("metadata").merge(
        "ownerReferences" => [Controller::Support.owner_reference(pod.merge("metadata" => {"name" => "other", "uid" => "other-uid", "namespace" => "default"}))]
      ))])
    end
    deleting = pod.merge("metadata" => pod.fetch("metadata").merge("deletionTimestamp" => "now"))

    assert_empty controller.plan(deleting, pvcs: []).operations
  end

  def test_storage_version_gc_prunes_invalid_leases_deletes_empty_objects_and_replays
    storage_version = storage_version_object("pods", [
                                               {"apiServerID" => "live", "encodingVersion" => "v1"},
                                               {"apiServerID" => "dead", "encodingVersion" => "v1"}
                                             ])
    live = lease_object("live", identity: true)
    controller = Controller::StorageVersionGarbageCollectorController.new(clock: -> { Time.utc(2026, 1, 1) })
    first = controller.plan(storage_version, leases: [live], now: Time.utc(2026, 1, 1))

    assert_equal :status_update, first.operations.first.action
    assert_equal(["live"], first.operations.first.patch.fetch("storageVersions").map { |entry| entry.fetch("apiServerID") })
    persisted = storage_version.merge("status" => first.operations.first.patch)

    assert_empty controller.plan(persisted, leases: [live], now: Time.utc(2026, 1, 1)).operations

    only_dead = storage_version_object("pods", [{"apiServerID" => "dead", "encodingVersion" => "v1"}])

    assert_equal :delete, controller.plan(only_dead, leases: [live]).operations.first.action
    removed_by_lease = controller.plan(storage_version, deleted_lease: "dead")

    assert_equal :status_update, removed_by_lease.operations.first.action
  end

  private

  def pvc_object(name)
    {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim",
     "metadata" => {"name" => name, "namespace" => "default", "uid" => "#{name}-uid"},
     "spec" => {}, "status" => {}}
  end

  def pv_object(name, phase: "Available")
    {"apiVersion" => "v1", "kind" => "PersistentVolume",
     "metadata" => {"name" => name, "uid" => "#{name}-uid"}, "spec" => {},
     "status" => {"phase" => phase}}
  end

  def vac_object(name)
    {"apiVersion" => "storage.k8s.io/v1", "kind" => "VolumeAttributesClass",
     "metadata" => {"name" => name, "uid" => "#{name}-uid"}, "spec" => {}, "status" => {}}
  end

  def pod_group_object(name)
    {"apiVersion" => "scheduling.k8s.io/v1alpha2", "kind" => "PodGroup",
     "metadata" => {"name" => name, "namespace" => "default", "uid" => "#{name}-uid"},
     "spec" => {}, "status" => {}}
  end

  def pod_object(name, node_name: nil, volumes: [])
    spec = {"volumes" => volumes}
    spec["nodeName"] = node_name if node_name
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "default", "uid" => "#{name}-uid"},
     "spec" => spec, "status" => {"phase" => "Running"}}
  end

  def job_object(ttl:, finished_at:)
    {"apiVersion" => "batch/v1", "kind" => "Job",
     "metadata" => {"name" => "job", "namespace" => "default", "uid" => "job-uid"},
     "spec" => {"ttlSecondsAfterFinished" => ttl},
     "status" => {"conditions" => [{"type" => "Complete", "status" => "True",
                                    "lastTransitionTime" => finished_at.iso8601}]}}
  end

  def namespace_object(name)
    {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => name, "uid" => "#{name}-uid"},
     "status" => {"phase" => "Active"}}
  end

  def cluster_trust_bundle(name, signer:, trust_bundle:)
    {"apiVersion" => "certificates.k8s.io/v1beta1", "kind" => "ClusterTrustBundle",
     "metadata" => {"name" => name}, "spec" => {"signerName" => signer, "trustBundle" => trust_bundle}}
  end

  def storage_version_object(name, entries)
    {"apiVersion" => "internal.apiserver.k8s.io/v1alpha1", "kind" => "StorageVersion",
     "metadata" => {"name" => name, "uid" => "#{name}-uid"}, "status" => {"storageVersions" => entries}}
  end

  def lease_object(name, identity: false)
    labels = identity ? {Support::IDENTITY_LEASE_LABEL => Support::KUBE_APISERVER_IDENTITY} : {}
    {"apiVersion" => "coordination.k8s.io/v1", "kind" => "Lease",
     "metadata" => {"name" => name, "namespace" => Support::KUBE_SYSTEM_NAMESPACE, "labels" => labels}}
  end
end
