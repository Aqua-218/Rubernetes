# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "tmpdir"

# pkg/controller/volume/persistentvolume/binder_test.go (v1.36.2): each case
# runs one syncClaim or syncVolume, applies the writes it plans the way the
# fake client does, and compares volumes, claims and event reasons with the
# upstream table.  Plus the reclaim (delete_test / recycle_test) and
# provisioning (provision_test) paths this controller performs itself.
class PVBinderUpstreamTest < Minitest::Test
  Controller = Rubernetes::Controller
  NS = "default"
  WAIT = "wait"

  def volume(name, capacity, claim_uid, claim_name, phase, policy = "Retain", storage_class = "", *annotations,
             source: {"csi" => {"driver" => "d", "volumeHandle" => name}})
    spec = {"capacity" => {"storage" => capacity}, "accessModes" => %w[ReadWriteOnce ReadOnlyMany], "persistentVolumeReclaimPolicy" => policy,
            "storageClassName" => storage_class, "volumeMode" => "Filesystem"}.merge(source)
    unless claim_name.empty?
      spec["claimRef"] =
        {"kind" => "PersistentVolumeClaim", "apiVersion" => "v1", "uid" => claim_uid, "namespace" => NS, "name" => claim_name}
    end
    object = {"apiVersion" => "v1", "kind" => "PersistentVolume", "metadata" => {"name" => name, "resourceVersion" => "1"},
              "spec" => spec, "status" => {"phase" => phase}}
    object["metadata"]["annotations"] = annotations.to_h { |key| [key, "yes"] } unless annotations.empty?
    object
  end

  def claim(name, uid, capacity, volume_name, phase, storage_class = nil, *annotations)
    spec = {"accessModes" => %w[ReadWriteOnce ReadOnlyMany], "resources" => {"requests" => {"storage" => capacity}},
            "volumeMode" => "Filesystem"}
    spec["volumeName"] = volume_name unless volume_name.empty?
    spec["storageClassName"] = storage_class unless storage_class.nil?
    object = {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim",
              "metadata" => {"name" => name, "namespace" => NS, "uid" => uid, "resourceVersion" => "1"}, "spec" => spec,
              "status" => {"phase" => phase}}
    object["metadata"]["annotations"] = annotations.to_h { |key| [key, "yes"] } unless annotations.empty?
    if phase == "Bound"
      object["status"]["accessModes"] = spec["accessModes"]
      object["status"]["capacity"] = {"storage" => capacity}
    end
    object
  end

  BOUND_BY = "pv.kubernetes.io/bound-by-controller"
  COMPLETED = "pv.kubernetes.io/bind-completed"

  # The store the operations are applied to.
  class Store
    attr_reader :objects

    def initialize(objects) = @objects = objects.map { |object| Marshal.load(Marshal.dump(object)) }

    def find(kind, name, namespace = nil)
      @objects.find do |object|
        object["kind"] == kind && object.dig("metadata",
                                             "name") == name && (namespace.nil? || object.dig("metadata", "namespace") == namespace)
      end
    end

    def apply(operation)
      kind = operation.resource.kind
      name = operation.object.dig("metadata", "name")
      namespace = operation.object.dig("metadata", "namespace")
      current = find(kind, name, namespace)
      case operation.action
      when :update
        replacement = Marshal.load(Marshal.dump(operation.object))
        replacement["status"] = current["status"] if current
        @objects[@objects.index(current)] = replacement
      when :status_update
        current["status"] = Marshal.load(Marshal.dump(operation.patch))
      when :create then @objects << Marshal.load(Marshal.dump(operation.object))
      when :delete then @objects.delete(current)
      end
    end
  end

  def sync(target_kind, name, volumes:, claims:, classes: [], pods: [], controller: Controller::PersistentVolumeBinderController.new)
    store = Store.new(volumes + claims + classes + pods)
    target = store.find(target_kind, name)
    result = controller.plan(target, persistent_volumes: store.objects.select { |o| o["kind"] == "PersistentVolume" },
                                     claims: store.objects.select { |o| o["kind"] == "PersistentVolumeClaim" },
                                     storage_classes: classes, pods: pods)
    result.operations.each { |operation| store.apply(operation) }
    [store, result]
  end

  def normalize(object)
    object = Marshal.load(Marshal.dump(object))
    object["metadata"].delete("resourceVersion")
    object.dig("spec", "claimRef")&.delete("resourceVersion")
    object
  end

  def assert_state(store, volumes, claims, result, events)
    assert_equal(volumes.map { |v| normalize(v) }, store.objects.select { |o| o["kind"] == "PersistentVolume" }.map { |v| normalize(v) })
    assert_equal(claims.map { |c| normalize(c) }, store.objects.select do |o|
      o["kind"] == "PersistentVolumeClaim"
    end.map { |c| normalize(c) })
    assert_equal(events, result.events.map { |event| "#{event["type"]} #{event["reason"]}" })
  end

  def test_1_1_successful_bind
    store, result = sync("PersistentVolumeClaim", "claim1-1", volumes: [volume("volume1-1", "1Gi", "", "", "Available")],
                                                              claims: [claim("claim1-1", "uid1-1", "1Gi", "", "Pending")])

    assert_state(store, [volume("volume1-1", "1Gi", "uid1-1", "claim1-1", "Bound", "Retain", "", BOUND_BY)],
                 [claim("claim1-1", "uid1-1", "1Gi", "volume1-1", "Bound", nil, BOUND_BY, COMPLETED)], result, [])
  end

  def test_1_2_noop_and_1_3_reset_to_pending
    store, result = sync("PersistentVolumeClaim", "claim1-2", volumes: [volume("volume1-2", "1Gi", "", "", "Available")],
                                                              claims: [claim("claim1-2", "uid1-2", "10Gi", "", "Pending")])

    assert_state(store, [volume("volume1-2", "1Gi", "", "", "Available")], [claim("claim1-2", "uid1-2", "10Gi", "", "Pending")], result,
                 ["Normal FailedBinding"])
    store, result = sync("PersistentVolumeClaim", "claim1-3", volumes: [volume("volume1-3", "1Gi", "", "", "Available")],
                                                              claims: [claim("claim1-3", "uid1-3", "10Gi", "", "Bound")])

    assert_state(store, [volume("volume1-3", "1Gi", "", "", "Available")], [claim("claim1-3", "uid1-3", "10Gi", "", "Pending")], result,
                 ["Normal FailedBinding"])
  end

  def test_1_4_smallest_volume
    store, result = sync("PersistentVolumeClaim", "claim1-4",
                         volumes: [volume("volume1-4_1", "10Gi", "", "", "Available"), volume("volume1-4_2", "1Gi", "", "", "Available")],
                         claims: [claim("claim1-4", "uid1-4", "1Gi", "", "Pending")])

    assert_state(store, [volume("volume1-4_1", "10Gi", "", "", "Available"),
                         volume("volume1-4_2", "1Gi", "uid1-4", "claim1-4", "Bound", "Retain", "", BOUND_BY)],
                 [claim("claim1-4", "uid1-4", "1Gi", "volume1-4_2", "Bound", nil, BOUND_BY, COMPLETED)], result, [])
  end

  def test_1_5_and_1_6_prebound_volumes
    store, result = sync("PersistentVolumeClaim", "claim1-5",
                         volumes: [volume("volume1-5_1", "10Gi", "", "claim1-5", "Available"), volume("volume1-5_2", "1Gi", "", "", "Available")],
                         claims: [claim("claim1-5", "uid1-5", "1Gi", "", "Pending")])
    expected = claim("claim1-5", "uid1-5", "1Gi", "volume1-5_1", "Bound", nil, BOUND_BY, COMPLETED)
    expected["status"]["capacity"] = {"storage" => "10Gi"}

    assert_state(store, [volume("volume1-5_1", "10Gi", "uid1-5", "claim1-5", "Bound"), volume("volume1-5_2", "1Gi", "", "", "Available")],
                 [expected], result, [])

    store, = sync("PersistentVolumeClaim", "claim1-6",
                  volumes: [volume("volume1-6_1", "10Gi", "uid1-6", "claim1-6", "Available"), volume("volume1-6_2", "1Gi", "", "", "Available")],
                  claims: [claim("claim1-6", "uid1-6", "1Gi", "", "Pending")])

    assert_equal "Bound", store.find("PersistentVolume", "volume1-6_1").dig("status", "phase")
    refute store.find("PersistentVolume", "volume1-6_1").dig("metadata", "annotations"), "a user's pre-binding is not controller-bound"
  end

  def test_1_7_prebound_to_a_different_claim
    store, result = sync("PersistentVolumeClaim", "claim1-7", volumes: [volume("volume1-7", "10Gi", "uid1-777", "claim1-7", "Available")],
                                                              claims: [claim("claim1-7", "uid1-7", "1Gi", "", "Pending")])

    assert_state(store, [volume("volume1-7", "10Gi", "uid1-777", "claim1-7", "Available")], [claim("claim1-7", "uid1-7", "1Gi", "", "Pending")],
                 result, ["Normal FailedBinding"])
  end

  def test_1_8_and_1_10_complete_a_bind_after_a_crash
    store, result = sync("PersistentVolumeClaim", "claim1-8",
                         volumes: [volume("volume1-8", "1Gi", "uid1-8", "claim1-8", "Available", "Retain", "", BOUND_BY)],
                         claims: [claim("claim1-8", "uid1-8", "1Gi", "", "Pending")])

    assert_state(store, [volume("volume1-8", "1Gi", "uid1-8", "claim1-8", "Bound", "Retain", "", BOUND_BY)],
                 [claim("claim1-8", "uid1-8", "1Gi", "volume1-8", "Bound", nil, BOUND_BY, COMPLETED)], result, [])
    store, result = sync("PersistentVolumeClaim", "claim1-10",
                         volumes: [volume("volume1-10", "1Gi", "uid1-10", "claim1-10", "Bound", "Retain", "", BOUND_BY)],
                         claims: [claim("claim1-10", "uid1-10", "1Gi", "volume1-10", "Pending", nil, BOUND_BY, COMPLETED)])

    assert_state(store, [volume("volume1-10", "1Gi", "uid1-10", "claim1-10", "Bound", "Retain", "", BOUND_BY)],
                 [claim("claim1-10", "uid1-10", "1Gi", "volume1-10", "Bound", nil, BOUND_BY, COMPLETED)], result, [])
  end

  def test_1_12_selector_mismatch_and_1_13_delayed_binding
    selecting = claim("claim1-1", "uid1-1", "1Gi", "", "Pending")
    selecting["spec"]["selector"] = {"matchLabels" => {"foo" => "true"}}
    _, result = sync("PersistentVolumeClaim", "claim1-1", volumes: [volume("volume1-1", "1Gi", "", "", "Available")], claims: [selecting])

    assert_equal(["Normal FailedBinding"], result.events.map { |event| "#{event["type"]} #{event["reason"]}" })

    wait = {"apiVersion" => "storage.k8s.io/v1", "kind" => "StorageClass", "metadata" => {"name" => WAIT}, "provisioner" => "kubernetes.io/no-provisioner",
            "volumeBindingMode" => "WaitForFirstConsumer"}
    store, result = sync("PersistentVolumeClaim", "claim1-1", volumes: [volume("volume1-1", "1Gi", "", "", "Available", "Retain", WAIT)],
                                                              claims: [claim("claim1-1", "uid1-1", "1Gi", "", "Pending", WAIT)], classes: [wait])

    assert_state(store, [volume("volume1-1", "1Gi", "", "", "Available", "Retain", WAIT)], [claim("claim1-1", "uid1-1", "1Gi", "", "Pending", WAIT)],
                 result, ["Normal WaitForFirstConsumer"])
    assert_equal "waiting for first consumer to be created before binding", result.events.first["message"]

    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "consumer", "namespace" => NS},
           "spec" => {"volumes" => [{"name" => "v", "persistentVolumeClaim" => {"claimName" => "claim1-1"}}]}, "status" => {"phase" => "Pending"}}
    _, result = sync("PersistentVolumeClaim", "claim1-1", volumes: [], claims: [claim("claim1-1", "uid1-1", "1Gi", "", "Pending", WAIT)],
                                                          classes: [wait], pods: [pod])

    assert_equal([["WaitForPodScheduled", "waiting for pod consumer to be scheduled"]], result.events.map do |e|
      e.values_at("reason", "message")
    end)
  end

  def test_2_x_claims_prebound_to_volumes
    store, result = sync("PersistentVolumeClaim", "claim2-1", volumes: [],
                                                              claims: [claim("claim2-1", "uid2-1", "10Gi", "volume2-1", "Pending")])

    assert_state(store, [], [claim("claim2-1", "uid2-1", "10Gi", "volume2-1", "Pending")], result, [])
    assert_empty result.operations

    store, result = sync("PersistentVolumeClaim", "claim2-2", volumes: [],
                                                              claims: [claim("claim2-2", "uid2-2", "10Gi", "volume2-2", "Bound")])

    assert_state(store, [], [claim("claim2-2", "uid2-2", "10Gi", "volume2-2", "Pending")], result, [])

    store, result = sync("PersistentVolumeClaim", "claim2-3", volumes: [volume("volume2-3", "1Gi", "", "", "Available")],
                                                              claims: [claim("claim2-3", "uid2-3", "1Gi", "volume2-3", "Pending")])

    assert_state(store, [volume("volume2-3", "1Gi", "uid2-3", "claim2-3", "Bound", "Retain", "", BOUND_BY)],
                 [claim("claim2-3", "uid2-3", "1Gi", "volume2-3", "Bound", nil, COMPLETED)], result, [])

    store, result = sync("PersistentVolumeClaim", "claim2-6", volumes: [volume("volume2-6", "1Gi", "uid2-6_1", "claim2-6_1", "Bound")],
                                                              claims: [claim("claim2-6", "uid2-6", "1Gi", "volume2-6", "Bound")])

    assert_state(store, [volume("volume2-6", "1Gi", "uid2-6_1", "claim2-6_1", "Bound")], [claim("claim2-6", "uid2-6", "1Gi", "volume2-6", "Pending")],
                 result, ["Warning FailedBinding"])

    store, result = sync("PersistentVolumeClaim", "claim2-7", volumes: [volume("volume2-7", "1Gi", "uid2-7_1", "claim2-7_1", "Bound")],
                                                              claims: [claim("claim2-7", "uid2-7", "1Gi", "volume2-7", "Bound", nil, BOUND_BY)])

    assert_state(store, [volume("volume2-7", "1Gi", "uid2-7_1", "claim2-7_1", "Bound")],
                 [claim("claim2-7", "uid2-7", "1Gi", "volume2-7", "Bound", nil, BOUND_BY)], result, ["Warning FailedBinding"])
    assert result.requeue_after, "testSyncClaimError: retried"

    store, result = sync("PersistentVolumeClaim", "claim2-9", volumes: [volume("volume2-9", "1Gi", "", "", "Available")],
                                                              claims: [claim("claim2-9", "uid2-9", "2Gi", "volume2-9", "Bound")])

    assert_state(store, [volume("volume2-9", "1Gi", "", "", "Available")], [claim("claim2-9", "uid2-9", "2Gi", "volume2-9", "Pending")], result,
                 ["Warning VolumeMismatch"])
    assert_equal "Cannot bind to requested volume \"volume2-9\": requested PV is too small", result.events.first["message"]
  end

  def test_3_x_bound_claims
    store, result = sync("PersistentVolumeClaim", "claim3-1", volumes: [],
                                                              claims: [claim("claim3-1", "uid3-1", "10Gi", "", "Bound", nil, BOUND_BY, COMPLETED)])
    lost = claim("claim3-1", "uid3-1", "10Gi", "", "Lost", nil, BOUND_BY, COMPLETED)
    lost["status"] = {"phase" => "Lost"}

    assert_state(store, [], [lost], result, ["Warning ClaimLost"])

    store, result = sync("PersistentVolumeClaim", "claim3-3", volumes: [volume("volume3-3", "10Gi", "", "", "Available")],
                                                              claims: [claim("claim3-3", "uid3-3", "10Gi", "volume3-3", "Pending", nil, BOUND_BY, COMPLETED)])

    assert_state(store, [volume("volume3-3", "10Gi", "uid3-3", "claim3-3", "Bound", "Retain", "", BOUND_BY)],
                 [claim("claim3-3", "uid3-3", "10Gi", "volume3-3", "Bound", nil, BOUND_BY, COMPLETED)], result, [])

    store, result = sync("PersistentVolumeClaim", "claim3-6", volumes: [volume("volume3-6", "10Gi", "uid3-6-x", "claim3-6-x", "Available")],
                                                              claims: [claim("claim3-6", "uid3-6", "10Gi", "volume3-6", "Pending", nil, COMPLETED)])
    misbound = claim("claim3-6", "uid3-6", "10Gi", "volume3-6", "Lost", nil, COMPLETED)
    misbound["status"] = {"phase" => "Lost"}

    assert_state(store, [volume("volume3-6", "10Gi", "uid3-6-x", "claim3-6-x", "Available")], [misbound], result, ["Warning ClaimMisbound"])
  end

  def test_4_x_volumes
    store, = sync("PersistentVolume", "volume4-1", volumes: [volume("volume4-1", "10Gi", "", "", "Available")], claims: [])

    assert_equal "Available", store.find("PersistentVolume", "volume4-1").dig("status", "phase")

    store, = sync("PersistentVolume", "volume4-3", volumes: [volume("volume4-3", "10Gi", "uid4-3", "claim4-3", "Bound")], claims: [])

    assert_equal "Released", store.find("PersistentVolume", "volume4-3").dig("status", "phase")

    store, = sync("PersistentVolume", "volume4-4", volumes: [volume("volume4-4", "10Gi", "uid4-4", "claim4-4", "Bound")],
                                                   claims: [claim("claim4-4", "uid4-4-x", "10Gi", "volume4-4", "Bound", nil, COMPLETED)])

    assert_equal "Released", store.find("PersistentVolume", "volume4-4").dig("status", "phase")

    store, result = sync("PersistentVolume", "volume4-5", volumes: [volume("volume4-5", "10Gi", "uid4-5", "claim4-5", "Bound", "Retain", "", BOUND_BY)],
                                                          claims: [claim("claim4-5", "uid4-5", "10Gi", "", "Pending")])

    assert_empty result.operations, "the claim's own sync binds it"
    _ = store

    store, = sync("PersistentVolume", "volume4-7", volumes: [volume("volume4-7", "10Gi", "uid4-7", "claim4-7", "Bound", "Retain", "", BOUND_BY)],
                                                   claims: [claim("claim4-7", "uid4-7", "10Gi", "volume4-7-x", "Bound")])

    assert_equal normalize(volume("volume4-7", "10Gi", "", "", "Available")), normalize(store.find("PersistentVolume", "volume4-7"))

    store, = sync("PersistentVolume", "volume4-8", volumes: [volume("volume4-8", "10Gi", "uid4-8", "claim4-8", "Bound")],
                                                   claims: [claim("claim4-8", "uid4-8", "10Gi", "volume4-8-x", "Bound")])

    assert_equal normalize(volume("volume4-8", "10Gi", "", "claim4-8", "Available")), normalize(store.find("PersistentVolume", "volume4-8"))

    store, = sync("PersistentVolume", "volume4-9", volumes: [volume("volume4-9", "10Gi", "uid4-9", "claim4-9", "Available", "Delete")],
                                                   claims: [claim("claim4-9", "uid4-9", "10Gi", "volume4-9", "Bound")])

    assert_equal "Bound", store.find("PersistentVolume", "volume4-9").dig("status", "phase")
  end

  def test_released_volumes_are_reclaimed
    deleted = []
    controller = Controller::PersistentVolumeBinderController.new(host_path_deleter: ->(path) { deleted << path })
    host = {"hostPath" => {"path" => "/tmp/data-1"}}
    store, = sync("PersistentVolume", "hp", volumes: [volume("hp", "1Gi", "uid", "gone", "Bound", "Delete", source: host)], claims: [],
                                            controller: controller)

    assert_nil store.find("PersistentVolume", "hp"), "a released hostPath volume is deleted"
    assert_equal ["/tmp/data-1"], deleted

    store, result = sync("PersistentVolume", "csi", volumes: [volume("csi", "1Gi", "uid", "gone", "Bound", "Delete")], claims: [])

    assert_equal "Released", store.find("PersistentVolume", "csi").dig("status", "phase"), "a CSI volume is the provisioner's to delete"
    assert_empty result.events

    local = {"local" => {"path" => "/mnt/disk"}}
    store, result = sync("PersistentVolume", "local", volumes: [volume("local", "1Gi", "uid", "gone", "Bound", "Delete", source: local)],
                                                      claims: [])

    assert_equal "Failed", store.find("PersistentVolume", "local").dig("status", "phase")
    assert_equal([["VolumeFailedDelete", "error getting deleter volume plugin for volume \"local\": no deletable volume plugin matched"]],
                 result.events.map { |event| event.values_at("reason", "message") })

    real = Controller::PersistentVolumeBinderController.new
    unsafe = {"hostPath" => {"path" => "/var/lib/data"}}
    store, result = sync("PersistentVolume", "unsafe", volumes: [volume("unsafe", "1Gi", "uid", "gone", "Bound", "Delete", source: unsafe)],
                                                       claims: [], controller: real)

    assert_equal "Failed", store.find("PersistentVolume", "unsafe").dig("status", "phase")
    assert_equal "host_path deleter only supports /tmp/.+ but received provided /var/lib/data", result.events.first["message"]

    store, result = sync("PersistentVolume", "odd", volumes: [volume("odd", "1Gi", "uid", "gone", "Bound", "Bogus")], claims: [])

    assert_equal(["VolumeUnknownReclaimPolicy"], result.events.map { |event| event["reason"] })
    assert_equal "Failed", store.find("PersistentVolume", "odd").dig("status", "phase")
  end

  def test_external_provisioning_and_the_default_class
    fast = {"apiVersion" => "storage.k8s.io/v1", "kind" => "StorageClass", "metadata" => {"name" => "fast"}, "provisioner" => "csi.example.com",
            "volumeBindingMode" => "Immediate"}
    store, result = sync("PersistentVolumeClaim", "c", volumes: [], claims: [claim("c", "u", "1Gi", "", "Pending", "fast")],
                                                       classes: [fast])
    annotations = store.find("PersistentVolumeClaim", "c").dig("metadata", "annotations")

    assert_equal({"volume.kubernetes.io/storage-provisioner" => "csi.example.com",
                  "volume.beta.kubernetes.io/storage-provisioner" => "csi.example.com"}, annotations)
    assert_equal(["ExternalProvisioning"], result.events.map { |event| event["reason"] })

    default = fast.merge("metadata" => {"name" => "fast", "annotations" => {"storageclass.kubernetes.io/is-default-class" => "true"}})
    store, result = sync("PersistentVolumeClaim", "c", volumes: [], claims: [claim("c", "u", "1Gi", "", "Pending")], classes: [default])

    assert_equal "fast", store.find("PersistentVolumeClaim", "c").dig("spec", "storageClassName"), "retroactive default class"
    assert_empty result.events
  end

  def test_a_recycled_volume_uses_a_recycler_pod
    host = {"hostPath" => {"path" => "/data"}}
    released = volume("rv", "2Gi", "uid", "gone", "Released", "Recycle", source: host)
    adapter = Class.new(Controller::StoreAdapter) do
      attr_accessor :pod

      def initialize = super({})
      def find(descriptor, name:, namespace: nil) = descriptor.kind == "Pod" ? pod : nil
      def list(*) = []
    end.new
    controller = Controller::PersistentVolumeBinderController.new
    result = controller.plan(released, store: adapter, persistent_volumes: [released], claims: [], storage_classes: [], pods: [])
    create = result.operations.find { |operation| operation.action == :create }

    assert_equal "recycler-for-rv", create.object.dig("metadata", "name")
    assert_equal({"name" => "vol", "hostPath" => {"path" => "/data"}}, create.object.dig("spec", "volumes", 0))
    assert_equal 60, create.object.dig("spec", "activeDeadlineSeconds")

    adapter.pod = create.object.merge("status" => {"phase" => "Succeeded"})
    result = controller.plan(released, store: adapter, persistent_volumes: [released], claims: [], storage_classes: [], pods: [])

    assert_equal(["VolumeRecycled"], result.events.map { |event| event["reason"] })
    assert(result.operations.any? { |operation| operation.action == :delete && operation.resource.kind == "Pod" })
    unbound = result.operations.find { |operation| operation.action == :update && operation.resource.kind == "PersistentVolume" }

    assert_equal "", unbound.object.dig("spec", "claimRef", "uid"), "a user-bound volume keeps its claim name, loses the UID"
  end
end
