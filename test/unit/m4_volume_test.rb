# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/volume"
require "tmpdir"

class M4VolumeTest < Minitest::Test
  class RecordingCSI
    attr_reader :calls

    def initialize
      @calls = []
    end

    def identity
      Rubernetes::Volume::Identity.new(name: "example.csi", vendor_version: "test")
    end

    def create_volume(spec, token:)
      @calls << [:create_volume, spec, token]
      {"volumeId" => "remote-volume"}
    end

    def delete_volume(id, token:)
      @calls << [:delete_volume, id, token]
      {}
    end

    def publish(id, node, token:)
      @calls << [:publish, id, node, token]
      {}
    end

    def unpublish(id, node, token:)
      @calls << [:unpublish, id, node, token]
      {}
    end

    def stage(id, path, token:, readonly:, context:)
      @calls << [:stage, id, path, token, readonly, context]
      {}
    end

    def unstage(id, path, token:)
      @calls << [:unstage, id, path, token]
      {}
    end

    def publish_node(id, stage_path, target, token:, readonly:, context:)
      @calls << [:publish_node, id, stage_path, target, token, readonly, context]
      {}
    end

    def unpublish_node(id, target, token:)
      @calls << [:unpublish_node, id, target, token]
      {}
    end

    def stats(_id)
      {"capacityBytes" => 1}
    end

    def expand(_id, _capacity, token:)
      @calls << [:expand, token]
      {}
    end
  end

  class RecordingDeviceAdapter
    attr_reader :calls

    def initialize(fail_dm: false)
      @calls = []
      @fail_dm = fail_dm
    end

    def create_loop(path:, volume_id:, size_bytes:)
      @calls << [:create_loop, path, volume_id, size_bytes]
      {"id" => "/dev/loop-test", "path" => "/dev/loop-test"}
    end

    def create_dm(device:, volume_id:, size_bytes:)
      @calls << [:create_dm, device, volume_id, size_bytes]
      raise Rubernetes::Volume::MountIdentityError, "device-mapper setup failed" if @fail_dm

      {"id" => "/dev/mapper/rubernetes-test", "path" => "/dev/mapper/rubernetes-test"}
    end

    def destroy_device(id:, volume_id:)
      @calls << [:destroy_device, id, volume_id]
      true
    end
  end

  def setup
    @directory = Dir.mktmpdir("m4-volume")
    @manager = Rubernetes::Volume::Manager.new(data_dir: @directory, fsync: false)
  end

  def teardown
    FileUtils.remove_entry(@directory) if File.exist?(@directory)
  end

  def test_attach_stage_publish_and_reverse_lifecycle_is_idempotent
    id = @manager.create_volume({"name" => "work", "emptyDir" => {}}, token: "create")

    assert_equal id, @manager.create_volume({"name" => "work", "emptyDir" => {}}, token: "create")
    @manager.controller.publish(id, "node-a", token: "attach")
    stage = File.join(@directory, "stage")
    target = File.join(@directory, "target")
    @manager.node.stage(id, stage, token: "stage", node: "node-a")
    @manager.node.publish(id, {"metadata" => {"uid" => "pod-a"}}, target, readonly: false, token: "publish", node: "node-a")

    assert_equal "Published", @manager.fetch_record(id).state
    @manager.node.unpublish(id, {"metadata" => {"uid" => "pod-a"}}, target, token: "unpublish")
    @manager.node.unstage(id, stage, token: "unstage")
    @manager.controller.unpublish(id, "node-a", token: "detach")

    assert_equal "Detached", @manager.fetch_record(id).state
    assert @manager.delete_volume(id, token: "delete")
  end

  def test_rwo_and_rwop_reject_cross_node_or_cross_pod_attach
    rwo = @manager.create_volume({"name" => "rwo", "emptyDir" => {}, "accessModes" => ["ReadWriteOnce"]}, token: "rwo")
    @manager.controller.publish(rwo, "node-a", token: "rwo-a")
    assert_raises(Rubernetes::Volume::MultiAttachError) { @manager.controller.publish(rwo, "node-b", token: "rwo-b") }

    rwop = @manager.create_volume({"name" => "rwop", "emptyDir" => {}, "accessModes" => ["ReadWriteOncePod"]}, token: "rwop")
    @manager.controller.publish(rwop, "node-a", token: "rwop-a")
    @manager.node.stage(rwop, File.join(@directory, "rwop-stage"), token: "rwop-stage", node: "node-a")
    @manager.node.publish(rwop, {"metadata" => {"uid" => "pod-a"}}, File.join(@directory, "rwop-a"), readonly: false,
                                                                                                     token: "rwop-pod-a", node: "node-a")
    assert_raises(Rubernetes::Volume::MultiAttachError) do
      @manager.node.publish(rwop, {"metadata" => {"uid" => "pod-b"}}, File.join(@directory, "rwop-b"), readonly: false,
                                                                                                       token: "rwop-pod-b", node: "node-a")
    end
  end

  def test_wait_for_first_consumer_and_online_expansion
    @manager.register_storage_class({"metadata" => {"name" => "fast"}, "provisioner" => "example", "volumeBindingMode" => "WaitForFirstConsumer",
                                     "allowVolumeExpansion" => true})
    @manager.register_pv({"metadata" => {"name" => "pv"}, "capacity" => {"storage" => "10Gi"}, "accessModes" => ["RWO"],
                          "storageClassName" => "fast", "nodeAffinity" => {"required" => {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "zone", "operator" => "In", "values" => ["a"]}]}]}}})
    pvc = @manager.register_pvc({"metadata" => {"name" => "claim", "namespace" => "default"}, "resources" => {"requests" => {"storage" => "1Gi"}},
                                 "accessModes" => ["RWO"], "storageClassName" => "fast"})

    assert_predicate @manager.bind(pvc), :pending?
    bound = @manager.bind(pvc, node: "node-a", node_labels: {"zone" => "a"})

    assert_predicate bound, :bound?
    assert_equal "Bound", @manager.binder.expand(pvc, capacity: "2Gi").status
  end

  def test_snapshot_restore_and_clone_issue_new_volume_identities
    id = @manager.create_volume({"name" => "base", "emptyDir" => {}}, token: "base")
    snapshot = @manager.create_snapshot(id, token: "snapshot")
    restored = @manager.restore(snapshot, spec: {"name" => "restored", "emptyDir" => {}}, token: "restore")
    cloned = @manager.clone(id, spec: {"name" => "clone", "emptyDir" => {}}, token: "clone")

    refute_equal id, restored
    refute_equal id, cloned
    refute_equal restored, cloned
  end

  def test_secret_projection_is_atomic_and_tmpfs_backed
    id = @manager.create_volume({"name" => "secret", "secret" => {"data" => {"token" => "c2VjcmV0"}}}, token: "secret")
    root = File.join(@directory, "volumes", id)

    assert_equal "secret", File.read(File.join(root, "token"))
    assert File.symlink?(File.join(root, "..data"))
    assert(@manager.mount_adapter.list_mounts.any? { |mount| mount["filesystem"] == "tmpfs" })
  end

  def test_csi_source_is_detected_and_missing_adapter_fails_closed
    spec = {"name" => "remote", "csi" => {"driver" => "example.csi"}}

    assert_equal "csi", @manager.normalize_spec(spec)["backend"]
    assert_raises(Rubernetes::Volume::CSIUnavailable) do
      @manager.create_volume(spec, token: "remote")
    end
    assert_empty @manager.list_volumes
  end

  def test_csi_lifecycle_does_not_double_mount_through_generic_adapter
    csi = RecordingCSI.new
    manager = Rubernetes::Volume::Manager.new(data_dir: @directory, csi: csi, fsync: false)
    id = manager.create_volume({"name" => "remote", "csi" => {"driver" => "example.csi"}}, token: "create-remote")
    stage = File.join(@directory, "remote-stage")
    target = File.join(@directory, "remote-target")
    pod = {"metadata" => {"uid" => "remote-pod"}}

    manager.controller.publish(id, "node-a", token: "attach-remote")
    manager.node.stage(id, stage, token: "stage-remote", node: "node-a")
    manager.node.publish(id, pod, target, readonly: false, token: "publish-remote", node: "node-a")
    manager.node.unpublish(id, pod, target, token: "unpublish-remote")
    manager.node.unstage(id, stage, token: "unstage-remote")
    manager.controller.unpublish(id, "node-a", token: "detach-remote")
    manager.delete_volume(id, token: "delete-remote")

    assert_empty manager.mount_adapter.list_mounts
    assert_equal %i[create_volume publish stage publish_node unpublish_node unstage unpublish delete_volume],
                 csi.calls.map(&:first)
  end

  def test_native_readback_mode_rejects_the_implicit_filesystem_adapter
    assert_raises(Rubernetes::Volume::MountIdentityError) do
      Rubernetes::Volume::Manager.new(data_dir: @directory, require_real_readback: true, fsync: false)
    end
  end

  def test_loop_dm_uses_the_device_adapter_and_releases_dm_before_loop
    devices = RecordingDeviceAdapter.new
    backend = Rubernetes::Volume::LoopDMBackend.new(
      id: "loop-volume", spec: {"backend" => "loopDM", "size" => 1},
      adapter: @manager.mount_adapter, mount_adapter: @manager.mount_adapter,
      device_adapter: devices, root: File.join(@directory, "volumes")
    )

    backend.provision
    backend.delete

    # Cleanup passes the full durable identity so the adapter can verify the
    # device before releasing it; the ordering (dm before loop) is what matters.
    destroy_ids = devices.calls.select { |call| call.first == :destroy_device }
      .map { |call| call[1].is_a?(Hash) ? call[1].fetch("id") : call[1] }

    assert_equal ["/dev/mapper/rubernetes-test", "/dev/loop-test"], destroy_ids
  end

  def test_loop_dm_failure_cleans_up_the_loop_device
    devices = RecordingDeviceAdapter.new(fail_dm: true)
    backend = Rubernetes::Volume::LoopDMBackend.new(
      id: "loop-volume", spec: {"backend" => "loopDM", "size" => 1},
      adapter: @manager.mount_adapter, mount_adapter: @manager.mount_adapter,
      device_adapter: devices, root: File.join(@directory, "volumes")
    )

    assert_raises(Rubernetes::Volume::MountIdentityError) { backend.provision }
    destroy_calls = devices.calls.select { |call| call.first == :destroy_device }
      .map { |call| [call[0], call[1].is_a?(Hash) ? call[1].fetch("id") : call[1], call[2]] }

    assert_equal [[:destroy_device, "/dev/loop-test", "loop-volume"]], destroy_calls
  end
end
