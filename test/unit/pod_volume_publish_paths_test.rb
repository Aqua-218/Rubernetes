# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/volume"

class PodVolumePublishPathsTest < Minitest::Test
  class RecordingManager < Rubernetes::Volume::Manager
    attr_reader :targets, :unpublished, :stages
    attr_accessor :fail_target, :fail_unstage

    def initialize(...)
      super
      @specs = {}
      @targets = {}
      @stages = {}
      @unpublished = []
    end

    def kubelet_csi_filesystem?(id)
      @specs.fetch(id)["csi"] && @specs.fetch(id).fetch("volumeMode", "Filesystem") == "Filesystem"
    end

    def create_volume(spec, token:)
      @specs[spec.fetch("name")] = spec
      spec.fetch("name")
    end

    def stage(id, path, **)
      FileUtils.mkdir_p(path)
      @stages[id] = path
    end

    def node_publish(id, _pod, target, **)
      raise "publish failed" if target == @fail_target

      FileUtils.mkdir_p(target)
      @targets[id] = target
    end

    def node_unpublish(id, _pod, target, **)
      @unpublished << target
      @targets.delete(id)
      Dir.rmdir(target) if File.directory?(target)
    end

    def unstage(id, _path, **)
      raise "NFS stage release is pending" if @fail_unstage

      @stages.delete(id)
    end

    def delete_volume(*, **) = true
  end

  class Reader
    def initialize(mode = "Filesystem")
      @mode = mode
    end

    def get(resource, _name, namespace:)
      case resource
      when "persistentvolumeclaims" then {"spec" => {"volumeName" => "pvc-abcd"}, "status" => {"phase" => "Bound"}}
      when "persistentvolumes"
        {"spec" => {"volumeMode" => @mode, "capacity" => {"storage" => "1Mi"},
                    "csi" => {"driver" => "test.example", "volumeHandle" => "opaque-handle"}}}
      end
    end
  end

  def setup
    @storage = Dir.mktmpdir("csi-pod-publish")
    @manager = RecordingManager.new(data_dir: @storage, fsync: false)
    @manager.mount_adapter.define_singleton_method(:find_mount) { |_path| nil }
    @pods = File.join(@storage, "pods")
    @old = File.join(@pods, "volumes")
    @volumes = new_pod_volumes
  end

  def teardown
    @manager.close
    FileUtils.remove_entry(@storage)
  end

  def test_persistent_filesystem_path_uses_pv_name_and_persisted_path_survives_reopen
    pod = source_pod("first")
    handle = @volumes.prepare(pod)
    reopened_handle = JSON.parse(JSON.generate(handle))

    assert_equal canonical_target, handle.dig("mounts", "first", "path")
    assert_path_exists canonical_target

    new_pod_volumes.release(pod, reopened_handle)

    assert_equal [canonical_target], @manager.unpublished
    refute_path_exists canonical_target
  end

  def test_old_handles_continue_to_use_their_original_publishes
    pod = source_pod("first")
    old_volume_manager = Rubernetes::Node::PodVolumes.new(volume: @manager, reader: Reader.new, root: @old)
    handle = old_volume_manager.prepare(pod)

    assert_equal legacy_target("first"), handle.dig("mounts", "first", "path")

    @volumes.release(pod, JSON.parse(JSON.generate(handle)))

    assert_equal [legacy_target("first")], @manager.unpublished
  end

  def test_aliases_of_one_claim_preserve_both_publications
    pod = source_pod("first", "second")
    handle = @volumes.prepare(pod)

    assert_equal({"first" => canonical_target, "second" => legacy_target("second")}, @manager.targets)

    @volumes.release(pod, handle)

    assert_equal [legacy_target("second"), canonical_target], @manager.unpublished
  end

  def test_rollback_of_late_alias_leaves_the_first_publication_and_stage
    handle = @volumes.prepare(source_pod("first"))
    original_stage = @manager.stages.fetch("first")
    @manager.fail_target = legacy_target("third")

    assert_raises(RuntimeError) { @volumes.prepare_newly_used(source_pod("first", "second", "third"), handle) }

    assert_equal({"first" => canonical_target}, @manager.targets)
    assert_path_exists canonical_target
    assert_path_exists original_stage
    assert_equal [legacy_target("second")], @manager.unpublished
  end

  def test_an_existing_canonical_mount_is_preserved
    adapter = @manager.mount_adapter
    adapter.define_singleton_method(:find_mount) { |_path| {"mountId" => 42} }
    error = assert_raises(Rubernetes::Node::PodVolumes::Error) { @volumes.prepare(source_pod("first")) }

    assert_match(/already has a mount/, error.message)
    assert_empty @manager.unpublished
    assert_empty @manager.targets
  end

  def test_inline_csi_uses_the_pod_volume_name
    pod = source_pod("inline")
    pod["spec"]["volumes"] = [{"name" => "inline", "csi" => {"driver" => "test.example"}}]

    assert_equal File.join(@pods, "uid-1", "volumes", "kubernetes.io~csi", "inline", "mount"),
                 @volumes.prepare(pod).dig("mounts", "inline", "path")
  end

  def test_block_keeps_its_existing_path
    pod = source_pod("block")
    volumes = new_pod_volumes(reader: Reader.new("Block"))
    mount = volumes.prepare(pod).dig("mounts", "block")

    assert_equal legacy_target("block"), mount["path"]
    assert_equal "Block", mount["volumeMode"]
  end

  def test_inline_nfs_keeps_its_standard_directory_until_the_stage_is_released
    pod = inline_nfs_pod
    handle = nfs_volumes.prepare(pod)
    target = File.join(@pods, "uid-1", "volumes", "kubernetes.io~nfs", "export")
    pod_volume_directory = File.dirname(target, 2)

    assert_equal target, handle.dig("mounts", "export", "path")

    @manager.fail_unstage = true
    assert_raises(Rubernetes::Node::PodVolumes::Error) { nfs_volumes.release(pod, handle) }

    assert_path_exists pod_volume_directory

    @manager.fail_unstage = false
    nfs_volumes.release(pod, handle)

    refute_path_exists pod_volume_directory
  end

  def test_nfs_recovery_uses_the_saved_legacy_target
    pod = inline_nfs_pod
    old = Rubernetes::Node::PodVolumes.new(volume: @manager, root: @old)
    handle = JSON.parse(JSON.generate(old.prepare(pod)))

    assert_equal legacy_target("export"), handle.dig("mounts", "export", "path")

    nfs_volumes.release(pod, handle)

    assert_equal [legacy_target("export")], @manager.unpublished
  end

  private

  def inline_nfs_pod
    pod = source_pod
    pod["spec"]["volumes"] = [{"name" => "export", "nfs" => {"server" => "192.0.2.1", "path" => "/"}}]
    pod
  end

  def nfs_volumes
    new_pod_volumes.tap do |volumes|
      volumes.define_singleton_method(:real_mounts?) { true }
      volumes.define_singleton_method(:ensure_propagating_root!) { true }
    end
  end

  def new_pod_volumes(reader: Reader.new)
    Rubernetes::Node::PodVolumes.new(volume: @manager, reader: reader, root: @old, kubelet_pod_root: @pods)
  end

  def source_pod(*names)
    volumes = names.map { |name| {"name" => name, "persistentVolumeClaim" => {"claimName" => "claim"}} }
    {"metadata" => {"name" => "test", "uid" => "uid-1"}, "spec" => {"volumes" => volumes}}
  end

  def canonical_target
    File.join(@pods, "uid-1", "volumes", "kubernetes.io~csi", "pvc-abcd", "mount")
  end

  def legacy_target(name)
    File.join(@old, "uid-1", "volumes", name)
  end
end
