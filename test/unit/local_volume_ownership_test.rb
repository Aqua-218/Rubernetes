# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/platform/linux/openat2"

class LocalVolumeOwnershipTest < Minitest::Test
  Volume = Rubernetes::Volume

  def test_local_volume_fs_group_is_applied_only_to_the_first_active_mount
    skip "native bind mounts and file ownership require root" unless Process.uid.zero?

    Dir.mktmpdir("local-ownership") do |root|
      source = File.join(root, "backing")
      Dir.mkdir(source, 0o700)
      item = File.join(source, "data")
      File.write(item, "preserved")
      volumes = build_volumes(root, source)
      first = pod("first", 3001)
      second = pod("second", 3002)
      first_handle = volumes.prepare(first)
      second_handle = volumes.prepare(second)

      assert_equal 3001, File.stat(source).gid
      assert_equal 3001, File.stat(item).gid
      assert_equal({"requested" => 3002, "current" => 3001}, second_handle.dig("mounts", "data", "localFsGroupConflict"))

      volumes.release(first, first_handle)
      first_handle = nil
      volumes.release(second, second_handle)
      second_handle = nil
      second_handle = volumes.prepare(second)

      assert_equal 3002, File.stat(source).gid
      assert_equal 3002, File.stat(item).gid
      assert_equal "preserved", File.read(item)
    ensure
      volumes&.release(first, first_handle) if first_handle
      volumes&.release(second, second_handle) if second_handle
      Rubernetes::Platform::Linux::Mount.new.unmount(target: volumes.root) if volumes&.propagating_root?
    end
  end

  private

  def build_volumes(root, source)
    reader = Object.new
    reader.define_singleton_method(:get) do |resource, _name, namespace:|
      case resource
      when "persistentvolumeclaims" then {"spec" => {"volumeName" => "local"}, "status" => {"phase" => "Bound"}}
      when "persistentvolumes" then {"spec" => {"local" => {"path" => source}, "accessModes" => ["ReadWriteOnce"]}}
      end
    end
    trusted_root = File.dirname(root)
    security = Volume::PathSecurity.secure(root: trusted_root, adapter: Rubernetes::Platform::Linux::Openat2.new(root: trusted_root))
    manager = Volume::Manager.new(data_dir: File.join(root, "state"), path_security: security, mount_adapter: Volume::NativeMountAdapter.new,
                                  require_real_readback: true)
    Rubernetes::Node::PodVolumes.new(volume: manager, reader: reader, root: File.join(root, "pods"), node_name: "worker")
  end

  def pod(name, group)
    {"metadata" => {"uid" => name, "name" => name, "namespace" => "default"},
     "spec" => {"securityContext" => {"fsGroup" => group},
                "containers" => [{"name" => "work", "volumeMounts" => [{"name" => "data", "mountPath" => "/data"}]}],
                "volumes" => [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "data"}}]}}
  end
end
