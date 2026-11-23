# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/volume"

# kubelet binds a ConfigMap, Secret, downward API or projected volume's
# per-Pod directory straight into the container.  Each such volume here was
# staged and published -- two bind mounts, each read back from the node's
# whole mount table, and their ledger records -- which was 73% of the agent
# CPU "EmptyDir wrapper volumes should not cause race condition when used for
# configmaps" (fifty ConfigMap volumes per Pod) spent.  The node-written
# volumes are now used from the backend's own directory.
class PodVolumeDirectPathTest < Minitest::Test
  Node = Rubernetes::Node

  class Reader
    def get(*_args, **_options) = {"metadata" => {"name" => "cm"}, "data" => {"k" => "v"}}
  end

  def pod(mount)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"},
     "spec" => {"containers" => [{"name" => "c", "volumeMounts" => [mount]}],
                "volumes" => [{"name" => "cm", "configMap" => {"name" => "cm"}}]}}
  end

  def with_volumes
    Dir.mktmpdir do |dir|
      manager = Rubernetes::Volume::Manager.new(data_dir: dir, fsync: false)
      volumes = Node::PodVolumes.new(volume: manager, root: File.join(dir, "pods"), node_name: "worker-0")
      volumes.instance_variable_set(:@reader, Reader.new)
      yield manager, volumes
    end
  end

  def test_a_configmap_volume_is_used_from_its_backend_directory
    with_volumes do |manager, volumes|
      stages = []
      manager.define_singleton_method(:stage) do |*args, **options|
        stages << args
        super(*args, **options)
      end
      subject = pod({"name" => "cm", "mountPath" => "/etc/cm"})
      handle = volumes.prepare(subject)
      mount = handle.dig("mounts", "cm")

      assert mount["direct"]
      assert mount["readonly"], "the container binds it read-only"
      assert_equal manager.backends.fetch(mount["id"]).source_path, mount["path"]
      assert_equal "v", File.read(File.join(mount["path"], "k"))
      assert_equal "Provisioned", manager.volume(mount["id"]).state
      assert_empty stages, "nothing is staged"

      volumes.release(subject, handle)

      refute_path_exists mount["path"]
      assert_raises(Rubernetes::Volume::NotFoundError) { manager.volume(mount["id"]) }
    end
  end

  def test_a_volume_mounted_with_a_subpath_keeps_its_publish
    with_volumes do |_manager, volumes|
      subject = pod({"name" => "cm", "mountPath" => "/etc/cm", "subPath" => "k"})
      direct = volumes.send(:direct_volume?, "configMap", subject, "cm")

      refute direct
      refute volumes.send(:direct_volume?, "emptyDir", pod({"name" => "cm", "mountPath" => "/x"}), "cm"),
             "an emptyDir is not node-written content"
      assert_raises(Node::PodVolumes::Error) do
        volumes.sub_path(subject, {"mounts" => {"cm" => {"id" => "v", "direct" => true}}},
                         volume_name: "cm", sub_path: "k", container_name: "c", index: 0, readonly: true)
      end
    end
  end

  def test_first_sync_compares_the_current_configmap_to_the_files_actually_mounted
    with_volumes do |_manager, volumes|
      subject = pod({"name" => "cm", "mountPath" => "/etc/cm"})
      handle = volumes.prepare(subject)
      file = File.join(handle.dig("mounts", "cm", "path"), "k")
      reader = volumes.instance_variable_get(:@reader)
      reader.define_singleton_method(:get) { |*, **| {"data" => {"k" => "updated"}} }

      assert_equal("v", File.read(file))
      assert_equal(["cm"], volumes.refresh_contents(subject, handle))
      assert_equal("updated", File.read(file))
      assert_empty(volumes.refresh_contents(subject, handle))
    ensure
      volumes.release(subject, handle) if handle
    end
  end

  def test_only_node_written_backends_can_be_used_directly
    with_volumes do |manager, _volumes|
      id = manager.create_volume({"name" => "scratch", "backend" => "emptyDir", "podUid" => "u1", "attempt" => "a"},
                                 token: "create-scratch")

      assert_raises(Rubernetes::Volume::ValidationError) { manager.direct_path(id, pod: pod({})) }
    end
  end

  def test_nested_projection_mountpoints_survive_configuration_refresh
    with_volumes do |_manager, volumes|
      subject = pod({"name" => "cm", "mountPath" => "/run/secrets/istio"})
      spec = subject.fetch("spec")
      spec.fetch("containers").first.fetch("volumeMounts").push(
        {"name" => "middle", "mountPath" => "/run/secrets/istio/crl"},
        {"name" => "inner", "mountPath" => "/run/secrets/istio/crl/secondary"}
      )
      spec.fetch("volumes").concat(%w[middle inner].map { |name| {"name" => name, "configMap" => {"name" => "cm"}} })
      handle = volumes.prepare(subject)
      outer = File.join(handle.dig("mounts", "cm", "path"), "crl")
      middle = File.join(handle.dig("mounts", "middle", "path"), "secondary")

      assert(File.directory?(outer))
      assert(File.directory?(middle))
      refute_path_exists(File.join(outer, "secondary"))
      reader = volumes.instance_variable_get(:@reader)
      reader.define_singleton_method(:get) { |*, **| {"data" => {"k" => "updated"}} }

      assert_equal(%w[cm middle inner], volumes.refresh_contents(subject, handle))
      assert(File.directory?(outer))
      assert(File.directory?(middle))
    ensure
      volumes.release(subject, handle) if handle
    end
  end

  def test_projection_mountpoints_refuse_existing_symlinks
    Dir.mktmpdir do |dir|
      root = File.join(dir, "projection")
      Dir.mkdir(root)
      File.symlink(dir, File.join(root, "link"))
      writer = Rubernetes::Volume::AtomicWriter.new(root, mountpoints: ["link/nested"])

      assert_raises(Rubernetes::Volume::PathSecurityError) { writer.write({"k" => "v"}) }
      refute_path_exists(File.join(dir, "nested"))
    end
  end
end
