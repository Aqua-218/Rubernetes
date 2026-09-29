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
      manager.define_singleton_method(:stage) { |*args, **options| stages << args; super(*args, **options) }
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
      refute File.exist?(mount["path"])
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

  def test_only_node_written_backends_can_be_used_directly
    with_volumes do |manager, _volumes|
      id = manager.create_volume({"name" => "scratch", "backend" => "emptyDir", "podUid" => "u1", "attempt" => "a"},
                                 token: "create-scratch")

      assert_raises(Rubernetes::Volume::ValidationError) { manager.direct_path(id, pod: pod({})) }
    end
  end
end
