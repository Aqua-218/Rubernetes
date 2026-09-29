# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# ContainerStatus.user (SupplementalGroupsPolicy) and .volumeMounts
# (RecursiveReadOnlyMounts): the identity a started container runs with, in
# the runtime's group order, and each mount's read-only mode.
class ContainerUserStatusTest < Minitest::Test
  def lifecycle = Rubernetes::Node::Lifecycle.allocate

  def entry(state, context)
    {id: "c1", status: {"state" => state}, spec: {"security_context" => context}}
  end

  def test_the_user_of_a_started_container
    context = {"runAsUser" => 1000, "runAsGroup" => 3000, "supplementalGroups" => [60_000, 50_000],
               "imageSupplementalGroups" => [50_000], "fsGroup" => 2000}
    user = lifecycle.send(:container_user, entry("running", context))
    assert_equal({"linux" => {"uid" => 1000, "gid" => 3000, "supplementalGroups" => [3000, 50_000, 60_000, 2000]}}, user)
    assert_equal({"linux" => {"uid" => 0, "gid" => 0, "supplementalGroups" => [0]}}, lifecycle.send(:container_user, entry("terminated", {})))
    assert_nil lifecycle.send(:container_user, entry("waiting", context)), "not before the container exists"
  end

  def test_volume_mount_statuses
    status = Rubernetes::Node::Status.allocate
    definition = {"volumeMounts" => [{"name" => "a", "mountPath" => "/a"},
                                     {"name" => "b", "mountPath" => "/b", "readOnly" => true},
                                     {"name" => "c", "mountPath" => "/c", "readOnly" => true, "recursiveReadOnly" => "IfPossible"}]}
    assert_equal [{"name" => "a", "mountPath" => "/a"},
                  {"name" => "b", "mountPath" => "/b", "readOnly" => true, "recursiveReadOnly" => "Disabled"},
                  {"name" => "c", "mountPath" => "/c", "readOnly" => true, "recursiveReadOnly" => "Enabled"}],
                 status.send(:volume_mount_statuses, definition)
    running = status.send(:normalize_container_status, definition.merge("name" => "x", "image" => "i"),
                          {"state" => "running", "user" => {"linux" => {"uid" => 1}}})
    assert_equal({"linux" => {"uid" => 1}}, running["user"])
    assert_equal 3, running["volumeMounts"].length
    waiting = status.send(:normalize_container_status, definition.merge("name" => "x", "image" => "i"), {"state" => "waiting"})
    refute waiting.key?("volumeMounts")
  end
end

# node.status.volumesInUse (volumeManager.GetVolumesInUse): the CSI
# PersistentVolumes of the Pods still on the node, sorted, by unique name.
class NodeVolumesInUseTest < Minitest::Test
  def test_attachable_names_and_the_nodes_list
    volumes = Rubernetes::Node::PodVolumes.allocate
    assert_equal "kubernetes.io/csi/ebs.csi.aws.com^vol-1",
                 volumes.send(:attachable_name, {"persistentVolume" => "pv1", "csi" => {"driver" => "ebs.csi.aws.com", "volumeHandle" => "vol-1"}})
    assert_nil volumes.send(:attachable_name, {"csi" => {"driver" => "inline.csi", "volumeHandle" => "x"}}), "inline CSI is not attached"
    assert_nil volumes.send(:attachable_name, {"backend" => "emptyDir"})

    lifecycle = Rubernetes::Node::Lifecycle.allocate
    lifecycle.instance_variable_set(:@mutex, Mutex.new)
    lifecycle.instance_variable_set(:@records, {
      "a" => {state: "Running", volume: {"mounts" => {"d" => {"uniqueName" => "kubernetes.io/csi/d^2"}, "e" => {"name" => "e"}}}},
      "b" => {state: "Terminating", volume: {"mounts" => {"d" => {"uniqueName" => "kubernetes.io/csi/d^1"}}}},
      "c" => {state: "Removed", volume: {"mounts" => {"d" => {"uniqueName" => "kubernetes.io/csi/d^9"}}}}
    })
    assert_equal %w[kubernetes.io/csi/d^1 kubernetes.io/csi/d^2], lifecycle.volumes_in_use
  end
end
