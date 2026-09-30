# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"

# nodevolumelimits.CSILimits (pkg/scheduler/framework/plugins/nodevolumelimits,
# v1.36.2): limits from CSINode allocatable.count, volumes unique by driver
# and handle, PVCs resolved through their PV or StorageClass, generic
# ephemeral volumes, migrated in-tree volumes and VolumeAttachments.
class NodeVolumeLimitsCSITest < Minitest::Test
  S = Rubernetes::Scheduler
  DRIVER = "ebs.csi.aws.com"

  def pod(name, volumes, uid: "uid-#{name}", node: nil)
    spec = {"containers" => [{"name" => "c", "image" => "i"}], "volumes" => volumes}
    spec["nodeName"] = node if node
    S::Pod.new({"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "ns", "uid" => uid}, "spec" => spec})
  end

  def claim_volume(claim) = {"name" => claim, "persistentVolumeClaim" => {"claimName" => claim}}

  def pvc(name, volume: nil, storage_class: nil, owner: nil)
    metadata = {"name" => name, "namespace" => "ns"}
    metadata["ownerReferences"] = [{"uid" => owner, "controller" => true, "kind" => "Pod", "name" => "x", "apiVersion" => "v1"}] if owner
    {"metadata" => metadata, "spec" => {"volumeName" => volume, "storageClassName" => storage_class}.compact}
  end

  def pv(name, handle, driver: DRIVER)
    {"metadata" => {"name" => name}, "spec" => {"csi" => {"driver" => driver, "volumeHandle" => handle}}}
  end

  def csi_node(limit, driver: DRIVER)
    {"metadata" => {"name" => "node-a"},
     "spec" => {"drivers" => [{"name" => driver, "nodeID" => "n", "allocatable" => {"count" => limit}.compact}]}}
  end

  def node(pods = [])
    S::Node.new({"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "node-a"},
                 "status" => {"allocatable" => {"cpu" => "4", "memory" => "4Gi", "pods" => "110"}}}, pods: pods)
  end

  def filter(new_pod, existing: [], limit: 2, claims: [], volumes: [], classes: [], attachments: [], csi_nodes: nil, drivers: [],
             plugin: S::Filters::NodeVolumeLimits.new)
    context = S::CycleContext.new(nodes: [], pods: [], volume_data: {
                                    "persistentVolumeClaims" => claims, "persistentVolumes" => volumes, "storageClasses" => classes,
                                    "csiNodes" => csi_nodes || [csi_node(limit)], "csiDrivers" => drivers, "volumeAttachments" => attachments
                                  })
    plugin.filter(new_pod, node(existing), context)
  end

  def claims(count) = Array.new(count) { |index| pvc("c#{index}", volume: "pv#{index}") }
  def volumes(count) = Array.new(count) { |index| pv("pv#{index}", "vol-#{index}") }

  def test_within_and_over_the_limit
    existing = [pod("old", [claim_volume("c0")], node: "node-a")]

    assert_equal true, filter(pod("new", [claim_volume("c1")]), existing: existing, claims: claims(3), volumes: volumes(3))
    result = filter(pod("new", [claim_volume("c1"), claim_volume("c2")]), existing: existing, claims: claims(3), volumes: volumes(3))

    assert_equal "node(s) exceed max volume count", result.reason
    assert_equal "NodeVolumeLimits", result.code
  end

  def test_a_volume_already_on_the_node_counts_once
    existing = [pod("old", [claim_volume("c0"), claim_volume("c1")], node: "node-a")]

    assert_equal true,
                 filter(pod("new", [claim_volume("c0"), claim_volume("c1")]), existing: existing, claims: claims(2), volumes: volumes(2))
  end

  def test_no_csinode_or_no_count_means_no_limit
    many = pod("new", Array.new(5) { |index| claim_volume("c#{index}") })

    assert_equal true, filter(many, claims: claims(5), volumes: volumes(5), csi_nodes: [])
    assert_equal true, filter(many, claims: claims(5), volumes: volumes(5), csi_nodes: [csi_node(nil)])
    refute_equal true, filter(many, claims: claims(5), volumes: volumes(5), limit: 4)
  end

  def test_a_missing_pvc_is_unresolvable_for_the_new_pod_only
    result = filter(pod("new", [claim_volume("gone")]))

    assert_equal "UnschedulableAndUnresolvable", result.code
    assert_equal %(looking up PVC ns/gone: persistentvolumeclaim "gone" not found), result.reason
    existing = [pod("old", [claim_volume("gone")], node: "node-a")]

    assert_equal true, filter(pod("new", [claim_volume("c0")]), existing: existing, claims: claims(1), volumes: volumes(1), limit: 1)
  end

  def test_unbound_claims_count_through_their_storage_class
    classes = [{"metadata" => {"name" => "fast"}, "provisioner" => DRIVER}]
    unbound = [pvc("u0", storage_class: "fast"), pvc("u1", storage_class: "fast")]

    assert_equal true, filter(pod("new", [claim_volume("u0")]), claims: unbound, classes: classes, limit: 1)
    refute_equal true, filter(pod("new", [claim_volume("u0"), claim_volume("u1")]), claims: unbound, classes: classes, limit: 1)
    no_class = [pvc("n0"), pvc("n1")]

    assert_equal true, filter(pod("new", [claim_volume("n0"), claim_volume("n1")]), claims: no_class, limit: 1)
  end

  def test_generic_ephemeral_volumes_must_belong_to_the_pod
    volume = {"name" => "scratch", "ephemeral" => {"volumeClaimTemplate" => {"spec" => {}}}}
    owned = [pvc("new-scratch", volume: "pv0", owner: "uid-new")]

    assert_equal true, filter(pod("new", [volume]), claims: owned, volumes: volumes(1), limit: 1)
    foreign = [pvc("new-scratch", volume: "pv0", owner: "someone-else")]
    result = filter(pod("new", [volume]), claims: foreign, volumes: volumes(1), limit: 1)

    assert_includes result.reason, "was not created for pod ns/new (pod is not owner)"
  end

  def test_migrated_in_tree_volumes_count_against_the_csi_driver
    inline = Array.new(2) { |index| {"name" => "ebs#{index}", "awsElasticBlockStore" => {"volumeID" => "aws://zone/vol-#{index}"}} }

    refute_equal true, filter(pod("new", inline), limit: 1)
    assert_equal true, filter(pod("new", inline), limit: 1, csi_nodes: [], claims: [])
    in_tree_pv = [{"metadata" => {"name" => "pv-tree"}, "spec" => {"awsElasticBlockStore" => {"volumeID" => "vol-9"}}}]
    existing = [pod("old", [claim_volume("tree")], node: "node-a")]
    result = filter(pod("new", [claim_volume("c0")]), existing: existing, limit: 1,
                                                      claims: [pvc("tree", volume: "pv-tree")] + claims(1), volumes: in_tree_pv + volumes(1))

    refute_equal true, result, "the migrated PV on the node counts for ebs.csi.aws.com"
  end

  def test_volume_attachments_to_the_node_count
    attachments = [{"metadata" => {"name" => "va"}, "spec" => {"nodeName" => "node-a", "attacher" => DRIVER,
                                                               "source" => {"persistentVolumeName" => "pv5"}}}]
    result = filter(pod("new", [claim_volume("c0")]), limit: 1, claims: claims(1), volumes: volumes(1) + [pv("pv5", "vol-5")],
                                                      attachments: attachments)

    refute_equal true, result
    elsewhere = [attachments.first.merge("spec" => attachments.first["spec"].merge("nodeName" => "node-b"))]

    assert_equal true, filter(pod("new", [claim_volume("c0")]), limit: 1, claims: claims(1),
                                                                volumes: volumes(1) + [pv("pv5", "vol-5")], attachments: elsewhere)
  end

  def test_volume_limit_scaling_requires_an_opted_in_driver_on_the_node
    plugin = S::Filters::NodeVolumeLimits.new(volume_limit_scaling: true)
    drivers = [{"metadata" => {"name" => DRIVER}, "spec" => {"preventPodSchedulingIfMissing" => true}}]
    other_node = [csi_node(5, driver: "other.csi")]
    result = filter(pod("new", [claim_volume("c0")]), claims: claims(1), volumes: volumes(1), drivers: drivers, csi_nodes: other_node,
                                                      plugin: plugin)

    assert_equal "ebs.csi.aws.com CSI driver is not installed on the node", result.reason
    assert_equal true, filter(pod("new", [claim_volume("c0")]), claims: claims(1), volumes: volumes(1), drivers: [], csi_nodes: other_node,
                                                                plugin: plugin)
  end

  def test_pods_without_csi_capable_volumes_skip
    assert_equal true, filter(pod("new", [{"name" => "tmp", "emptyDir" => {}}]), limit: 0)
  end
end
