# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "digest"

# The attach-detach controller for CSI volumes (pkg/controller/volume/
# attachdetach, v1.36.2): which nodes it manages, the VolumeAttachment it
# creates, when it detaches, and the Pod events it records.
class AttachDetachControllerUpstreamTest < Minitest::Test
  ADC = Rubernetes::Controller::PersistentVolumeAttachDetachController

  def node(name, managed: true, in_use: [])
    annotations = managed ? {"volumes.kubernetes.io/controller-managed-attach-detach" => "true"} : {}
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "annotations" => annotations},
     "status" => {"volumesInUse" => in_use}}
  end

  def pv(modes = ["ReadWriteOnce"])
    {"apiVersion" => "v1", "kind" => "PersistentVolume", "metadata" => {"name" => "pv1", "uid" => "pvu"},
     "spec" => {"accessModes" => modes, "csi" => {"driver" => "csi.example.com", "volumeHandle" => "h1"}}}
  end

  def claim(name = "c1")
    {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim", "metadata" => {"name" => name, "namespace" => "ns"},
     "spec" => {"volumeName" => "pv1"}}
  end

  def pod(name, node_name, namespace: "ns", phase: "Running")
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => namespace, "uid" => "u-#{name}"},
     "spec" => {"nodeName" => node_name, "volumes" => [{"name" => "v", "persistentVolumeClaim" => {"claimName" => "c1"}}]},
     "status" => {"phase" => phase}}
  end

  def attachment(node_name, attached: true, error: nil, rv: "1")
    status = {"attached" => attached}
    status["attachError"] = {"message" => error} if error
    {"apiVersion" => "storage.k8s.io/v1", "kind" => "VolumeAttachment",
     "metadata" => {"name" => "csi-#{Digest::SHA256.hexdigest("h1csi.example.com#{node_name}")}", "resourceVersion" => rv},
     "spec" => {"attacher" => "csi.example.com", "nodeName" => node_name, "source" => {"persistentVolumeName" => "pv1"}}, "status" => status}
  end

  def plan(controller = ADC.new, pods: [], nodes: [node("n1")], attachments: [], drivers: [], volume: pv, claims: [claim])
    controller.plan(volume, pods: pods, claims: claims, attachments: attachments, nodes: nodes, csi_drivers: drivers)
  end

  # The attach/detach operations, without the node.status.volumesAttached
  # reports (covered by their own tests below).
  def volume_operations(result) = result.operations.reject { |operation| operation.action == :status_merge }

  def reports(result)
    result.operations.select { |operation| operation.action == :status_merge }.to_h do |operation|
      [operation.object.dig("metadata", "name"), operation.patch["volumesAttached"]]
    end
  end

  def test_attached_volumes_are_reported_on_the_node_status
    result = plan(pods: [pod("p", "n1")], attachments: [attachment("n1")])

    assert_equal({"n1" => [{"name" => "kubernetes.io/csi/csi.example.com^h1", "devicePath" => ""}]}, reports(result))

    reported = node("n1").tap do |item|
      item["status"]["volumesAttached"] = [{"name" => "kubernetes.io/csi/csi.example.com^h1", "devicePath" => ""}]
    end

    assert_empty reports(plan(pods: [pod("p", "n1")], nodes: [reported], attachments: [attachment("n1")])), "already reported: no write"
  end

  def test_a_volume_leaves_the_report_when_its_detach_starts_or_it_is_not_attached_yet
    reported = node("n1").tap do |item|
      item["status"]["volumesAttached"] = [{"name" => "kubernetes.io/csi/csi.example.com^h1", "devicePath" => ""}]
    end
    detaching = plan(nodes: [reported], attachments: [attachment("n1")])

    assert_equal %i[delete status_merge], detaching.operations.map(&:action)
    assert_equal({"n1" => nil}, reports(detaching), "the report is cleared together with the detach")

    pending = plan(pods: [pod("p", "n1")], attachments: [attachment("n1", attached: false)])

    assert_empty reports(pending), "not attached yet: nothing to report"
    assert_empty reports(plan(pods: [pod("p", "n1")], nodes: [node("n1", managed: false)], attachments: [attachment("n1")])),
                 "an unmanaged node's status is the kubelet's"
  end

  def test_a_scheduled_pod_on_a_managed_node_gets_a_volume_attachment
    result = plan(pods: [pod("p", "n1")])
    create = result.operations.first

    assert_equal :create, create.action
    assert_equal "csi-#{Digest::SHA256.hexdigest("h1csi.example.comn1")}", create.object.dig("metadata", "name")
    assert_equal({"attacher" => "csi.example.com", "nodeName" => "n1", "source" => {"persistentVolumeName" => "pv1"}},
                 create.object["spec"])
  end

  def test_nothing_is_attached_for_unmanaged_nodes_terminated_pods_or_attach_free_drivers
    assert_empty plan(pods: [pod("p", "n1")], nodes: [node("n1", managed: false)]).operations
    assert_empty plan(pods: [pod("p", "n1", phase: "Succeeded")]).operations
    driver = {"apiVersion" => "storage.k8s.io/v1", "kind" => "CSIDriver", "metadata" => {"name" => "csi.example.com"},
              "spec" => {"attachRequired" => false}}

    assert_empty plan(pods: [pod("p", "n1")], drivers: [driver]).operations
  end

  def test_detach_waits_for_the_unmount_up_to_six_minutes
    now = Time.utc(2026, 9, 23, 12)
    controller = ADC.new(clock: -> { now })
    in_use = [node("n1", in_use: ["kubernetes.io/csi/csi.example.com^h1"])]
    waiting = plan(controller, nodes: in_use, attachments: [attachment("n1")])

    assert_empty volume_operations(waiting)
    assert waiting.requeue_after
    now += 361
    forced = plan(controller, nodes: in_use, attachments: [attachment("n1")])

    assert_equal [:delete], volume_operations(forced).map(&:action), "maxWaitForUnmountDuration passed: force detach"
    assert_equal [:delete], volume_operations(plan(nodes: [node("n1")], attachments: [attachment("n1")])).map(&:action),
                 "unmounted: detach now"
  end

  def test_attach_outcomes_are_reported_once_on_the_pods
    controller = ADC.new
    first = plan(controller, pods: [pod("p", "n1")], attachments: [attachment("n1")])

    assert_equal([["SuccessfulAttachVolume", "AttachVolume.Attach succeeded for volume \"pv1\" ", "p"]],
                 first.events.map { |event| [event["reason"], event["message"], event.dig("involvedObject", "name")] })
    assert_empty plan(controller, pods: [pod("p", "n1")], attachments: [attachment("n1")]).events

    failed = plan(ADC.new, pods: [pod("p", "n1")], attachments: [attachment("n1", attached: false, error: "rpc error: busy")])

    assert_equal(["AttachVolume.Attach failed for volume \"pv1\" : rpc error: busy"], failed.events.map { |event| event["message"] })
  end

  def test_multi_attach_errors_name_the_blocking_pods
    nodes = [node("n1"), node("n2")]
    pods = [pod("user", "n1"), pod("other", "n1", namespace: "elsewhere"), pod("new", "n2")]
    result = plan(pods: pods, nodes: nodes, attachments: [attachment("n1")],
                  claims: [claim, claim.merge("metadata" => {"name" => "c1", "namespace" => "elsewhere"})])
    events = result.events.select { |event| event["reason"] == "FailedAttachVolume" }

    assert_equal(["Multi-Attach error for volume \"pv1\" Volume is already used by pod(s) user and 1 pod(s) in different namespaces"],
                 events.map { |event| event["message"] })
    assert_empty(result.operations.select { |operation| operation.action == :create })

    rwx = plan(pods: pods, nodes: nodes, attachments: [attachment("n1")], volume: pv(["ReadWriteMany"]),
               claims: [claim, claim.merge("metadata" => {"name" => "c1", "namespace" => "elsewhere"})])

    assert_equal [:create], volume_operations(rwx).map(&:action), "an RWX volume attaches to the second node"
  end
end
