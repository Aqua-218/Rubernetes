# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes"
require "rubernetes/bootstrap"
require "rubernetes/observability/metrics"

# The controller manager's scrape-time collectors registered by running
# controllers (v1.36.2): resourceclaim_controller_resource_claims (the
# resourceclaim controller's customCollector) and the attach/detach
# controller's storage_count_attachable_volumes_in_use and
# attachdetach_controller_total_volumes -- absent while their controller
# does not run.
class ControllerManagerCollectorsTest < Minitest::Test
  class Store
    def initialize(objects) = @objects = objects
    def list(kind, namespace: :all) = @objects.fetch(kind, [])
  end

  Manager = Struct.new(:controllers)

  def service(objects, controllers)
    service = Rubernetes::Bootstrap::ControllerManagerService.allocate
    service.instance_variable_set(:@store, Store.new(objects))
    service.instance_variable_set(:@manager, Manager.new(controllers.to_h { |name| [name, true] }))
    service
  end

  def registry = Rubernetes::Observability::Metrics.new(apiserver: false, process: false, component: "kube-controller-manager")

  def test_resource_claims_by_allocation_admin_access_and_source
    claims = [{"metadata" => {"annotations" => {"resource.kubernetes.io/pod-claim-name" => "gpu"}}, "spec" => {}},
              {"metadata" => {"annotations" => {"resource.kubernetes.io/pod-claim-name" => "gpu"}}, "spec" => {}},
              {"metadata" => {}, "spec" => {"devices" => {"requests" => [{"exactly" => {"adminAccess" => true}}]}},
               "status" => {"allocation" => {}}}]
    metrics = registry
    service(%w[ResourceClaim].zip([claims]).to_h, ["resourceclaim-controller"]).send(:collect_resource_claims, metrics)
    text = metrics.render

    assert_includes text,
                    %(resourceclaim_controller_resource_claims{admin_access="false",allocated="false",source="resource_claim_template"} 2)
    assert_includes text, %(resourceclaim_controller_resource_claims{admin_access="true",allocated="true",source=""} 1)
    assert_match(/^# HELP resourceclaim_controller_resource_claims \[ALPHA\] Number of ResourceClaims, categorized by allocation status/,
                 text)

    idle = registry
    service({"ResourceClaim" => claims}, []).send(:collect_resource_claims, idle)

    refute_includes idle.render, "resourceclaim_controller_resource_claims"
  end

  def test_attach_detach_state
    objects = {
      "Pod" => [{"metadata" => {"name" => "p", "namespace" => "ns"},
                 "spec" => {"nodeName" => "a", "volumes" => [{"name" => "v", "persistentVolumeClaim" => {"claimName" => "c"}}]}, "status" => {"phase" => "Running"}}],
      "PersistentVolumeClaim" => [{"metadata" => {"name" => "c", "namespace" => "ns"}, "spec" => {"volumeName" => "data"}}],
      "PersistentVolume" => [{"metadata" => {"name" => "data"}, "spec" => {"csi" => {"driver" => "d.example", "volumeHandle" => "h"}}}],
      "Node" => [{"metadata" => {"name" => "a", "annotations" => {"volumes.kubernetes.io/controller-managed-attach-detach" => "true"}}}],
      "VolumeAttachment" => [{"metadata" => {"name" => "va"}, "spec" => {"nodeName" => "a", "source" => {"persistentVolumeName" => "data"}},
                              "status" => {"attached" => true}}]
    }
    metrics = registry
    service(objects, ["persistent-volume-attach-detach-controller"]).send(:collect_attach_detach_state, metrics)
    text = metrics.render

    assert_includes text, %(storage_count_attachable_volumes_in_use{node="a",volume_plugin="kubernetes.io/csi:d.example"} 1)
    assert_includes text,
                    %(attachdetach_controller_total_volumes{plugin_name="kubernetes.io/csi:d.example",state="desired_state_of_world"} 1)
    assert_includes text,
                    %(attachdetach_controller_total_volumes{plugin_name="kubernetes.io/csi:d.example",state="actual_state_of_world"} 1)
    assert_match(/^# TYPE attachdetach_controller_total_volumes gauge$/, text)
  end
end
