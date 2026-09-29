# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes"
require "rubernetes/bootstrap"
require "rubernetes/observability/metrics"

# persistentvolume/metrics pvAndPVCCountCollector (v1.36.2), read from the
# controller manager's informer caches at scrape time.
class PVCollectorMetricsTest < Minitest::Test
  class Store
    def initialize(volumes, claims) = (@volumes, @claims = volumes, claims)
    def list(kind, namespace: :all) = kind == "PersistentVolume" ? @volumes : @claims
  end

  def test_counts_by_class_plugin_and_binding
    volumes = [{"spec" => {"storageClassName" => "fast", "csi" => {"driver" => "d.example"}, "volumeMode" => "Block"}, "status" => {"phase" => "Bound"}},
               {"spec" => {"storageClassName" => "", "hostPath" => {"path" => "/x"}}, "status" => {"phase" => "Available"}}]
    claims = [{"metadata" => {"namespace" => "ns", "annotations" => {"volume.beta.kubernetes.io/storage-class" => "legacy"}},
               "spec" => {"storageClassName" => "fast"}, "status" => {"phase" => "Pending"}}]
    service = Rubernetes::Bootstrap::ControllerManagerService.allocate
    service.instance_variable_set(:@store, Store.new(volumes, claims))
    registry = Rubernetes::Observability::Metrics.new(apiserver: false, process: false, component: "kube-controller-manager")
    service.send(:collect_persistent_volumes, registry)
    text = registry.render
    assert_includes text, %(pv_collector_bound_pv_count{storage_class="fast"} 1)
    assert_includes text, %(pv_collector_unbound_pv_count{storage_class=""} 1)
    assert_includes text, %(pv_collector_total_pv_count{plugin_name="kubernetes.io/csi:d.example",volume_mode="Block"} 1)
    assert_includes text, %(pv_collector_total_pv_count{plugin_name="kubernetes.io/host-path",volume_mode="Filesystem"} 1)
    assert_includes text, %(pv_collector_unbound_pvc_count{namespace="ns",storage_class="legacy",volume_attributes_class=""} 1),
                    "the beta annotation wins over spec.storageClassName"
    service.instance_variable_set(:@store, Store.new([], []))
    service.send(:collect_persistent_volumes, registry)
    refute_includes registry.render, "pv_collector_bound_pv_count{"
  end
end
