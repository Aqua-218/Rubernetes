# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/kubelet_metrics"
require "rubernetes/node/resource_metrics"
require "rubernetes/volume/csi"

# The kubelet series wired on 2026-09-29: CSI operation timing, volume
# reconstruction and orphan sweeps, end-to-end volume operations, the
# plugin manager gauge, the metrics provider, and swap on /metrics/resource.
class KubeletMetricsExtrasTest < Minitest::Test
  def value(text, name, **labels)
    found = text.lines.map(&:chomp).find do |entry|
      entry.start_with?("#{name}{", "#{name} ") && labels.all? { |key, item| entry.include?("#{key}=\"#{item}\"") }
    end
    found && found.split[1].to_f
  end

  def metrics
    Rubernetes::Node::KubeletMetrics.new(node_name: "worker-0")
  end

  def test_csi_reconstruction_orphans_and_volume_operations
    km = metrics
    km.csi_operation("hostpath.csi.k8s.io", "NodePublishVolume", "OK", 0.02)
    km.csi_operation("hostpath.csi.k8s.io", "NodeStageVolume", "DEADLINE_EXCEEDED", 30.0)
    km.volume_reconstruction(3, 1)
    km.orphan_pod_volumes(2, 0)
    km.storage_operation("kubernetes.io/csi", "volume_mount", "success", 0.4)
    km.volume_metric_collection("csi", 0.01)
    km.image_volume_mount_failed
    text = km.registry.render

    assert_in_delta(1.0,
                    value(text, "csi_operations_seconds_count", driver_name: "hostpath.csi.k8s.io", grpc_status_code: "OK", method_name: "NodePublishVolume",
                                                                migrated: "false"))
    assert_in_delta(1.0, value(text, "csi_operations_seconds_count", grpc_status_code: "DEADLINE_EXCEEDED", method_name: "NodeStageVolume"))
    assert_in_delta(3.0, value(text, "reconstruct_volume_operations_total"))
    assert_in_delta(1.0, value(text, "reconstruct_volume_operations_errors_total"))
    assert_in_delta(2.0, value(text, "kubelet_orphan_pod_cleaned_volumes"))
    assert_in_delta(0.0, value(text, "kubelet_orphan_pod_cleaned_volumes_errors"))
    assert_in_delta(1.0,
                    value(text, "volume_operation_total_seconds_count", operation_name: "volume_mount", plugin_name: "kubernetes.io/csi"))
    assert_in_delta(1.0,
                    value(text, "storage_operation_duration_seconds_count", operation_name: "volume_mount",
                                                                            volume_plugin: "kubernetes.io/csi"))
    assert_in_delta(1.0, value(text, "kubelet_volume_metric_collection_duration_seconds_count", metric_source: "csi"))
    assert_in_delta(1.0, value(text, "kubelet_image_volume_mounted_errors_total"))
    assert_in_delta(1.0, value(text, "kubelet_metrics_provider", provider: "cadvisor"))
    assert_in_delta(0.0, value(text, "disabled_metrics_total"))
  end

  def test_plugin_manager_gauge_follows_the_registry_directory
    km = metrics
    manager = Object.new
    manager.define_singleton_method(:plugin_states) do
      [["/var/lib/kubelet/plugins_registry/csi.sock", "desired_state_of_world"],
       ["/var/lib/kubelet/plugins_registry/csi.sock", "actual_state_of_world"],
       ["/var/lib/kubelet/plugins_registry/dra.sock", "desired_state_of_world"]]
    end
    km.plugin_manager = manager
    text = km.registry.render

    assert_in_delta(1.0, value(text, "plugin_manager_total_plugins", socket_path: "/var/lib/kubelet/plugins_registry/csi.sock",
                                                                     state: "actual_state_of_world"))
    assert_in_delta(1.0, value(text, "plugin_manager_total_plugins", socket_path: "/var/lib/kubelet/plugins_registry/dra.sock",
                                                                     state: "desired_state_of_world"))
    assert_nil value(text, "plugin_manager_total_plugins", socket_path: "/var/lib/kubelet/plugins_registry/dra.sock",
                                                           state: "actual_state_of_world")
  end

  def test_csi_bridge_times_every_rpc_with_its_status
    client = Object.new
    client.define_singleton_method(:invoke) do |operation, _request, **|
      if operation == "NodeUnpublishVolume"
        raise Rubernetes::Volume::CSIError.new("boom", operation: operation,
                                                       details: {"grpcCode" => "NOT_FOUND"})
      end

      {"capabilities" => []}
    end
    bridge = Rubernetes::Volume::CSIBridge.new(client: client)
    calls = []
    bridge.driver_name = "test.csi"
    bridge.metrics_observer = ->(driver, method_name, code, seconds) { calls << [driver, method_name, code, seconds.class] }
    bridge.node_capabilities
    assert_raises(Rubernetes::Volume::CSIError) { bridge.send(:invoke, "NodeUnpublishVolume", {}) }
    assert_equal [["test.csi", "NodeGetCapabilities", "OK", Float], ["test.csi", "NodeUnpublishVolume", "NOT_FOUND", Float]], calls
  end

  def test_resource_metrics_render_swap
    summary = {"node" => {"swap" => {"time" => "2026-09-29T10:00:00Z", "swapUsageBytes" => 4096}},
               "pods" => [{"podRef" => {"name" => "p", "namespace" => "n"}, "swap" => {"time" => "2026-09-29T10:00:00Z", "swapUsageBytes" => 100},
                           "containers" => [{"name" => "c",
                                             "swap" => {"time" => "2026-09-29T10:00:00Z", "swapUsageBytes" => 60, "swapAvailableBytes" => 40}}]}]}
    text = Rubernetes::Node::ResourceMetrics.render(summary)

    assert_in_delta(4096.0, value(text, "node_swap_usage_bytes"))
    assert_in_delta(100.0, value(text, "pod_swap_usage_bytes", pod: "p", namespace: "n"))
    assert_in_delta(60.0, value(text, "container_swap_usage_bytes", container: "c", pod: "p"))
    assert_in_delta(100.0, value(text, "container_swap_limit_bytes", container: "c", pod: "p"))
    assert_includes text,
                    "# HELP node_swap_usage_bytes [ALPHA] Current swap usage of the node in bytes. Reported only on non-windows systems"
  end
end
