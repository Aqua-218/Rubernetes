# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# kubelet volume metrics: storage_operation_duration_seconds
# (OperationCompleteHook, per plugin / operation / status) observed from the
# Pod volumes' mount and unmount, and volume_manager_total_volumes
# (totalVolumesCollector: desired and actual state per plugin).
class KubeletVolumeMetricsTest < Minitest::Test
  Metrics = Rubernetes::Node::KubeletMetrics

  class Manager
    attr_reader :calls

    def initialize(fail_on: nil)
      @calls = []
      @fail_on = fail_on
      @next = 0
    end

    def root = "/tmp/fake-volume-root"

    def create_volume(spec, token:)
      raise "create failed" if @fail_on == spec["name"]

      @next += 1
      "vol-#{@next}"
    end

    def publish(*, **) = {}
    def stage(*, **) = {}
    def node_publish(*, **) = {}
    def node_unpublish(*, **) = {}
    def unstage(*, **) = {}
    def unpublish(*, **) = {}
    def delete_volume(*, **) = {}
    def direct_path(*, **) = "/direct"
    def method_missing(name, *) = @calls << name
    def respond_to_missing?(*) = true
  end

  def pod
    {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"},
     "spec" => {"volumes" => [{"name" => "tmp", "emptyDir" => {}}, {"name" => "cfg", "configMap" => {"name" => "c"}}]}}
  end

  def test_mount_and_unmount_operations_are_observed_per_plugin
    Dir.mktmpdir do |root|
      observed = []
      volumes = Rubernetes::Node::PodVolumes.new(volume: Manager.new, root: root, reader: Class.new do
        def get(*) = {"data" => {"k" => "v"}}
      end.new)
      volumes.metrics_observer = ->(plugin, operation, status, seconds) { observed << [plugin, operation, status, seconds.class] }
      volumes.stub(:mount, nil) do
        handle = volumes.prepare(pod)
        volumes.release(pod, handle)
      end

      assert_equal [["kubernetes.io/empty-dir", "volume_mount", "success", Float], ["kubernetes.io/configmap", "volume_mount", "success", Float],
                    ["kubernetes.io/configmap", "volume_unmount", "success", Float], ["kubernetes.io/empty-dir", "volume_unmount", "success", Float]],
                   observed
    end
  end

  def test_a_failed_mount_is_observed_as_fail_unknown
    Dir.mktmpdir do |root|
      observed = []
      volumes = Rubernetes::Node::PodVolumes.new(volume: Manager.new(fail_on: "cfg"), root: root, reader: Class.new do
        def get(*) = {"data" => {"k" => "v"}}
      end.new)
      volumes.metrics_observer = ->(plugin, operation, status, _seconds) { observed << [plugin, operation, status] }

      volumes.stub(:mount, nil) do
        assert_raises(StandardError) { volumes.prepare(pod) }
      end
      # The rollback releases what was mounted: an unmount of the first volume.
      assert_equal [["kubernetes.io/empty-dir", "volume_mount", "success"], ["kubernetes.io/configmap", "volume_mount", "fail-unknown"],
                    ["kubernetes.io/empty-dir", "volume_unmount", "success"]], observed
    end
  end

  def test_storage_operation_histogram_and_total_volumes_gauge
    metrics = Metrics.new(node_name: "n")
    metrics.storage_operation("kubernetes.io/csi", "volume_mount", "success", 0.3)
    csi_mount = {"name" => "data", "id" => "v1", "source" => "persistentVolumeClaim", "backend" => "csi",
                 "uniqueName" => "kubernetes.io/csi/d^h"}
    records = [
      # Mounted: in both states.
      {pod: pod.merge("spec" => {"volumes" => [{"name" => "tmp", "emptyDir" => {}}, {"name" => "data", "persistentVolumeClaim" => {"claimName" => "c"}}]}),
       state: "Running", volume: {"mounts" => {"tmp" => {"name" => "tmp", "source" => "emptyDir", "backend" => "emptyDir"}, "data" => csi_mount}},
       cleanup_completed: {}},
      # Admitted, not mounted yet: desired only (the claim resolved to an attachable CSI volume).
      {pod: pod.merge("metadata" => {"uid" => "u2"}, "spec" => {"volumes" => [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "c"}}]}),
       state: "Validated", volume: nil, attachable_volumes: ["kubernetes.io/csi/d^h"], cleanup_completed: {}},
      # Terminated and unmounted: in neither.
      {pod: pod, state: "Removed", volume: {"mounts" => {"tmp" => {"name" => "tmp", "source" => "emptyDir"}}},
       cleanup_completed: {"volume" => true}}
    ]
    text = metrics.render(records)

    assert_match(
      # rubocop:disable-next Layout/LineLength -- the pattern reads better whole
      /storage_operation_duration_seconds_bucket\{[^}]*operation_name="volume_mount"[^}]*status="success"[^}]*volume_plugin="kubernetes.io\/csi"[^}]*le="0.5"\} 1/, text
    )
    assert_match(%r{volume_manager_total_volumes\{plugin_name="kubernetes.io/csi",state="desired_state_of_world"\} 2}, text)
    assert_match(%r{volume_manager_total_volumes\{plugin_name="kubernetes.io/empty-dir",state="desired_state_of_world"\} 1}, text)
    assert_match(%r{volume_manager_total_volumes\{plugin_name="kubernetes.io/csi",state="actual_state_of_world"\} 1}, text)
    assert_match(%r{volume_manager_total_volumes\{plugin_name="kubernetes.io/empty-dir",state="actual_state_of_world"\} 1}, text)
    refute_match(/actual_state_of_world"\} 2/, text)
  end
end
