# frozen_string_literal: true

module Conformance
  module K3CSISnapshotFixture
    SNAPSHOT_ADDON = "cluster/addons/volumesnapshots"
    SNAPSHOT_RESOURCES = %w[volumesnapshotclasses volumesnapshotcontents volumesnapshots].freeze
    SNAPSHOT_CONTROLLER_ACCOUNT = "snapshot-controller"

    private

    def publish_snapshot_objects
      crds = SNAPSHOT_RESOURCES.map do |kind|
        name = "snapshot.storage.k8s.io_#{kind}.yaml"
        definition = YAML.safe_load(pinned_source("#{SNAPSHOT_ADDON}/crd/#{name}"))
        create(definition)
        "crd/#{definition.dig("metadata", "name")}"
      end
      kubectl!("wait", "--for=condition=Established", "--timeout=90s", *crds)
      kubectl!("create", "serviceaccount", SNAPSHOT_CONTROLLER_ACCOUNT, "-n", @name)
      role = pinned_source("#{SNAPSHOT_ADDON}/volume-snapshot-controller/rbac-volume-snapshot-controller.yaml")
      publish_role("snapshot-controller", role, service_account: SNAPSHOT_CONTROLLER_ACCOUNT)
      publish_role("csi-snapshotter", pinned_manifest("external-snapshotter/csi-snapshotter/rbac-csi-snapshotter.yaml"))
    end

    def start_snapshot_controllers(directory, sidecar_config)
      controller_config = service_account_kubeconfig(directory, SNAPSHOT_CONTROLLER_ACCOUNT)
      start("snapshot-controller", "--kubeconfig=#{controller_config}", "--leader-election=false")
      start("csi-snapshotter", "--kubeconfig=#{sidecar_config}", "--leader-election=false", "--csi-address=#{@socket}", "--timeout=120s")
    end

    def wait_for_snapshot_deletion
      report = File.join(@reports, "snapshots-cleanup.json")
      K7ClusterDriver.wait_until("snapshot contents deletion", 180) do
        contents = driver_objects("volumesnapshotcontents", "driver")
        File.write(report, JSON.generate("volumeSnapshotContents" => contents))
        contents.empty?
      end
    end
  end
end
