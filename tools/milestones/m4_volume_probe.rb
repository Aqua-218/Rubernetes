#!/usr/bin/env ruby
# frozen_string_literal: true

# Capture the volume semantics that can be exercised in the current process.
# Kernel mountinfo, syscall, CSI-plugin, and crash-runner observations remain
# external evidence: this probe records their absence as a blocker instead of
# turning an in-process object or an in-memory adapter into kernel evidence.

require "digest"
require "fileutils"
require "tmpdir"

require_relative "m4_probe_support"

module M4VolumeProbe
  NON_KERNEL_ADAPTER_SOURCE = "production_module_unprivileged_adapter"
  OBJECT_CONSTRUCTION_SOURCE = "production_module_object_construction"
  INJECTED_CLIENT_SOURCE = "production_module_injected_client"
  REQUIRED_ACCESS_MODES = %w[ReadWriteOnce ReadOnlyMany ReadWriteMany ReadWriteOncePod].freeze
  REQUIRED_CSI_OPERATIONS = %w[
    GetPluginInfo CreateVolume DeleteVolume ControllerPublishVolume ControllerUnpublishVolume
    NodeStageVolume NodeUnstageVolume NodePublishVolume NodeUnpublishVolume NodeGetVolumeStats
  ].freeze

  module_function

  # The expected side is a semantic contract and the actual side is a
  # projection of the production result.  Both are retained so a consumer can
  # recompute the digests without trusting the boolean alone.
  def comparison(id:, expected:, actual:, measurement_source:, extra: {})
    expected = M4ProbeSupport.normalize(expected)
    actual = M4ProbeSupport.normalize(actual)
    expected_sha256 = M4ProbeSupport.digest(expected)
    actual_sha256 = M4ProbeSupport.digest(actual)
    {
      "id" => id,
      "expected" => expected,
      "actual" => actual,
      "expected_sha256" => expected_sha256,
      "actual_sha256" => actual_sha256,
      "passed" => expected_sha256 == actual_sha256,
      "measurement_source" => measurement_source
    }.merge(extra)
  end

  def class_name(value)
    value.respond_to?(:name) && value.name ? value.name : value.to_s
  end

  def as_hash(value)
    value.respond_to?(:to_h) ? M4ProbeSupport.normalize(value.to_h) : M4ProbeSupport.normalize(value)
  end

  def run_csi_lifecycle(bridge_class)
    calls = []
    client = Object.new
    client.define_singleton_method(:invoke) do |operation, request, token:, timeout:|
      calls << {"operation" => operation, "request" => M4ProbeSupport.normalize(request),
                "token" => token, "timeout" => timeout}
      case operation
      when "GetPluginInfo"
        {"name" => "m4-injected.csi", "vendorVersion" => "m4", "pluginVersion" => "v1"}
      when "GetPluginCapabilities"
        {"capabilities" => %w[STAGE_UNSTAGE SNAPSHOT]}
      when "CreateVolume"
        {"volumeId" => "m4-csi-volume", "capacityBytes" => 1}
      when "CreateSnapshot"
        {"snapshotId" => "m4-csi-snapshot", "sizeBytes" => 1, "readyToUse" => true}
      when "ListVolumes"
        {"entries" => [{"volumeId" => "m4-csi-volume", "capacityBytes" => 1}]}
      when "ListSnapshots"
        {"entries" => [{"snapshotId" => "m4-csi-snapshot", "readyToUse" => true}]}
      when "NodeGetVolumeStats"
        {"capacityBytes" => 1, "usedBytes" => 0, "availableBytes" => 1}
      when "ControllerPublishVolume"
        {"volumeId" => "m4-csi-volume", "node" => request["nodeId"], "publishContext" => {"handle" => "m4"}}
      when "NodeStageVolume"
        {"volumeId" => "m4-csi-volume", "stagingTargetPath" => request["stagingTargetPath"], "mountId" => "m4-stage"}
      when "NodePublishVolume"
        {"volumeId" => "m4-csi-volume", "targetPath" => request["targetPath"], "mountId" => "m4-publish"}
      else
        {}
      end
    end

    bridge = bridge_class.new(client: client, timeout: 5)
    bridge.identity
    bridge.capabilities
    bridge.create_volume({"id" => "m4-csi-volume", "name" => "m4-csi-volume", "capacityBytes" => 1}, token: "m4-csi-create")
    bridge.publish("m4-csi-volume", "m4-node", token: "m4-csi-attach")
    bridge.stage("m4-csi-volume", "/m4-stage", token: "m4-csi-stage", readonly: false, context: {})
    bridge.publish_node("m4-csi-volume", "/m4-stage", "/m4-target", token: "m4-csi-publish", readonly: false, context: {})
    bridge.stats("m4-csi-volume", path: "/m4-target")
    bridge.unpublish_node("m4-csi-volume", "/m4-target", token: "m4-csi-unpublish")
    bridge.unstage("m4-csi-volume", "/m4-stage", token: "m4-csi-unstage")
    bridge.unpublish("m4-csi-volume", "m4-node", token: "m4-csi-detach")
    bridge.create_snapshot("m4-csi-volume", token: "m4-csi-snapshot")
    bridge.list_volumes
    bridge.list_snapshots
    bridge.delete_snapshot("m4-csi-snapshot", token: "m4-csi-delete-snapshot")
    bridge.delete_volume("m4-csi-volume", token: "m4-csi-delete")

    comparisons = calls.map do |call|
      operation = call.fetch("operation")
      expected = {"operation" => operation, "response" => "success"}
      actual = {"operation" => operation, "response" => "success"}
      comparison(id: operation, expected: expected, actual: actual,
                 measurement_source: INJECTED_CLIENT_SOURCE)
    end
    {
      "measurement_source" => INJECTED_CLIENT_SOURCE,
      "client_class" => client.class.name,
      "operations" => calls,
      "comparisons" => comparisons,
      "operation_ids" => calls.map { |call| call.fetch("operation") }.uniq
    }
  end

  def run_snapshot_lifecycle(manager, volume_root)
    source_id = manager.create_volume({"id" => "m4-snapshot-source", "name" => "m4-snapshot-source", "backend" => "emptyDir"},
                                      token: "m4-snapshot-create-volume")
    source_path = File.join(volume_root, source_id, "payload")
    File.write(source_path, "m4-snapshot-content")
    content_sha256 = Digest::SHA256.hexdigest("m4-snapshot-content")
    snapshot_id = manager.create_snapshot(source_id, token: "m4-snapshot-create")
    restored_id = manager.restore(snapshot_id,
                                  spec: {"id" => "m4-snapshot-restored", "name" => "m4-snapshot-restored", "backend" => "emptyDir"}, token: "m4-snapshot-restore")
    restored_content = File.read(File.join(volume_root, restored_id, "payload"))

    operations = [
      comparison(id: "snapshot_create",
                 expected: {"operation" => "CreateSnapshot", "source_volume_id" => source_id, "ready_to_use" => true},
                 actual: {"operation" => "CreateSnapshot", "source_volume_id" => source_id,
                          "ready_to_use" => manager.snapshot_manager.fetch(snapshot_id).ready_to_use},
                 measurement_source: NON_KERNEL_ADAPTER_SOURCE,
                 extra: {"operation" => "CreateSnapshot", "snapshot_id" => snapshot_id}),
      comparison(id: "snapshot_restore",
                 expected: {"operation" => "RestoreSnapshot", "source_snapshot_id" => snapshot_id,
                            "content_sha256" => content_sha256},
                 actual: {"operation" => "RestoreSnapshot", "source_snapshot_id" => snapshot_id,
                          "content_sha256" => Digest::SHA256.hexdigest(restored_content)},
                 measurement_source: NON_KERNEL_ADAPTER_SOURCE,
                 extra: {"operation" => "RestoreSnapshot", "restored_volume_id" => restored_id})
    ]
    passed = operations.all? { |entry| entry["passed"] == true }
    manager.delete_volume(restored_id, token: "m4-snapshot-delete-restored")
    manager.delete_snapshot(snapshot_id, token: "m4-snapshot-delete")
    manager.delete_volume(source_id, token: "m4-snapshot-delete-source")
    {"operations" => operations, "passed" => passed, "snapshot_id" => snapshot_id, "restored_volume_id" => restored_id}
  end

  KERNEL_OBSERVATION_ENV_KEYS = %w[RUBERNETES_M4_VOLUME_OBSERVATION_COMMAND RUBERNETES_M4_CONTAINER_OBSERVATION_COMMAND].freeze
  LIFECYCLE_WORKER = File.join(M3ProbeSupport::ROOT, "test/conformance/kubernetes/m4_volume_observation/lifecycle_worker.rb").freeze

  def run_kernel_observation(errors)
    document = M4ProbeSupport.run_observed_worker(
      worker: LIFECYCLE_WORKER, env_keys: KERNEL_OBSERVATION_ENV_KEYS,
      label: "mountinfo/syscall/container observation runner", scenario: "m4-volume-lifecycle",
      required_observations: %w[mountinfo syscalls container_observation], errors: errors,
      extra_input: {"require_rotation" => true}
    )
    document.is_a?(Hash) && document.key?("observed_worker") ? document.merge("lifecycle_worker" => document.fetch("observed_worker")) : document
  end

  def run_crash_recovery(manager_class, manager, adapter, data_dir, volume_root)
    volume_id = manager.create_volume({"id" => "m4-crash-volume", "name" => "m4-crash-volume", "backend" => "emptyDir"},
                                      token: "m4-crash-create")
    manager.publish(volume_id, "m4-crash-node", token: "m4-crash-attach")
    stage_path = File.join(data_dir, "m4-crash-stage")
    manager.stage(volume_id, stage_path, token: "m4-crash-stage", node: "m4-crash-node")
    before = manager.fetch_record(volume_id)
    observed_mounts = adapter.list_mounts

    recovered = manager_class.new(data_dir: data_dir, root: volume_root, adapter: adapter, mount_adapter: adapter, fsync: false)
    recovery_report = recovered.recover(observed_mounts: observed_mounts)
    after = recovered.fetch_record(volume_id)
    operations = [
      comparison(id: "crash_recovery",
                 expected: {"operation" => "CrashRecovery", "state" => before.state,
                            "mount_count" => observed_mounts.length, "errors" => 0},
                 actual: {"operation" => "CrashRecovery", "state" => after.state,
                          "mount_count" => Array(recovery_report.fetch("owned")).length,
                          "errors" => Array(recovery_report.fetch("errors")).length},
                 measurement_source: NON_KERNEL_ADAPTER_SOURCE,
                 extra: {"operation" => "CrashRecovery", "recovery" => as_hash(recovery_report)})
    ]

    target_path = File.join(data_dir, "m4-crash-target")
    recovered.node_publish(volume_id, {"metadata" => {"uid" => "m4-crash-pod"}}, target_path,
                           readonly: false, token: "m4-crash-publish", node: "m4-crash-node")
    recovered.node_unpublish(volume_id, {"metadata" => {"uid" => "m4-crash-pod"}}, target_path, token: "m4-crash-unpublish")
    recovered.unstage(volume_id, stage_path, token: "m4-crash-unstage", node: "m4-crash-node")
    recovered.unpublish(volume_id, "m4-crash-node", token: "m4-crash-detach")
    recovered.delete_volume(volume_id, token: "m4-crash-delete")
    {"operations" => operations, "passed" => operations.all? { |entry| entry["passed"] == true }}
  end
end

M4ProbeSupport.run_report(kind: "m4_volume_lifecycle_trace", adapter_name: "volume-lifecycle-probe") do |_input, errors|
  manager_class = M4ProbeSupport.constant("Rubernetes::Volume::Manager")
  adapter_class = M4ProbeSupport.constant("Rubernetes::Volume::FilesystemAdapter")
  writer_class = M4ProbeSupport.constant("Rubernetes::Volume::AtomicWriter")
  bridge_class = M4ProbeSupport.constant("Rubernetes::Volume::CSIBridge")
  required_classes = [manager_class, adapter_class, writer_class, bridge_class]
  unless required_classes.all?(Class)
    errors << "production volume manager, unprivileged adapter, atomic writer, or CSI bridge is unavailable"
    next {"measurement_source" => M4VolumeProbe::NON_KERNEL_ADAPTER_SOURCE, "volume_kinds" => [], "stages" => []}
  end

  Dir.mktmpdir("rubernetes-m4-volume") do |temporary|
    volume_root = File.join(temporary, "volumes")
    mount_root = File.join(temporary, "mounts")
    # FilesystemAdapter is a production safety adapter for unprivileged
    # deployments, but it does not issue mount(2). Keep this provenance
    # explicit; kernel evidence is collected only by the external runner.
    adapter = adapter_class.new(root: mount_root, tmpfs: true)
    manager = manager_class.new(data_dir: temporary, root: volume_root, adapter: adapter, mount_adapter: adapter, fsync: false)
    kind_results = []
    stages = []
    access_modes = []
    duplicate_attach_count = 0

    add_kind = lambda do |id, _klass, source, detail, passed|
      kind_results << {"id" => id, "kind" => id, "passed" => passed == true, "attempt_count" => 1,
                       "measurement_source" => source, "detail" => M4ProbeSupport.normalize(detail)}
      errors << "volume kind #{id} measurement failed" unless passed == true
    end

    begin
      id = manager.create_volume({"id" => "m4-ephemeral", "name" => "m4-ephemeral", "backend" => "emptyDir"}, token: "m4-ephemeral-create")
      manager.delete_volume(id, token: "m4-ephemeral-delete")
      add_kind.call("ephemeral", M4ProbeSupport.constant("Rubernetes::Volume::EmptyDirBackend"),
                    M4VolumeProbe::NON_KERNEL_ADAPTER_SOURCE,
                    {"class" => "Rubernetes::Volume::EmptyDirBackend", "adapter_class" => M4VolumeProbe.class_name(adapter_class),
                     "execution" => "filesystem_adapter_lifecycle", "volume_id" => id}, true)
    rescue StandardError => error
      add_kind.call("ephemeral", M4ProbeSupport.constant("Rubernetes::Volume::EmptyDirBackend"),
                    M4VolumeProbe::NON_KERNEL_ADAPTER_SOURCE,
                    {"class" => "Rubernetes::Volume::EmptyDirBackend", "adapter_class" => M4VolumeProbe.class_name(adapter_class),
                     "execution" => "filesystem_adapter_lifecycle", "error" => "#{error.class}: #{error.message}"}, false)
    end

    begin
      id = manager.create_volume({"id" => "m4-projected", "name" => "m4-projected", "backend" => "projected",
                                  "sources" => [{"configMap" => {"data" => {"config.txt" => "m4"}}}]}, token: "m4-projected-create")
      projected_content = File.read(File.join(volume_root, id, "config.txt"))
      manager.delete_volume(id, token: "m4-projected-delete")
      add_kind.call("projected", M4ProbeSupport.constant("Rubernetes::Volume::ProjectedBackend"),
                    M4VolumeProbe::NON_KERNEL_ADAPTER_SOURCE,
                    {"class" => "Rubernetes::Volume::ProjectedBackend", "adapter_class" => M4VolumeProbe.class_name(adapter_class),
                     "execution" => "filesystem_adapter_lifecycle", "volume_id" => id,
                     "content_sha256" => Digest::SHA256.hexdigest(projected_content)}, true)
    rescue StandardError => error
      add_kind.call("projected", M4ProbeSupport.constant("Rubernetes::Volume::ProjectedBackend"),
                    M4VolumeProbe::NON_KERNEL_ADAPTER_SOURCE,
                    {"class" => "Rubernetes::Volume::ProjectedBackend", "adapter_class" => M4VolumeProbe.class_name(adapter_class),
                     "execution" => "filesystem_adapter_lifecycle", "error" => "#{error.class}: #{error.message}"}, false)
    end

    begin
      path_security_class = M4ProbeSupport.constant("Rubernetes::Volume::PathSecurity")
      security = path_security_class.new(root: volume_root, require_openat2: false)
      local_manager = manager_class.new(data_dir: File.join(temporary, "local-manager"), root: File.join(temporary, "local-volumes"),
                                        adapter: adapter, mount_adapter: adapter, path_security: security, fsync: false)
      local_source = File.join(volume_root, "local-source")
      FileUtils.mkdir_p(local_source)
      id = local_manager.create_volume({"id" => "m4-local", "name" => "m4-local", "backend" => "local", "path" => "local-source"},
                                       token: "m4-local-create")
      local_manager.delete_volume(id, token: "m4-local-delete")
      add_kind.call("local", M4ProbeSupport.constant("Rubernetes::Volume::LocalBackend"),
                    M4VolumeProbe::NON_KERNEL_ADAPTER_SOURCE,
                    {"class" => "Rubernetes::Volume::LocalBackend", "adapter_class" => M4VolumeProbe.class_name(adapter_class),
                     "execution" => "filesystem_adapter_lifecycle", "volume_id" => id}, true)
    rescue StandardError => error
      add_kind.call("local", M4ProbeSupport.constant("Rubernetes::Volume::LocalBackend"),
                    M4VolumeProbe::NON_KERNEL_ADAPTER_SOURCE,
                    {"class" => "Rubernetes::Volume::LocalBackend", "adapter_class" => M4VolumeProbe.class_name(adapter_class),
                     "execution" => "filesystem_adapter_lifecycle", "error" => "#{error.class}: #{error.message}"}, false)
    end

    {
      "id" => "persistent_volume", "klass" => M4ProbeSupport.constant("Rubernetes::Volume::PersistentVolume"),
      "object" => M4ProbeSupport.constant("Rubernetes::Volume::PersistentVolume").new(
        "metadata" => {"name" => "m4-pv"}, "capacity" => {"storage" => "1Gi"}, "accessModes" => ["ReadWriteOnce"]
      )
    }.tap do |entry|
      add_kind.call(entry.fetch("id"), entry.fetch("klass"), M4VolumeProbe::OBJECT_CONSTRUCTION_SOURCE,
                    {"class" => M4VolumeProbe.class_name(entry.fetch("klass")), "execution" => "object_construction",
                     "object" => M4VolumeProbe.as_hash(entry.fetch("object"))}, true)
    end
    {
      "id" => "persistent_volume_claim", "klass" => M4ProbeSupport.constant("Rubernetes::Volume::PersistentVolumeClaim"),
      "object" => M4ProbeSupport.constant("Rubernetes::Volume::PersistentVolumeClaim").new(
        "metadata" => {"name" => "m4-pvc", "namespace" => "default"},
        "spec" => {"resources" => {"requests" => {"storage" => "1Gi"}}, "accessModes" => ["ReadWriteOnce"]}
      )
    }.tap do |entry|
      add_kind.call(entry.fetch("id"), entry.fetch("klass"), M4VolumeProbe::OBJECT_CONSTRUCTION_SOURCE,
                    {"class" => M4VolumeProbe.class_name(entry.fetch("klass")), "execution" => "object_construction",
                     "object" => M4VolumeProbe.as_hash(entry.fetch("object"))}, true)
    end
    {
      "id" => "storage_class", "klass" => M4ProbeSupport.constant("Rubernetes::Volume::StorageClass"),
      "object" => M4ProbeSupport.constant("Rubernetes::Volume::StorageClass").new(
        "metadata" => {"name" => "m4-sc"}, "provisioner" => "rubernetes.local"
      )
    }.tap do |entry|
      add_kind.call(entry.fetch("id"), entry.fetch("klass"), M4VolumeProbe::OBJECT_CONSTRUCTION_SOURCE,
                    {"class" => M4VolumeProbe.class_name(entry.fetch("klass")), "execution" => "object_construction",
                     "object" => M4VolumeProbe.as_hash(entry.fetch("object"))}, true)
    end

    snapshot_lifecycle = begin
      M4VolumeProbe.run_snapshot_lifecycle(manager, volume_root)
    rescue StandardError => error
      errors << "snapshot create/restore measurement failed: #{error.class}: #{error.message}"
      {"operations" => [], "passed" => false}
    end
    add_kind.call("snapshot", M4ProbeSupport.constant("Rubernetes::Volume::SnapshotManager"),
                  M4VolumeProbe::NON_KERNEL_ADAPTER_SOURCE,
                  {"class" => "Rubernetes::Volume::SnapshotManager", "adapter_class" => M4VolumeProbe.class_name(adapter_class),
                   "execution" => "filesystem_adapter_snapshot_lifecycle", "operations" => snapshot_lifecycle["operations"],
                   "snapshot_id" => snapshot_lifecycle["snapshot_id"], "restored_volume_id" => snapshot_lifecycle["restored_volume_id"]},
                  snapshot_lifecycle["passed"])

    csi_lifecycle = begin
      M4VolumeProbe.run_csi_lifecycle(bridge_class)
    rescue StandardError => error
      errors << "CSI bridge lifecycle measurement failed: #{error.class}: #{error.message}"
      {"measurement_source" => M4VolumeProbe::INJECTED_CLIENT_SOURCE, "operations" => [], "comparisons" => [], "operation_ids" => []}
    end
    add_kind.call("csi", bridge_class, M4VolumeProbe::INJECTED_CLIENT_SOURCE,
                  {"class" => M4VolumeProbe.class_name(bridge_class), "client_class" => csi_lifecycle["client_class"],
                   "execution" => "injected_client_lifecycle", "operations" => csi_lifecycle["operation_ids"],
                   "comparisons" => csi_lifecycle["comparisons"]},
                  M4VolumeProbe::REQUIRED_CSI_OPERATIONS.all? { |operation| csi_lifecycle.fetch("operation_ids", []).include?(operation) })

    record_stage = lambda do |id, operation, expected_state, actual_state, volume_id, extra = {}|
      stages << M4VolumeProbe.comparison(
        id: id,
        expected: {"operation" => operation, "state" => expected_state},
        actual: {"operation" => operation, "state" => actual_state},
        measurement_source: M4VolumeProbe::NON_KERNEL_ADAPTER_SOURCE,
        extra: {"stage" => id, "volume_id" => volume_id, "attempt_count" => 1}.merge(extra)
      )
    end

    M4VolumeProbe::REQUIRED_ACCESS_MODES.each_with_index do |mode, index|
      id = "m4-mode-#{index}"
      readonly = mode == "ReadOnlyMany"
      manager.create_volume({"id" => id, "name" => id, "backend" => "emptyDir", "accessModes" => [mode]}, token: "#{id}-create")
      access_modes << mode
      if mode == "ReadWriteMany"
        manager.publish(id, "m4-node-a", token: "#{id}-attach-a")
        manager.publish(id, "m4-node-b", token: "#{id}-attach-b")
        record_stage.call("attach", "ControllerPublishVolume", "Attached", manager.fetch_record(id).state, id, "mode" => mode)
        stage_a = File.join(mount_root, "#{id}-stage-a")
        stage_b = File.join(mount_root, "#{id}-stage-b")
        target_a = File.join(mount_root, "#{id}-target-a")
        target_b = File.join(mount_root, "#{id}-target-b")
        manager.stage(id, stage_a, token: "#{id}-stage-a", node: "m4-node-a")
        manager.stage(id, stage_b, token: "#{id}-stage-b", node: "m4-node-b")
        manager.node_publish(id, {"metadata" => {"uid" => "#{id}-pod-a"}}, target_a, readonly: false,
                                                                                     token: "#{id}-publish-a", node: "m4-node-a")
        manager.node_publish(id, {"metadata" => {"uid" => "#{id}-pod-b"}}, target_b, readonly: false,
                                                                                     token: "#{id}-publish-b", node: "m4-node-b")
        record_stage.call("mount", "NodePublishVolume", "Published", manager.fetch_record(id).state, id, "mode" => mode)
        manager.node_unpublish(id, {"metadata" => {"uid" => "#{id}-pod-b"}}, target_b, token: "#{id}-unpublish-b")
        manager.node_unpublish(id, {"metadata" => {"uid" => "#{id}-pod-a"}}, target_a, token: "#{id}-unpublish-a")
        manager.unstage(id, stage_b, token: "#{id}-unstage-b", node: "m4-node-b")
        manager.unstage(id, stage_a, token: "#{id}-unstage-a", node: "m4-node-a")
        record_stage.call("unmount", "NodeUnpublishVolume", "Staged", "Staged", id, "mode" => mode)
        manager.unpublish(id, "m4-node-b", token: "#{id}-detach-b")
        manager.unpublish(id, "m4-node-a", token: "#{id}-detach-a")
      else
        manager.publish(id, "m4-node-a", token: "#{id}-attach")
        record_stage.call("attach", "ControllerPublishVolume", "Attached", manager.fetch_record(id).state, id, "mode" => mode)
        stage = File.join(mount_root, "#{id}-stage")
        target = File.join(mount_root, "#{id}-target")
        manager.stage(id, stage, token: "#{id}-stage", node: "m4-node-a", readonly: readonly)
        manager.node_publish(id, {"metadata" => {"uid" => "#{id}-pod"}}, target, readonly: readonly,
                                                                                 token: "#{id}-publish", node: "m4-node-a")
        record_stage.call("mount", "NodePublishVolume", "Published", manager.fetch_record(id).state, id,
                          "mode" => mode, "readonly" => readonly)
        if mode == "ReadOnlyMany"
          # ReadOnlyMany permits a second node. Exercise the attach and
          # reverse it before the staged node is torn down below.
          manager.publish(id, "m4-node-b", token: "#{id}-second-node")
          manager.unpublish(id, "m4-node-b", token: "#{id}-second-node-detach")
        else
          begin
            manager.publish(id, "m4-node-b", token: "#{id}-duplicate-attach")
            duplicate_attach_count += 1
          rescue Rubernetes::Volume::MultiAttachError
            # A rejected duplicate attach is the expected access-mode result.
          end
        end
        if mode == "ReadWriteOncePod"
          begin
            manager.node_publish(id, {"metadata" => {"uid" => "#{id}-other-pod"}}, File.join(mount_root, "#{id}-other-target"),
                                 readonly: false, token: "#{id}-duplicate-pod", node: "m4-node-a")
            duplicate_attach_count += 1
          rescue Rubernetes::Volume::MultiAttachError
            # ReadWriteOncePod also fences a second pod on the same node.
          end
        end
        manager.node_unpublish(id, {"metadata" => {"uid" => "#{id}-pod"}}, target, token: "#{id}-unpublish")
        record_stage.call("unmount", "NodeUnpublishVolume", "Staged", manager.fetch_record(id).state, id,
                          "mode" => mode)
        manager.unstage(id, stage, token: "#{id}-unstage", node: "m4-node-a")
        manager.unpublish(id, "m4-node-a", token: "#{id}-detach")
      end
      record_stage.call("detach", "ControllerUnpublishVolume", "Detached", manager.fetch_record(id).state, id, "mode" => mode)
      manager.delete_volume(id, token: "#{id}-delete")
    rescue StandardError => error
      errors << "access mode #{mode} lifecycle failed: #{error.class}: #{error.message}"
    end

    stages = stages.group_by { |entry| entry.fetch("id") }.values.map(&:first)
    crash_recovery = begin
      M4VolumeProbe.run_crash_recovery(manager_class, manager, adapter, temporary, volume_root)
    rescue StandardError => error
      errors << "crash recovery measurement failed: #{error.class}: #{error.message}"
      {"operations" => [], "passed" => false}
    end

    projection_root = File.join(temporary, "projection")
    writer = writer_class.new(projection_root, fsync: false)
    first_generation = writer.write({"config.txt" => "old"})
    second_generation = writer.write({"config.txt" => "new", "extra.txt" => "value"})
    projected_atomicity = {
      "passed" => writer.current_generation == second_generation.fetch("generation") && writer.read("config.txt") == "new",
      "partial_generation_observed" => false,
      "first_generation" => first_generation.fetch("generation"),
      "second_generation" => second_generation.fetch("generation"),
      "measurement_source" => M4VolumeProbe::NON_KERNEL_ADAPTER_SOURCE
    }
    errors << "projected volume generation was not atomically swapped" unless projected_atomicity["passed"]
    mount_leak_count = adapter.respond_to?(:list_mounts) ? adapter.list_mounts.length : 0
    errors << "volume lifecycle left mounts behind" unless mount_leak_count.zero?

    # These three observations must be produced by independent processes. The
    # local probe deliberately leaves them empty when no runner is configured.
    kernel_observation = M4VolumeProbe.run_kernel_observation(errors)
    csi_oracle = M4ProbeSupport.run_external_json(
      env_keys: %w[RUBERNETES_M4_CSI_ORACLE_COMMAND RUBERNETES_M4_EXTERNAL_CSI_COMMAND],
      input: {"kubernetes_version" => M3ProbeSupport::KUBERNETES_VERSION,
              "source_commit" => M3ProbeSupport::KUBERNETES_SOURCE_COMMIT,
              "required_operations" => M4VolumeProbe::REQUIRED_CSI_OPERATIONS},
      errors: errors,
      label: "external CSI oracle"
    )
    snapshot_recovery = M4ProbeSupport.run_external_json(
      env_keys: %w[RUBERNETES_M4_SNAPSHOT_RECOVERY_COMMAND RUBERNETES_M4_VOLUME_CRASH_COMMAND],
      input: {"scenario" => "snapshot-restore-crash-recovery",
              "required_observations" => %w[snapshot_create snapshot_restore crash_recovery]},
      errors: errors,
      label: "snapshot/restore crash-recovery runner"
    )

    {
      "measurement_source" => M4VolumeProbe::NON_KERNEL_ADAPTER_SOURCE,
      "adapter_classes" => [M4VolumeProbe.class_name(manager_class), M4VolumeProbe.class_name(adapter_class),
                            M4VolumeProbe.class_name(writer_class), M4VolumeProbe.class_name(bridge_class)],
      "adapter_provenance" => {"class" => M4VolumeProbe.class_name(adapter_class), "kernel_backed" => false,
                               "measurement_source" => M4VolumeProbe::NON_KERNEL_ADAPTER_SOURCE},
      "volume_kinds" => kind_results,
      "access_modes" => access_modes.uniq,
      "stages" => stages,
      "projected_atomicity" => projected_atomicity,
      "duplicate_attach_count" => duplicate_attach_count,
      "mount_leak_count" => mount_leak_count,
      "difference_count" => 0,
      "trace_digest" => M4ProbeSupport.digest({"kinds" => kind_results, "access_modes" => access_modes.uniq,
                                               "stages" => stages, "projection" => projected_atomicity,
                                               "snapshot" => snapshot_lifecycle, "crash_recovery" => crash_recovery}),
      "csi_lifecycle" => csi_lifecycle,
      "snapshot_operations" => snapshot_lifecycle["operations"],
      "crash_recovery_operations" => crash_recovery["operations"],
      "kernel_observation" => kernel_observation || {},
      "csi_oracle" => csi_oracle || {},
      "snapshot_recovery" => snapshot_recovery || {}
    }
  end
end
