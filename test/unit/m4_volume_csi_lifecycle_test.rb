# frozen_string_literal: true

# Volume lifecycle contract tests.
# Specification: spec/node/volume.md §5.11.1–§5.11.2 and
# spec/delivery/milestones.md M4 exit criteria 5–6.
# Coverage: CSI context propagation, durable snapshot reconciliation,
# fail-closed built-in media, and restart ownership fencing.

require_relative "../test_helper"
require "rubernetes/volume"
require "tmpdir"

class M4VolumeCsiLifecycleTest < Minitest::Test
  class CSI
    attr_reader :calls

    def initialize
      @calls = []
      @publish_generation = 0
    end

    def identity
      Rubernetes::Volume::Identity.new(name: "example.csi", vendor_version: "test")
    end

    def create_volume(spec, token:)
      @calls << [:create, spec, token]
      {"volumeId" => "remote-volume", "volumeContext" => {"device" => "pci-1", "fsType" => "ext4"}}
    end

    def delete_volume(id, token:, secrets: {})
      @calls << [:delete, id, token, secrets]
      {}
    end

    def publish(id, node, token:, readonly: false, context: {})
      @publish_generation += 1
      result = {"volumeId" => id, "node" => node, "publishContext" => {"handle" => "h#{@publish_generation}"}}
      @calls << [:publish, id, node, token, readonly, context, result]
      result
    end

    def unpublish(id, node, token:, context: {})
      @calls << [:unpublish, id, node, token, context]
      {}
    end

    def stage(id, path, token:, readonly:, context:)
      @calls << [:stage, id, path, token, readonly, context]
      {"volumeId" => id, "target" => path, "mountId" => "11", "deviceId" => "0:11", "root" => "/",
       "filesystem" => "ext4", "source" => "/dev/test"}
    end

    def unstage(id, path, token:)
      @calls << [:unstage, id, path, token]
      {}
    end

    def publish_node(id, stage_path, target, token:, readonly:, context:)
      @calls << [:publish_node, id, stage_path, target, token, readonly, context]
      {"volumeId" => id, "target" => target, "mountId" => "12", "deviceId" => "0:12", "root" => "/",
       "filesystem" => "bind", "source" => stage_path}
    end

    def unpublish_node(id, target, token:)
      @calls << [:unpublish_node, id, target, token]
      {}
    end

    def create_snapshot(id, token:, name: nil)
      @calls << [:snapshot, id, token, name]
      {"snapshotId" => "snap-1", "sizeBytes" => 1, "readyToUse" => true}
    end

    def list_snapshots
      {"entries" => []}
    end
  end

  # Adversarial adapter used to prove that an exception from each node-side
  # CSI RPC still runs the descriptor lease identity check. The callback
  # replaces the user-visible leaf before returning an error; CSI only sees
  # the held /proc fd path.
  class LeaseFaultCSI < CSI
    attr_accessor :fault, :fault_path

    def stage(id, path, token:, readonly:, context:)
      fault_if!(:stage, path)
      super
    end

    def unstage(id, path, token:)
      fault_if!(:unstage, path)
      super
    end

    def publish_node(id, stage_path, target, token:, readonly:, context:)
      fault_if!(:publish, target)
      super
    end

    def unpublish_node(id, target, token:)
      fault_if!(:unpublish, target)
      super
    end

    def expand(_id, capacity, token:, secrets: {}, volume_capability: nil)
      fault_if!(:expand, fault_path)
      {"capacityBytes" => capacity, "nodeExpansionRequired" => true}
    end

    def expand_node(_id, path, token:, capacity_bytes: nil, volume_capability: nil, secrets: {})
      fault_if!(:expand_node, path)
      {"capacityBytes" => capacity_bytes}
    end

    def stats(_id, path:)
      fault_if!(:stats, path)
      {"capacityBytes" => 1, "usedBytes" => 0, "availableBytes" => 1}
    end

    private

    def fault_if!(operation, dispatch_path)
      return unless fault == operation

      original = File.realpath(dispatch_path.to_s)
      held = "#{original}.m4-held"
      outside = "#{original}.m4-outside"
      File.rename(original, held)
      if File.directory?(held)
        FileUtils.mkdir_p(outside)
      else
        File.write(outside, "outside")
      end
      File.symlink(outside, original)
      raise Rubernetes::Volume::CSIError.new(
        "simulated #{operation} response failure", operation: operation.to_s, ambiguous: false
      )
    end
  end

  class NoTmpfsAdapter
    def mkdir(path, mode: 0o755)
      FileUtils.mkdir_p(path)
      File.chmod(mode, path)
      true
    end
  end

  class KernelReadback
    def initialize
      @mounts = {}
      @next_mount_id = 100
    end

    def add(target, source: "tmpfs", filesystem: "tmpfs")
      @next_mount_id += 1
      resolved_target = canonical_target(target)
      @mounts[resolved_target] = {
        "mountId" => @next_mount_id.to_s, "deviceId" => "0:#{@next_mount_id}", "root" => "/",
        "source" => source, "target" => resolved_target, "filesystem" => filesystem,
        "filesystemUuid" => nil, "filesystemUuidAvailable" => false, "options" => "rw"
      }
    end

    def remove(target)
      @mounts.delete(canonical_target(target))
    end

    def find_mount(target)
      @mounts[canonical_target(target)]&.dup
    end

    def list_mounts
      @mounts.values.map(&:dup)
    end

    private

    # A real mount performed through /proc/<pid>/fd/<fd> is reported by
    # mountinfo at the descriptor's original mountpoint, not at the procfs
    # alias. Mirror that kernel readback behavior in this fake.
    def canonical_target(target)
      File.realpath(target.to_s)
    rescue SystemCallError
      File.expand_path(target.to_s)
    end
  end

  class EffectCSI < CSI
    attr_accessor :stage_readback, :publish_readback, :unpublish_readback, :unstage_readback
    attr_reader :mutations

    def initialize(readback)
      super()
      @readback = readback
      @stage_readback = true
      @publish_readback = true
      @unpublish_readback = true
      @unstage_readback = true
      @mutations = []
      @lost_responses = {}
      @capacity = 1
    end

    def lose_next_response(operation)
      @lost_responses[operation.to_sym] = true
    end

    def stage(id, path, token:, readonly:, context:)
      # The plugin receives the canonical target; record the inode-resolved
      # path exactly as a driver would see it.
      @mutations << [:stage, path, File.realpath(path)]
      @readback.add(path) if stage_readback
      result = super
      lose_response!(:stage)
      result
    end

    def publish_node(id, stage_path, target, token:, readonly:, context:)
      @mutations << [:publish, target]
      @readback.add(target, source: stage_path, filesystem: "bind") if publish_readback
      result = super
      lose_response!(:publish)
      result
    end

    def unpublish_node(id, target, token:)
      @mutations << [:unpublish, target]
      @readback.remove(target) if unpublish_readback
      result = super
      lose_response!(:unpublish)
      result
    end

    def unstage(id, path, token:)
      @mutations << [:unstage, path]
      @readback.remove(path) if unstage_readback
      result = super
      lose_response!(:unstage)
      result
    end

    def list_volumes
      {"entries" => [{"volumeId" => "remote-volume", "capacityBytes" => @capacity}]}
    end

    def expand(id, capacity, token:, secrets: {}, volume_capability: nil)
      @capacity = capacity
      @mutations << [:expand, id, capacity]
      {"capacityBytes" => capacity, "nodeExpansionRequired" => true}
    end

    def expand_node(id, path, token:, capacity_bytes: nil, volume_capability: nil)
      leased_target = File.realpath(path)
      @mutations << [:expand_node, id, path, capacity_bytes, volume_capability, leased_target]
      lose_response!(:expand_node)
      {"capacityBytes" => capacity_bytes}
    end

    private

    def lose_response!(operation)
      return unless @lost_responses.delete(operation)

      raise Rubernetes::Volume::CSIError.new(
        "simulated #{operation} response loss", operation: operation.to_s, ambiguous: true
      )
    end
  end

  class ControllerFaultCSI
    attr_reader :calls, :max_snapshots

    def initialize
      @calls = []
      @volumes = {}
      @snapshots = {}
      @lost_responses = {}
      @max_snapshots = 0
    end

    def identity
      Rubernetes::Volume::Identity.new(name: "example.csi", vendor_version: "fault-test")
    end

    def lose_next_response(operation)
      @lost_responses[operation.to_sym] = true
    end

    def create_volume(spec, token:)
      name = spec.fetch("name")
      volume = @volumes[name] ||= {"volumeId" => "driver-#{name}", "capacityBytes" => spec.fetch("capacityBytes")}
      @calls << [:create_volume, volume.fetch("volumeId"), token]
      lose_response!(:create_volume)
      volume.dup
    end

    def delete_volume(id, token:, secrets: {})
      @volumes.delete_if { |_name, volume| volume.fetch("volumeId") == id }
      @calls << [:delete_volume, id, token, secrets]
      lose_response!(:delete_volume)
      {}
    end

    def publish(id, node, token:, readonly: false, context: {})
      volume = volume_by_id(id)
      volume["publishedNodeIds"] ||= []
      volume["publishedNodeIds"] |= [node]
      @calls << [:publish, id, node, token, readonly, context]
      lose_response!(:publish)
      {"volumeId" => id, "publishContext" => {"attachment" => "#{id}@#{node}"}}
    end

    def unpublish(id, node, token:, context: {})
      volume_by_id(id)["publishedNodeIds"] = Array(volume_by_id(id)["publishedNodeIds"]) - [node]
      @calls << [:unpublish, id, node, token, context]
      lose_response!(:unpublish)
      {}
    end

    def create_snapshot(id, token:, name: nil, secrets: {})
      snapshot_name = name || "snapshot-#{id}-#{token}"
      snapshot = @snapshots[snapshot_name] ||= {
        "snapshotId" => "driver-#{snapshot_name}", "sourceVolumeId" => id,
        "sizeBytes" => 64, "readyToUse" => true
      }
      @max_snapshots = [@max_snapshots, @snapshots.length].max
      @calls << [:create_snapshot, id, token, name, secrets]
      lose_response!(:create_snapshot)
      snapshot.dup
    end

    def delete_snapshot(id, token: nil, secrets: {})
      @snapshots.delete_if { |_name, snapshot| snapshot.fetch("snapshotId") == id }
      @calls << [:delete_snapshot, id, token, secrets]
      lose_response!(:delete_snapshot)
      {}
    end

    def expand(id, capacity, token:, secrets: {}, volume_capability: nil)
      volume_by_id(id)["capacityBytes"] = capacity
      @calls << [:expand, id, capacity, token, secrets, volume_capability]
      lose_response!(:expand)
      {"capacityBytes" => capacity}
    end

    def list_volumes
      {"entries" => @volumes.values.map do |volume|
        volume.slice("volumeId", "capacityBytes").merge(
          "status" => {"publishedNodeIds" => Array(volume["publishedNodeIds"])}
        )
      end}
    end

    def list_snapshots
      {"entries" => @snapshots.values.map(&:dup)}
    end

    private

    def volume_by_id(id)
      @volumes.values.find { |volume| volume.fetch("volumeId") == id } || raise("missing driver volume #{id}")
    end

    def lose_response!(operation)
      return unless @lost_responses.delete(operation)

      raise Rubernetes::Volume::CSIError.new(
        "simulated #{operation} response loss", operation: operation.to_s, ambiguous: true
      )
    end
  end

  class OneShotFailingSnapshotStore
    def initialize
      @values = {}
      @fail_next_write = true
    end

    def []=(id, value)
      if @fail_next_write
        @fail_next_write = false
        raise Rubernetes::Volume::JournalError, "simulated snapshot fsync failure"
      end
      @values[id.to_s] = value
    end

    def fetch(id, &)
      @values.fetch(id.to_s, &)
    end

    def delete(id)
      @values.delete(id.to_s)
    end

    def values
      @values.values
    end
  end

  class ObservationFailCSI < ControllerFaultCSI
    attr_accessor :fail_delete_snapshot, :fail_list_volumes, :fail_list_snapshots, :leaked_message

    def delete_snapshot(id, token: nil, secrets: {})
      raise Rubernetes::Volume::CSIError, (leaked_message || "DeleteSnapshot unavailable") if fail_delete_snapshot

      super
    end

    def list_volumes
      raise Rubernetes::Volume::CSIError, (leaked_message || "ListVolumes unavailable") if fail_list_volumes

      super
    end

    def list_snapshots(**_options)
      raise Rubernetes::Volume::CSIError, (leaked_message || "ListSnapshots unavailable") if fail_list_snapshots

      super()
    end
  end

  def setup
    @directory = Dir.mktmpdir("m4-csi-lifecycle")
  end

  def teardown
    FileUtils.remove_entry(@directory) if File.exist?(@directory)
  end

  # Requirement: ControllerPublishVolume's result is node-scoped and the
  # exact volume/publish context is forwarded to NodeStage/NodePublish.
  def test_controller_publish_context_survives_restart_and_old_node_context_is_removed
    csi = CSI.new
    resolver = lambda do |reference, volume_id:, purpose:|
      raise "unexpected secret reference" unless reference == {"name" => "remote-credentials"}
      raise "missing resolver context" if volume_id.empty? || purpose.empty?

      {"token" => "secret"}
    end
    manager = Rubernetes::Volume::Manager.new(data_dir: @directory, csi: csi, secret_resolver: resolver, fsync: true)
    id = manager.create_volume({"name" => "remote", "csi" => {"driver" => "example.csi"},
                                "accessModes" => ["ReadWriteOnce"],
                                "secretRef" => {"name" => "remote-credentials"}}, token: "create")

    manager.controller.publish(id, "node-a", token: "attach-a")
    manager = Rubernetes::Volume::Manager.new(data_dir: @directory, csi: csi, secret_resolver: resolver, fsync: true)
    manager.node.stage(id, File.join(@directory, "stage-a"), token: "stage-a", node: "node-a")
    stage_context = csi.calls.reverse.find { |call| call.first == :stage }.fetch(5)

    assert_equal({"device" => "pci-1", "fsType" => "ext4"}, stage_context.fetch("volumeContext"))
    assert_equal({"handle" => "h1"}, stage_context.fetch("publishContext"))
    assert_equal({"token" => "secret"}, stage_context.fetch("secrets"))
    assert_equal ["ReadWriteOnce"], stage_context.fetch("accessModes")

    # ControllerUnpublish removes node-a's context. Reattaching node-a must
    # use the new plugin result, not the old publishContext.
    manager.node.unstage(id, File.join(@directory, "stage-a"), token: "unstage-a", node: "node-a")
    manager.controller.unpublish(id, "node-a", token: "detach-a")
    manager.controller.publish(id, "node-a", token: "attach-a-2")
    manager.node.stage(id, File.join(@directory, "stage-b"), token: "stage-b", node: "node-a")
    second_context = csi.calls.reverse.find { |call| call.first == :stage }.fetch(5)

    assert_equal({"handle" => "h2"}, second_context.fetch("publishContext"))
    refute_equal "h1", second_context.fetch("publishContext").fetch("handle")
  end

  # Requirement: acknowledged snapshot metadata is durable, and absence from
  # CSI ListSnapshots fences restore as Unknown rather than deleting locally.
  def test_snapshot_store_is_durable_and_list_snapshots_marks_missing_remote_object_unknown
    csi = CSI.new
    first = Rubernetes::Volume::Manager.new(data_dir: @directory, csi: csi, fsync: true)
    volume_id = first.create_volume({"name" => "remote", "csi" => {"driver" => "example.csi"}}, token: "create")
    snapshot_id = first.create_snapshot(volume_id, token: "snapshot")

    assert_equal snapshot_id, first.list_snapshots.first.id

    restarted = Rubernetes::Volume::Manager.new(data_dir: @directory, csi: csi, fsync: true)

    assert_equal snapshot_id, restarted.list_snapshots.first.id
    report = restarted.recover

    assert_includes report.unknown.map { |entry| entry["id"] }, snapshot_id
    assert_raises(Rubernetes::Volume::StateUnknownError) do
      restarted.restore(snapshot_id, spec: {"name" => "restore", "csi" => {"driver" => "example.csi"}}, token: "restore")
    end
  end

  # Requirement: a node may host built-in and CSI snapshots concurrently.
  # CSI discovery is authoritative only for records owned by a CSI backend.
  def test_builtin_snapshot_is_not_dispatched_to_or_fenced_by_global_csi
    csi = CSI.new
    first = Rubernetes::Volume::Manager.new(data_dir: @directory, csi: csi, fsync: true)
    volume_id = first.create_volume({"name" => "scratch", "emptyDir" => {}}, token: "create-local")
    snapshot_id = first.create_snapshot(volume_id, token: "snapshot-local")

    refute(csi.calls.any? { |call| call.first == :snapshot })
    snapshot = first.list_snapshots.find { |candidate| candidate.id == snapshot_id }

    assert_equal false, snapshot.metadata.fetch("remote")
    assert_equal "emptyDir", snapshot.metadata.fetch("backend")

    restarted = Rubernetes::Volume::Manager.new(data_dir: @directory, csi: csi, fsync: true)
    report = restarted.recover

    refute_includes report.unknown.map { |entry| entry["id"] }, snapshot_id
    restored = restarted.list_snapshots.find { |candidate| candidate.id == snapshot_id }

    assert restored.ready_to_use
    refute_equal "Unknown", restored.metadata["state"]
  end

  # Requirement: emptyDir medium Memory must never silently become a disk
  # directory when the node cannot establish tmpfs.
  def test_emptydir_memory_fails_closed_without_tmpfs_adapter
    backend = Rubernetes::Volume::EmptyDirBackend.new(
      id: "memory", spec: {"backend" => "emptyDir", "medium" => "Memory"},
      adapter: NoTmpfsAdapter.new, mount_adapter: NoTmpfsAdapter.new, root: File.join(@directory, "volumes")
    )
    assert_raises(Rubernetes::Volume::UnsupportedError) { backend.provision }
  end

  # Requirement: CSI restore and clone are CreateVolume content-source
  # operations; no local generic restore/clone effect is issued afterwards.
  def test_csi_restore_and_clone_use_create_volume_content_source
    csi = CSI.new
    manager = Rubernetes::Volume::Manager.new(data_dir: @directory, csi: csi, fsync: true)
    source_id = manager.create_volume({"name" => "source", "csi" => {"driver" => "example.csi"}}, token: "source")
    snapshot_id = manager.create_snapshot(source_id, token: "snapshot")
    restored = manager.restore(snapshot_id, spec: {"name" => "restored", "csi" => {"driver" => "example.csi"}}, token: "restore")
    cloned = manager.clone(source_id, spec: {"name" => "clone", "csi" => {"driver" => "example.csi"}}, token: "clone")

    refute_equal source_id, restored
    refute_equal source_id, cloned
    creates = csi.calls.select { |call| call.first == :create }

    assert_equal "snap-1", creates[-2][1].fetch("sourceSnapshotId")
    assert_equal "remote-volume", creates[-1][1].fetch("cloneSourceId")
  end

  # Requirement: backend reconstruction failure after restart is durable
  # Unknown and blocks mutations instead of surfacing a missing-hash error.
  def test_backend_reconstruction_failure_fences_volume_unknown
    csi = CSI.new
    manager = Rubernetes::Volume::Manager.new(data_dir: @directory, csi: csi, fsync: true)
    id = manager.create_volume({"name" => "remote", "csi" => {"driver" => "example.csi"}}, token: "create")

    restarted = Rubernetes::Volume::Manager.new(data_dir: @directory, fsync: true)

    assert_equal "Unknown", restarted.fetch_record(id).state
    assert_raises(Rubernetes::Volume::StateUnknownError) { restarted.delete_volume(id, token: "delete") }
  end

  # Requirement: an RPC that was sent cannot be downgraded to a deterministic
  # failure when independent readback fails. The durable effect marker must
  # produce OperationUnknown and fence the volume across restart.
  def test_stage_rpc_followed_by_missing_readback_is_durably_unknown
    readback = KernelReadback.new
    csi = EffectCSI.new(readback)
    csi.stage_readback = false
    manager, id = strict_csi_manager(csi, readback, suffix: "stage")
    stage = File.join(@directory, "stage-fault")

    assert_raises(Rubernetes::Volume::OperationUnknown) do
      manager.node.stage(id, stage, token: "stage-fault", node: "node-a")
    end
    stage_call = csi.mutations.find { |call| call.first == :stage }

    assert_equal stage, stage_call.fetch(1)
    assert_equal File.realpath(File.dirname(stage)).then { |parent| File.join(parent, File.basename(stage)) }, stage_call.fetch(2)
    assert_equal "Unknown", manager.fetch_record(id).state
    assert_equal "unknown", manager.operations.entries.find { |entry| entry.operation.start_with?("stage:") }.status

    restarted = Rubernetes::Volume::Manager.new(
      data_dir: File.join(@directory, "stage"), csi: csi, adapter: readback,
      mount_adapter: readback, require_real_readback: true, fsync: true
    )

    assert_equal "Unknown", restarted.fetch_record(id).state
    assert_raises(Rubernetes::Volume::StateUnknownError) do
      restarted.node.stage(id, stage, token: "stage-after-restart", node: "node-a")
    end
  end

  def test_restart_reconciles_unobserved_csi_effect_to_retryable_known_state
    csi = CSI.new
    csi.define_singleton_method(:list_volumes) do
      {"entries" => [{"volumeId" => "remote-volume", "capacityBytes" => 1}]}
    end
    first = Rubernetes::Volume::Manager.new(data_dir: @directory, csi: csi, fsync: true)
    id = first.create_volume({"name" => "remote", "csi" => {"driver" => "example.csi"}}, token: "create")
    first.controller.publish(id, "node-a", token: "attach")
    operation = "stage:#{File.join(@directory, "interrupted-stage")}"
    token = "stage-interrupted"
    first.operations.begin!(key: id, operation: operation, token: token, fingerprint: Rubernetes::Volume::Types.digest({"rpc" => "sent"}))
    first.operations.effecting!(key: id, operation: operation, token: token)

    assert_equal "Attached", first.fetch_record(id).state

    restarted = Rubernetes::Volume::Manager.new(data_dir: @directory, csi: csi, fsync: true)
    restarted.recover

    assert_equal "failed", restarted.operations.fetch(key: id, operation: operation).status
    assert_equal "Attached", restarted.fetch_record(id).state
    result = restarted.node.stage(id, File.join(@directory, "new-stage"), token: "retry", node: "node-a")

    assert_equal File.join(@directory, "new-stage"), result.fetch("target")
  end

  # Requirement: all four CSI node mutation classes share the same durable
  # ambiguity boundary, including remove operations whose readback remains.
  def test_publish_unpublish_and_unstage_readback_faults_fence_unknown
    {
      publish: lambda do |manager, id, csi, _readback, root|
        csi.publish_readback = false
        stage = File.join(root, "stage")
        manager.node.stage(id, stage, token: "stage", node: "node-a")
        manager.node.publish(id, {"metadata" => {"uid" => "pod"}}, File.join(root, "target"),
                             readonly: false, token: "publish", node: "node-a")
      end,
      unpublish: lambda do |manager, id, csi, _readback, root|
        csi.unpublish_readback = false
        stage = File.join(root, "stage")
        target = File.join(root, "target")
        pod = {"metadata" => {"uid" => "pod"}}
        manager.node.stage(id, stage, token: "stage", node: "node-a")
        manager.node.publish(id, pod, target, readonly: false, token: "publish", node: "node-a")
        manager.node.unpublish(id, pod, target, token: "unpublish")
      end,
      unstage: lambda do |manager, id, csi, _readback, root|
        csi.unstage_readback = false
        stage = File.join(root, "stage")
        manager.node.stage(id, stage, token: "stage", node: "node-a")
        manager.node.unstage(id, stage, token: "unstage", node: "node-a")
      end
    }.each do |operation, scenario|
      readback = KernelReadback.new
      csi = EffectCSI.new(readback)
      manager, id = strict_csi_manager(csi, readback, suffix: operation.to_s)

      assert_raises(Rubernetes::Volume::OperationUnknown, operation.to_s) do
        scenario.call(manager, id, csi, readback, File.join(@directory, operation.to_s))
      end
      assert_equal "Unknown", manager.fetch_record(id).state, operation.to_s
      entry = manager.operations.entries.find { |candidate| candidate.operation.start_with?("#{operation}:") }

      refute_nil entry, "#{operation}: #{manager.operations.entries.map(&:operation).inspect}"
      assert_equal "unknown", entry.status, operation.to_s
    end
  end

  # Requirement: actual mount state resolves every node-side response loss to
  # the observed lifecycle state and clears the Unknown retry fence.
  def test_node_response_loss_operations_reconcile_from_mount_observation
    scenarios = {
      stage: lambda do |manager, id, csi, root|
        path = File.join(root, "stage")
        csi.lose_next_response(:stage)
        assert_raises(Rubernetes::Volume::OperationUnknown) do
          manager.node.stage(id, path, token: "stage", node: "node-a")
        end
        manager.recover

        assert_equal "Staged", manager.fetch_record(id).state
        assert_equal "succeeded", manager.operations.entries.find { |entry| entry.operation.start_with?("stage:") }.status
        manager.node.unstage(id, path, token: "unstage-after-recovery", node: "node-a")

        assert_equal "Attached", manager.fetch_record(id).state
      end,
      publish: lambda do |manager, id, csi, root|
        stage = File.join(root, "stage")
        target = File.join(root, "target")
        manager.node.stage(id, stage, token: "stage", node: "node-a")
        csi.lose_next_response(:publish)
        assert_raises(Rubernetes::Volume::OperationUnknown) do
          manager.node.publish(id, {"metadata" => {"uid" => "pod"}}, target,
                               readonly: false, token: "publish", node: "node-a")
        end
        manager.recover

        assert_equal "Published", manager.fetch_record(id).state
        assert_equal target, manager.fetch_record(id).publishes.values.first.fetch("target")
      end,
      unpublish: lambda do |manager, id, csi, root|
        stage = File.join(root, "stage")
        target = File.join(root, "target")
        pod = {"metadata" => {"uid" => "pod"}}
        manager.node.stage(id, stage, token: "stage", node: "node-a")
        manager.node.publish(id, pod, target, readonly: false, token: "publish", node: "node-a")
        csi.lose_next_response(:unpublish)
        assert_raises(Rubernetes::Volume::OperationUnknown) do
          manager.node.unpublish(id, pod, target, token: "unpublish")
        end
        manager.recover

        assert_equal "Staged", manager.fetch_record(id).state
        assert_empty manager.fetch_record(id).publishes
      end,
      unstage: lambda do |manager, id, csi, root|
        stage = File.join(root, "stage")
        manager.node.stage(id, stage, token: "stage", node: "node-a")
        csi.lose_next_response(:unstage)
        assert_raises(Rubernetes::Volume::OperationUnknown) do
          manager.node.unstage(id, stage, token: "unstage", node: "node-a")
        end
        manager.recover

        assert_equal "Attached", manager.fetch_record(id).state
        assert_empty manager.fetch_record(id).stages
      end
    }

    scenarios.each do |operation, scenario|
      root = File.join(@directory, "node-response-loss-#{operation}")
      readback = KernelReadback.new
      csi = EffectCSI.new(readback)
      manager, id = strict_csi_manager(csi, readback, suffix: "node-response-loss-#{operation}")
      scenario.call(manager, id, csi, root)
    end
  end

  # Requirement: §5.11.2 classifies every remote controller response loss as
  # Unknown, then resolves it from driver-observed state before allowing retry.
  def test_controller_response_loss_operations_reconcile_from_driver_state
    scenarios = {
      create_volume: lambda do |manager, csi, _id|
        csi.lose_next_response(:create_volume)
        error = assert_raises(Rubernetes::Volume::OperationUnknown) do
          manager.create_volume({"name" => "lost-create", "capacityBytes" => 64,
                                 "csi" => {"driver" => "example.csi"}}, token: "create")
        end
        local_id = manager.volume_id_for(manager.normalize_spec(
          {"name" => "lost-create", "capacityBytes" => 64, "csi" => {"driver" => "example.csi"}}
        ))

        assert_match(/ambiguous result/, error.message)
        assert_equal "Unknown", manager.fetch_record(local_id).state
        manager.recover

        assert_equal "Provisioned", manager.fetch_record(local_id).state
      end,
      delete_volume: lambda do |manager, csi, id|
        csi.lose_next_response(:delete_volume)
        assert_raises(Rubernetes::Volume::OperationUnknown) { manager.delete_volume(id, token: "delete") }
        assert_equal "Unknown", manager.fetch_record(id).state
        manager.recover
        assert_raises(Rubernetes::Volume::NotFoundError) { manager.fetch_record(id) }
      end,
      publish: lambda do |manager, csi, id|
        csi.lose_next_response(:publish)
        assert_raises(Rubernetes::Volume::OperationUnknown) { manager.controller.publish(id, "node-a", token: "attach") }
        assert_equal "Unknown", manager.fetch_record(id).state
        manager.recover

        assert_equal "Attached", manager.fetch_record(id).state
        assert_equal "driver-remote@node-a",
                     manager.fetch_record(id).attachments.fetch("node-a").fetch("publishContext").fetch("attachment")
      end,
      unpublish: lambda do |manager, csi, id|
        manager.controller.publish(id, "node-a", token: "attach")
        csi.lose_next_response(:unpublish)
        assert_raises(Rubernetes::Volume::OperationUnknown) { manager.controller.unpublish(id, "node-a", token: "detach") }
        manager.recover

        assert_equal "Detached", manager.fetch_record(id).state
        assert_empty manager.fetch_record(id).attachments
      end,
      create_snapshot: lambda do |manager, csi, id|
        csi.lose_next_response(:create_snapshot)
        assert_raises(Rubernetes::Volume::OperationUnknown) do
          manager.create_snapshot(id, token: "snapshot", name: "lost-snapshot")
        end
        manager.recover

        assert_equal "Provisioned", manager.fetch_record(id).state
        assert_equal "driver-lost-snapshot", manager.list_snapshots.first.id
      end,
      expand: lambda do |manager, csi, id|
        csi.lose_next_response(:expand)
        assert_raises(Rubernetes::Volume::OperationUnknown) { manager.expand(id, 128, token: "expand") }
        manager.recover

        assert_equal "Provisioned", manager.fetch_record(id).state
        assert_equal 128, manager.fetch_record(id).capacity_bytes
      end,
      delete_snapshot: lambda do |manager, csi, id|
        snapshot_id = manager.create_snapshot(id, token: "snapshot", name: "delete-me")
        csi.lose_next_response(:delete_snapshot)
        assert_raises(Rubernetes::Volume::OperationUnknown) do
          manager.delete_snapshot(snapshot_id, token: "delete-snapshot")
        end
        manager.recover

        assert_empty manager.list_snapshots
      end
    }

    scenarios.each do |operation, scenario|
      root = File.join(@directory, "controller-#{operation}")
      csi = ControllerFaultCSI.new
      manager = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, fsync: true)
      id = unless operation == :create_volume
             manager.create_volume({"name" => "remote", "capacityBytes" => 64,
                                    "csi" => {"driver" => "example.csi"}}, token: "create")
           end
      scenario.call(manager, csi, id)
    end
  end

  # Requirement: §5.11.2 keeps ControllerExpand and every required
  # NodeExpand in one durable Unknown/recovery boundary.
  def test_node_expand_response_loss_is_fenced_and_reissued_after_restart
    readback = KernelReadback.new
    csi = EffectCSI.new(readback)
    root = File.join(@directory, "node-expand-restart")
    manager, id = strict_csi_manager(csi, readback, suffix: "node-expand-restart")
    stage = File.join(root, "stage")
    target = File.join(root, "target")
    manager.node.stage(id, stage, token: "stage", node: "node-a")
    manager.node.publish(id, "pod-a", target, readonly: false, token: "publish", node: "node-a")
    csi.lose_next_response(:expand_node)

    assert_raises(Rubernetes::Volume::OperationUnknown) do
      manager.expand(id, 128, token: "expand")
    end
    assert_equal "Unknown", manager.volume(id).state

    restarted = Rubernetes::Volume::Manager.new(
      data_dir: manager.data_dir, csi: csi, adapter: readback, mount_adapter: readback,
      require_real_readback: true, fsync: true
    )
    restarted.recover

    assert_equal "Published", restarted.volume(id).state
    assert_equal 128, restarted.volume(id).capacity_bytes
    expand_calls = csi.mutations.select { |call| call.first == :expand_node }
    # The plugin receives canonical paths; the leased inode is verified by the manager.
    assert(expand_calls.all? { |call| [stage, target].include?(call.fetch(2)) })
    expanded_paths = expand_calls.map { |call| call.fetch(5) }

    assert_includes expanded_paths, stage
    assert_includes expanded_paths, target
    assert_equal "succeeded", restarted.operations.fetch(key: id, operation: "expand").status
  end

  # Every CSI node RPC must fence on a target identity change even when the
  # plugin raises a deterministic error after touching the pathname.
  def test_target_lease_identity_change_fences_all_six_node_rpcs
    scenarios = {
      stage: lambda do |manager, id, csi, path|
        csi.fault = :stage
        assert_raises(Rubernetes::Volume::OperationUnknown) do
          manager.node.stage(id, path, token: "stage-fault", node: "node-a")
        end
      end,
      unstage: lambda do |manager, id, csi, path|
        manager.node.stage(id, path, token: "stage", node: "node-a")
        csi.fault = :unstage
        assert_raises(Rubernetes::Volume::OperationUnknown) do
          manager.node.unstage(id, path, token: "unstage-fault", node: "node-a")
        end
      end,
      publish: lambda do |manager, id, csi, path|
        manager.node.stage(id, path, token: "stage", node: "node-a")
        target = "#{path}-target"
        csi.fault = :publish
        assert_raises(Rubernetes::Volume::OperationUnknown) do
          manager.node.publish(id, "pod-a", target, readonly: false, token: "publish-fault", node: "node-a")
        end
        target
      end,
      unpublish: lambda do |manager, id, csi, path|
        manager.node.stage(id, path, token: "stage", node: "node-a")
        target = "#{path}-target"
        manager.node.publish(id, "pod-a", target, readonly: false, token: "publish", node: "node-a")
        csi.fault = :unpublish
        assert_raises(Rubernetes::Volume::OperationUnknown) do
          manager.node.unpublish(id, "pod-a", target, token: "unpublish-fault")
        end
        target
      end,
      expand: lambda do |manager, id, csi, path|
        manager.node.stage(id, path, token: "stage", node: "node-a")
        csi.fault = :expand
        csi.fault_path = path
        assert_raises(Rubernetes::Volume::OperationUnknown) do
          manager.expand(id, 128, token: "expand-fault")
        end
      end,
      stats: lambda do |manager, id, csi, path|
        manager.node.stage(id, path, token: "stage", node: "node-a")
        csi.fault = :stats
        assert_raises(Rubernetes::Volume::OperationUnknown) do
          manager.node.stats(id, path: path)
        end
      end
    }

    scenarios.each do |operation, scenario|
      root = File.join(@directory, "lease-fault-#{operation}")
      csi = LeaseFaultCSI.new
      manager = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, fsync: true)
      id = manager.create_volume({"name" => "remote", "csi" => {"driver" => "example.csi"}}, token: "create")
      manager.controller.publish(id, "node-a", token: "attach")
      path = File.join(root, "stage")
      scenario.call(manager, id, csi, path)

      changed_path = %i[publish unpublish].include?(operation) ? "#{path}-target" : path

      assert File.symlink?(changed_path), operation.to_s
      expected_state = operation == :stats ? "Staged" : "Unknown"

      assert_equal expected_state, manager.volume(id).state, operation.to_s
    end
  end

  def test_descriptor_disabled_expand_makes_zero_csi_calls_before_controller_mutation
    csi = EffectCSI.new(KernelReadback.new)
    secure, id = strict_csi_manager(csi, csi.instance_variable_get(:@readback), suffix: "expand-raw-source")
    stage = File.join(@directory, "expand-raw-source", "stage")
    secure.node.stage(id, stage, token: "stage", node: "node-a")
    calls_before = csi.mutations.length

    raw_security = Rubernetes::Volume::PathSecurity.new(root: "/", require_openat2: false)
    restarted = Rubernetes::Volume::Manager.new(
      data_dir: secure.data_dir, csi: csi, path_security: raw_security, fsync: true
    )
    error = assert_raises(Rubernetes::Volume::PathSecurityError) do
      restarted.expand(id, 128, token: "expand-raw")
    end

    assert_match(/descriptor lease/, error.message)
    assert_equal calls_before, csi.mutations.length
    assert_equal "Staged", restarted.volume(id).state
  end

  # Requirement: an acknowledged remote snapshot is compensated before a
  # catalog fsync error becomes retryable, so a retry cannot create two objects.
  def test_snapshot_catalog_failure_compensates_before_retry
    csi = ControllerFaultCSI.new
    store = OneShotFailingSnapshotStore.new
    manager = Rubernetes::Volume::Manager.new(
      data_dir: File.join(@directory, "snapshot-fsync"), csi: csi, snapshot_store: store, fsync: true
    )
    id = manager.create_volume({"name" => "remote", "capacityBytes" => 64,
                                "csi" => {"driver" => "example.csi"}}, token: "create")

    assert_raises(Rubernetes::Volume::JournalError) do
      manager.create_snapshot(id, token: "snapshot-first", name: "backup-first")
    end
    assert_equal(1, csi.calls.count { |call| call.first == :delete_snapshot })
    assert_empty manager.list_snapshots
    assert_equal "Provisioned", manager.fetch_record(id).state

    snapshot_id = manager.create_snapshot(id, token: "snapshot-retry", name: "backup-retry")

    assert_equal "driver-backup-retry", snapshot_id
    assert_equal 1, csi.max_snapshots
    assert_equal [snapshot_id], manager.list_snapshots.map(&:id)
  end

  def test_observed_snapshot_resolves_unknown_catalog_record_back_to_ready
    csi = ControllerFaultCSI.new
    manager = Rubernetes::Volume::Manager.new(
      data_dir: File.join(@directory, "snapshot-ready-reconcile"), csi: csi, fsync: true
    )
    id = manager.create_volume({"name" => "remote", "capacityBytes" => 64,
                                "csi" => {"driver" => "example.csi"}}, token: "create")
    snapshot_id = manager.create_snapshot(id, token: "snapshot", name: "recoverable")
    csi.delete_snapshot(snapshot_id, token: "external-delete")

    manager.recover
    unknown = manager.list_snapshots.first

    assert_equal "Unknown", unknown.metadata.fetch("state")
    refute unknown.ready_to_use

    csi.create_snapshot("driver-remote", token: "external-recreate", name: "recoverable")
    manager.recover
    restored = manager.list_snapshots.first

    assert restored.ready_to_use
    refute_equal "Unknown", restored.metadata["state"]
  end

  def test_csi_driver_identity_mismatch_fails_before_create_rpc
    csi = ControllerFaultCSI.new
    manager = Rubernetes::Volume::Manager.new(data_dir: File.join(@directory, "driver-mismatch"), csi: csi, fsync: true)

    error = assert_raises(Rubernetes::Volume::CSIUnavailable) do
      manager.create_volume({"name" => "wrong", "csi" => {"driver" => "other.csi"}}, token: "create")
    end
    assert_match(/driver mismatch/, error.message)
    refute(csi.calls.any? { |call| call.first == :create_volume })
  end

  def test_inline_csi_secrets_are_memory_only_and_restart_fails_closed_without_resolver
    csi = CSI.new
    root = File.join(@directory, "inline-secrets")
    secret = "never-persist-this-csi-secret"
    manager = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, fsync: true)

    id = manager.create_volume(
      {"name" => "inline-secret", "csi" => {"driver" => "example.csi"},
       "secrets" => {"credential" => secret}}, token: "create"
    )

    assert_equal secret, csi.calls.find { |call| call.first == :create }.fetch(1).fetch("secrets").fetch("credential")
    manager.controller.publish(id, "node-a", token: "attach")
    publish_context = csi.calls.reverse.find { |call| call.first == :publish }.fetch(5)

    assert_equal secret, publish_context.fetch("secrets").fetch("credential")
    manager.controller.unpublish(id, "node-a", token: "detach")

    persisted = Dir.glob(File.join(root, "**", "*.json")).map { |path| File.binread(path) }.join("\n")

    refute_includes persisted, secret
    refute_includes persisted, "\"credential\""

    restarted = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, fsync: true)
    error = assert_raises(Rubernetes::Volume::CSIUnavailable) do
      restarted.controller.publish(id, "node-b", token: "attach-after-restart")
    end
    assert_match(/secret resolver is not configured/, error.message)
    refute_equal "Unknown", restarted.volume(id).state
  end

  def test_failed_csi_observation_never_replays_unknown_mutations
    csi = ObservationFailCSI.new
    root = File.join(@directory, "observation-fence")
    manager = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, fsync: true)
    csi.lose_next_response(:create_volume)
    assert_raises(Rubernetes::Volume::OperationUnknown) do
      manager.create_volume({"name" => "unknown-create", "capacityBytes" => 64,
                             "csi" => {"driver" => "example.csi"}}, token: "create")
    end
    local_id = manager.volume_id_for(manager.normalize_spec(
      {"name" => "unknown-create", "capacityBytes" => 64, "csi" => {"driver" => "example.csi"}}
    ))
    mutation_count = csi.calls.length
    csi.fail_list_volumes = true
    csi.fail_list_snapshots = true

    report = manager.recover

    assert_equal mutation_count, csi.calls.length
    assert_equal "Unknown", manager.volume(local_id).state
    assert_equal "unknown", manager.operations.fetch(key: local_id, operation: "create").status
    assert(report.errors.any? { |entry| entry["kind"] == "csi-list-volumes" })
  end

  def test_paginated_list_volumes_failure_keeps_unknown_create_fenced
    csi = ObservationFailCSI.new
    root = File.join(@directory, "paginated-create-fence")
    manager = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, fsync: true)
    csi.lose_next_response(:create_volume)
    assert_raises(Rubernetes::Volume::OperationUnknown) do
      manager.create_volume({"name" => "page-two", "capacityBytes" => 64,
                             "csi" => {"driver" => "example.csi"}}, token: "create")
    end
    local_id = manager.list_volumes.first.id
    create_calls = csi.calls.count { |entry| entry.first == :create_volume }
    tokens = []
    csi.define_singleton_method(:list_volumes) do |starting_token: nil|
      tokens << starting_token
      return {"entries" => [{"volumeId" => "unrelated"}], "nextToken" => "page-2"} if starting_token.nil?

      raise Rubernetes::Volume::CSIError, "second ListVolumes page unavailable"
    end

    report = manager.recover

    assert_equal [nil, "page-2"], tokens
    assert_equal(create_calls, csi.calls.count { |entry| entry.first == :create_volume })
    assert_equal "Unknown", manager.volume(local_id).state
    assert_equal "unknown", manager.operations.fetch(key: local_id, operation: "create").status
    assert(report.errors.any? { |entry| entry["kind"] == "csi-list-volumes" })
  end

  def test_paginated_list_volumes_observes_delete_target_before_unfencing
    csi = ObservationFailCSI.new
    root = File.join(@directory, "paginated-delete-observation")
    manager = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, fsync: true)
    id = manager.create_volume({"name" => "remote", "capacityBytes" => 64,
                                "csi" => {"driver" => "example.csi"}}, token: "create")
    csi.lose_next_response(:delete_volume)
    assert_raises(Rubernetes::Volume::OperationUnknown) { manager.delete_volume(id, token: "delete") }
    delete_calls = csi.calls.count { |entry| entry.first == :delete_volume }
    tokens = []
    csi.define_singleton_method(:list_volumes) do |starting_token: nil|
      tokens << starting_token
      if starting_token.nil?
        {"entries" => [{"volumeId" => "unrelated"}], "nextToken" => "page-2"}
      else
        {"entries" => [{"volume" => {"volumeId" => "driver-remote"},
                        "status" => {"publishedNodeIds" => []}}],
         "nextToken" => ""}
      end
    end

    report = manager.recover

    assert_empty report.errors
    assert_equal [nil, "page-2"], tokens
    assert_equal(delete_calls, csi.calls.count { |entry| entry.first == :delete_volume })
    assert_equal "Provisioned", manager.volume(id).state
    assert_equal "failed", manager.operations.fetch(key: id, operation: "delete").status
  end

  def test_paginated_list_volumes_failure_keeps_unknown_delete_fenced
    csi = ObservationFailCSI.new
    root = File.join(@directory, "paginated-delete-fence")
    manager = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, fsync: true)
    id = manager.create_volume({"name" => "remote", "capacityBytes" => 64,
                                "csi" => {"driver" => "example.csi"}}, token: "create")
    csi.lose_next_response(:delete_volume)
    assert_raises(Rubernetes::Volume::OperationUnknown) { manager.delete_volume(id, token: "delete") }
    delete_calls = csi.calls.count { |entry| entry.first == :delete_volume }
    tokens = []
    csi.define_singleton_method(:list_volumes) do |starting_token: nil|
      tokens << starting_token
      return {"entries" => [{"volumeId" => "unrelated"}], "nextToken" => "page-2"} if starting_token.nil?

      raise Rubernetes::Volume::CSIError, "second ListVolumes page unavailable"
    end

    report = manager.recover

    assert_equal [nil, "page-2"], tokens
    assert_equal(delete_calls, csi.calls.count { |entry| entry.first == :delete_volume })
    assert_equal "Unknown", manager.volume(id).state
    assert_equal "unknown", manager.operations.fetch(key: id, operation: "delete").status
    assert(report.errors.any? { |entry| entry["kind"] == "csi-list-volumes" })
  end

  def test_malformed_list_volumes_response_keeps_unknown_delete_fenced
    csi = ObservationFailCSI.new
    root = File.join(@directory, "malformed-delete-fence")
    manager = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, fsync: true)
    id = manager.create_volume({"name" => "remote", "capacityBytes" => 64,
                                "csi" => {"driver" => "example.csi"}}, token: "create")
    csi.lose_next_response(:delete_volume)
    assert_raises(Rubernetes::Volume::OperationUnknown) { manager.delete_volume(id, token: "delete") }
    delete_calls = csi.calls.count { |entry| entry.first == :delete_volume }
    csi.define_singleton_method(:list_volumes) { nil }

    report = manager.recover

    assert_equal(delete_calls, csi.calls.count { |entry| entry.first == :delete_volume })
    assert_equal "Unknown", manager.volume(id).state
    assert_equal "unknown", manager.operations.fetch(key: id, operation: "delete").status
    assert(report.errors.any? do |entry|
      entry["kind"] == "csi-list-volumes" && entry["error"].include?("malformed pagination page")
    end)
  end

  def test_recovery_oracles_reject_repeated_pagination_tokens
    csi = ObservationFailCSI.new
    root = File.join(@directory, "pagination-token-loop")
    manager = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, fsync: true)
    csi.lose_next_response(:create_volume)
    assert_raises(Rubernetes::Volume::OperationUnknown) do
      manager.create_volume({"name" => "loop", "capacityBytes" => 64,
                             "csi" => {"driver" => "example.csi"}}, token: "create")
    end
    local_id = manager.list_volumes.first.id
    create_calls = csi.calls.count { |entry| entry.first == :create_volume }
    volume_tokens = []
    csi.define_singleton_method(:list_volumes) do |starting_token: nil|
      volume_tokens << starting_token
      {"entries" => [], "nextToken" => "loop"}
    end

    report = manager.recover

    assert_equal [nil, "loop"], volume_tokens
    assert_equal(create_calls, csi.calls.count { |entry| entry.first == :create_volume })
    assert_equal "Unknown", manager.volume(local_id).state
    assert(report.errors.any? do |entry|
      entry["kind"] == "csi-list-volumes" && entry["error"].include?("repeated token")
    end)
  end

  def test_snapshot_recovery_rejects_repeated_pagination_tokens
    csi = ObservationFailCSI.new
    root = File.join(@directory, "snapshot-pagination-token-loop")
    manager = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, fsync: true)
    id = manager.create_volume({"name" => "remote", "capacityBytes" => 64,
                                "csi" => {"driver" => "example.csi"}}, token: "create")
    snapshot_id = manager.create_snapshot(id, token: "snapshot", name: "loop")
    snapshot_calls = csi.calls.count { |entry| entry.first == :create_snapshot }
    snapshot_tokens = []
    csi.define_singleton_method(:list_snapshots) do |starting_token: nil, **_options|
      snapshot_tokens << starting_token
      {"entries" => [{"snapshotId" => snapshot_id, "sourceVolumeId" => "driver-remote"}],
       "nextToken" => "loop"}
    end

    report = manager.recover

    assert_equal [nil, "loop"], snapshot_tokens
    assert_equal(snapshot_calls, csi.calls.count { |entry| entry.first == :create_snapshot })
    assert(report.errors.any? do |entry|
      entry["kind"] == "snapshot-reconcile" && entry["error"].include?("repeated token")
    end)
    assert_equal "Unknown", manager.list_snapshots.find { |snapshot| snapshot.id == snapshot_id }.metadata["state"]
  end

  def test_projected_nested_secret_payloads_are_recursively_redacted
    manager = Rubernetes::Volume::Manager.new(data_dir: File.join(@directory, "projected-redaction"), fsync: true)
    normalized = manager.normalize_spec(
      "name" => "nested", "backend" => "projected",
      "sources" => [
        {"wrapper" => {"secret" => {"name" => "credentials", "data" => {"password" => "DISK-SECRET"},
                                    "items" => [{"key" => "password", "path" => "password"}]}}},
        {"nested" => {"serviceAccountToken" => {"audience" => "api", "token" => "JWT-SECRET"}}}
      ]
    )

    persisted = manager.persisted_spec(normalized)
    json = JSON.generate(persisted)

    refute_includes json, "DISK-SECRET"
    refute_includes json, "JWT-SECRET"
    assert_equal "credentials", persisted.dig("sources", 0, "wrapper", "secret", "name")
    assert_equal "api", persisted.dig("sources", 1, "nested", "serviceAccountToken", "audience")
    refute persisted.dig("sources", 0, "wrapper", "secret").key?("data")
    refute persisted.dig("sources", 1, "nested", "serviceAccountToken").key?("token")
  end

  def test_snapshot_recovery_redacts_secret_bearing_driver_errors_everywhere
    csi = ObservationFailCSI.new
    root = File.join(@directory, "snapshot-error-redaction")
    secret = "RECOVERY-SECRET"
    resolver = ->(_reference, **_options) { {"credential" => secret} }
    manager = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, secret_resolver: resolver, fsync: true)
    id = manager.create_volume({"name" => "remote", "capacityBytes" => 64,
                                "csi" => {"driver" => "example.csi"},
                                "secretRef" => {"name" => "credentials"}}, token: "create")
    snapshot_id = manager.create_snapshot(id, token: "snapshot", name: "safe")
    csi.fail_list_snapshots = true
    csi.leaked_message = "driver rejected #{secret}"

    restarted = Rubernetes::Volume::Manager.new(
      data_dir: root, csi: csi, secret_resolver: resolver, fsync: true
    )
    report = restarted.recover
    snapshot = restarted.list_snapshots.find { |entry| entry.id == snapshot_id }
    persisted = Dir.glob(File.join(root, "**", "*.json")).map { |path| File.binread(path) }.join("\n")

    refute_includes JSON.generate(report.to_h), secret
    refute_includes snapshot.metadata.fetch("reason"), secret
    refute_includes persisted, secret
    assert_includes snapshot.metadata.fetch("reason"), "[REDACTED]"
  end

  # ListVolumes is the first recovery RPC. Its driver error must already be
  # sanitized, even when the only persisted evidence of the secret is the
  # post-restart resolver reference.
  def test_recovery_primes_secret_redaction_before_list_volumes
    csi = ObservationFailCSI.new
    root = File.join(@directory, "list-volume-error-redaction")
    secret = "LIST-VOLUMES-RECOVERY-SECRET"
    resolver = ->(_reference, **_options) { {"credential" => secret} }
    manager = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, secret_resolver: resolver, fsync: true)
    id = manager.create_volume({"name" => "remote", "capacityBytes" => 64,
                                "csi" => {"driver" => "example.csi"},
                                "secretRef" => {"name" => "credentials"}}, token: "create")
    csi.fail_list_volumes = true
    csi.leaked_message = "ListVolumes leaked #{secret}"

    restarted = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, secret_resolver: resolver, fsync: true)
    report = restarted.recover

    refute_includes JSON.generate(report.to_h), secret
    assert(report.errors.any? { |entry| entry["kind"] == "csi-list-volumes" && entry["error"].include?("[REDACTED]") })
    assert_equal "Provisioned", restarted.volume(id).state
  end

  def test_snapshot_recovery_requires_exact_source_volume_identity
    ["wrong-driver", nil, {"malformed" => true}].each_with_index do |source_volume_id, index|
      csi = ControllerFaultCSI.new
      root = File.join(@directory, "snapshot-source-fence-#{index}")
      manager = Rubernetes::Volume::Manager.new(data_dir: root, csi: csi, fsync: true)
      id = manager.create_volume({"name" => "remote", "capacityBytes" => 64,
                                  "csi" => {"driver" => "example.csi"}}, token: "create")
      snapshot_id = manager.create_snapshot(id, token: "snapshot", name: "source-#{index}")
      manager.snapshot_manager.mark_unknown(snapshot_id, reason: "ambiguous")
      snapshot_calls = csi.calls.count { |entry| entry.first == :create_snapshot }
      csi.define_singleton_method(:list_snapshots) do |**_options|
        {"entries" => [{"snapshotId" => snapshot_id, "sourceVolumeId" => source_volume_id}]}
      end

      report = manager.recover
      snapshot = manager.list_snapshots.find { |entry| entry.id == snapshot_id }

      assert_equal "Unknown", snapshot.metadata.fetch("state"), source_volume_id.inspect
      assert_equal snapshot_calls, csi.calls.count { |entry| entry.first == :create_snapshot }, source_volume_id.inspect
      assert(report.errors.any? do |entry|
        entry["kind"] == "snapshot-reconcile" && entry["error"].include?("unexpected source volume")
      end)
    end
  end

  def test_snapshot_failure_redacts_the_raised_error_and_durable_diagnostics
    csi = ObservationFailCSI.new
    root = File.join(@directory, "snapshot-delete-redaction")
    secret = "DELETE-SNAPSHOT-SECRET"
    resolver = ->(_reference, **_options) { {"credential" => secret} }
    manager = Rubernetes::Volume::Manager.new(
      data_dir: root, csi: csi, secret_resolver: resolver, fsync: true
    )
    id = manager.create_volume({"name" => "remote", "capacityBytes" => 64,
                                "csi" => {"driver" => "example.csi"},
                                "secretRef" => {"name" => "credentials"}}, token: "create")
    snapshot_id = manager.create_snapshot(id, token: "snapshot", name: "safe")
    csi.fail_delete_snapshot = true
    csi.leaked_message = "driver rejected #{secret}"

    error = assert_raises(Rubernetes::Volume::CSIError) do
      manager.delete_snapshot(snapshot_id, token: "delete")
    end
    persisted = Dir.glob(File.join(root, "**", "*.json")).map { |path| File.binread(path) }.join("\n")

    refute_includes error.message, secret
    assert_includes error.message, "[REDACTED]"
    snapshot = manager.list_snapshots.find { |entry| entry.id == snapshot_id }

    refute_includes snapshot.metadata.fetch("reason"), secret
    refute_includes persisted, secret
  end

  private

  def strict_csi_manager(csi, readback, suffix:)
    root = File.join(@directory, suffix)
    manager = Rubernetes::Volume::Manager.new(
      data_dir: root, csi: csi, adapter: readback, mount_adapter: readback,
      require_real_readback: true, fsync: true
    )
    id = manager.create_volume({"name" => "remote-#{suffix}", "csi" => {"driver" => "example.csi"}}, token: "create")
    manager.controller.publish(id, "node-a", token: "attach")
    [manager, id]
  end
end
