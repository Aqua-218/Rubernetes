# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/volume"
require "rubernetes/bootstrap"
require "rubernetes/volume/generated/csi_services_pb"
require "timeout"

class CSIUDSClientTest < Minitest::Test
  class State
    attr_accessor :after_create, :controller_advertised, :delete_status, :volume_context, :publish_context, :publish_status
    attr_reader :requests

    def initialize
      @controller_advertised = true
      @delete_status = nil
      @volume_context = {"driver" => "test.csi"}
      @publish_context = {"published" => "true"}
      @publish_status = nil
      @requests = {}
      @history = Hash.new { |hash, key| hash[key] = [] }
      @descriptor_targets = Hash.new { |hash, key| hash[key] = [] }
      @lock = Mutex.new
    end

    def record(name, request)
      @lock.synchronize do
        @requests[name] = request
        @history[name] << request
        path = request.volume_path if request.respond_to?(:volume_path)
        @descriptor_targets[name] << File.readlink(path) if path&.match?(%r{\A/proc/\d+/fd/\d+\z})
      end
    end

    def request(name)
      @lock.synchronize { @requests[name] }
    end

    def requests_for(name)
      @lock.synchronize { @history[name].dup }
    end

    def descriptor_targets_for(name)
      @lock.synchronize { @descriptor_targets[name].dup }
    end
  end

  class IdentityService < Csi::V1::Identity::Service
    def initialize(state)
      @state = state
    end

    def get_plugin_info(_request, _call = nil)
      Csi::V1::GetPluginInfoResponse.new(name: "test.csi", vendor_version: "test-vendor")
    end

    def get_plugin_capabilities(_request, _call = nil)
      capabilities = if @state.controller_advertised
                       [Csi::V1::PluginCapability.new(
                         service: Csi::V1::PluginCapability::Service.new(type: :CONTROLLER_SERVICE)
                       )]
                     else
                       []
                     end
      Csi::V1::GetPluginCapabilitiesResponse.new(capabilities: capabilities)
    end

    def probe(_request, _call = nil)
      Csi::V1::ProbeResponse.new(ready: Google::Protobuf::BoolValue.new(value: true))
    end
  end

  class ControllerService < Csi::V1::Controller::Service
    def initialize(state)
      @state = state
    end

    def controller_get_capabilities(_request, _call = nil)
      capabilities = %i[
        CREATE_DELETE_VOLUME PUBLISH_UNPUBLISH_VOLUME CREATE_DELETE_SNAPSHOT LIST_SNAPSHOTS LIST_VOLUMES
        EXPAND_VOLUME
      ].map { |type| Csi::V1::ControllerServiceCapability.new(rpc: Csi::V1::ControllerServiceCapability::RPC.new(type: type)) }
      Csi::V1::ControllerGetCapabilitiesResponse.new(capabilities: capabilities)
    end

    def create_volume(request, _call = nil)
      @state.record(:create_volume, request)
      @state.after_create&.call
      Csi::V1::CreateVolumeResponse.new(
        volume: Csi::V1::Volume.new(
          volume_id: "volume-1", capacity_bytes: request.capacity_range.required_bytes,
          volume_context: @state.volume_context
        )
      )
    end

    def delete_volume(request, _call = nil)
      @state.record(:delete_volume, request)
      raise GRPC::BadStatus.new(@state.delete_status, "volume absent") if @state.delete_status

      Csi::V1::DeleteVolumeResponse.new
    end

    def controller_publish_volume(request, _call = nil)
      @state.record(:publish, request)
      raise GRPC::BadStatus.new(@state.publish_status, @state.publish_context.fetch("error")) if @state.publish_status

      Csi::V1::ControllerPublishVolumeResponse.new(publish_context: @state.publish_context)
    end

    def controller_unpublish_volume(request, _call = nil)
      @state.record(:unpublish, request)
      Csi::V1::ControllerUnpublishVolumeResponse.new
    end

    def create_snapshot(request, _call = nil)
      @state.record(:create_snapshot, request)
      snapshot = Csi::V1::Snapshot.new(
        snapshot_id: "snapshot-1", source_volume_id: request.source_volume_id, size_bytes: 64,
        creation_time: Google::Protobuf::Timestamp.new(seconds: 1), ready_to_use: true
      )
      Csi::V1::CreateSnapshotResponse.new(snapshot: snapshot)
    end

    def delete_snapshot(request, _call = nil)
      @state.record(:delete_snapshot, request)
      Csi::V1::DeleteSnapshotResponse.new
    end

    def list_snapshots(request, _call = nil)
      @state.record(:list_snapshots, request)
      snapshot = Csi::V1::Snapshot.new(snapshot_id: "snapshot-1", source_volume_id: "volume-1", ready_to_use: true)
      Csi::V1::ListSnapshotsResponse.new(
        entries: [Csi::V1::ListSnapshotsResponse::Entry.new(snapshot: snapshot)],
        next_token: request.starting_token.to_s.empty? ? "next-snapshot" : ""
      )
    end

    def list_volumes(request, _call = nil)
      @state.record(:list_volumes, request)
      volume = Csi::V1::Volume.new(volume_id: "volume-1", capacity_bytes: 64)
      Csi::V1::ListVolumesResponse.new(
        entries: [Csi::V1::ListVolumesResponse::Entry.new(volume: volume)],
        next_token: request.starting_token.to_s.empty? ? "next-volume" : ""
      )
    end

    def controller_expand_volume(request, _call = nil)
      @state.record(:expand, request)
      Csi::V1::ControllerExpandVolumeResponse.new(capacity_bytes: request.capacity_range.required_bytes,
                                                  node_expansion_required: true)
    end
  end

  class NodeService < Csi::V1::Node::Service
    def initialize(state)
      @state = state
    end

    def node_get_capabilities(_request, _call = nil)
      capabilities = %i[STAGE_UNSTAGE_VOLUME GET_VOLUME_STATS EXPAND_VOLUME].map do |type|
        Csi::V1::NodeServiceCapability.new(rpc: Csi::V1::NodeServiceCapability::RPC.new(type: type))
      end
      Csi::V1::NodeGetCapabilitiesResponse.new(capabilities: capabilities)
    end

    def node_stage_volume(request, _call = nil)
      @state.record(:stage, request)
      Csi::V1::NodeStageVolumeResponse.new
    end

    def node_unstage_volume(request, _call = nil)
      @state.record(:unstage, request)
      Csi::V1::NodeUnstageVolumeResponse.new
    end

    def node_publish_volume(request, _call = nil)
      @state.record(:publish_node, request)
      Csi::V1::NodePublishVolumeResponse.new
    end

    def node_unpublish_volume(request, _call = nil)
      @state.record(:unpublish_node, request)
      Csi::V1::NodeUnpublishVolumeResponse.new
    end

    def node_get_volume_stats(request, _call = nil)
      @state.record(:stats, request)
      Csi::V1::NodeGetVolumeStatsResponse.new(
        usage: [Csi::V1::VolumeUsage.new(available: 1, total: 2, used: 1, unit: :BYTES)]
      )
    end

    def node_expand_volume(request, _call = nil)
      @state.record(:expand_node, request)
      Csi::V1::NodeExpandVolumeResponse.new(capacity_bytes: 128)
    end
  end

  def setup
    @directory = Dir.mktmpdir("csi-uds")
    @socket = File.join(@directory, "plugin.sock")
    @state = State.new
    @server = GRPC::RpcServer.new(pool_size: 4)
    @server.add_http2_port("unix:#{@socket}", :this_port_is_insecure)
    @server.handle(IdentityService.new(@state))
    @server.handle(ControllerService.new(@state))
    @server.handle(NodeService.new(@state))
    @server_thread = Thread.new { @server.run }
    Timeout.timeout(5) { sleep 0.01 until File.socket?(@socket) }
    @clients = []
  end

  def teardown
    @clients.reverse_each(&:close)
    @server&.stop
    @server_thread&.join(5)
    FileUtils.rm_rf(@directory)
  end

  def new_client
    client = Rubernetes::Volume::CSIUDSClient.new(socket: @socket, timeout: 2)
    @clients << client
    client
  end

  def test_real_uds_frames_cover_negotiation_controller_node_and_snapshot_paths
    client = new_client

    assert_equal "test.csi", client.identity.name
    assert_equal "1.9.0", client.identity.plugin_version
    assert_includes client.capabilities.fetch("controller"), "CREATE_DELETE_VOLUME"
    assert_includes client.capabilities.fetch("node"), "STAGE_UNSTAGE_VOLUME"
    bridge = Rubernetes::Volume::CSIBridge.new(socket: @socket, timeout: 2)
    @clients << bridge.client

    assert_equal client.capabilities, bridge.capabilities

    volume = client.create_volume({"name" => "claim", "capacityBytes" => 4096, "accessModes" => ["ReadWriteOnce"],
                                   "parameters" => {"fstype" => "ext4"}, "secrets" => {"user" => "u"}}, token: "create-token")
    create_request = @state.request(:create_volume)

    assert_equal "claim", create_request.name
    assert_equal 4096, create_request.capacity_range.required_bytes
    assert_equal :SINGLE_NODE_WRITER, create_request.volume_capabilities.first.access_mode.mode
    assert_equal({"user" => "u"}, create_request.secrets.to_h)
    assert_equal "volume-1", volume.fetch("volumeId")

    client.create_volume({"name" => "restored", "capacityBytes" => 4096, "sourceSnapshotId" => "snapshot-1"},
                         token: "restore-token")
    source = @state.request(:create_volume).volume_content_source

    assert_equal "snapshot-1", source.snapshot.snapshot_id
    bridge.create_volume({"name" => "bridge-restored", "capacityBytes" => 4096, "sourceSnapshotId" => "snapshot-1"},
                         token: "bridge-restore-token")

    assert_equal "snapshot-1", @state.request(:create_volume).volume_content_source.snapshot.snapshot_id

    client.publish("volume-1", "node-a", token: "publish-token",
                                         context: {"volumeContext" => {"device" => "pci-1"}, "secrets" => {"user" => "u"},
                                                   "accessModes" => ["ReadWriteOnce"]})

    assert_equal "volume-1", @state.request(:publish).volume_id
    assert_equal({"device" => "pci-1"}, @state.request(:publish).volume_context.to_h)
    assert_equal({"user" => "u"}, @state.request(:publish).secrets.to_h)
    client.stage("volume-1", "/staging/volume-1", token: "stage-token",
                                                  context: {"volumeContext" => {"x" => "y"}, "publishContext" => {"published" => "true"},
                                                            "secrets" => {"user" => "u"}, "accessModes" => ["ReadWriteOnce"]})

    assert_equal "/staging/volume-1", @state.request(:stage).staging_target_path
    assert_equal({"published" => "true"}, @state.request(:stage).publish_context.to_h)
    assert_equal({"x" => "y"}, @state.request(:stage).volume_context.to_h)
    assert_equal({"user" => "u"}, @state.request(:stage).secrets.to_h)
    client.publish_node("volume-1", "/staging/volume-1", "/pods/pod-a", token: "node-publish-token",
                                                                        context: {"publishContext" => {"published" => "true"}, "volumeContext" => {"x" => "y"},
                                                                                  "secrets" => {"user" => "u"}, "accessModes" => ["ReadWriteOnce"]})

    assert_equal "/pods/pod-a", @state.request(:publish_node).target_path
    assert_equal({"published" => "true"}, @state.request(:publish_node).publish_context.to_h)
    assert_equal({"x" => "y"}, @state.request(:publish_node).volume_context.to_h)
    assert_equal({"user" => "u"}, @state.request(:publish_node).secrets.to_h)

    bridge_context = {
      "publishContext" => {"bridge-publish" => "p"}, "volumeContext" => {"bridge-volume" => "v"},
      "secrets" => {"bridge-secret" => "s"}, "accessModes" => ["ReadWriteOnce"]
    }
    bridge.stage("volume-1", "/staging/bridge", token: "bridge-stage", context: bridge_context)

    assert_equal({"bridge-publish" => "p"}, @state.request(:stage).publish_context.to_h)
    assert_equal({"bridge-volume" => "v"}, @state.request(:stage).volume_context.to_h)
    assert_equal({"bridge-secret" => "s"}, @state.request(:stage).secrets.to_h)
    bridge.publish_node("volume-1", "/staging/bridge", "/pods/bridge", token: "bridge-publish",
                                                                       context: bridge_context)

    assert_equal({"bridge-publish" => "p"}, @state.request(:publish_node).publish_context.to_h)
    assert_equal({"bridge-volume" => "v"}, @state.request(:publish_node).volume_context.to_h)
    assert_equal({"bridge-secret" => "s"}, @state.request(:publish_node).secrets.to_h)
    assert_equal 2, client.stats("volume-1").fetch("capacityBytes")

    snapshot = client.create_snapshot("volume-1", token: "snapshot-token")

    assert_equal "volume-1", @state.request(:create_snapshot).source_volume_id
    assert_equal "snapshot-1", snapshot.fetch("snapshotId")
    assert_equal "next-snapshot", client.list_snapshots(max_entries: 1, source_volume_id: "volume-1").fetch("nextToken")
    assert_equal 1, @state.request(:list_snapshots).max_entries
    assert_equal "volume-1", @state.request(:list_snapshots).source_volume_id
    client.delete_snapshot("snapshot-1", token: "delete-snapshot-token")
    client.unpublish_node("volume-1", "/pods/pod-a", token: "node-unpublish-token")
    client.unstage("volume-1", "/staging/volume-1", token: "unstage-token")
    client.unpublish("volume-1", "node-a", token: "unpublish-token")
    client.delete_volume("volume-1", token: "delete-token")

    assert_equal "volume-1", @state.request(:delete_volume).volume_id
  end

  def test_socket_and_capability_absence_fail_closed
    missing = File.join(@directory, "missing.sock")
    missing_client = Rubernetes::Volume::CSIUDSClient.new(socket: missing, timeout: 1)
    @clients << missing_client
    assert_raises(Rubernetes::Volume::CSIUnavailable) { missing_client.identity }

    @state.controller_advertised = false
    client = new_client
    error = assert_raises(Rubernetes::Volume::CSIUnavailable) { client.create_volume({"capacityBytes" => 1}, token: "token") }
    assert_match(/CONTROLLER_SERVICE/, error.message)
  end

  def test_socket_filesystem_and_peer_identity_are_pinned_and_replacement_is_rejected
    client = new_client
    identity = client.endpoint_identity

    assert_equal Process.euid, identity.fetch("uid")
    assert_equal Process.egid, identity.fetch("gid")
    assert_equal Process.euid, identity.fetch("peerUid")
    assert_equal Process.egid, identity.fetch("peerGid")
    assert_predicate identity.fetch("inode"), :positive?

    assert_raises(Rubernetes::Volume::CSIUnavailable) do
      Rubernetes::Volume::CSIUDSClient.new(
        socket: @socket, timeout: 1, expected_socket_uid: Process.euid + 1
      )
    end
    assert_raises(Rubernetes::Volume::CSIUnavailable) do
      Rubernetes::Volume::CSIUDSClient.new(
        socket: @socket, timeout: 1, expected_socket_gid: Process.egid + 1
      )
    end
    assert_raises(Rubernetes::Volume::CSIUnavailable) do
      Rubernetes::Volume::CSIUDSClient.new(
        socket: @socket, timeout: 1, expected_socket_mode: identity.fetch("mode") ^ 0o100
      )
    end
    assert_raises(Rubernetes::Volume::CSIUnavailable) do
      Rubernetes::Volume::CSIUDSClient.new(
        socket: @socket, timeout: 1, expected_peer_uid: Process.euid + 1
      )
    end
    assert_raises(Rubernetes::Volume::CSIUnavailable) do
      Rubernetes::Volume::CSIUDSClient.new(
        socket: @socket, timeout: 1, expected_peer_gid: Process.egid + 1
      )
    end

    File.unlink(@socket)
    replacement = UNIXServer.new(@socket)
    error = assert_raises(Rubernetes::Volume::CSIUnavailable) { client.identity }
    assert_match(/identity changed/, error.message)
  ensure
    replacement&.close
  end

  def test_socket_replacement_after_mutating_rpc_is_ambiguous
    client = new_client
    replacement = nil
    @state.after_create = lambda do
      File.unlink(@socket)
      replacement = UNIXServer.new(@socket)
    end

    error = assert_raises(Rubernetes::Volume::CSIError) do
      client.create_volume({"name" => "replaced", "capacityBytes" => 1}, token: "replace")
    end
    assert_predicate error, :ambiguous?
    assert_match(/identity changed while the RPC was in flight/, error.message)
    assert_equal 1, @state.requests_for(:create_volume).length
  ensure
    replacement&.close
  end

  def test_direct_client_forces_readonly_for_readonlymany_capability
    client = new_client
    context = {"accessModes" => ["ReadOnlyMany"], "volumeContext" => {}, "secrets" => {}}

    client.publish("volume-1", "node-a", token: "readonly-controller", context: context)

    assert @state.request(:publish).readonly
    assert_equal :MULTI_NODE_READER_ONLY, @state.request(:publish).volume_capability.access_mode.mode

    client.publish_node("volume-1", "/staging/volume-1", "/pods/readonly",
                        token: "readonly-node", context: context)

    assert @state.request(:publish_node).readonly
    assert_equal :MULTI_NODE_READER_ONLY, @state.request(:publish_node).volume_capability.access_mode.mode
    assert_includes @state.request(:publish_node).volume_capability.mount.mount_flags, "ro"
  end

  def test_bootstrap_builds_and_validates_real_uds_bridge_from_volume_config
    data_dir = File.join(@directory, "manager")
    socket_stat = File.lstat(@socket)
    process = {
      "runtime_profile" => "pure",
      "volume" => {
        "data_dir" => data_dir, "profile" => "test", "fsync" => true,
        "csi" => {
          "socket" => @socket, "timeout" => 2, "probe" => true,
          "socket_uid" => socket_stat.uid, "socket_gid" => socket_stat.gid,
          "socket_mode" => format("%04o", socket_stat.mode & 0o7777),
          "peer_uid" => Process.euid, "peer_gid" => Process.egid,
          "identity" => {"name" => "test.csi", "vendor_version" => "test-vendor"}
        }
      }
    }
    assembler = Rubernetes::Bootstrap::Assembler.new(process_name: "rubernetes-agent")
    manager = assembler.send(:build_volume, process, adapters: {})
    bridge = manager.instance_variable_get(:@csi)
    @clients << bridge.client

    assert_instance_of Rubernetes::Volume::CSIBridge, bridge
    id = manager.create_volume(
      {"name" => "assembled", "capacityBytes" => 512, "csi" => {"driver" => "test.csi"}},
      token: "assembled-create"
    )

    assert_equal "csi", manager.fetch_record(id).backend
    assert_equal "assembled", @state.request(:create_volume).name
    manager.controller.publish(id, "node-a", token: "assembled-attach")
    stage_path = File.join(@directory, "assembled-stage")
    manager.node.stage(id, stage_path, token: "assembled-stage", node: "node-a")

    assert_equal stage_path, @state.request(:stage).staging_target_path
    assert_equal stage_path, manager.volume(id).stages.fetch(stage_path).fetch("target")
  end

  # Requirement: spec/node/volume.md §5.11.2. The local claim identity never
  # replaces the CSI driver's opaque volume_id, including after restart.
  def test_manager_persists_driver_volume_id_and_uses_it_for_every_real_uds_rpc
    data_dir = File.join(@directory, "driver-id-manager")
    bridge = Rubernetes::Volume::CSIBridge.new(socket: @socket, timeout: 2)
    @clients << bridge.client
    resolver = lambda do |reference, volume_id:, purpose:|
      raise "unexpected secret reference" unless reference == {"name" => "csi-credentials"}
      raise "missing resolver context" if volume_id.empty? || purpose.empty?

      {"credential" => "memory-only-secret"}
    end
    first = Rubernetes::Volume::Manager.new(
      data_dir: data_dir, csi: bridge, secret_resolver: resolver, fsync: true
    )
    local_id = first.create_volume(
      {"name" => "claim", "capacityBytes" => 64, "csi" => {"driver" => "test.csi"},
       "secretRef" => {"name" => "csi-credentials"}}, token: "create"
    )

    refute_equal "volume-1", local_id
    assert_equal "volume-1", first.fetch_record(local_id).spec.fetch("backendResult").fetch("volumeId")
    assert_equal({"credential" => "memory-only-secret"}, @state.request(:create_volume).secrets.to_h)

    manager = Rubernetes::Volume::Manager.new(
      data_dir: data_dir, csi: bridge, secret_resolver: resolver, fsync: true
    )
    manager.controller.publish(local_id, "node-a", token: "attach")

    assert_equal "volume-1", @state.request(:publish).volume_id
    assert_equal({"credential" => "memory-only-secret"}, @state.request(:publish).secrets.to_h)

    stage_path = File.join(@directory, "stage")
    target_path = File.join(@directory, "target")
    pod = {"metadata" => {"uid" => "pod-a"}}
    manager.node.stage(local_id, stage_path, token: "stage", node: "node-a")

    assert_equal "volume-1", @state.request(:stage).volume_id
    assert_equal({"credential" => "memory-only-secret"}, @state.request(:stage).secrets.to_h)
    manager.node.publish(local_id, pod, target_path, readonly: false, token: "publish", node: "node-a")

    assert_equal "volume-1", @state.request(:publish_node).volume_id
    assert_equal({"credential" => "memory-only-secret"}, @state.request(:publish_node).secrets.to_h)
    manager.stats(local_id, path: target_path)

    assert_equal "volume-1", @state.request(:stats).volume_id
    assert_equal target_path, @state.request(:stats).volume_path
    manager.expand(local_id, 128, token: "expand")

    assert_equal "volume-1", @state.request(:expand).volume_id
    assert_equal({"credential" => "memory-only-secret"}, @state.request(:expand).secrets.to_h)
    manager.node.unpublish(local_id, pod, target_path, token: "unpublish")

    assert_equal "volume-1", @state.request(:unpublish_node).volume_id
    snapshot_id = manager.create_snapshot(local_id, token: "snapshot", name: "backup")

    assert_equal "volume-1", @state.request(:create_snapshot).source_volume_id
    assert_equal({"credential" => "memory-only-secret"}, @state.request(:create_snapshot).secrets.to_h)
    manager.delete_snapshot(snapshot_id, token: "delete-snapshot")

    assert_equal "snapshot-1", @state.request(:delete_snapshot).snapshot_id
    assert_equal({"credential" => "memory-only-secret"}, @state.request(:delete_snapshot).secrets.to_h)
    manager.node.unstage(local_id, stage_path, token: "unstage", node: "node-a")

    assert_equal "volume-1", @state.request(:unstage).volume_id
    manager.controller.unpublish(local_id, "node-a", token: "detach")

    assert_equal "volume-1", @state.request(:unpublish).volume_id
    manager.delete_volume(local_id, token: "delete")

    assert_equal "volume-1", @state.request(:delete_volume).volume_id

    persisted = Dir.glob(File.join(data_dir, "*.json")).map { |path| File.binread(path) }.join

    refute_includes persisted, "memory-only-secret"
  end

  # Requirement: spec/node/volume.md §5.11.2. ROX is read-only at the
  # controller boundary and online expansion reaches every active node path.
  def test_manager_sends_rox_readonly_and_runs_node_expand_for_active_paths
    bridge = Rubernetes::Volume::CSIBridge.new(socket: @socket, timeout: 2)
    @clients << bridge.client
    manager = Rubernetes::Volume::Manager.new(
      data_dir: File.join(@directory, "rox-expand"), csi: bridge, fsync: true
    )
    id = manager.create_volume(
      {"name" => "rox", "capacityBytes" => 64, "accessModes" => ["ReadOnlyMany"],
       "csi" => {"driver" => "test.csi"}}, token: "create-rox"
    )

    manager.controller.publish(id, "node-a", token: "attach-rox")
    controller_request = @state.request(:publish)

    assert controller_request.readonly
    assert_equal :MULTI_NODE_READER_ONLY, controller_request.volume_capability.access_mode.mode

    stage_path = File.join(@directory, "rox-stage")
    target_path = File.join(@directory, "rox-target")
    manager.node.stage(id, stage_path, token: "stage-rox", node: "node-a")
    manager.node.publish(id, "pod-rox", target_path, readonly: true, token: "publish-rox", node: "node-a")

    assert_equal 128, manager.expand(id, 128, token: "expand-rox")
    node_requests = @state.requests_for(:expand_node).last(2)

    assert_equal 2, node_requests.length
    assert_equal [stage_path, target_path].sort, node_requests.map(&:volume_path).sort
    node_requests.each do |request|
      assert_includes [stage_path, target_path], request.volume_path
      assert_equal "volume-1", request.volume_id
      assert_equal 128, request.capacity_range.required_bytes
      assert_equal :MULTI_NODE_READER_ONLY, request.volume_capability.access_mode.mode
    end
  end

  # Requirement: spec/node/volume.md §5.11.3. A driver cannot smuggle a
  # resolved secret back into durable contexts or surfaced CSI errors.
  def test_driver_echoed_secret_is_redacted_from_context_error_and_disk
    secret = "SECRET_ECHO"
    @state.volume_context = {"driver" => "test.csi", "opaque" => secret}
    @state.publish_context = {"opaque" => "prefix-#{secret}-suffix"}
    bridge = Rubernetes::Volume::CSIBridge.new(socket: @socket, timeout: 2)
    @clients << bridge.client
    resolver = ->(_reference, **) { {"credential" => secret} }
    data_dir = File.join(@directory, "secret-echo")
    manager = Rubernetes::Volume::Manager.new(
      data_dir: data_dir, csi: bridge, secret_resolver: resolver, fsync: true
    )
    id = manager.create_volume(
      {"name" => "echo", "accessModes" => ["ReadWriteMany"], "csi" => {"driver" => "test.csi"},
       "secretRef" => {"name" => "echo-secret"}}, token: "create-echo"
    )
    manager.controller.publish(id, "node-a", token: "attach-echo")

    record = manager.volume(id)

    assert_equal "[REDACTED]", record.spec.fetch("backendResult").fetch("volumeContext").fetch("opaque")
    assert_equal "prefix-[REDACTED]-suffix", record.attachments.fetch("node-a").fetch("publishContext").fetch("opaque")

    @state.publish_context = {"error" => "driver rejected #{secret}"}
    @state.publish_status = GRPC::Core::StatusCodes::INVALID_ARGUMENT
    error = assert_raises(Rubernetes::Volume::CSIError) do
      manager.controller.publish(id, "node-b", token: "attach-error")
    end
    refute_includes error.message, secret
    refute_includes JSON.generate(error.details), secret
    persisted = Dir.glob(File.join(data_dir, "**", "*.json")).map { |path| File.binread(path) }.join("\n")

    refute_includes persisted, secret
  end

  # Requirement: spec/node/volume.md §5.11.2–§5.11.3. Snapshot recovery
  # resolves the source volume's secret reference for List/DeleteSnapshot.
  def test_snapshot_restart_recovery_supplies_resolved_secrets_to_list_and_delete
    secret = "snapshot-runtime-secret"
    bridge = Rubernetes::Volume::CSIBridge.new(socket: @socket, timeout: 2)
    @clients << bridge.client
    resolver = ->(_reference, **) { {"credential" => secret} }
    data_dir = File.join(@directory, "snapshot-recovery")
    first = Rubernetes::Volume::Manager.new(
      data_dir: data_dir, csi: bridge, secret_resolver: resolver, fsync: true
    )
    id = first.create_volume(
      {"name" => "snapshot-source", "csi" => {"driver" => "test.csi"},
       "secretRef" => {"name" => "snapshot-secret"}}, token: "create"
    )
    snapshot_id = first.create_snapshot(id, token: "snapshot", name: "recoverable")
    first.snapshot_manager.mark_unknown(snapshot_id, reason: "response lost")
    payload = {"snapshotId" => snapshot_id}
    first.operations.begin!(
      key: "snapshot-#{snapshot_id}", operation: "delete-snapshot", token: "lost-delete",
      fingerprint: Rubernetes::Volume::Types.digest(payload), payload: payload
    )
    first.operations.effecting!(key: "snapshot-#{snapshot_id}", operation: "delete-snapshot", token: "lost-delete")

    restarted = Rubernetes::Volume::Manager.new(
      data_dir: data_dir, csi: bridge, secret_resolver: resolver, fsync: true
    )
    report = restarted.recover

    assert_empty report.errors
    assert_empty restarted.list_snapshots
    list_request = @state.request(:list_snapshots)

    assert_equal "volume-1", list_request.source_volume_id
    assert_equal({"credential" => secret}, list_request.secrets.to_h)
    assert_equal({"credential" => secret}, @state.request(:delete_snapshot).secrets.to_h)
    refute_includes Dir.glob(File.join(data_dir, "**", "*.json")).map { |path| File.binread(path) }.join, secret
  end

  def test_not_found_is_idempotent_and_transient_mutations_are_ambiguous
    client = new_client
    @state.delete_status = GRPC::Core::StatusCodes::NOT_FOUND

    assert_equal({}, client.delete_volume("already-gone", token: "delete-token"))

    @state.delete_status = GRPC::Core::StatusCodes::UNAVAILABLE
    error = assert_raises(Rubernetes::Volume::CSIError) { client.delete_volume("maybe-gone", token: "delete-token-2") }
    assert_predicate error, :ambiguous?
    assert_equal "UNAVAILABLE", error.details.fetch("grpcCode")
  end
end
