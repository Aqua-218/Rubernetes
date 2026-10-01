# frozen_string_literal: true

# The kubelet's CSI flow (pkg/volume/csi, v1.36.2): a node plugin registering
# as CSIPlugin publishes CSINode, the nodeid annotation and topology labels;
# volumes then go through the node plugin only -- the VolumeAttachment's
# attachmentMetadata as publish context, NodeStage only with
# STAGE_UNSTAGE_VOLUME, and podInfoOnMount / tokenRequests in the volume
# context.

require_relative "../test_helper"
require "digest"
require "json"
require "tmpdir"
require "rubernetes/node/csi_plugins"
require "rubernetes/node/pod_volumes"
require "rubernetes/volume"

class KubeletCSIPluginRegistrationTest < Minitest::Test
  Response = Struct.new(:status)

  class FakeClient
    attr_reader :objects, :tokens

    def initialize
      @objects = {}
      @tokens = []
      @rv = 0
      put("nodes", {"apiVersion" => "v1", "kind" => "Node",
                    "metadata" => {"name" => "n1", "uid" => "node-uid", "labels" => {"kubernetes.io/hostname" => "n1"}}})
    end

    def put(resource, object)
      @rv += 1
      object = JSON.parse(JSON.generate(object))
      object["metadata"]["resourceVersion"] = @rv.to_s
      @objects[[resource, object.dig("metadata", "name")]] = object
    end

    def get(resource, name, namespace: nil, api_version: "v1")
      object = @objects[[resource, name]]
      raise Rubernetes::Client::APIError.new("not found", response: Response.new(404)) unless object

      JSON.parse(JSON.generate(object))
    end

    def resource_of(object)
      {"Node" => "nodes", "CSINode" => "csinodes"}.fetch(object["kind"])
    end

    def create(object, namespace: nil, api_version: "v1", path: nil)
      if path&.end_with?("/token")
        @tokens << [path, object]
        return {"status" => {"token" => "tok-#{object.dig("spec", "audiences", 0)}", "expirationTimestamp" => "2026-09-25T01:00:00Z"}}
      end
      resource = resource_of(object)
      key = [resource, object.dig("metadata", "name")]
      raise Rubernetes::Client::APIError.new("exists", response: Response.new(409)) if @objects.key?(key)

      put(resource, object)
    end

    def delete(resource, name, namespace: nil, api_version: "v1")
      @objects.delete([resource, name]) || raise(Rubernetes::Client::APIError.new("not found", response: Response.new(404)))
    end

    def update(object)
      key = [resource_of(object), object.dig("metadata", "name")]
      current = @objects.fetch(key)
      unless current.dig("metadata", "resourceVersion") == object.dig("metadata", "resourceVersion")
        raise Rubernetes::Client::APIError.new("conflict", response: Response.new(409))
      end

      put(key.first, object)
    end
  end

  class FakeBridge
    attr_reader :calls
    attr_accessor :info, :capabilities

    def initialize(info:, capabilities: [])
      @info = info
      @capabilities = capabilities
      @calls = []
    end

    def node_info
      raise @info if @info.is_a?(Exception)

      @info
    end

    def node_capabilities = @capabilities
    def identity = Rubernetes::Volume::Identity.new(name: "hostpath.csi.k8s.io", vendor_version: "test")
    def probe = {"ready" => true}

    def stage(id, path, token:, readonly: false, context: {})
      @calls << [:stage, id, path, context]
      {"volumeId" => id, "target" => path, "mountId" => "11", "deviceId" => "0:11", "root" => "/",
       "filesystem" => "ext4", "source" => "/dev/test"}
    end

    def unstage(id, path, token:)
      @calls << [:unstage, id, path]
      {}
    end

    def publish_node(id, stage_path, target, token:, readonly: false, context: {})
      @calls << [:publish_node, id, stage_path, target, context]
      {"volumeId" => id, "target" => target, "mountId" => "12", "deviceId" => "0:12", "root" => "/",
       "filesystem" => "bind", "source" => "/dev/test"}
    end

    def unpublish_node(id, target, token:)
      @calls << [:unpublish_node, id, target]
      {}
    end

    def stats(id, token: nil, path: nil)
      @calls << [:stats, id, path]
      {"volumeId" => id, "capacityBytes" => 100, "availableBytes" => 70, "usedBytes" => 30, "inodes" => 9}
    end
  end

  def setup
    @client = FakeClient.new
    @bridges = {}
    @registry = Rubernetes::Node::CSIPlugins.new(
      client: @client, node_name: "n1",
      bridge_factory: ->(endpoint) { @bridges.fetch(endpoint) },
      adapter_options: {attach_timeout: 0.0, sleeper: ->(_) {}}
    )
  end

  def csi_node = @client.objects.fetch(%w[csinodes n1])
  def node = @client.objects.fetch(%w[nodes n1])

  MIGRATED = "kubernetes.io/aws-ebs,kubernetes.io/azure-disk,kubernetes.io/azure-file,kubernetes.io/cinder,kubernetes.io/gce-pd," \
             "kubernetes.io/portworx-volume,kubernetes.io/vsphere-volume"

  # nodeinfomanager_test TestInitializeCSINodeWithAnnotation / setMigrationAnnotation.
  def test_csinode_carries_the_migrated_plugins_annotation
    @registry.initialize_csi_node

    assert_equal MIGRATED, csi_node.dig("metadata", "annotations", "storage.alpha.kubernetes.io/migrated-plugins")
    # An existing CSINode with a stale annotation is corrected, an equal one left alone.
    stale = csi_node.merge("metadata" => csi_node["metadata"].merge("annotations" => {"storage.alpha.kubernetes.io/migrated-plugins" => "kubernetes.io/gce-pd"}))
    @client.put("csinodes", stale)
    version = csi_node.dig("metadata", "resourceVersion")
    Rubernetes::Node::CSIPlugins.new(client: @client, node_name: "n1", bridge_factory: ->(_) {}).initialize_csi_node

    assert_equal MIGRATED, csi_node.dig("metadata", "annotations", "storage.alpha.kubernetes.io/migrated-plugins")
    refute_equal version, csi_node.dig("metadata", "resourceVersion")
    version = csi_node.dig("metadata", "resourceVersion")
    Rubernetes::Node::CSIPlugins.new(client: @client, node_name: "n1", bridge_factory: ->(_) {}).initialize_csi_node

    assert_equal version, csi_node.dig("metadata", "resourceVersion"), "no update when nothing changed"
    object = {"metadata" => {"annotations" => {"storage.alpha.kubernetes.io/migrated-plugins" => "b,a"}}}

    refute Rubernetes::Node::CSIPlugins.set_migration_annotation(object, %w[a b]), "order does not matter"
    assert Rubernetes::Node::CSIPlugins.set_migration_annotation(object, [])
    refute object["metadata"]["annotations"].key?("storage.alpha.kubernetes.io/migrated-plugins")
  end

  # ensureNodeOwnsCSINode: a CSINode of this name owned by another Node UID
  # (the Node was recreated) is deleted and created again for this Node.
  def test_csinode_owned_by_another_node_is_replaced
    @client.put("csinodes", {"apiVersion" => "storage.k8s.io/v1", "kind" => "CSINode",
                             "metadata" => {"name" => "n1",
                                            "ownerReferences" => [{"apiVersion" => "v1", "kind" => "Node", "name" => "n1", "uid" => "old-uid"}]},
                             "spec" => {"drivers" => [{"name" => "stale.csi", "nodeID" => "x", "topologyKeys" => []}]}})
    @registry.initialize_csi_node

    assert_equal "node-uid", csi_node.dig("metadata", "ownerReferences", 0, "uid")
    assert_empty csi_node.dig("spec", "drivers")
  end

  # installDriverToCSINode: the attach limit is clamped to int32, a negative
  # one adds no allocatable, and an entry that already says the same is not
  # rewritten.
  def test_attach_limit_clamp_negative_and_unchanged_entry
    @bridges["/big.sock"] = FakeBridge.new(info: {"nodeId" => "node-x", "maxVolumesPerNode" => 2**40, "topology" => {}})
    @registry.register_plugin("big.csi", "/big.sock", ["1.0.0"])

    assert_equal (2**31) - 1, csi_node.dig("spec", "drivers").find { |driver| driver["name"] == "big.csi" }.dig("allocatable", "count")
    errors = []
    registry = Rubernetes::Node::CSIPlugins.new(client: @client, node_name: "n1", bridge_factory: ->(endpoint) { @bridges.fetch(endpoint) },
                                                adapter_options: {attach_timeout: 0.0, sleeper: lambda { |_|
                                                }}, error_handler: lambda { |error, *|
                                                      errors << error
                                                    })
    @bridges["/neg.sock"] = FakeBridge.new(info: {"nodeId" => "node-y", "maxVolumesPerNode" => -3, "topology" => {}})
    registry.register_plugin("neg.csi", "/neg.sock", ["1.0.0"])

    refute csi_node.dig("spec", "drivers").find { |driver| driver["name"] == "neg.csi" }.key?("allocatable")
    assert_match(/Invalid attach limit value -3/, errors.first.message)
    csi_node.dig("metadata", "resourceVersion")
    registry.deregister_plugin("neg.csi", "/neg.sock")
    registry.register_plugin("neg.csi", "/neg.sock", ["1.0.0"])
    # Re-registering the same driver twice more: the second time nothing changes.
    version = csi_node.dig("metadata", "resourceVersion")
    registry.register_plugin("neg.csi", "/neg.sock", ["1.0.0"])

    assert_equal version, csi_node.dig("metadata", "resourceVersion")
  end

  def test_validate_requires_a_1x_version
    assert_raises(Rubernetes::Node::CSIPlugins::Error) { @registry.validate_plugin("d", "/s", ["0.3.0"]) }
    assert_raises(Rubernetes::Node::CSIPlugins::Error) { @registry.validate_plugin("", "/s", ["1.0.0"]) }
    assert @registry.validate_plugin("d", "/s", ["0.3.0", "1.0.0"])
  end

  def test_initialize_csi_node_creates_an_empty_node_owned_csinode
    @registry.initialize_csi_node

    assert_equal [], csi_node.dig("spec", "drivers")
    assert_equal [{"apiVersion" => "v1", "kind" => "Node", "name" => "n1", "uid" => "node-uid"}],
                 csi_node.dig("metadata", "ownerReferences")
  end

  def test_registration_publishes_csinode_annotation_and_topology_labels
    @bridges["/a.sock"] = FakeBridge.new(info: {"nodeId" => "node-a", "maxVolumesPerNode" => 7,
                                                "topology" => {"topology.hostpath.csi/node" => "n1"}})
    @bridges["/b.sock"] = FakeBridge.new(info: {"nodeId" => "node-b", "maxVolumesPerNode" => 0, "topology" => {}})
    @registry.register_plugin("a.csi", "/a.sock", ["1.0.0"])
    @registry.register_plugin("b.csi", "/b.sock", ["v1.2.0"])

    assert_equal [{"name" => "a.csi", "nodeID" => "node-a", "topologyKeys" => ["topology.hostpath.csi/node"],
                   "allocatable" => {"count" => 7}},
                  # TopologyKeys has no omitempty: an empty list is published.
                  {"name" => "b.csi", "nodeID" => "node-b", "topologyKeys" => []}], csi_node.dig("spec", "drivers")
    assert_equal({"a.csi" => "node-a", "b.csi" => "node-b"},
                 JSON.parse(node.dig("metadata", "annotations", "csi.volume.kubernetes.io/nodeid")))
    assert_equal "n1", node.dig("metadata", "labels", "topology.hostpath.csi/node")
    assert_equal %w[a.csi b.csi], @registry.registered_drivers
    assert_instance_of Rubernetes::Volume::KubernetesCSIAdapter, @registry.for_driver("a.csi")

    @registry.deregister_plugin("a.csi", "/a.sock")

    assert_equal(["b.csi"], csi_node.dig("spec", "drivers").map { |driver| driver["name"] })
    assert_equal({"b.csi" => "node-b"}, JSON.parse(node.dig("metadata", "annotations", "csi.volume.kubernetes.io/nodeid")))
    # Topology labels stay, as upstream.
    assert_equal "n1", node.dig("metadata", "labels", "topology.hostpath.csi/node")
    assert_raises(Rubernetes::Volume::CSIUnavailable) { @registry.for_driver("a.csi") }

    @registry.deregister_plugin("b.csi", "/b.sock")

    assert_equal [], csi_node.dig("spec", "drivers")
    refute node.dig("metadata", "annotations").key?("csi.volume.kubernetes.io/nodeid")
  end

  def test_failed_node_get_info_leaves_the_driver_unregistered
    @bridges["/a.sock"] = FakeBridge.new(info: RuntimeError.new("boom"))
    error = assert_raises(Rubernetes::Node::CSIPlugins::Error) { @registry.register_plugin("a.csi", "/a.sock", ["1.0.0"]) }
    assert_match(/boom/, error.message)
    assert_empty @registry.registered_drivers
    @bridges["/b.sock"] = FakeBridge.new(info: {"nodeId" => "", "topology" => {}})
    assert_raises(Rubernetes::Node::CSIPlugins::Error) { @registry.register_plugin("b.csi", "/b.sock", ["1.0.0"]) }
    assert_empty @registry.registered_drivers
  end

  def test_topology_label_collision_fails_registration
    @client.objects[%w[nodes n1]]["metadata"]["labels"]["zone"] = "a"
    @bridges["/a.sock"] = FakeBridge.new(info: {"nodeId" => "x", "topology" => {"zone" => "b"}})
    assert_raises(Rubernetes::Node::CSIPlugins::Error) { @registry.register_plugin("a.csi", "/a.sock", ["1.0.0"]) }
  end

  def test_handle_and_attachment_names_match_upstream
    assert_equal "csi-#{Digest::SHA256.hexdigest("uid-1vol")}",
                 Rubernetes::Volume::KubernetesCSIAdapter.inline_volume_handle("uid-1", "vol")
    assert_equal "csi-#{Digest::SHA256.hexdigest("handlehostpath.csi.k8s.ion1")}",
                 Rubernetes::Volume::KubernetesCSIAdapter.attachment_name("handle", "hostpath.csi.k8s.io", "n1")
  end

  def adapter(capabilities: [], attach_timeout: 0.0)
    bridge = FakeBridge.new(info: {}, capabilities: capabilities)
    api = Rubernetes::Node::CSIPlugins::API.new(@client)
    [Rubernetes::Volume::KubernetesCSIAdapter.new(driver: "hostpath.csi.k8s.io", bridge: bridge, api: api, node_name: "n1",
                                                  attach_timeout: attach_timeout, sleeper: ->(_) {}), bridge]
  end

  def put_driver(spec)
    @client.put("csidrivers", {"apiVersion" => "storage.k8s.io/v1", "kind" => "CSIDriver",
                               "metadata" => {"name" => "hostpath.csi.k8s.io"},
                               "spec" => {"fsGroupPolicy" => "ReadWriteOnceWithFSType", "volumeLifecycleModes" => ["Persistent"]}.merge(spec)})
  end

  def test_attach_waits_for_the_volume_attachment_and_returns_its_metadata
    csi, = adapter
    name = Rubernetes::Volume::KubernetesCSIAdapter.attachment_name("h1", "hostpath.csi.k8s.io", "n1")
    error = assert_raises(Rubernetes::Volume::CSIError) { csi.publish("h1", "n1", context: {}) }
    assert_match(/VolumeAttachment #{name}/, error.message)

    @client.put("volumeattachments", {"metadata" => {"name" => name},
                                      "status" => {"attached" => true, "attachmentMetadata" => {"dev" => "/dev/x"}}})

    assert_equal({"dev" => "/dev/x"}, csi.publish("h1", "n1", context: {})["publishContext"])
  end

  def test_attach_is_skipped_when_not_required_or_ephemeral
    csi, = adapter

    assert_equal({}, csi.publish("h1", "n1", context: {"ephemeral" => true})["publishContext"])
    put_driver({"attachRequired" => false})

    assert_equal({}, csi.publish("h1", "n1", context: {})["publishContext"])
  end

  def test_stage_is_skipped_without_stage_unstage_capability
    csi, bridge = adapter
    result = csi.stage("h1", "/stage", context: {})

    assert_equal true, result["stageSkipped"]
    assert_equal false, result["mounted"]
    assert_equal({}, csi.unstage("h1", "/stage"))
    assert_empty bridge.calls

    csi, bridge = adapter(capabilities: ["STAGE_UNSTAGE_VOLUME"])
    csi.stage("h1", "/stage", context: {})

    assert_equal :stage, bridge.calls.first.first
  end

  def test_publish_passes_pod_info_ephemeral_flag_and_service_account_tokens
    put_driver({"podInfoOnMount" => true, "tokenRequests" => [{"audience" => "vault", "expirationSeconds" => 3600}]})
    csi, bridge = adapter
    pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"}, "spec" => {"serviceAccountName" => "sa"}}
    csi.publish_node("h1", "/stage", "/target", context: {"pod" => pod, "ephemeral" => false,
                                                          "volumeContext" => {"k" => "v"}})
    _, _, stage_path, _, context = bridge.calls.last

    assert_equal "", stage_path
    refute context.key?("pod")
    volume_context = context.fetch("volumeContext")

    assert_equal "v", volume_context["k"]
    assert_equal "p", volume_context["csi.storage.k8s.io/pod.name"]
    assert_equal "ns", volume_context["csi.storage.k8s.io/pod.namespace"]
    assert_equal "u1", volume_context["csi.storage.k8s.io/pod.uid"]
    assert_equal "sa", volume_context["csi.storage.k8s.io/serviceAccount.name"]
    assert_equal "false", volume_context["csi.storage.k8s.io/ephemeral"]
    tokens = JSON.parse(volume_context.fetch("csi.storage.k8s.io/serviceAccount.tokens"))

    assert_equal "tok-vault", tokens.dig("vault", "token")
    path, request = @client.tokens.last

    assert_equal "/api/v1/namespaces/ns/serviceaccounts/sa/token", path
    assert_equal({"apiVersion" => "v1", "kind" => "Pod", "name" => "p", "uid" => "u1"}, request.dig("spec", "boundObjectRef"))
    assert_equal 3600, request.dig("spec", "expirationSeconds")
  end

  def test_publish_without_pod_info_on_mount_adds_nothing
    csi, bridge = adapter(capabilities: ["STAGE_UNSTAGE_VOLUME"])
    pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"}, "spec" => {}}
    csi.publish_node("h1", "/stage", "/target", context: {"pod" => pod, "volumeContext" => {}})
    _, _, stage_path, _, context = bridge.calls.last

    assert_equal "/stage", stage_path
    assert_equal({}, context.fetch("volumeContext"))
  end

  def test_lifecycle_modes_follow_the_csidriver
    csi, = adapter
    error = assert_raises(Rubernetes::Volume::CSIError) { csi.publish_node("h", "/s", "/t", context: {"ephemeral" => true}) }
    assert_match(/no CSIDriver object/, error.message)
    csi.publish_node("h", "/s", "/t", context: {})
    put_driver({})
    error = assert_raises(Rubernetes::Volume::CSIError) { csi.publish_node("h", "/s", "/t", context: {"ephemeral" => true}) }
    assert_match(/only supports \["Persistent"\]/, error.message)
    put_driver({"volumeLifecycleModes" => ["Ephemeral"]})
    assert_raises(Rubernetes::Volume::CSIError) { csi.publish_node("h", "/s", "/t", context: {}) }
    csi.publish_node("h", "/s", "/t", context: {"ephemeral" => true})
  end

  def test_an_ephemeral_volume_is_neither_staged_nor_given_a_staging_path
    put_driver({"volumeLifecycleModes" => ["Ephemeral"], "podInfoOnMount" => true})
    csi, bridge = adapter(capabilities: ["STAGE_UNSTAGE_VOLUME"])

    assert_equal true, csi.stage("h", "/s", context: {"ephemeral" => true})["stageSkipped"]
    pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"}, "spec" => {"serviceAccountName" => "sa"}}
    csi.publish_node("h", "/s", "/t", context: {"ephemeral" => true, "pod" => pod, "publishContext" => {"x" => "y"}})
    _, _, stage_path, _, context = bridge.calls.last

    assert_equal "", stage_path
    assert_equal({}, context["publishContext"])
    assert_equal "true", context.dig("volumeContext", "csi.storage.k8s.io/ephemeral")
    refute context.key?("ephemeral")
  end

  def test_tokens_go_to_secrets_when_the_driver_asks
    put_driver({"tokenRequests" => [{"audience" => ""}], "serviceAccountTokenInSecrets" => true})
    csi, bridge = adapter
    pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"}, "spec" => {"serviceAccountName" => "sa"}}
    csi.publish_node("h", "/s", "/t", context: {"pod" => pod, "secrets" => {"a" => "b"}})
    context = bridge.calls.last.last

    refute context["volumeContext"].key?("csi.storage.k8s.io/serviceAccount.tokens")
    assert_equal "b", context.dig("secrets", "a")
    assert JSON.parse(context.dig("secrets", "csi.storage.k8s.io/serviceAccount.tokens")).key?("")
    assert_equal [], @client.tokens.last.last.dig("spec", "audiences")
  end

  def test_fs_group_policy_decisions_match_supports_fs_group
    csi, = adapter
    args = {fs_group: 1000, fs_type: "ext4", access_modes: ["ReadWriteOnce"], ephemeral: false, readonly: false}

    assert_equal :kubelet, csi.fs_group_mode(**args)
    assert_equal :none, csi.fs_group_mode(**args, fs_group: nil)
    assert_equal :none, csi.fs_group_mode(**args, fs_type: "")
    assert_equal :none, csi.fs_group_mode(**args, access_modes: ["ReadWriteMany"])
    assert_equal :none, csi.fs_group_mode(**args, readonly: true)
    assert_equal :kubelet, csi.fs_group_mode(**args, access_modes: [], ephemeral: true)
    put_driver({"fsGroupPolicy" => "File"})

    assert_equal :kubelet, csi.fs_group_mode(**args, fs_type: "", access_modes: ["ReadWriteMany"])
    put_driver({"fsGroupPolicy" => "None"})

    assert_equal :none, csi.fs_group_mode(**args)
    csi, = adapter(capabilities: ["VOLUME_MOUNT_GROUP"])

    assert_equal :delegate, csi.fs_group_mode(**args)
  end

  def test_volume_mount_group_and_mount_options_reach_the_driver
    csi, bridge = adapter(capabilities: %w[STAGE_UNSTAGE_VOLUME VOLUME_MOUNT_GROUP])
    csi.stage("h", "/s", context: {"fsGroup" => 2000, "fsType" => "xfs", "mountOptions" => ["noatime"]})
    context = bridge.calls.last.last

    assert_equal({"fsType" => "xfs", "mountFlags" => ["noatime"], "volumeMountGroup" => "2000"}, context["mount"])
    refute context.key?("fsGroup")
    csi.publish_node("h", "/s", "/t", context: {"volumeMountGroup" => "2000", "fsType" => "xfs"})

    assert_equal({"fsType" => "xfs", "volumeMountGroup" => "2000"}, bridge.calls.last.last["mount"])

    csi, bridge = adapter(capabilities: %w[STAGE_UNSTAGE_VOLUME])
    csi.stage("h", "/s", context: {"fsGroup" => 2000})

    refute bridge.calls.last.last["mount"].key?("volumeMountGroup")
  end

  class FsGroupRecorder
    attr_reader :paths

    def initialize = @paths = []

    def apply_fs_group(path:, fs_group:, **)
      @paths << [path, fs_group]
    end
  end

  def test_the_kubelet_applies_fs_group_to_the_published_target
    @bridges["/a.sock"] = FakeBridge.new(info: {"nodeId" => "node-a", "topology" => {}})
    @registry.register_plugin("hostpath.csi.k8s.io", "/a.sock", ["1.0.0"])
    put_driver({"attachRequired" => false, "fsGroupPolicy" => "File"})
    recorder = FsGroupRecorder.new
    Dir.mktmpdir do |directory|
      manager = Rubernetes::Volume::Manager.new(data_dir: directory, fsync: false, mount_adapter: recorder)
      manager.csi_registry = @registry
      id = manager.create_volume({"name" => "v", "csi" => {"driver" => "hostpath.csi.k8s.io", "volumeHandle" => "h"},
                                  "accessModes" => ["ReadWriteOnce"]}, token: "create")
      manager.controller.publish(id, "n1", token: "attach")
      stage = File.join(directory, "stage")
      target = File.join(directory, "target")
      manager.node.stage(id, stage, token: "stage", node: "n1")
      pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"}, "spec" => {}}
      manager.node.publish(id, pod, target, readonly: false, token: "publish", node: "n1", fs_group: 3000)

      assert_equal([[File.realpath(target), 3000]], recorder.paths.map { |path, group| [File.realpath(path), group] })
      assert manager.node.reapply_fs_group(id, pod: pod, stage_path: stage, fs_group: 3000)
      assert_equal 1, recorder.paths.length
    end
  end

  def test_an_unregistered_driver_is_a_retryable_error_until_it_registers
    put_driver({"attachRequired" => false})
    Dir.mktmpdir do |directory|
      manager = Rubernetes::Volume::Manager.new(data_dir: directory, fsync: false)
      manager.csi_registry = @registry
      spec = {"name" => "v", "csi" => {"driver" => "hostpath.csi.k8s.io", "volumeHandle" => "h"}, "accessModes" => ["ReadWriteOnce"]}
      error = assert_raises(Rubernetes::Volume::CSIUnavailable) { manager.create_volume(spec, token: "create") }
      assert_match(/not found in the list of registered CSI drivers/, error.message)
      @bridges["/a.sock"] = FakeBridge.new(info: {"nodeId" => "node-a", "topology" => {}})
      @registry.register_plugin("hostpath.csi.k8s.io", "/a.sock", ["1.0.0"])
      id = manager.create_volume(spec, token: "create-2")
      manager.controller.publish(id, "n1", token: "attach")
      manager.node.stage(id, File.join(directory, "stage"), token: "stage", node: "n1")

      assert_equal "Staged", manager.volume(id).state
    end
  end

  def test_a_restarted_node_reconstructs_csi_volumes_once_the_registry_is_attached
    put_driver({"attachRequired" => false})
    @bridges["/a.sock"] = FakeBridge.new(info: {"nodeId" => "node-a", "topology" => {}})
    @registry.register_plugin("hostpath.csi.k8s.io", "/a.sock", ["1.0.0"])
    Dir.mktmpdir do |directory|
      manager = Rubernetes::Volume::Manager.new(data_dir: directory, fsync: false)
      manager.csi_registry = @registry
      id = manager.create_volume({"name" => "v", "csi" => {"driver" => "hostpath.csi.k8s.io", "volumeHandle" => "h"},
                                  "accessModes" => ["ReadWriteOnce"]}, token: "create")
      manager.controller.publish(id, "n1", token: "attach")
      stage = File.join(directory, "stage")
      manager.node.stage(id, stage, token: "stage", node: "n1")

      restarted = Rubernetes::Volume::Manager.new(data_dir: directory, fsync: false)
      record = restarted.volume(id)

      assert_equal "Unknown", record.state
      assert_equal true, record.operation["csiUnconfigured"]
      restarted.csi_registry = @registry

      assert_equal "Staged", restarted.volume(id).state
      restarted.node.unstage(id, stage, token: "unstage", node: "n1")

      assert_equal "Attached", restarted.volume(id).state
    end
  end

  def test_requires_republish_calls_node_publish_again_with_fresh_tokens
    @bridges["/a.sock"] = FakeBridge.new(info: {"nodeId" => "node-a", "topology" => {}})
    @registry.register_plugin("hostpath.csi.k8s.io", "/a.sock", ["1.0.0"])
    put_driver({"attachRequired" => false, "requiresRepublish" => false, "tokenRequests" => [{"audience" => "vault"}]})
    Dir.mktmpdir do |directory|
      manager = Rubernetes::Volume::Manager.new(data_dir: directory, fsync: false)
      manager.csi_registry = @registry
      id = manager.create_volume({"name" => "v", "csi" => {"driver" => "hostpath.csi.k8s.io", "volumeHandle" => "h"},
                                  "accessModes" => ["ReadWriteOnce"]}, token: "create")
      manager.controller.publish(id, "n1", token: "attach")
      manager.node.stage(id, File.join(directory, "stage"), token: "stage", node: "n1")
      pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"}, "spec" => {"serviceAccountName" => "sa"}}
      target = File.join(directory, "target")
      manager.node.publish(id, pod, target, readonly: false, token: "publish", node: "n1")
      bridge = @bridges["/a.sock"]

      refute manager.node_republish(id, pod, target, token: "r1")
      assert_equal(1, bridge.calls.count { |call| call.first == :publish_node })

      put_driver({"attachRequired" => false, "requiresRepublish" => true, "tokenRequests" => [{"audience" => "vault"}]})

      assert manager.node_republish(id, pod, target, token: "r2")
      calls = bridge.calls.select { |call| call.first == :publish_node }

      assert_equal 2, calls.length
      assert_equal calls.first[3], calls.last[3]
      assert calls.last[4].dig("volumeContext", "csi.storage.k8s.io/serviceAccount.tokens")
      assert_equal 2, @client.tokens.length
      refute manager.node_republish(id, {"metadata" => {"uid" => "other"}}, target, token: "r3")
    end
  end

  def test_csi_volume_stats_come_from_the_driver_only_with_get_volume_stats
    @bridges["/a.sock"] = FakeBridge.new(info: {"nodeId" => "node-a", "topology" => {}})
    @registry.register_plugin("hostpath.csi.k8s.io", "/a.sock", ["1.0.0"])
    put_driver({"attachRequired" => false})
    Dir.mktmpdir do |directory|
      manager = Rubernetes::Volume::Manager.new(data_dir: directory, fsync: false)
      manager.csi_registry = @registry
      id = manager.create_volume({"name" => "v", "csi" => {"driver" => "hostpath.csi.k8s.io", "volumeHandle" => "h"},
                                  "accessModes" => ["ReadWriteOnce"]}, token: "create")
      manager.controller.publish(id, "n1", token: "attach")
      manager.node.stage(id, File.join(directory, "stage"), token: "stage", node: "n1")
      target = File.join(directory, "target")
      pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"}, "spec" => {}}
      manager.node.publish(id, pod, target, readonly: false, token: "publish", node: "n1")

      assert_equal :unsupported, manager.csi_volume_stats(id, target)
      assert_nil manager.csi_volume_stats("missing", target)

      @bridges["/a.sock"].capabilities = ["GET_VOLUME_STATS"]
      @registry.for_driver("hostpath.csi.k8s.io").instance_variable_set(:@node_capabilities, nil)
      stats = manager.csi_volume_stats(id, target)

      assert_equal [100, 70, 30, 9], stats.values_at("capacityBytes", "availableBytes", "usedBytes", "inodes")
      call = @bridges["/a.sock"].calls.find { |entry| entry.first == :stats }

      assert_equal "h", call[1]
      assert_equal File.realpath(target), File.realpath(call[2])
    end
  end

  # The volume manager resolves the driver through the registry; with no
  # STAGE_UNSTAGE_VOLUME the stage is recorded unmounted and publish gets no
  # staging path.
  def test_volume_manager_uses_the_registered_plugin
    @bridges["/a.sock"] = FakeBridge.new(info: {"nodeId" => "node-a", "topology" => {}})
    @registry.register_plugin("hostpath.csi.k8s.io", "/a.sock", ["1.0.0"])
    put_driver({"attachRequired" => false, "podInfoOnMount" => true})
    Dir.mktmpdir do |directory|
      manager = Rubernetes::Volume::Manager.new(data_dir: directory, fsync: false)
      manager.csi_registry = @registry
      id = manager.create_volume({"name" => "v", "csi" => {"driver" => "hostpath.csi.k8s.io", "volumeHandle" => "pv-handle",
                                                           "volumeAttributes" => {"a" => "b"}},
                                  "accessModes" => ["ReadWriteOnce"]}, token: "create")
      manager.controller.publish(id, "n1", token: "attach")
      stage = File.join(directory, "stage")
      manager.node.stage(id, stage, token: "stage", node: "n1")
      pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"}, "spec" => {}}
      manager.node.publish(id, pod, File.join(directory, "target"), readonly: false, token: "publish", node: "n1")
      bridge = @bridges["/a.sock"]
      call = bridge.calls.find { |entry| entry.first == :publish_node }

      refute_nil call
      assert_equal "pv-handle", call[1]
      assert_equal "", call[2]
      assert_equal "p", call[4].dig("volumeContext", "csi.storage.k8s.io/pod.name")
      assert_equal "b", call[4].dig("volumeContext", "a")
      refute(bridge.calls.any? { |entry| entry.first == :stage })
    end
  end
end

class KubeletInlineCSIVolumeTranslationTest < Minitest::Test
  def test_inline_csi_volume_gets_the_upstream_ephemeral_handle
    volumes = Rubernetes::Node::PodVolumes.new(volume: Object.new, root: "/tmp/fake-pods")
    pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "uid-1"}, "spec" => {}}
    entry = {"name" => "inline", "csi" => {"driver" => "hostpath.csi.k8s.io", "volumeAttributes" => {"size" => "1Mi"}}}
    spec, readonly = volumes.send(:translate, entry, pod, pod_ip: nil, host_ip: nil)
    csi = spec.fetch("csi")

    assert_equal "csi-#{Digest::SHA256.hexdigest("uid-1inline")}", csi["volumeHandle"]
    assert_equal true, csi["ephemeral"]
    assert_equal({"size" => "1Mi"}, csi["volumeAttributes"])
    refute readonly
  end
end

class KubeletCSIPluginAgentWiringTest < Minitest::Test
  Node = Rubernetes::Node

  class API
    attr_reader :client

    def initialize(client) = @client = client
    def create_or_update_node(node) = node
    def renew_lease(**) = {}
  end

  class Lifecycle
    def admitted_pods = []
    def pods = {}
  end

  class Loop
    def start = nil
    def stop = nil
    def running? = false
  end

  class Volume
    attr_reader :registry

    def csi_registry=(registry)
      @registry = registry
    end
  end

  def test_the_agent_registers_the_csi_handler_and_hands_the_registry_to_the_volume_manager
    Dir.mktmpdir do |dir|
      pod_root = File.join(dir, "pods")
      FileUtils.mkdir_p(pod_root)
      volume = Volume.new
      agent = Node::Agent.new(node_name: "n1", api: API.new(KubeletCSIPluginRegistrationTest::FakeClient.new), volume: volume,
                              lifecycle: Lifecycle.new, sync_loop: Loop.new, sleeper: ->(_) {}, pod_root: pod_root,
                              capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "110"}, dra: {"enabled" => false})

      assert_instance_of Node::CSIPlugins, agent.csi_plugins
      assert_same agent.csi_plugins, volume.registry
      refute_nil agent.plugin_manager
      handlers = agent.plugin_manager.instance_variable_get(:@handlers)

      assert_same agent.csi_plugins, handlers.fetch("CSIPlugin")
      refute handlers.key?("DRAPlugin")
    end
  end
end
