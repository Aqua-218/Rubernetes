# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

class InTreeStorageTest < Minitest::Test
  Volume = Rubernetes::Volume
  IQN = "iqn.2026-11.example:storage"
  WWN = "50060e801049b1fd"

  class Reader
    attr_reader :gets

    def initialize(objects)
      @objects = objects
      @gets = []
    end

    def get(resource, name, namespace:)
      key = [resource, name, namespace]
      @gets << key
      @objects[key]
    end
  end

  class Devices
    attr_accessor :unavailable
    attr_reader :stages, :releases

    def initialize
      @stages = []
      @releases = []
    end

    def with_device(backend, readonly:, credentials:)
      @stages << [backend, readonly, credentials]
      raise Volume::Error, "LUN unavailable" if unavailable

      yield "/dev/mock-#{backend.type}", nil
    end

    def release(backend)
      @releases << backend.id
    end
  end

  def setup
    @scratch = Dir.mktmpdir
    @devices = Devices.new
    @manager = Volume::Manager.new(data_dir: @scratch, storage_devices: @devices)
  end

  def teardown
    FileUtils.remove_entry(@scratch)
  end

  def test_nfs_retries_the_same_export_with_v3_when_absent_in_the_v4_namespace
    backend_class = Class.new(Volume::NFSBackend) do
      attr_reader :attempts

      def mount_stage(_target, source:, readonly:, options:)
        (@attempts ||= []) << [source, readonly, options]
        return {"source" => source} if options.include?("vers=3")

        raise Rubernetes::Platform::Linux::Error.new(errno: Errno::ENOENT::Errno, operation: "mount", resource_id: source)
      end
    end
    source = {"server" => "192.0.2.40", "path" => "/exports"}
    backend = backend_class.new(id: "example", spec: source, root: @scratch, require_real_readback: true)
    mounted = backend.stage(path: @scratch, node: "worker", readonly: true)

    assert_equal "192.0.2.40:/exports", mounted.fetch("source")
    assert_equal(%w[vers=4.2 vers=4.1 vers=4 vers=3], backend.attempts.map { |_, _, options| options.last })
    assert_equal [["192.0.2.40:/exports", true]], backend.attempts.map { |address, readonly, _| [address, readonly] }.uniq

    explicit = source.merge("mountOptions" => ["vers=4.1"])
    backend = backend_class.new(id: "explicit", spec: explicit, root: @scratch, require_real_readback: true)

    assert_raises(Rubernetes::Platform::Linux::Error) { backend.stage(path: @scratch, node: "worker") }
    assert_equal 1, backend.attempts.size
  end

  def test_mounted_pv_gid_joins_explicit_groups_under_strict_policy
    claim = {"metadata" => {"uid" => "pvc-uid"}, "spec" => {"volumeName" => "storage"}, "status" => {"phase" => "Bound"}}
    volume = {"metadata" => {"annotations" => {"pv.beta.kubernetes.io/gid" => "777"}},
              "spec" => {"accessModes" => ["ReadWriteOnce"], "claimRef" => {"uid" => "pvc-uid"},
                         "nfs" => {"server" => "192.0.2.40", "path" => "/shared"}}}
    volumes = node_volumes(Reader.new(%w[persistentvolumeclaims disk apps] => claim, ["persistentvolumes", "storage", nil] => volume))
    pod = pod_with(claim_volume)
    pod["spec"]["securityContext"] = {"supplementalGroupsPolicy" => "Strict", "supplementalGroups" => [888]}
    handle = volumes.prepare(pod)

    assert_equal 777, handle.dig("mounts", "claim", "volumeGid")

    builder = Rubernetes::Node::ContainerSpec.new(pod_volumes: volumes)
    definition = {"name" => "app", "volumeMounts" => [{"name" => "claim", "mountPath" => "/data"}]}
    built = builder.build(pod: pod, container: definition, category: "app", volumes: handle)

    assert_equal [888, 777], built.dig("security_context", "supplementalGroups")
    assert_equal [888], pod.dig("spec", "securityContext", "supplementalGroups")
    assert volumes.release(pod, handle)
  end

  def test_inline_nfs_and_readonly_nfs_claim_stage_mount_options_and_teardown
    reader = reader_for_claim("nfs" => {"server" => "192.0.2.40", "path" => "/shared"},
                              "mountOptions" => ["vers=3,nolock", "proto=tcp"], "accessModes" => ["ReadOnlyMany"])
    volumes = node_volumes(reader)
    pod = pod_with({"name" => "inline", "nfs" => {"server" => "2001:db8::1", "path" => "/inline"}},
                   claim_volume)
    pod["spec"]["securityContext"] = {"fsGroup" => 1234}

    handle = volumes.prepare(pod)

    assert_equal false, handle.dig("mounts", "inline", "readonly")
    assert_equal true, handle.dig("mounts", "claim", "readonly")
    stages = stages_by_source

    assert_equal "nfs", stages.fetch("[2001:db8::1]:/inline")["filesystem"]
    assert_equal %w[vers=3 nolock proto=tcp], stages.fetch("192.0.2.40:/shared")["options"]
    assert_empty volumes.attachable_volume_names(pod)
    assert_equal "kubernetes.io/nfs", Rubernetes::Node::KubeletMetrics.mount_plugin(handle.dig("mounts", "claim"))

    assert volumes.release(pod, handle)
    assert_empty @manager.mount_adapter.list_mounts
    assert_empty @manager.volume_store.values
  end

  def test_inline_fc_and_iscsi_claim_resolve_storage_and_keep_credentials_out_of_records
    iscsi = {"targetPortal" => "192.0.2.50", "portals" => ["[2001:db8::2]:3261"], "iqn" => IQN, "lun" => 3,
             "chapAuthSession" => true, "secretRef" => {"name" => "chap", "namespace" => "storage"}}
    secret = {"data" => {"node.session.auth.username" => "dXNlcg==",
                         "node.session.auth.password" => "dm9sdW1lLXBhc3N3b3Jk"}}
    reader = reader_for_claim({"iscsi" => iscsi, "mountOptions" => ["ro"]},
                              %w[secrets chap storage] => secret)
    volumes = node_volumes(reader)
    pod = pod_with({"name" => "fc", "fc" => {"targetWWNs" => [WWN], "lun" => 9, "fsType" => "xfs"}}, claim_volume)

    expected_names = ["kubernetes.io/fc/[#{WWN}]:9", "kubernetes.io/iscsi/192.0.2.50:#{IQN}:3"]

    assert_equal expected_names, volumes.attachable_volume_names(pod)
    refute_includes reader.gets, %w[secrets chap storage]
    handle = volumes.prepare(pod)

    assert_equal(expected_names, handle["mounts"].values.map { |mount| mount["uniqueName"] })
    assert_equal "kubernetes.io/iscsi", Rubernetes::Node::KubeletMetrics.mount_plugin(handle.dig("mounts", "claim"))
    fibre, iscsi = @devices.stages

    assert_equal ["fc", "xfs", false], [fibre.first.type, fibre.first.filesystem, fibre[1]]
    assert_equal ["iscsi", "ext4", true], [iscsi.first.type, iscsi.first.filesystem, iscsi[1]]
    assert_equal ["192.0.2.50:3260", "[2001:db8::2]:3261"], iscsi.first.portals
    assert_equal "volume-password", iscsi[2]["node.session.auth.password"]
    assert_includes reader.gets, %w[secrets chap storage]
    records = Dir.glob(File.join(@scratch, "**", "*.json")).map { |path| File.read(path) }.join

    refute_includes records, "volume-password"
    refute_includes records, "iscsiCredentials"

    assert volumes.release(pod, handle)
    assert_equal handle["ids"].reverse, @devices.releases
  end

  def test_inline_chap_secret_is_read_in_pod_namespace_and_failure_rolls_back
    reader = Reader.new(%w[secrets chap apps] => {"data" => {"node.session.auth.password" => "c2VjcmV0"}})
    volumes = node_volumes(reader)
    volume = {"name" => "disk", "iscsi" => {"targetPortal" => "192.0.2.50", "iqn" => IQN, "lun" => 1,
                                            "chapAuthSession" => true, "secretRef" => {"name" => "chap"}}}
    @devices.unavailable = true

    error = assert_raises(Volume::Error) { volumes.prepare(pod_with(volume)) }
    assert_match(/LUN unavailable/, error.message)
    assert_equal [%w[secrets chap apps]], reader.gets
    assert_equal 1, @devices.releases.size
    assert_empty @manager.volume_store.values
  end

  def test_rejects_bind_and_raw_block_options_before_staging
    [{"mountOptions" => ["vers=3,bind"]}, {"volumeMode" => "Block"}].each do |options|
      reader = reader_for_claim({"nfs" => {"server" => "192.0.2.40", "path" => "/shared"}}.merge(options))
      assert_raises(Volume::ValidationError, Volume::UnsupportedError) { node_volumes(reader).prepare(pod_with(claim_volume)) }
      assert_empty @manager.mount_adapter.list_mounts
    end
  end

  def test_claim_volume_mode_mismatch_leaves_storage_unstaged
    [["Filesystem", "volumeDevices", {"devicePath" => "/dev/claim"}],
     ["Block", "volumeMounts", {"mountPath" => "/claim"}]].each do |mode, field, path|
      reader = reader_for_claim("fc" => {"wwids" => ["360000123"]}, "volumeMode" => mode)
      pod = pod_with(claim_volume)
      pod["spec"]["containers"] = [{"name" => "main", field => [path.merge("name" => "claim")]}]
      error = assert_raises(Rubernetes::Node::PodVolumes::Unsupported) { node_volumes(reader).prepare(pod) }

      assert_equal "volume claim has volumeMode #{mode}, but is specified in #{field}", error.message
      assert_empty @devices.stages
      assert_empty @manager.volume_store.values
    end
  end

  def test_fc_block_claim_skips_filesystem_setup_and_builds_readonly_device
    reader = reader_for_claim("fc" => {"wwids" => ["360000123"]}, "volumeMode" => "Block")
    volumes = node_volumes(reader)
    pod = pod_with(claim_volume)
    pod["spec"]["volumes"][0]["persistentVolumeClaim"]["readOnly"] = true
    handle = volumes.prepare(pod)
    mount = handle.dig("mounts", "claim")

    assert_equal "Block", mount["volumeMode"]
    assert_nil @devices.stages.first.first.filesystem

    builder = Rubernetes::Node::ContainerSpec.new(pod_volumes: volumes)
    File.stub(:blockdev?, ->(path) { path == mount["path"] }) do
      definition = {"name" => "main", "volumeDevices" => [{"name" => "claim", "devicePath" => "/dev/data"}]}
      container = builder.build(pod: pod, container: definition, category: "app", volumes: handle)

      assert_equal [{"name" => "claim", "source" => mount["path"], "destination" => "/dev/data", "readonly" => true,
                     "propagation" => "None", "device" => true, "permissions" => "r"}], container["mounts"]
    end
    definition = {"name" => "main", "volumeMounts" => [{"name" => "claim", "mountPath" => "/data"}]}
    assert_raises(Rubernetes::Node::ContainerSpec::ConfigError) do
      builder.build(pod: pod, container: definition, category: "app", volumes: handle)
    end
    assert volumes.release(pod, handle)
  end

  private

  def node_volumes(reader)
    Rubernetes::Node::PodVolumes.new(volume: @manager, reader: reader, node_name: "probe")
  end

  def reader_for_claim(spec, additional = {})
    objects = {%w[persistentvolumeclaims disk apps] => {"spec" => {"volumeName" => "storage"}, "status" => {"phase" => "Bound"}},
               ["persistentvolumes", "storage", nil] => {"spec" => {"accessModes" => ["ReadWriteOnce"]}.merge(spec)}}
    Reader.new(objects.merge(additional))
  end

  def pod_with(*volumes)
    {"metadata" => {"name" => "work", "uid" => "storage-probe", "namespace" => "apps"}, "spec" => {"volumes" => volumes}}
  end

  def claim_volume
    {"name" => "claim", "persistentVolumeClaim" => {"claimName" => "disk"}}
  end

  def stages_by_source
    @manager.mount_adapter.list_mounts.select { |mount| mount["stage"] }.to_h { |mount| [mount.fetch("source"), mount] }
  end
end
