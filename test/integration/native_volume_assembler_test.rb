# frozen_string_literal: true

require_relative "../test_helper"
require "fileutils"
require "rubernetes/bootstrap"
require "stringio"
require "tempfile"
require "tmpdir"

class NativeVolumeAssemblerIntegrationTest < Minitest::Test
  class StartupCSI
    attr_reader :calls

    def initialize(name: "test.csi", vendor_version: "1.2.3", ready: true)
      @identity = Rubernetes::Volume::Identity.new(name: name, vendor_version: vendor_version)
      @ready = ready
      @calls = []
    end

    def identity
      @calls << :identity
      @identity
    end

    def ready?
      @calls << :probe
      @ready
    end

    def create_volume(spec, token:)
      @calls << [:create_volume, spec, token]
      {"volumeId" => "assembled-csi-volume", "volumeContext" => {"driver" => @identity.name}}
    end
  end

  class ReadbackMountAdapter
    def initialize(filesystem_uuid: nil)
      @filesystem_uuid = filesystem_uuid
      @mounts = {}
    end

    def mkdir(path, mode: 0o755)
      FileUtils.mkdir_p(path)
      File.chmod(mode, path) if mode
      true
    end

    def mount(source:, target:, filesystem: nil, readonly: false, options: {}, **_kwargs)
      identity = {
        "mountId" => "101",
        "deviceId" => "8:1",
        "root" => "/",
        "source" => "/dev/sda1",
        "target" => File.expand_path(target),
        "filesystem" => filesystem || "ext4",
        "filesystemUuid" => @filesystem_uuid,
        "filesystemUuidAvailable" => !@filesystem_uuid.nil?,
        "options" => readonly ? "ro" : "rw",
        "requestedOptions" => options
      }
      @mounts[identity["target"]] = identity
      identity
    end

    def bind(source:, target:, readonly: false, options: {}, **)
      mount(source: source, target: target, filesystem: nil, readonly: readonly,
            options: options.merge("bind" => true), **)
    end

    def unmount(target:, **_kwargs)
      @mounts.delete(File.expand_path(target))
      true
    end

    def list_mounts
      @mounts.values.map(&:dup)
    end
  end

  class DeviceAdapter
    def create_loop(**_kwargs)
      {"id" => "/dev/loop-test", "path" => "/dev/loop-test"}
    end

    def create_dm(**_kwargs)
      {"id" => "/dev/mapper/rubernetes-test", "path" => "/dev/mapper/rubernetes-test"}
    end
  end

  def test_native_agent_volume_wiring_uses_kernel_adapters_and_strict_readback
    skip "native volume wiring requires Linux" unless RUBY_PLATFORM.include?("linux")

    Dir.mktmpdir("native-volume-assembler") do |directory|
      process = {
        "runtime_profile" => "host_integration",
        "volume" => {"data_dir" => directory, "root" => File.join(directory, "volumes"), "fsync" => false}
      }
      assembler = Rubernetes::Bootstrap::Assembler.new(process_name: "rubernetes-agent", log_io: StringIO.new)

      manager = assembler.send(:build_volume, process, adapters: {})

      assert_instance_of Rubernetes::Volume::NativeMountAdapter, manager.mount_adapter
      assert_instance_of Rubernetes::Volume::NativeDeviceAdapter, manager.device_adapter
      assert_same manager.mount_adapter, manager.adapter
      assert_instance_of Rubernetes::Volume::PathSecurity, manager.path_security
      assert_predicate manager.path_security, :descriptor_capable?
      assert_instance_of Rubernetes::Platform::Linux::Openat2,
                         manager.path_security.resolver.instance_variable_get(:@adapter)
      assert_predicate manager, :require_real_readback
      refute_instance_of Rubernetes::Volume::FilesystemAdapter, manager.mount_adapter
    end
  end

  def test_assembled_agent_exposes_the_native_volume_manager_to_lifecycle
    skip "native volume wiring requires Linux" unless RUBY_PLATFORM.include?("linux")

    Dir.mktmpdir("assembled-native-volume") do |directory|
      Tempfile.create(["native-volume", ".yml"]) do |file|
        file.write(<<~YAML)
          processes:
            rubernetes-agent:
              runtime_profile: host_integration
              volume:
                data_dir: #{directory}
                root: #{File.join(directory, "volumes")}
                profile: native
                fsync: false
        YAML
        file.flush

        assembly = Rubernetes::Bootstrap::Assembler.new(
          process_name: "rubernetes-agent", config_path: file.path, log_io: StringIO.new
        ).build
        manager = assembly.service.node_agent.lifecycle.volume

        assert_instance_of Rubernetes::Volume::Manager, manager
        assert_instance_of Rubernetes::Volume::NativeMountAdapter, manager.mount_adapter
        assert_instance_of Rubernetes::Volume::NativeDeviceAdapter, manager.device_adapter
        assert_predicate manager, :require_real_readback
      end
    end
  end

  def test_fake_volume_adapter_requires_an_explicit_test_profile
    Dir.mktmpdir("test-volume-assembler") do |directory|
      process = {
        "runtime_profile" => "pure",
        "volume" => {
          "data_dir" => directory,
          "root" => File.join(directory, "volumes"),
          "profile" => "test",
          "fsync" => false
        }
      }
      assembler = Rubernetes::Bootstrap::Assembler.new(process_name: "rubernetes-agent", log_io: StringIO.new)

      manager = assembler.send(:build_volume, process, adapters: {})

      assert_instance_of Rubernetes::Volume::FilesystemAdapter, manager.mount_adapter
      assert_instance_of Rubernetes::Volume::PathSecurity, manager.path_security
      assert_predicate manager.path_security, :descriptor_capable?
      assert_instance_of Rubernetes::Platform::Linux::Openat2,
                         manager.path_security.resolver.instance_variable_get(:@adapter)
      refute_predicate manager, :require_real_readback
    end
  end

  def test_pure_agent_volume_wiring_rejects_an_implicit_fake_profile
    Dir.mktmpdir("implicit-volume-assembler") do |directory|
      process = {
        "runtime_profile" => "pure",
        "volume" => {"data_dir" => directory, "root" => File.join(directory, "volumes"), "fsync" => false}
      }
      assembler = Rubernetes::Bootstrap::Assembler.new(process_name: "rubernetes-agent", log_io: StringIO.new)

      error = assert_raises(Rubernetes::Bootstrap::Config::Error) do
        assembler.send(:build_volume, process, adapters: {})
      end
      assert_match(/volume\.profile.*test/, error.message)
    end
  end

  def test_volume_csi_config_validates_identity_and_probe_before_wiring_adapter
    Dir.mktmpdir("csi-volume-assembler") do |directory|
      process = {
        "runtime_profile" => "pure",
        "volume" => {
          "data_dir" => directory, "root" => File.join(directory, "volumes"),
          "profile" => "test", "fsync" => true,
          "csi" => {
            "socket" => File.join(directory, "plugin.sock"), "timeout" => 2,
            "probe" => true, "identity" => {"name" => "test.csi", "vendor_version" => "1.2.3"}
          }
        }
      }
      csi = StartupCSI.new
      secret_resolver = lambda do |reference, volume_id:, purpose:|
        raise "unexpected resolver input" unless reference == {"name" => "assembled-secret"}
        raise "missing resolver context" if volume_id.empty? || purpose.empty?

        {"credential" => "runtime-only"}
      end
      assembler = Rubernetes::Bootstrap::Assembler.new(process_name: "rubernetes-agent", log_io: StringIO.new)

      manager = assembler.send(
        :build_volume, process, adapters: {csi: csi, csi_secret_resolver: secret_resolver}
      )
      id = manager.create_volume(
        {"name" => "remote", "csi" => {"driver" => "test.csi"},
         "secretRef" => {"name" => "assembled-secret"}}, token: "create"
      )

      assert_equal "csi", manager.fetch_record(id).backend
      assert_equal %i[identity probe], csi.calls.first(2)
      create_call = csi.calls.find { |call| call.is_a?(Array) && call.first == :create_volume }

      assert_equal({"credential" => "runtime-only"}, create_call.fetch(1).fetch("secrets"))
    end
  end

  def test_volume_csi_startup_is_fail_closed_for_identity_or_probe_failure
    Dir.mktmpdir("csi-volume-startup-failure") do |directory|
      base = {
        "runtime_profile" => "pure",
        "volume" => {
          "data_dir" => directory, "profile" => "test",
          "csi" => {"socket" => File.join(directory, "plugin.sock"), "identity" => {"name" => "expected.csi"}}
        }
      }
      assembler = Rubernetes::Bootstrap::Assembler.new(process_name: "rubernetes-agent", log_io: StringIO.new)

      mismatch = assert_raises(Rubernetes::Bootstrap::Config::Error) do
        assembler.send(:build_volume, base, adapters: {csi: StartupCSI.new(name: "other.csi")})
      end
      assert_match(/identity mismatch/, mismatch.message)

      expected = Marshal.load(Marshal.dump(base))
      expected["volume"]["csi"]["identity"]["name"] = "test.csi"
      unavailable = assert_raises(Rubernetes::Bootstrap::Config::Error) do
        expected = Marshal.load(Marshal.dump(base))
        expected["volume"]["csi"]["identity"]["name"] = "test.csi"
        assembler.send(:build_volume, expected, adapters: {csi: StartupCSI.new(ready: false)})
      end
      assert_match(/not ready/, unavailable.message)
    end
  end

  def test_assembled_manager_without_csi_configuration_rejects_csi_volumes
    Dir.mktmpdir("unconfigured-csi-volume") do |directory|
      process = {
        "runtime_profile" => "pure",
        "volume" => {"data_dir" => directory, "profile" => "test", "fsync" => false}
      }
      assembler = Rubernetes::Bootstrap::Assembler.new(process_name: "rubernetes-agent", log_io: StringIO.new)
      manager = assembler.send(:build_volume, process, adapters: {})

      assert_raises(Rubernetes::Volume::CSIUnavailable) do
        manager.create_volume({"name" => "remote", "csi" => {"driver" => "missing.csi"}}, token: "create")
      end
    end
  end

  def test_strict_native_mounts_keep_uuid_unavailable_for_tmpfs_or_bind_identity
    Dir.mktmpdir("native-volume-identity") do |directory|
      adapter = ReadbackMountAdapter.new
      backend = Rubernetes::Volume::EmptyDirBackend.new(
        id: "empty", spec: {"backend" => "emptyDir"}, adapter: adapter, mount_adapter: adapter,
        root: File.join(directory, "volumes"), require_real_readback: true
      )
      backend.provision

      stage = backend.stage(path: File.join(directory, "stage"), node: "node", readonly: false)
      publish = backend.publish(stage_path: stage.fetch("target"), target: File.join(directory, "target"),
                                node: "node", pod: "pod", readonly: false)

      assert_nil stage.fetch("filesystemUuid")
      refute stage.fetch("filesystemUuidAvailable")
      assert_nil publish.fetch("filesystemUuid")
      refute publish.fetch("filesystemUuidAvailable")
      assert_equal "8:1", stage.fetch("deviceId")
      assert_equal "/", stage.fetch("root")
    end
  end

  def test_strict_loop_dm_mounts_fail_closed_without_a_real_filesystem_uuid
    Dir.mktmpdir("native-loop-identity") do |directory|
      adapter = ReadbackMountAdapter.new
      backend = Rubernetes::Volume::LoopDMBackend.new(
        id: "loop", spec: {"backend" => "loopDM", "size" => 1}, adapter: adapter,
        mount_adapter: adapter, device_adapter: DeviceAdapter.new,
        root: File.join(directory, "volumes"), require_real_readback: true
      )
      backend.provision

      assert_raises(Rubernetes::Volume::MountIdentityError) do
        backend.stage(path: File.join(directory, "stage"), node: "node", readonly: false)
      end
    end
  end
end
