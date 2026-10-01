# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/volume"
require "rubernetes/platform/linux/openat2"
require "socket"
require "tmpdir"

class M4VolumeSecurityTest < Minitest::Test
  class TargetRaceMount
    attr_reader :mount_calls, :unmount_calls, :mountinfo
    attr_accessor :race_target

    def initialize(outside:)
      @outside = outside
      @mountinfo = ""
      @mount_calls = []
      @unmount_calls = []
      @next_mount_id = 100
    end

    def mount(**kwargs)
      @mount_calls << kwargs
      logical_target = File.realpath(kwargs.fetch(:target).to_s)
      if logical_target == @race_target
        held_target = "#{logical_target}.held"
        File.rename(logical_target, held_target)
        File.symlink(@outside, logical_target)
        return true
      end

      @next_mount_id += 1
      filesystem = kwargs[:filesystem] || "bind"
      source = kwargs[:source].to_s
      @mountinfo = "#{@next_mount_id} 1 8:1 / #{logical_target} rw - #{filesystem} #{source} rw\n"
      true
    end

    def unmount(**kwargs)
      @unmount_calls << kwargs
      @mountinfo = "" unless kwargs[:target].to_s.start_with?("/proc/self/fd/")
      true
    end
  end

  class CleanupFalseAdapter
    def mkdir(path, mode: 0o755)
      FileUtils.mkdir_p(path)
      File.chmod(mode, path) if mode
      true
    end

    def remove(path)
      FileUtils.rm_rf(path)
      true
    end

    def mount(source:, target:, **_kwargs)
      FileUtils.mkdir_p(target)
      {"mountId" => "m-cleanup", "filesystemUuid" => "fs-cleanup", "deviceId" => "d-cleanup",
       "root" => "/", "target" => target, "source" => source, "filesystem" => "bind", "options" => "rw"}
    end

    def unmount(**_kwargs)
      false
    end
  end

  class FailingMountLedger
    def register(**_kwargs)
      raise Rubernetes::Volume::MountIdentityError, "simulated mount ledger failure"
    end

    def remove(**_kwargs)
      true
    end

    def identity_for(_entry)
      "cleanup-test"
    end
  end

  def test_host_path_fails_closed_without_openat2_resolver
    directory = Dir.mktmpdir("m4-volume-security")
    manager = Rubernetes::Volume::Manager.new(data_dir: directory, fsync: false)
    assert_raises(Rubernetes::Volume::PathSecurityError) do
      manager.create_volume({"name" => "host", "hostPath" => {"path" => directory, "type" => "Directory"}}, token: "host")
    end
  ensure
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end

  def test_path_validator_rejects_traversal_before_adapter_call
    calls = []
    adapter = Object.new
    adapter.define_singleton_method(:open) do |*args, **kwargs|
      calls << [args, kwargs]
      1
    end
    security = Rubernetes::Volume::PathSecurity.new(root: "/tmp", adapter: adapter)
    assert_raises(Rubernetes::Volume::PathSecurityError) { security.open("../etc/passwd") }
    assert_empty calls
  end

  def test_mount_identity_replacement_is_not_removed
    ledger = Rubernetes::Volume::MountIdentityLedger.new
    ledger.register(volume_id: "v", source: "/s", target: "/t", mount_id: "m1", filesystem_uuid: "fs1", device_id: "d1", owner: "v")
    assert_raises(Rubernetes::Volume::MountIdentityError) do
      ledger.remove(identity: "m1/fs1/d1//t",
                    expected: {"mountId" => "m1", "filesystemUuid" => "fs2", "deviceId" => "d1", "target" => "/t"})
    end
  end

  def test_manager_stage_cleanup_false_fences_unknown_and_persists_cleanup_error
    directory = Dir.mktmpdir("m4-manager-stage-cleanup")
    adapter = CleanupFalseAdapter.new
    manager = Rubernetes::Volume::Manager.new(
      data_dir: File.join(directory, "data"), root: File.join(directory, "volumes"),
      adapter: adapter, mount_adapter: adapter, mount_ledger: FailingMountLedger.new, fsync: true
    )
    id = manager.create_volume({"name" => "cleanup", "emptyDir" => {}}, token: "create")
    manager.controller.publish(id, "node-a", token: "attach")
    stage = File.join(directory, "stage")

    assert_raises(Rubernetes::Volume::OperationUnknown) do
      manager.node.stage(id, stage, token: "stage", node: "node-a")
    end

    assert_equal "Unknown", manager.volume(id).state
    entry = manager.operations.entries.find { |candidate| candidate.operation.start_with?("stage:") }

    assert_equal "unknown", entry.status
    assert_equal Rubernetes::Volume::CleanupError.name, entry.error.fetch("class")
    refute_empty entry.error.fetch("details").fetch("cleanupErrors")
  ensure
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end

  def test_secret_projection_rejects_non_tmpfs_adapter
    directory = Dir.mktmpdir("m4-volume-security")
    adapter = Object.new
    adapter.define_singleton_method(:mkdir) { |_path, **| true }
    adapter.define_singleton_method(:remove) { |_path| true }
    manager = Rubernetes::Volume::Manager.new(data_dir: directory, adapter: adapter, mount_adapter: adapter, fsync: false)
    assert_raises(Rubernetes::Volume::SecretPersistenceError) do
      manager.create_volume({"name" => "secret", "secret" => {"stringData" => {"a" => "b"}}}, token: "secret")
    end
  ensure
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end

  # Requirement: spec/node/volume.md §5.11.3. Default Manager validation is
  # not lexical-only: an existing symlink target is rejected before mount.
  def test_default_manager_rejects_symlink_stage_and_publish_targets
    directory = Dir.mktmpdir("m4-volume-target-symlink")
    manager = Rubernetes::Volume::Manager.new(data_dir: File.join(directory, "data"), fsync: false)

    assert_instance_of Rubernetes::Volume::PathSecurity, manager.path_security
    id = manager.create_volume({"name" => "safe", "emptyDir" => {}}, token: "create")
    manager.controller.publish(id, "node-a", token: "attach")
    real_target = File.join(directory, "real-target")
    FileUtils.mkdir_p(real_target)
    symlink_stage = File.join(directory, "symlink-stage")
    File.symlink(real_target, symlink_stage)

    stage_error = assert_raises(Rubernetes::Volume::PathSecurityError) do
      manager.node.stage(id, symlink_stage, token: "stage-symlink", node: "node-a")
    end
    assert_match(/symlink/, stage_error.message)

    stage_path = File.join(directory, "stage")
    manager.node.stage(id, stage_path, token: "stage", node: "node-a")
    symlink_publish = File.join(directory, "symlink-publish")
    File.symlink(real_target, symlink_publish)
    publish_error = assert_raises(Rubernetes::Volume::PathSecurityError) do
      manager.node.publish(id, "pod-a", symlink_publish, readonly: false, token: "publish-symlink", node: "node-a")
    end
    assert_match(/symlink/, publish_error.message)
  ensure
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end

  def test_builtin_local_stage_uses_a_held_target_descriptor
    directory = Dir.mktmpdir("m4-local-stage-race")
    source = File.join(directory, "local-source")
    stage = File.join(directory, "stage")
    outside = File.join(directory, "outside")
    FileUtils.mkdir_p([source, outside])
    mount = TargetRaceMount.new(outside: outside)
    native = Rubernetes::Volume::NativeMountAdapter.new(
      mount: mount, mountinfo_reader: -> { mount.mountinfo }
    )
    openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
    security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
    manager = Rubernetes::Volume::Manager.new(
      data_dir: File.join(directory, "data"), root: File.join(directory, "volumes"),
      adapter: native, mount_adapter: native, path_security: security,
      require_real_readback: true, fsync: false
    )
    id = manager.create_volume({"name" => "local", "local" => {"path" => source, "type" => "Directory"}},
                               token: "local-create")
    manager.controller.publish(id, "node-a", token: "local-attach")
    mount.race_target = stage

    assert_raises(Rubernetes::Volume::PathSecurityError) do
      manager.node.stage(id, stage, token: "local-stage", node: "node-a")
    end

    assert_equal "Attached", manager.volume(id).state
    assert_equal 1, mount.unmount_calls.length
    assert_match(%r{\A/proc/#{Process.pid}/fd/\d+\z}, mount.unmount_calls.fetch(0).fetch(:target))
    assert File.symlink?(stage)
  ensure
    openat2&.close
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end

  def test_builtin_local_publish_uses_a_held_target_descriptor
    directory = Dir.mktmpdir("m4-local-publish-race")
    source = File.join(directory, "local-source")
    stage = File.join(directory, "stage")
    target = File.join(directory, "target")
    outside = File.join(directory, "outside")
    FileUtils.mkdir_p([source, outside])
    mount = TargetRaceMount.new(outside: outside)
    native = Rubernetes::Volume::NativeMountAdapter.new(
      mount: mount, mountinfo_reader: -> { mount.mountinfo }
    )
    openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
    security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
    manager = Rubernetes::Volume::Manager.new(
      data_dir: File.join(directory, "data"), root: File.join(directory, "volumes"),
      adapter: native, mount_adapter: native, path_security: security,
      require_real_readback: true, fsync: false
    )
    id = manager.create_volume({"name" => "local", "local" => {"path" => source, "type" => "Directory"}},
                               token: "local-create")
    manager.controller.publish(id, "node-a", token: "local-attach")
    manager.node.stage(id, stage, token: "local-stage", node: "node-a")
    mount.race_target = target

    assert_raises(Rubernetes::Volume::PathSecurityError) do
      manager.node.publish(id, "pod-a", target, readonly: false, token: "local-publish", node: "node-a")
    end

    assert_equal "Staged", manager.volume(id).state
    assert_equal 1, mount.unmount_calls.length
    assert_match(%r{\A/proc/#{Process.pid}/fd/\d+\z}, mount.unmount_calls.fetch(0).fetch(:target))
    assert File.symlink?(target)
  ensure
    openat2&.close
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end

  def test_csi_manager_fails_closed_when_injected_path_security_cannot_lease_descriptors
    directory = Dir.mktmpdir("m4-csi-raw-path-fence")
    target = File.join(directory, "stage")
    outside = File.join(directory, "outside")
    FileUtils.mkdir_p(outside)
    validations = 0
    security = Rubernetes::Volume::PathSecurity.new(root: "/", require_openat2: false)
    validate_target = security.method(:validate_target!)
    security.define_singleton_method(:validate_target!) do |path|
      result = validate_target.call(path)
      validations += 1
      File.symlink(outside, target) if validations == 2
      result
    end
    stage_calls = []
    csi = Object.new
    csi.define_singleton_method(:identity) do
      Rubernetes::Volume::Identity.new(name: "raw-path.csi", vendor_version: "test")
    end
    csi.define_singleton_method(:create_volume) { |_spec, token:| {"volumeId" => "driver-volume"} }
    csi.define_singleton_method(:publish) do |_id, _node, token:, readonly: false, context: {}|
      {"publishContext" => {}}
    end
    csi.define_singleton_method(:stage) do |_id, path, token:, readonly:, context:|
      stage_calls << path
      {"target" => path}
    end
    manager = Rubernetes::Volume::Manager.new(
      data_dir: File.join(directory, "data"), csi: csi, path_security: security, fsync: true
    )
    id = manager.create_volume({"name" => "raw-path", "csi" => {"driver" => "raw-path.csi"}}, token: "create")
    manager.controller.publish(id, "node-a", token: "attach")

    error = assert_raises(Rubernetes::Volume::PathSecurityError) do
      manager.node.stage(id, target, token: "stage", node: "node-a")
    end

    assert_match(/descriptor lease/, error.message)
    assert_empty stage_calls
    assert File.symlink?(target)
    assert_equal "Attached", manager.volume(id).state
  ensure
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end

  def test_host_path_or_create_creates_then_validates_and_retains_descriptor_until_delete
    directory = Dir.mktmpdir("m4-hostpath-security")
    root = File.join(directory, "host-root")
    FileUtils.mkdir_p(root)
    path_security = Rubernetes::Volume::PathSecurity.new(root: root, require_openat2: false)
    adapter = Rubernetes::Volume::FilesystemAdapter.new(root: File.join(directory, "volumes"))
    manager = Rubernetes::Volume::Manager.new(data_dir: File.join(directory, "data"), adapter: adapter,
                                              mount_adapter: adapter, path_security: path_security, fsync: false)

    id = manager.create_volume({"name" => "created-dir", "hostPath" => {"path" => "nested/dir", "type" => "DirectoryOrCreate"}},
                               token: "created-dir")
    backend = manager.backends.fetch(id)
    handle = backend.instance_variable_get(:@host_handle)

    assert File.directory?(File.join(root, "nested", "dir"))
    assert_same handle, backend.send(:source_handle_for, backend.source_path)
    refute_nil handle

    manager.delete_volume(id, token: "delete-created-dir")

    assert_nil backend.instance_variable_get(:@host_handle)

    file_id = manager.create_volume({"name" => "created-file", "hostPath" => {"path" => "nested/file", "type" => "FileOrCreate"}},
                                    token: "created-file")

    assert File.file?(File.join(root, "nested", "file"))
    manager.delete_volume(file_id, token: "delete-created-file")
  ensure
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end

  def test_host_path_checks_actual_file_directory_and_socket_types
    directory = Dir.mktmpdir("m4-hostpath-types")
    root = File.join(directory, "host-root")
    FileUtils.mkdir_p(root)
    File.write(File.join(root, "file"), "data")
    FileUtils.mkdir_p(File.join(root, "dir"))
    socket_path = File.join(root, "socket")
    server = UNIXServer.new(socket_path)
    path_security = Rubernetes::Volume::PathSecurity.new(root: root, require_openat2: false)
    adapter = Rubernetes::Volume::FilesystemAdapter.new(root: File.join(directory, "volumes"))
    manager = Rubernetes::Volume::Manager.new(data_dir: File.join(directory, "data"), adapter: adapter,
                                              mount_adapter: adapter, path_security: path_security, fsync: false)

    file_id = manager.create_volume({"name" => "file", "hostPath" => {"path" => "file", "type" => "File"}}, token: "file")
    socket_id = manager.create_volume({"name" => "socket", "hostPath" => {"path" => "socket", "type" => "Socket"}}, token: "socket")

    assert file_id
    assert socket_id
    assert_raises(Rubernetes::Volume::ValidationError) do
      manager.create_volume({"name" => "wrong-file", "hostPath" => {"path" => "dir", "type" => "File"}}, token: "wrong-file")
    end
    assert_raises(Rubernetes::Volume::ValidationError) do
      manager.create_volume({"name" => "wrong-socket", "hostPath" => {"path" => "file", "type" => "Socket"}}, token: "wrong-socket")
    end
  ensure
    server&.close
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end

  def test_csi_dispatch_uses_held_descriptor_and_fences_path_exchange
    skip "descriptor-relative CSI dispatch requires Linux openat2" unless RUBY_PLATFORM.include?("linux")

    begin
      directory = Dir.mktmpdir("m4-csi-target-lease")
      target = File.join(directory, "stage")
      held = File.join(directory, "stage-held")
      outside = File.join(directory, "outside")
      FileUtils.mkdir_p(outside)
      observations = {}
      csi = Object.new
      csi.define_singleton_method(:identity) do
        Rubernetes::Volume::Identity.new(name: "lease.csi", vendor_version: "test")
      end
      csi.define_singleton_method(:create_volume) { |_spec, token:| {"volumeId" => "driver-volume"} }
      csi.define_singleton_method(:publish) do |_id, _node, token:, readonly: false, context: {}|
        {"publishContext" => {}}
      end
      csi.define_singleton_method(:stage) do |_id, dispatch_path, token:, readonly:, context:|
        original_inode = File.stat(target).ino
        File.rename(target, held)
        File.symlink(outside, target)
        observations["dispatch"] = dispatch_path
        observations["dispatchInode"] = File.stat(dispatch_path).ino
        observations["originalInode"] = original_inode
        observations["outsideInode"] = File.stat(outside).ino
        {"target" => dispatch_path}
      end
      openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
      security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
      manager = Rubernetes::Volume::Manager.new(
        data_dir: File.join(directory, "data"), csi: csi, path_security: security, fsync: true
      )
      id = manager.create_volume({"name" => "lease", "csi" => {"driver" => "lease.csi"}}, token: "create")
      manager.controller.publish(id, "node-a", token: "attach")

      assert_raises(Rubernetes::Volume::OperationUnknown) do
        manager.node.stage(id, target, token: "stage", node: "node-a")
      end
      # The plugin receives the canonical pathname (kubelet-compatible); the
      # lease still pins the original inode and the post-effect verification
      # detects the swap, fences the volume Unknown, and refuses to adopt the
      # attacker's directory as the staged target.
      assert_equal target, observations.fetch("dispatch")
      assert_equal observations.fetch("outsideInode"), observations.fetch("dispatchInode"),
                   "the swapped pathname now resolves to the attacker directory"
      refute_equal observations.fetch("originalInode"), observations.fetch("dispatchInode")
      assert_equal File.stat(held).ino, observations.fetch("originalInode")
      assert_equal "Unknown", manager.volume(id).state
      assert_empty manager.mount_ledger.entries
    ensure
      openat2&.close
      FileUtils.remove_entry(directory) if directory && File.exist?(directory)
    end
  end

  # The parent directory is replaced immediately after its descriptor is
  # opened. A safe resolver must create/open the leaf through that held fd,
  # then reject the now-different user-visible parent/leaf identity.
  def test_target_lease_uses_parent_fd_for_leaf_and_rejects_parent_replacement
    skip "descriptor-relative CSI dispatch requires Linux openat2" unless RUBY_PLATFORM.include?("linux")

    directory = Dir.mktmpdir("m4-parent-fd-race")
    parent = File.join(directory, "parent")
    held_parent = "#{parent}.held"
    target = File.join(parent, "target")
    FileUtils.mkdir_p(parent)
    openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
    adapter = Object.new
    adapter.define_singleton_method(:open) do |path, **kwargs|
      handle = openat2.open(path, **kwargs)
      if kwargs[:resource_id].to_s.start_with?("volume-target-parent:")
        File.rename(parent, held_parent)
        FileUtils.mkdir_p(parent)
        FileUtils.mkdir_p(target)
      end
      handle
    end
    adapter.define_singleton_method(:open_relative) do |**kwargs|
      openat2.open_relative(**kwargs)
    end
    security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: adapter, require_openat2: true)

    lease = security.acquire_target!(target, directory: true, create: true)
    held_target = File.join(held_parent, "target")

    assert_equal File.stat(held_target).ino, File.stat(lease.dispatch_path).ino
    refute_equal File.stat(target).ino, File.stat(lease.dispatch_path).ino
    assert_raises(Rubernetes::Volume::PathSecurityError) { lease.verify_original! }
  ensure
    lease&.close
    openat2&.close
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end

  def test_target_lease_rejects_ordinary_leaf_replacement_after_mount_readback
    skip "descriptor-relative CSI dispatch requires Linux openat2" unless RUBY_PLATFORM.include?("linux")

    directory = Dir.mktmpdir("m4-leaf-post-readback-race")
    target = File.join(directory, "target")
    held = File.join(directory, "target.held")
    FileUtils.mkdir_p(target)
    openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
    security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
    lease = security.acquire_target!(target, directory: true, create: true)

    File.rename(target, held)
    FileUtils.mkdir_p(target)
    mount_identity = {"target" => target, "mountId" => lease.identity.fetch("mountId")}
    assert_raises(Rubernetes::Volume::PathSecurityError) do
      lease.verify_original!(mounted: true, mount_identity: mount_identity)
    end
  ensure
    lease&.close
    openat2&.close
    FileUtils.remove_entry(directory) if directory && File.exist?(directory)
  end
end
