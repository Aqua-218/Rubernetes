# frozen_string_literal: true

require_relative "../test_helper"
require "open3"
require "rbconfig"
require "tmpdir"

class NativeVolumeMountAdapterIntegrationTest < Minitest::Test
  KERNEL_SCRIPT = <<~'RUBY'
    require "fileutils"
    require "rubernetes/volume"
    require "rubernetes/node"

    root = ARGV.fetch(0)
    source = File.join(root, "source")
    stage = File.join(root, "stage")
    target = File.join(root, "target")
    FileUtils.mkdir_p(source)
    FileUtils.mkdir_p(stage)
    FileUtils.mkdir_p(target)

    adapter = Rubernetes::Volume::NativeMountAdapter.new
    kernel_mount = Rubernetes::Platform::Linux::Mount.new
    stage_identity = nil
    target_identity = nil
    begin
      File.write(File.join(source, "before"), "source")
      stage_identity = adapter.ensure_tmpfs(stage, size_limit: "1Mi")
      raise "tmpfs readback did not identify the stage" unless stage_identity.fetch("filesystem") == "tmpfs"
      File.write(File.join(stage, "hello"), "native")

      target_identity = adapter.bind(source: stage, target: target, readonly: true)
      raise "bind readback did not identify the target" unless target_identity.fetch("target") == target
      raise "bind readback was not read-only" unless target_identity.fetch("readonly")
      raise "bind effect was not observable" unless File.read(File.join(target, "hello")) == "native"

      adapter.unmount(target: target, mount_id: target_identity.fetch("mountId"))
      adapter.unmount(target: stage, mount_id: stage_identity.fetch("mountId"))
      raise "target mount remained after umount2" if adapter.find_mount(target)
      raise "stage mount remained after umount2" if adapter.find_mount(stage)

      kernel_mount.mount(source: "tmpfs", target: target, filesystem: "tmpfs", flags: 0, data: "size=1m")
      lower = adapter.find_mount(target).fetch("mountId")
      kernel_mount.mount(source: "tmpfs", target: target, filesystem: "tmpfs", flags: 0, data: "size=1m")
      descriptor = File.open(target, Rubernetes::Platform::Linux::Openat2::O_PATH)
      upper = File.read("/proc/self/fdinfo/#{descriptor.fileno}")[/^mnt_id:\s*(\d+)/, 1]
      descriptor.close
      raise "fixture did not create a second kernel mount" if upper == lower
      raise "lookup returned the hidden lower mount" unless adapter.find_mount(target).fetch("mountId") == upper

      kernel_mount.unmount(target: target)
      raise "lookup did not follow the newly visible lower mount" unless adapter.find_mount(target).fetch("mountId") == lower
      kernel_mount.unmount(target: target)

      kubelet_root = File.join(root, "kubelet")
      FileUtils.mkdir_p(kubelet_root)
      kernel_mount.mount(source: "tmpfs", target: kubelet_root, filesystem: "tmpfs", flags: 0, data: "size=1m")
      root_id = adapter.find_mount(kubelet_root).fetch("mountId")
      openat2 = Rubernetes::Platform::Linux::Openat2.new(root: root, strict: true)
      security = Rubernetes::Volume::PathSecurity.new(root: root, adapter: openat2, require_openat2: true)
      manager = Rubernetes::Volume::Manager.new(data_dir: File.join(root, "storage"), mount_adapter: adapter, path_security: security)
      manager.configure_kubelet_csi_paths(kubelet_root)
      pods_path = File.join(kubelet_root, "pods")
      Rubernetes::Node::PodVolumes.new(volume: manager, root: pods_path)
      paths = [File.join(pods_path, "volumes"), File.join(manager.kubelet_csi_paths.directory, "driver.test")]
      paths.each do |path|
        FileUtils.mkdir_p(path)
        handle = security.open(path)
        raise "configured kubelet directory was not opened through its mount boundary" unless handle.stat.directory?

        handle.close
      end
      raise "configuration changed the enclosing kubelet mount" unless adapter.find_mount(kubelet_root).fetch("mountId") == root_id

      local_source = File.join(root, "local-source")
      local_stage = File.join(root, "local-stage")
      FileUtils.mkdir_p([local_source, local_stage])
      kernel_mount.mount(source: "tmpfs", target: local_source, filesystem: "tmpfs", flags: 0, data: "size=1m")
      File.write(File.join(local_source, "readback"), "local data")
      local = Rubernetes::Volume::LocalBackend.new(id: "pv-local", spec: {"path" => local_source},
                                                    root: root, mount_adapter: adapter, path_security: security)
      local.provision
      begin
        kernel_mount.unmount(target: local_source)
      rescue Rubernetes::Platform::Linux::Error => error
        raise unless error.errno == Errno::EBUSY::Errno
      else
        raise "local source mount was released before staging"
      end
      local_identity = local.stage(path: local_stage, node: "worker")
      kernel_mount.unmount(target: local_source)
      raise "the staged bind lost local data" unless File.read(File.join(local_stage, "readback")) == "local data"

      local.unstage(path: local_stage, identity: local_identity)
      raise "local stage remained mounted" if adapter.find_mount(local_stage)

      begin
        local.stage(path: local_stage, node: "worker")
      rescue Rubernetes::Volume::PathSecurityError
        # Unmount exposed a different source inode at the same host path.
      else
        raise "local volume adopted a different source inode"
      end

      bind_source = File.join(root, "bind-source")
      bind_path = File.join(root, "local-bind")
      FileUtils.mkdir_p([bind_source, bind_path])
      adapter.bind(source: bind_source, target: bind_path, readonly: false)
      bind_volume = Rubernetes::Volume::LocalBackend.new(id: "pv-local-bind", spec: {"path" => bind_path},
                                                          root: root, mount_adapter: adapter, path_security: security)
      bind_volume.provision
      bind_stage = bind_volume.stage(path: local_stage, node: "worker")
      bind_volume.unstage(path: local_stage, identity: bind_stage)
      kernel_mount.unmount(target: bind_path)
      new_bind = adapter.bind(source: bind_source, target: bind_path, readonly: true)
      raise "fixture did not retain the same inode" unless File.identical?(bind_source, bind_path)
      raise "fixture replacement did not use new flags" unless new_bind.fetch("readonly")

      begin
        bind_volume.stage(path: local_stage, node: "worker")
      rescue Rubernetes::Volume::PathSecurityError
        # The new bind has the same inode and can reuse the mount ID.
      else
        raise "local volume adopted a replacement bind mount"
      end
      kernel_mount.unmount(target: bind_path)

      volumes = %w[first second].map do |name|
        source_dir = File.join(root, "#{name}-local-source")
        stage_dir = File.join(root, "#{name}-local-stage")
        FileUtils.mkdir_p([source_dir, stage_dir])
        volume = Rubernetes::Volume::LocalBackend.new(id: "pv-#{name}", spec: {"path" => source_dir},
                                                       root: root, mount_adapter: adapter, path_security: security)
        volume.provision
        [volume, stage_dir]
      end
      identities = volumes.map { |volume, stage_dir| volume.stage(path: stage_dir, node: "worker") }
      volumes.each_with_index do |(_, stage_dir), index|
        File.write(File.join(stage_dir, "sample"), "local volume #{index}")
      end
      volumes.each_with_index do |(volume, stage_dir), index|
        volume.unstage(path: stage_dir, identity: identities.fetch(index))
        raise "local stage remained mounted after release" if adapter.find_mount(stage_dir)
      end
      volumes.each_with_index do |(volume, stage_dir), index|
        identity = volume.stage(path: stage_dir, node: "worker")
        raise "local volume lost its independent sample" unless File.read(File.join(stage_dir, "sample")) == "local volume #{index}"

        volume.unstage(path: stage_dir, identity: identity)
      end
      openat2.close
    rescue Rubernetes::Platform::Linux::Error => error
      if [Errno::EPERM::Errno, Errno::EACCES::Errno, Errno::EOPNOTSUPP::Errno].include?(error.errno)
        warn "SKIP: kernel denied mount capability (errno #{error.errno})"
        exit 77
      end
      raise
    ensure
      begin
        adapter.unmount(target: target, mount_id: target_identity.fetch("mountId")) if target_identity && adapter.find_mount(target)
      rescue StandardError
        nil
      end
      begin
        adapter.unmount(target: stage, mount_id: stage_identity.fetch("mountId")) if stage_identity && adapter.find_mount(stage)
      rescue StandardError
        nil
      end
    end
  RUBY

  def test_native_mount_and_bind_effects_are_verified_inside_an_isolated_mount_namespace
    skip "native mount integration requires root" unless Process.uid.zero?

    Dir.mktmpdir("native-volume-mount") do |directory|
      output, error, status = Open3.capture3(
        "unshare", "--mount", "--propagation", "private", "--", RbConfig.ruby, "-Ilib", "-e", KERNEL_SCRIPT, directory
      )
      skip error.strip if status.exitstatus == 77 && error.start_with?("SKIP:")
      if !status.success? && error.match?(/Operation not permitted|Permission denied/i)
        skip "missing CAP_SYS_ADMIN for isolated mount namespace: #{error.strip}"
      end

      assert_predicate status, :success?, "isolated native mount script failed: #{error.empty? ? output : error}"
    end
  rescue Errno::ENOENT => error
    flunk "unshare is required for the isolated mount integration test: #{error.message}"
  end
end
