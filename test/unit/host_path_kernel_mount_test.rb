# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/volume"
require "rubernetes/platform/linux/openat2"

class HostPathKernelMountTest < Minitest::Test
  def setup
    adapter = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
    @security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: adapter)
  end

  def test_proc_and_nested_cgroup_mounts_keep_kernel_descriptors
    skip "requires proc and cgroup v2 mounts" unless kernel_mount?("/proc", "proc") && kernel_mount?("/sys/fs/cgroup", "cgroup2")

    begin
      version = @security.validate_host_path!("/proc/version")
      cgroup = @security.validate_host_path!("/sys/fs/cgroup")

      assert_predicate version.stat, :file?
      assert_predicate cgroup.stat, :directory?
      assert_equal "proc/version", version.path
      assert_equal "sys/fs/cgroup", cgroup.path
      assert_equal File.stat("/sys/fs/cgroup").ino, cgroup.stat.ino
    ensure
      version&.close
      cgroup&.close
    end
  end

  def test_unrecognized_kernel_submount_and_symlink_are_refused
    skip "requires debugfs and proc" unless kernel_mount?("/sys/kernel/debug", "debugfs") && kernel_mount?("/proc", "proc")

    assert_raises(Rubernetes::Volume::PathSecurityError) { @security.validate_host_path!("/sys/kernel/debug") }
    assert_raises(Rubernetes::Volume::PathSecurityError) { @security.validate_host_path!("/proc/self/status") }
  end

  def test_bpffs_is_provisioned_as_an_explicit_host_path
    skip "requires bpffs" unless kernel_mount?("/sys/fs/bpf", "bpf")

    path = "/sys/fs/bpf"
    backend = Rubernetes::Volume::HostPathBackend.new(id: "kernel-bpf", path_security: @security,
                                                      spec: {"type" => "Directory", "path" => path})
    begin
      result = backend.provision

      assert_equal path, result.fetch("source")
      assert_equal path, backend.source_path
    ensure
      backend.delete
    end
  end

  def test_known_mount_with_a_changed_mount_identity_is_refused
    skip "requires proc" unless kernel_mount?("/proc", "proc")

    @security.resolver.stub(:kernel_mounts_for, [%w[proc 0]]) do
      error = assert_raises(Rubernetes::Volume::PathSecurityError) { @security.validate_host_path!("/proc/version") }

      assert_match(/kernel mount identity changed/, error.message)
    end
  end

  private

  def kernel_mount?(path, type)
    File.foreach("/proc/self/mountinfo").any? do |line|
      fields, filesystem = line.split(" - ", 2)
      fields.split.fetch(4) == path && filesystem.split.first == type
    end
  end
end
