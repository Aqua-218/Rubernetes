# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux/cgroup_v2"
require "rubernetes/platform/linux/landlock"
require "rubernetes/platform/linux/openat2"
require "rubernetes/platform/linux/secure_rootfs"

class NativeRuntimeSecurityTest < Minitest::Test
  Linux = Rubernetes::Platform::Linux

  class OpenAdapter
    attr_reader :calls

    def initialize
      @calls = []
    end

    def openat2(**arguments)
      @calls << arguments
      17
    end
  end

  class LandlockAdapter
    attr_reader :calls

    def initialize
      @calls = []
    end

    def probe
      2
    end

    def create_ruleset(**arguments)
      @calls << [:create, arguments]
      4
    end

    def set_no_new_privs(**arguments)
      @calls << [:no_new_privs, arguments]
      true
    end

    def restrict_self(**arguments)
      @calls << [:restrict, arguments]
      true
    end
  end

  def test_openat2_rejects_traversal_before_adapter_call
    adapter = OpenAdapter.new
    resolver = Linux::Openat2.new(root: "/tmp", root_fd: 3, adapter: adapter)

    assert_raises(Linux::Openat2::UnsafePath) { resolver.open("safe/../escape") }
    assert_empty(adapter.calls)
  end

  def test_openat2_rejects_resolutions_without_symlink_bans
    adapter = OpenAdapter.new
    resolver = Linux::Openat2.new(root: "/tmp", root_fd: 3, adapter: adapter)
    resolve = Linux::Openat2::RESOLVE_BENEATH | Linux::Openat2::RESOLVE_NO_MAGICLINKS

    assert_raises(Linux::Openat2::UnsafePath) do
      resolver.open("safe", resolve: resolve)
    end
    assert_empty(adapter.calls)
  end

  def test_openat2_requires_no_xdev_for_mount_replacement_fencing
    adapter = OpenAdapter.new
    resolver = Linux::Openat2.new(root: "/tmp", root_fd: 3, adapter: adapter)
    resolve = Linux::Openat2::RESOLVE_BENEATH |
              Linux::Openat2::RESOLVE_NO_MAGICLINKS |
              Linux::Openat2::RESOLVE_NO_SYMLINKS

    error = assert_raises(Linux::Openat2::UnsafePath) do
      resolver.open("safe", resolve: resolve)
    end

    assert_match(/RESOLVE_NO_XDEV/, error.message)
    assert_empty adapter.calls
    assert_equal Linux::Openat2::RESOLVE_NO_XDEV,
                 Linux::Openat2::DEFAULT_RESOLVE & Linux::Openat2::RESOLVE_NO_XDEV
  end

  def test_secure_rootfs_fails_closed_when_openat2_is_unavailable
    unavailable = Object.new
    unavailable.define_singleton_method(:open) do |*_args, **|
      raise Linux::Openat2::Unsupported, "openat2 unavailable"
    end

    Dir.mktmpdir("rubernetes-secure-root-") do |root|
      assert_raises(Linux::SecureRootfs::Unsupported) do
        Linux::SecureRootfs.new(root: root, openat2: unavailable)
      end
    end
  end

  def test_landlock_sets_no_new_privs_before_restrict
    adapter = LandlockAdapter.new
    landlock = Linux::Landlock.new(adapter: adapter)
    ruleset = landlock.create_ruleset(handled_access_fs: Linux::Landlock::ACCESS_FS_READ_FILE)

    landlock.restrict_self(ruleset)

    assert_equal([:create, :no_new_privs, :restrict], adapter.calls.map(&:first))
  end

  def test_cgroup_path_rejects_components_that_escape_hierarchy
    cgroup = Linux::CgroupV2.new(root: "/sys/fs/cgroup", adapter: FakeCgroupFiles.new)

    assert_raises(Linux::CgroupV2::InvalidPath) do
      cgroup.path(qos: "besteffort", pod_id: "../pod", container_id: "container")
    end
  end

  def test_cgroup_remove_deletes_empty_per_pod_parent
    adapter = CleanupCgroupFiles.new
    cgroup = Linux::CgroupV2.new(root: "/sys/fs/cgroup", adapter: adapter)
    sandbox = Linux::CgroupV2::Handle.new(
      path: "/sys/fs/cgroup/rubernetes/besteffort/pod-a/sandbox",
      qos: "besteffort", pod_id: "pod-a", container_id: "sandbox", identity: "cgroup:pod-a"
    )
    main = Linux::CgroupV2::Handle.new(
      path: "/sys/fs/cgroup/rubernetes/besteffort/pod-a/main",
      qos: "besteffort", pod_id: "pod-a", container_id: "main", identity: "cgroup:pod-a:main"
    )
    adapter.add(sandbox.path, main.path)

    cgroup.remove(main)
    refute_includes(adapter.deleted, File.dirname(main.path))

    cgroup.remove(sandbox)
    assert_equal([main.path, sandbox.path, File.dirname(sandbox.path)], adapter.deleted)
  end

  class FakeCgroupFiles
    def directory?(_path)
      true
    end

    def exists?(_path)
      true
    end

    def read(_path)
      "cpu memory pids"
    end

    def write(_path, _value)
      true
    end

    def mkdir_p(_path)
      true
    end

    def delete(_path)
      true
    end
  end

  class CleanupCgroupFiles
    attr_reader :deleted

    def initialize
      @directories = {}
      @deleted = []
    end

    def add(*paths)
      paths.each do |path|
        @directories[path] = true
        @directories[File.dirname(path)] = true
      end
    end

    def directory?(path) = @directories.key?(path)
    def exists?(_path) = false
    def read(_path) = "populated 0\n"

    def delete(path)
      @deleted << path
      @directories.delete(path)
      true
    end

    def child_directories(path)
      prefix = "#{path}/"
      @directories.keys.select do |candidate|
        candidate.start_with?(prefix) && !candidate.delete_prefix(prefix).include?("/")
      end
    end
  end
end
