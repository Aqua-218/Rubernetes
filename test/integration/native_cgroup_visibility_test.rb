# frozen_string_literal: true

require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "timeout"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/platform/linux/cgroup_v2"
require "rubernetes/platform/linux/mount"
require "rubernetes/platform/linux/setns"

class NativeCgroupVisibilityTest < Minitest::Test
  Linux = Rubernetes::Platform::Linux
  FILES = %w[memory.max cpu.max].freeze
  INITIAL = {"memory.max" => "268435456", "cpu.max" => "20000 100000"}.freeze
  RESIZED = {"memory.max" => "402653184", "cpu.max" => "35000 100000"}.freeze

  def test_non_root_can_read_resized_limits_in_its_private_cgroup_mount
    skip "requires a writable Linux cgroup v2 hierarchy and root" unless Process.uid.zero? && File.directory?("/sys/fs/cgroup")

    [0o022, 0o077].each do |mask|
      before, after = observed_limits(mask)

      assert_equal 0o755, before.fetch("mode"), format("umask %04o", mask)
      assert_equal 0o700, before.fetch("parent_mode")
      assert before.fetch("same_cgroup")
      assert_empty before.fetch("child_directories")
      assert_match(/ - cgroup2 /, before.fetch("mountinfo"))
      assert_includes before.fetch("mountinfo").split.fetch(5).split(","), "ro"
      assert_equal INITIAL, before.fetch("limits")
      assert_equal RESIZED, after
    end
  end

  private

  def observed_limits(mask)
    root = Dir.mktmpdir("rubernetes-cgroup-visibility-", "/sys/fs/cgroup")
    adapter = Linux::CgroupV2.new(root: root)
    File.write(File.join(root, "cgroup.subtree_control"), "+cpu +memory +pids")
    previous_umask = File.umask(mask)
    begin
      handle = adapter.create(qos: "guaranteed", pod_id: "pod", container_id: "app", limits: INITIAL)
    ensure
      File.umask(previous_umask)
    end
    Dir.mktmpdir("rubernetes-cgroup-mount-") do |mountpoint|
      observe_mounted_limits(adapter, handle, root, mountpoint)
    end
  rescue Errno::EACCES, Errno::EPERM, Errno::EROFS
    skip "requires a writable, delegated cgroup v2 hierarchy"
  ensure
    adapter.remove(handle) if handle
    if adapter
      [adapter.hierarchy_path(qos: "guaranteed"), File.join(root, Linux::CgroupV2::HIERARCHY_PREFIX), root].each do |path|
        Dir.rmdir(path) if File.directory?(path)
      end
    end
  end

  def observe_mounted_limits(adapter, handle, root, mountpoint)
    results, result_writer = IO.pipe
    resize_reader, resize_writer = IO.pipe
    child = fork do
      results.close
      resize_writer.close
      result_writer.sync = true
      mount_leaf(handle, mountpoint)
      result_writer.puts(JSON.generate(
        mode: File.stat(mountpoint).mode & 0o777, parent_mode: File.stat(root).mode & 0o777,
        same_cgroup: File.stat(mountpoint).ino == File.stat(handle.path).ino,
        child_directories: Dir.children(mountpoint).select { |entry| File.directory?(File.join(mountpoint, entry)) },
        mountinfo: File.foreach("/proc/self/mountinfo").find { |line| line.split[4] == mountpoint },
        limits: non_root_limits(mountpoint)
      ))
      result_writer.puts(JSON.generate(non_root_limits(mountpoint))) if resize_reader.gets
      exit! true
    rescue Linux::Error => error
      result_writer.puts(JSON.generate(kernel_error: error.errno, message: error.message))
      exit!
    end
    result_writer.close
    resize_reader.close
    before = read_snapshot(results)
    adapter.configure(handle, RESIZED)
    resize_writer.puts("resized")
    after = read_snapshot(results)
    _, status = Process.wait2(child)
    child = nil

    assert_predicate status, :success?
    [before, after]
  ensure
    [resize_writer, results].compact.each(&:close)
    Process.wait(child) if child
  end

  def read_snapshot(pipe)
    line = Timeout.timeout(10) { pipe.gets }

    refute_nil line, "cgroup mount observer exited before readback"
    snapshot = JSON.parse(line)
    skip snapshot.fetch("message") if snapshot.fetch("kernel_error", nil) == Errno::EPERM::Errno

    snapshot
  end

  def mount_leaf(handle, mountpoint)
    File.write(File.join(handle.path, "cgroup.procs"), "0")
    Linux::Setns.new.unshare(flags: Linux::Setns::CLONE_NEWNS | Linux::Setns::CLONE_NEWCGROUP)
    mount = Linux::Mount.new
    mount.set_propagation(target: "/", propagation: Linux::Mount::MS_PRIVATE)
    mount.mount(source: "cgroup2", target: mountpoint, filesystem: "cgroup2", flags: Linux::Mount::MS_RDONLY)
  end

  def non_root_limits(path)
    program = <<~RUBY
      require "json"
      Process.groups = []
      Process::UID.change_privilege(1000)
      puts JSON.generate(ARGV.to_h { |name| [name, File.read(name).strip] })
    RUBY
    # Enter the mounted leaf before dropping privileges. The test suite's
    # temporary directory may itself be private to the test runner.
    out, error, status = Open3.capture3(RbConfig.ruby, "-e", program, *FILES, chdir: path)
    status.success? ? JSON.parse(out) : {"error" => error.strip, "exit_status" => status.exitstatus}
  end
end
