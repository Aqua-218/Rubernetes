# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/platform/linux"

# v1.VolumeMount.recursiveReadOnly through the production process gate: a
# read-only volume whose source has a submount keeps that submount writable
# (a bind remount is never recursive) unless recursiveReadOnly asks for the
# whole tree, which mount_setattr(AT_RECURSIVE) makes read-only.
class RecursiveReadOnlyMountTest < Minitest::Test
  Linux = Rubernetes::Platform::Linux

  def setup
    skip "needs root" unless Process.uid.zero?
    skip "static busybox is unavailable" unless File.executable?("/usr/bin/busybox")

    @dir = Dir.mktmpdir("rbn-rro-")
    @rootfs = File.join(@dir, "rootfs")
    FileUtils.mkdir_p(File.join(@rootfs, "bin"))
    FileUtils.cp("/usr/bin/busybox", File.join(@rootfs, "bin", "busybox"), preserve: true)
    @volume = File.join(@dir, "volume")
    FileUtils.mkdir_p(File.join(@volume, "sub"))
    @submount = File.join(@volume, "sub")
    raise "tmpfs mount failed" unless system("mount", "-t", "tmpfs", "-o", "size=1m", "rbn-rro-test", @submount)
  end

  def teardown
    system("umount", @submount, err: File::NULL) if @submount
    FileUtils.rm_rf(@dir) if @dir
  end

  def run_with(mode)
    security = Linux::Security.new(adapter: Linux::NativeAdapters::SecurityAdapter.new)
    adapter = Linux::NativeAdapters::ProcessGateAdapter.new(namespace_adapter: Object.new, security: security)
    context = Linux::Security::Context.from("seccomp" => "Unconfined")
    probe = Linux::Security::Probe.new(architecture: Linux::ABIManifest.current_architecture, capabilities: {},
                                       no_new_privs: true, seccomp: true, landlock: true, details: {})
    plan = Linux::Security::Plan.new(context: context, steps: [].freeze, seccomp_program: nil, probe: probe)
    mount = {"source" => @volume, "destination" => "/vol", "readonly" => true, "propagation" => "None",
             "recursive_readonly" => mode}.compact
    process = adapter.spawn(command: ["/bin/busybox", "sh", "-c", "touch /vol/sub/probe 2>/dev/null && echo writable || echo readonly"],
                            rootfs: @rootfs, security_plan: plan, mounts: [mount])
    adapter.release_gate(process.fetch(:gate))
    adapter.wait(pid: process.fetch(:pid), timeout: 5.0)
    process.fetch(:stdout).read.strip
  ensure
    process&.values_at(:stdout, :stderr)&.compact&.each { |io| io.close unless io.closed? }
  end

  def test_a_plain_read_only_mount_leaves_submounts_writable
    assert_equal "writable", run_with(nil)
    assert_equal "writable", run_with("Disabled")
  end

  def test_recursive_read_only_covers_the_submounts
    assert_equal "readonly", run_with("Enabled")
    assert_equal "readonly", run_with("IfPossible")
  end
end
