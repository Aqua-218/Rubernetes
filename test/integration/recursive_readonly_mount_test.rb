# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/platform/linux"
require "rubernetes/runtime/native"

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
    mount = {"source" => @volume, "destination" => "/vol", "readonly" => true, "propagation" => "None",
             "recursive_readonly" => mode}.compact
    run_with_mounts([mount], "touch /vol/sub/probe 2>/dev/null && echo writable || echo readonly")
  end

  def run_with_mounts(mounts, command, namespace: nil, privileged: false)
    security = Linux::Security.new(adapter: Linux::NativeAdapters::SecurityAdapter.new)
    namespace_adapter = @namespace_adapter || Object.new
    adapter = Linux::NativeAdapters::ProcessGateAdapter.new(namespace_adapter: namespace_adapter, security: security)
    context = Linux::Security::Context.from("seccomp" => "Unconfined", "privileged" => privileged)
    probe = Linux::Security::Probe.new(architecture: Linux::ABIManifest.current_architecture, capabilities: {},
                                       no_new_privs: true, seccomp: true, landlock: true, details: {})
    plan = Linux::Security::Plan.new(context: context, steps: [].freeze, seccomp_program: nil, probe: probe)
    process = adapter.spawn(command: ["/bin/busybox", "sh", "-c", command],
                            rootfs: @rootfs, security_plan: plan, mounts: mounts, namespace: namespace)
    adapter.release_gate(process.fetch(:gate))
    adapter.wait(pid: process.fetch(:pid), timeout: 5.0)
    process.fetch(:stdout).read.strip
  ensure
    process&.values_at(:stdout, :stderr)&.each { |io| io.close if io && !io.closed? }
  end

  def test_a_plain_read_only_mount_leaves_submounts_writable
    assert_equal "writable", run_with(nil)
    assert_equal "writable", run_with("Disabled")
  end

  def test_recursive_read_only_covers_the_submounts
    assert_equal "readonly", run_with("Enabled")
    assert_equal "readonly", run_with("IfPossible")
  end

  def test_bidirectional_empty_dir_shares_a_nested_mount_only_within_its_sandbox
    @namespace_adapter = Linux::NativeAdapters::NamespaceAdapter.new
    namespace = Rubernetes::Runtime::Native::Namespace.new(adapter: @namespace_adapter, profile: :kernel_isolation)
    handle = namespace.create(id: "rro-sandbox-#{Process.pid}")
    mount = {"source" => @volume, "destination" => "/vol", "sandbox_shared_volume" => true, "propagation" => "Bidirectional"}
    observed = run_with_mounts([mount], "mkdir /vol/local && /bin/busybox mount -t tmpfs none /vol/local && touch /vol/local/peer && echo mounted",
                               namespace: handle, privileged: true)

    assert_equal "mounted", observed

    readonly = {"source" => @volume, "destination" => "/vol", "readonly" => true}
    observed = run_with_mounts([readonly], "test -f /vol/local/peer && touch /vol/local/writable && echo shared", namespace: handle)

    assert_equal "shared", observed
    refute_path_exists File.join(@volume, "local", "peer")
    refute_path_exists File.join(@volume, "local", "writable")

    unmounted = run_with_mounts([mount], "/bin/busybox umount /vol/local && echo unmounted", namespace: handle, privileged: true)

    assert_equal "unmounted", unmounted
    assert_equal "", run_with_mounts([readonly], "test -f /vol/local/peer && echo leaked", namespace: handle)
  ensure
    namespace&.destroy(handle) if handle
  end

  def test_a_writable_child_declared_before_its_read_only_parent_remains_visible
    writable = File.join(@dir, "writable")
    FileUtils.mkdir_p([writable, File.join(@volume, "sockets")])
    mounts = [
      {"source" => writable, "destination" => "/vol/sockets"},
      {"source" => @volume, "destination" => "/vol/", "readonly" => true}
    ]
    observed = run_with_mounts(mounts, "touch /vol/sockets/probe && ! touch /vol/parent-probe 2>/dev/null && echo isolated")

    assert_equal "isolated", observed
    assert_path_exists File.join(writable, "probe")
    refute_path_exists File.join(@volume, "parent-probe")
  end
end
