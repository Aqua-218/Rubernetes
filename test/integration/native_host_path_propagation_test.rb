# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/platform/linux/native_adapters"
require "rubernetes/runtime/native"
require "rubernetes/volume"
require "timeout"
require "tmpdir"

class NativeHostPathPropagationTest < Minitest::Test
  Linux = Rubernetes::Platform::Linux
  Mount = Linux::Mount

  def setup
    skip "needs a private mount namespace with root" unless Process.euid.zero? && !Mount.new.initial_mount_namespace?
    skip "needs static BusyBox" unless File.executable?("/usr/bin/busybox")

    @root = Dir.mktmpdir("rbn-hostpath-propagation-")
    @mount = Mount.new
    @source = File.join(@root, "source")
    @rootfs = File.join(@root, "rootfs")
    FileUtils.mkdir_p([File.join(@source, "existing"), File.join(@source, "late"), File.join(@rootfs, "bin")])
    FileUtils.cp("/usr/bin/busybox", File.join(@rootfs, "bin", "busybox"), preserve: true)
    @openat2 = Linux::Openat2.new(root: "/")
    security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: @openat2)
    @manager = Rubernetes::Volume::Manager.new(data_dir: File.join(@root, "state"), fsync: false,
                                               mount_adapter: Rubernetes::Volume::NativeMountAdapter.new, path_security: security)
    @volumes = Rubernetes::Node::PodVolumes.new(volume: @manager, root: File.join(@root, "pods"), node_name: "worker-0")
    @mountpoints = []
  end

  def teardown
    return unless @root

    @volumes.release(@pod, @prepared) if @prepared
  ensure
    @mountpoints&.reverse_each { |path| @mount.unmount(target: path) }
    @mount.unmount(target: @volumes.root, flags: Mount::MNT_DETACH) if @volumes&.propagating_root?
    @openat2&.close
    FileUtils.remove_entry(@root) if @root
  end

  def test_a_propagating_host_path_sees_existing_and_later_mounts
    @mount.ensure_shared_self_bind(target: @source)
    @mountpoints << @source
    mount_marker("existing")
    mounts = prepare_mounts(@source)
    command = <<~SH
      /bin/busybox cat /host/existing/marker || exit 1
      while ! /bin/busybox test -f /host/late/marker; do /bin/busybox sleep 0.05; done
      /bin/busybox cat /host/late/marker
    SH
    run_workload(mounts, command) do |stdout|
      assert_equal "existing\n", stdout.gets
      mount_marker("late")

      assert_equal "late\n", stdout.gets
    end
    assert_host_submount_survives_release
  end

  def test_bidirectional_host_path_propagates_through_a_native_sandbox
    host_path = @source
    @mount.mount(source: host_path, target: host_path, filesystem: nil, flags: Mount::MS_BIND)
    @mount.make_private(target: host_path)
    @mountpoints << host_path
    @source = File.join(host_path, "shared")
    FileUtils.mkdir_p(%w[existing late].map { |path| File.join(@source, path) })
    @mount.ensure_shared_self_bind(target: @source)
    @mountpoints << @source
    mounts = prepare_mounts(host_path, propagation: "Bidirectional", readonly: false)
    command = <<~SH
      /bin/busybox mount -t tmpfs -o size=1m tmpfs /host/shared/late || exit 1
      echo workload > /host/shared/late/marker.tmp
      /bin/busybox mv /host/shared/late/marker.tmp /host/shared/late/marker || exit 1
      while ! /bin/busybox test -f /host/shared/existing/marker; do /bin/busybox sleep 0.05; done
      /bin/busybox cat /host/shared/existing/marker
    SH

    output = run_native_container(mounts, command, privileged: true) do
      path = File.join(@source, "late", "marker")
      Timeout.timeout(10) { sleep 0.05 until File.exist?(path) }
      @mountpoints << File.dirname(path)

      assert_equal "workload\n", File.read(path)
      mount_marker("existing")
    end

    assert_equal "existing", output
    assert_host_submount_survives_release
    assert_equal "workload\n", File.read(File.join(@source, "late", "marker"))
  end

  def test_a_propagating_host_root_contains_procfs_and_the_test_submount
    mount_marker("existing")

    assert_host_root_submounts(prepare_mounts("/"))
  end

  def test_a_private_host_root_also_contains_existing_submounts
    skip "needs a writable cgroup v2 root" unless File.writable?("/sys/fs/cgroup/cgroup.procs")

    mount_marker("existing")
    mounts = prepare_mounts("/", propagation: nil)
    output = run_native_container(mounts, "#{host_root_probe} || echo missing")

    assert_equal "existing", output
  end

  def test_a_private_host_path_remains_isolated_from_later_mounts
    @mount.ensure_shared_self_bind(target: @source)
    @mountpoints << @source
    mount_marker("existing")
    mounts = prepare_mounts(@source, propagation: nil)
    command = <<~SH
      /bin/busybox cat /host/existing/marker || exit 1
      while ! /bin/busybox test -f /host/check; do /bin/busybox sleep 0.05; done
      /bin/busybox test ! -e /host/late/marker && echo private
    SH
    run_workload(mounts, command) do |stdout|
      assert_equal "existing\n", stdout.gets
      mount_marker("late")
      FileUtils.touch(File.join(@source, "check"))

      assert_equal "private\n", stdout.gets
    end
    assert_host_submount_survives_release
  end

  def test_replaced_host_path_is_refused
    backup = "#{@source}-original"
    mounts = prepare_mounts(@source)
    File.rename(@source, backup)
    FileUtils.mkdir_p(@source)

    assert_gate_failure(mounts, /HostPath source changed after publication/)
    Dir.rmdir(@source)
    File.symlink(backup, @source)

    assert_gate_failure(mounts, /Too many levels of symbolic links/)
  ensure
    if backup && File.directory?(backup)
      File.unlink(@source) if File.symlink?(@source)
      Dir.rmdir(@source) if File.directory?(@source)
      File.rename(backup, @source)
    end
  end

  def test_taking_down_an_existing_shared_stage_preserves_the_host_submount
    @mount.ensure_shared_self_bind(target: @source)
    @mountpoints << @source
    native = @manager.mount_adapter.method(:mount)
    original_mount = ->(options: {}, **arguments) { native.call(options: options.except("private"), **arguments) }
    @manager.mount_adapter.stub(:mount, original_mount) { prepare_mounts(@source) }
    mount_marker("late")

    assert_host_submount_survives_release
  end

  private

  def assert_host_submount_survives_release
    marker = File.join(@source, "late", "marker")

    assert_path_exists marker, "container shutdown removed the host submount"
    @volumes.release(@pod, @prepared)
    @prepared = nil

    assert_path_exists marker, "volume release removed the host submount"
  end

  def assert_host_root_submounts(mounts)
    run_workload(mounts, host_root_probe) do |stdout|
      assert_equal "existing\n", stdout.gets
    end
  end

  def host_root_probe
    marker = "/host#{File.join(@source, "existing", "marker")}"
    "/bin/busybox test -L /host/proc/1/ns/mnt && /bin/busybox cat #{marker}"
  end

  def run_native_container(mounts, command, privileged: false)
    sandbox_root = File.join(@root, "sandboxes")
    FileUtils.mkdir_p(sandbox_root)
    runtime = Rubernetes::Runtime::Native.new(
      profile: :l3, l3: true,
      adapters: Linux::NativeAdapters.for_profile(profile: :l3, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup"),
      sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup", log_root: File.join(@root, "logs"),
      journal_path: File.join(@root, "native-runtime.jsonl"),
      security_context: {"allow_privilege_escalation" => privileged, "seccomp" => privileged ? "Unconfined" : "RuntimeDefault",
                         "privileged" => privileged}
    )
    sandbox = runtime.run_sandbox({"id" => "host-path-#{Process.pid}", "image_bytes" => "img",
                                   "image_digest" => "sha256:#{Digest::SHA256.hexdigest("img")}", "lowerdirs" => [@rootfs]})
    container = runtime.create_container(sandbox, {"id" => "host-root-test", "rootfs_path" => @rootfs, "mounts" => mounts,
                                                   "command" => ["/bin/busybox", "sh", "-c", command]})
    runtime.start_container(container)
    yield if block_given?
    Timeout.timeout(10) do
      loop do
        output = runtime.logs(container).to_s
        return output.strip if output.include?("\n")

        sleep 0.05
      end
    end
  ensure
    if sandbox
      runtime.stop_sandbox(sandbox, timeout: 1)
      runtime.remove_sandbox(sandbox)
    end
  end

  def assert_gate_failure(mounts, pattern)
    error = assert_raises(Linux::NativeAdapters::EffectError) do
      run_workload(mounts, "echo workload-started") { flunk "workload escaped the launch gate" }
    end
    assert_match(pattern, error.message)
  end

  def mount_marker(name)
    path = File.join(@source, name)
    @mount.mount(source: "tmpfs", target: path, filesystem: "tmpfs", flags: 0, data: "size=1m")
    @mountpoints << path
    temporary = File.join(path, "marker.tmp")
    File.write(temporary, "#{name}\n")
    File.rename(temporary, File.join(path, "marker"))
  end

  def prepare_mounts(source, propagation: "HostToContainer", readonly: true)
    container = {"name" => "test", "image" => "busybox", "volumeMounts" => [
      {"name" => "host", "mountPath" => "/host", "mountPropagation" => propagation, "readOnly" => readonly}.compact
    ]}
    @pod = {"metadata" => {"uid" => "host-path-test", "name" => "host-path-test", "namespace" => "default"},
            "spec" => {"volumes" => [{"name" => "host", "hostPath" => {"path" => source, "type" => "Directory"}}], "containers" => [container]}}
    @prepared = @volumes.prepare(@pod)
    builder = Rubernetes::Node::ContainerSpec.new(pod_volumes: @volumes)
    builder.build(pod: @pod, container: container, category: :containers, volumes: @prepared).fetch("mounts")
  end

  def run_workload(mounts, command)
    security = Linux::Security.new(adapter: Linux::NativeAdapters::SecurityAdapter.new)
    adapter = Linux::NativeAdapters::ProcessGateAdapter.new(namespace_adapter: Object.new, security: security)
    context = Linux::Security::Context.from("seccomp" => "Unconfined")
    probe = Linux::Security::Probe.new(architecture: Linux::ABIManifest.current_architecture, capabilities: {},
                                       no_new_privs: true, seccomp: true, landlock: true, details: {})
    plan = Linux::Security::Plan.new(context: context, steps: [].freeze, seccomp_program: nil, probe: probe)
    process = adapter.spawn(command: ["/bin/busybox", "sh", "-c", command], rootfs: @rootfs, security_plan: plan, mounts: mounts)
    adapter.release_gate(process.fetch(:gate))
    Timeout.timeout(10) { yield(*process.values_at(:stdout, :stderr)) }
  ensure
    if process
      wait_for_workload(adapter, process.fetch(:pid))
      process.values_at(:stdout, :stderr).each(&:close)
    end
  end

  def wait_for_workload(adapter, pid)
    return if adapter.wait(pid: pid, timeout: 2.0)

    Process.kill("KILL", pid)
    adapter.wait(pid: pid, timeout: 5.0)
  rescue Errno::ESRCH
    nil
  end
end
