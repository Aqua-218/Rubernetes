# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux"
require "digest"
require "fileutils"
require "tmpdir"
require "timeout"

class LinuxPlatformTest < Minitest::Test
  Linux = Rubernetes::Platform::Linux

  class NoopSecurity
    def apply(_plan, probe:)
      !probe.nil?
    end
  end

  def test_checked_in_manifest_matches_ruby_layout
    manifest = Linux::ABIManifest.load

    assert_equal(Linux::ABIManifest.current_architecture, manifest.architecture)
    assert(manifest.verify_ruby_layouts!)
    assert_equal(Linux::Clone3::CLONE_PIDFD, manifest.constant(:clone, :CLONE_PIDFD))
    assert_equal(Linux::Clone3::CLONE_NEWNS, manifest.constant(:clone, :CLONE_NEWNS))
    assert_equal(Linux::Clone3::CLONE_NEWPID, manifest.constant(:clone, :CLONE_NEWPID))
    assert_equal(Linux::Netlink::NLM_F_ACK, manifest.constant(:netlink, :NLM_F_ACK))
    assert_equal(Linux::Netlink::RTM_GETLINK, manifest.constant(:netlink, :RTM_GETLINK))
    assert_equal(Linux::BPF::BPF_PROG_LOAD, manifest.constant(:bpf, :BPF_PROG_LOAD))
    assert_equal(Linux::KVM::KVM_GET_API_VERSION, manifest.constant(:kvm, :KVM_GET_API_VERSION))
    assert_equal(Linux::Mount::MS_NOEXEC, manifest.constant(:mount, :MS_NOEXEC))
  end

  def test_clone3_intentional_failure_preserves_context
    error = assert_raises(Linux::Error) do
      Linux::Clone3.new.call(
        args: Linux::Clone3::Args.new(flags: 0),
        resource_id: "sandbox:invalid-clone",
        structure_size: 0
      )
    end

    assert_operator(error.errno, :>, 0)
    assert_equal("clone3", error.operation)
    assert_equal("sandbox:invalid-clone", error.resource_id)
  end

  def test_clone3_pidfd_wait_returns_exit_status_without_numeric_pid_wait
    clone = Linux::Clone3.new
    result = clone.call(
      args: Linux::Clone3::Args.new(flags: Linux::Clone3::CLONE_PIDFD),
      resource_id: "process:pidfd-test"
    )
    Process.exit!(23) if result.child?

    wait_result = Linux::Pidfd.new.wait(
      pidfd: result.pidfd,
      timeout: 5.0,
      resource_id: "process:pidfd-test"
    )

    refute_nil(wait_result)
    assert_equal(23, wait_result.exit_status)
  ensure
    IO.for_fd(result.pidfd).close if result && !result.child? && result.pidfd
  end

  def test_pidfd_intentional_failure_preserves_context
    error = assert_raises(Linux::Error) do
      Linux::Pidfd.new.open(pid: -1, resource_id: "process:missing")
    end

    assert_equal(Errno::EINVAL::Errno, error.errno)
    assert_equal("pidfd_open", error.operation)
    assert_equal("process:missing", error.resource_id)
  end

  def test_mount_intentional_failure_preserves_context
    error = assert_raises(Linux::Error) do
      Linux::Mount.new.mount(
        source: "none",
        target: "/rubernetes/does/not/exist",
        filesystem: "none",
        resource_id: "mount:missing-target"
      )
    end

    assert_operator(error.errno, :>, 0)
    assert_equal("mount", error.operation)
    assert_equal("mount:missing-target", error.resource_id)
  end

  def test_netlink_receives_kernel_ack
    ack = Linux::Netlink.new.get_link(index: 1, sequence: 12_345)

    assert_equal(12_345, ack.sequence)
    assert(ack.messages.any? { |message| message.type == Linux::Netlink::RTM_NEWLINK })
  end

  def test_bpf_exposes_program_or_verifier_failure
    program = Linux::BPF.new.probe(resource_id: "bpf:test-probe")

    assert_operator(program.fd, :>=, 0)
    assert_kind_of(String, program.verifier_log)
  rescue Linux::BPF::VerifierError => error
    assert_operator(error.errno, :>, 0)
    assert_equal("bpf(BPF_PROG_LOAD)", error.operation)
    assert_equal("bpf:test-probe", error.resource_id)
    assert_kind_of(String, error.verifier_log)
  ensure
    program&.close
  end

  def test_kvm_exposes_api_version_or_precise_host_error
    probe = Linux::KVM.new.probe(resource_id: "kvm:test-device")

    assert_equal(Linux::KVM::API_VERSION, probe.api_version)
    assert(probe.capabilities.key?(Linux::KVM::KVM_CAP_USER_MEMORY))
  rescue Linux::Error => error
    assert_operator(error.errno, :>, 0)
    assert_equal("kvm_probe", error.operation)
    assert_equal("kvm:test-device", error.resource_id)
  end

  def test_production_process_gate_returns_after_exec_readiness_not_process_exit
    security_adapter = Linux::NativeAdapters::SecurityAdapter.new
    adapter = Linux::NativeAdapters::ProcessGateAdapter.new(
      namespace_adapter: Object.new,
      security: Linux::Security.new(adapter: security_adapter)
    )
    context = Linux::Security::Context.from("seccomp" => "Unconfined")
    probe = Linux::Security::Probe.new(
      architecture: Linux::ABIManifest.current_architecture,
      capabilities: {},
      no_new_privs: true,
      seccomp: true,
      landlock: true,
      details: {}
    )
    plan = Linux::Security::Plan.new(context: context, steps: [].freeze, seccomp_program: nil, probe: probe)
    process = adapter.spawn(command: ["/bin/sh", "-c", "sleep 0.5"], security_plan: plan)

    started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    assert(adapter.release_gate(process.fetch(:gate)))
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at

    assert_operator(elapsed, :<, 0.4)
    assert(Process.kill(0, process.fetch(:pid)))
    refute_nil(adapter.wait(pid: process.fetch(:pid), timeout: 2.0))
  ensure
    process&.values_at(:stdout, :stderr)&.each { |io| io.close if io && !io.closed? }
  end

  def test_production_process_gate_executes_inside_selected_rootfs
    skip "static busybox is unavailable" unless File.executable?("/usr/bin/busybox")

    Dir.mktmpdir("rubernetes-rootfs-gate-") do |rootfs|
      FileUtils.mkdir_p(File.join(rootfs, "bin"))
      FileUtils.cp("/usr/bin/busybox", File.join(rootfs, "bin", "busybox"), preserve: true)
      security_adapter = Linux::NativeAdapters::SecurityAdapter.new
      security = Linux::Security.new(adapter: security_adapter)
      adapter = Linux::NativeAdapters::ProcessGateAdapter.new(
        namespace_adapter: Object.new,
        security: security
      )
      context = Linux::Security::Context.from("seccomp" => "Unconfined")
      probe = Linux::Security::Probe.new(
        architecture: Linux::ABIManifest.current_architecture,
        capabilities: {}, no_new_privs: true, seccomp: true, landlock: true, details: {}
      )
      plan = Linux::Security::Plan.new(context: context, steps: [].freeze, seccomp_program: nil, probe: probe)
      process = adapter.spawn(
        command: ["/bin/busybox", "sh", "-c", "test ! -e /etc/passwd"],
        rootfs: rootfs,
        security_plan: plan
      )

      assert(adapter.release_gate(process.fetch(:gate)))
      status = adapter.wait(pid: process.fetch(:pid), timeout: 2.0)

      assert_predicate(status, :success?)
    ensure
      process&.values_at(:stdout, :stderr)&.each { |io| io.close if io && !io.closed? }
    end
  end

  def test_production_process_gate_accepts_short_lived_exec_identity
    security_adapter = Linux::NativeAdapters::SecurityAdapter.new
    adapter = Linux::NativeAdapters::ProcessGateAdapter.new(
      namespace_adapter: Object.new,
      security: Linux::Security.new(adapter: security_adapter)
    )
    context = Linux::Security::Context.from("seccomp" => "Unconfined")
    probe = Linux::Security::Probe.new(
      architecture: Linux::ABIManifest.current_architecture,
      capabilities: {},
      no_new_privs: true,
      seccomp: true,
      landlock: true,
      details: {}
    )
    plan = Linux::Security::Plan.new(context: context, steps: [].freeze, seccomp_program: nil, probe: probe)
    process = adapter.spawn(command: ["/bin/true"], security_plan: plan)

    assert(adapter.release_gate(process.fetch(:gate)))
    assert_operator(process.fetch(:gate).workload_pid, :>, 0)
    assert_operator(process.fetch(:gate).workload_start_time, :>, 0)
    status = adapter.wait(pid: process.fetch(:pid), timeout: 2.0)

    assert_predicate(status, :success?)
  ensure
    process&.values_at(:stdout, :stderr)&.compact&.each { |io| io.close unless io.closed? }
  end

  def test_runtime_default_seccomp_allows_subprocess_wait_and_exit
    skip "static busybox is unavailable" unless File.executable?("/usr/bin/busybox")

    begin
      security_adapter = Linux::NativeAdapters::SecurityAdapter.new
      security = Linux::Security.new(adapter: security_adapter)
      adapter = Linux::NativeAdapters::ProcessGateAdapter.new(
        namespace_adapter: Object.new,
        security: security
      )
      plan = security.plan({"seccomp" => "RuntimeDefault", "allow_privilege_escalation" => false})
      process = adapter.spawn(
        command: ["/usr/bin/busybox", "sh", "-c", "(echo child-ok) & wait"],
        security_plan: plan
      )

      assert(adapter.release_gate(process.fetch(:gate)))
      status = adapter.wait(pid: process.fetch(:pid), timeout: 3.0)

      refute_nil(status, "RuntimeDefault workload spun after a denied signal-wait syscall")
      assert_predicate(status, :success?)
      assert_equal("child-ok\n", process.fetch(:stdout).read)
      assert_equal("", process.fetch(:stderr).read)
    ensure
      begin
        adapter&.signal(pid: process.fetch(:pid), signal: Signal.list.fetch("KILL")) if process && File.exist?("/proc/#{process.fetch(:pid)}")
      rescue StandardError
        nil
      end
      process&.values_at(:stdout, :stderr)&.compact&.each { |io| io.close unless io.closed? }
    end
  end

  def test_production_native_exec_and_port_forward_enter_pod_namespaces
    skip "production Native stream probe requires root" unless Process.uid.zero?
    skip "static busybox is unavailable" unless File.executable?("/usr/bin/busybox")
    skip "cgroup v2 hierarchy is unavailable" unless File.writable?("/sys/fs/cgroup")

    Dir.mktmpdir("rubernetes-native-stream-") do |directory|
      lower = File.join(directory, "lower")
      FileUtils.mkdir_p(File.join(lower, "bin"))
      FileUtils.cp("/usr/bin/busybox", File.join(lower, "bin", "busybox"), preserve: true)
      sandbox_root = File.join(directory, "sandboxes")
      sandbox_id = "m2-stream-#{Process.pid}-#{SecureRandom.hex(4)}"
      adapters = Linux::NativeAdapters.for_profile(
        profile: :l3,
        sandbox_root: sandbox_root,
        cgroup_root: "/sys/fs/cgroup"
      )
      runtime = Rubernetes::Runtime::Native.new(
        profile: :l3,
        l3: true,
        adapters: adapters,
        sandbox_root: sandbox_root,
        cgroup_root: "/sys/fs/cgroup",
        log_root: File.join(directory, "logs"),
        journal_path: File.join(directory, "journal.jsonl"),
        security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"}
      )
      image_bytes = "verified-stream-image"
      sandbox = runtime.run_sandbox(
        {"id" => sandbox_id, "image_bytes" => image_bytes,
         "image_digest" => "sha256:#{Digest::SHA256.hexdigest(image_bytes)}", "lowerdirs" => [lower]},
        request_id: sandbox_id
      )
      container = runtime.create_container(sandbox, {
                                             "id" => "main",
                                             "rootfs_path" => lower,
                                             "command" => [
                                               "/bin/busybox", "sh", "-c",
                                               "(while :; do echo port-ok | /bin/busybox nc -l -p 18080; " \
                                               "echo port-two | /bin/busybox nc -l -p 18081; done) & " \
                                               "while :; do echo attach-ok; /bin/busybox sleep 1; done"
                                             ]
                                           })
      runtime.start_container(container)

      runtime.logs(container)
      attached = Rubernetes::Node::AttachService.new(runtime: runtime, trusted: true).attach(container.id)

      assert_includes(Timeout.timeout(5) { attached.stdout.read(16 * 1024) }, "attach-ok\n")
      attached.stdout.close

      executed = runtime.exec(container, ["/bin/busybox", "echo", "exec-ok"])

      assert_equal("exec-ok\n", Timeout.timeout(5) { executed.fetch(:stdout).read })
      assert_predicate(Timeout.timeout(5) { executed.fetch(:status).pop }, :success?)

      multiplexed = runtime.port_forward(container, [18_080, 18_081], timeout: 5)
      observed = {}
      Timeout.timeout(5) do
        until observed.keys.sort == [0, 2]
          frame = multiplexed.fetch(:stdout).read(16 * 1024)
          break if frame.nil?

          channel = frame.getbyte(0)
          observed[channel] = frame.byteslice(1, frame.bytesize - 1)
        end
      end
      server_errors = runtime.logs(container, stream: :stderr).to_s

      assert_equal(
        {0 => "port-ok\n", 2 => "port-two\n"},
        observed.select { |channel, _| channel.even? },
        "port-forward=#{observed.inspect} container-stderr=#{server_errors.inspect}"
      )
      multiplexed.fetch(:status).each do |status|
        assert_predicate(Timeout.timeout(5) { status.pop }, :success?)
      end

      # A single requested port follows a separate adapter shape from the
      # multi-port Kubernetes channel multiplexer. Keep the real namespace
      # path covered so it cannot silently return an empty HTTP stream.
      single = runtime.port_forward(container, [18_080], timeout: 5)
      single_frame = Timeout.timeout(5) { single.fetch(:stdout).read }

      assert_equal(0, single_frame.getbyte(0))
      assert_equal("port-ok\n", single_frame.byteslice(1, single_frame.bytesize - 1))
      assert_predicate(Timeout.timeout(5) { single.fetch(:status).fetch(0).pop }, :success?)
      assert_equal("running", runtime.wait_container(container, timeout: 0).fetch("state"))

      runtime.stop_sandbox(sandbox, timeout: 2)
      runtime.remove_sandbox(sandbox)

      assert_empty(runtime.sandboxes)
      refute(File.directory?(File.join("/sys/fs/cgroup/rubernetes/besteffort", sandbox_id)))
    ensure
      begin
        runtime&.stop_sandbox(sandbox, timeout: 1) if sandbox && runtime.sandboxes.any?
        runtime&.remove_sandbox(sandbox) if sandbox && runtime.sandboxes.any?
      rescue StandardError
        nil
      end
    end
  end
end
