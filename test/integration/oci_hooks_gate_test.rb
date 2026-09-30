# frozen_string_literal: true

require "json"
require "tmpdir"
require "fileutils"
require_relative "../test_helper"
require "rubernetes/platform/linux"

# OCI hooks through the production process gate: the runtime-namespace stages
# are requested through the gate once the bootstrap is in the container
# namespaces, createContainer runs there before the root is built (its path
# is the host's), startContainer inside the container root before the
# workload -- and a failing hook stops the workload from ever running.
class OCIHooksGateTest < Minitest::Test
  Linux = Rubernetes::Platform::Linux

  def adapter
    security = Linux::Security.new(adapter: Linux::NativeAdapters::SecurityAdapter.new)
    Linux::NativeAdapters::ProcessGateAdapter.new(namespace_adapter: Object.new, security: security)
  end

  def plan
    context = Linux::Security::Context.from("seccomp" => "Unconfined")
    probe = Linux::Security::Probe.new(architecture: Linux::ABIManifest.current_architecture, capabilities: {},
                                       no_new_privs: true, seccomp: true, landlock: true, details: {})
    Linux::Security::Plan.new(context: context, steps: [].freeze, seccomp_program: nil, probe: probe)
  end

  def with_rootfs
    skip "static busybox is unavailable" unless File.executable?("/usr/bin/busybox")

    Dir.mktmpdir("rubernetes-hooks-gate-") do |directory|
      rootfs = File.join(directory, "rootfs")
      FileUtils.mkdir_p(File.join(rootfs, "bin"))
      FileUtils.cp("/usr/bin/busybox", File.join(rootfs, "bin", "busybox"), preserve: true)
      yield directory, rootfs
    end
  end

  def test_each_stage_runs_where_it_belongs
    with_rootfs do |directory, rootfs|
      host_log = File.join(directory, "host.log")
      runtime_calls = []
      hooks = {
        "createContainer" => [{"path" => "/bin/sh", "env" => [],
                               "args" => ["sh", "-c", "cat > #{directory}/create.state; test -e #{host_log} && echo seen-runtime-first >> #{host_log}"]}],
        # Resolved in the container root: /bin/busybox exists only there.
        "startContainer" => [{"path" => "/bin/busybox", "env" => ["MARK=inside"],
                              "args" => ["busybox", "sh", "-c", "cat > /start.state; echo $MARK > /marker"]}]
      }
      state = {"ociVersion" => "1.2.0", "id" => "c1", "bundle" => directory, "annotations" => {}}
      process = adapter.spawn(command: ["/bin/busybox", "sh", "-c", "cat /marker; cat /start.state"], rootfs: rootfs,
                              security_plan: plan,
                              container_hooks: {"hooks" => hooks, "state" => state,
                                                "runtime" => lambda { |pid|
                                                  runtime_calls << pid
                                                  File.write(host_log, "runtime #{pid}\n")
                                                }})

      assert adapter.release_gate(process.fetch(:gate))
      status = adapter.wait(pid: process.fetch(:pid), timeout: 5.0)
      output = process.fetch(:stdout).read

      assert_predicate status, :success?, output + process.fetch(:stderr).read

      workload_pid = process.fetch(:gate).workload_pid

      assert_equal [workload_pid], runtime_calls, "the runtime stages see the workload's host pid"
      assert_equal ["runtime #{workload_pid}", "seen-runtime-first"], File.readlines(host_log, chomp: true)
      create_state = JSON.parse(File.read(File.join(directory, "create.state")))

      assert_equal({"status" => "creating", "pid" => workload_pid, "id" => "c1", "bundle" => directory},
                   create_state.slice("status", "pid", "id", "bundle"))
      marker, start_state = output.lines(chomp: true)

      assert_equal "inside", marker
      assert_equal "created", JSON.parse(start_state)["status"]
      refute_path_exists File.join(directory, "marker"), "startContainer ran inside the container root"
    ensure
      process&.values_at(:stdout, :stderr)&.compact&.each { |io| io.close unless io.closed? }
    end
  end

  def test_a_failing_hook_keeps_the_workload_from_running
    with_rootfs do |_directory, rootfs|
      hooks = {"startContainer" => [{"path" => "/bin/busybox", "env" => [], "args" => ["busybox", "sh", "-c", "echo no-gpu; exit 7"]}]}
      process = adapter.spawn(command: ["/bin/busybox", "touch", "/ran"], rootfs: rootfs, security_plan: plan,
                              container_hooks: {"hooks" => hooks, "state" => {}, "runtime" => ->(_pid) {}})
      error = assert_raises(Linux::NativeAdapters::EffectError) { adapter.release_gate(process.fetch(:gate)) }
      assert_includes error.message, "error running startContainer hook #0: /bin/busybox: exit status 7, output: no-gpu"
      adapter.wait(pid: process.fetch(:pid), timeout: 5.0)

      refute_path_exists File.join(rootfs, "ran")

      failing_runtime = adapter.spawn(command: ["/bin/busybox", "true"], rootfs: rootfs, security_plan: plan,
                                      container_hooks: {"hooks" => {}, "state" => {}, "runtime" => lambda { |_pid|
                                        raise "createRuntime hook failed"
                                      }})
      error = assert_raises(Linux::NativeAdapters::EffectError) { adapter.release_gate(failing_runtime.fetch(:gate)) }
      assert_includes error.message, "createRuntime hook failed"
      adapter.wait(pid: failing_runtime.fetch(:pid), timeout: 5.0)
    ensure
      [process, failing_runtime].compact.each do |spawned|
        spawned.values_at(:stdout, :stderr).compact.each { |io| io.close unless io.closed? }
      end
    end
  end
end

# The whole path on the production L3 runtime: a sandbox with its own
# namespaces, the full security plan, CDI hooks from the container spec.
class OCIHooksNativeRuntimeTest < Minitest::Test
  Linux = Rubernetes::Platform::Linux

  def test_hooks_run_in_the_pod_namespaces_at_their_stages
    skip "production Native runtime requires root" unless Process.uid.zero?
    skip "static busybox is unavailable" unless File.executable?("/usr/bin/busybox")
    skip "cgroup v2 hierarchy is unavailable" unless File.writable?("/sys/fs/cgroup")

    require "rubernetes/runtime/native"
    require "securerandom"
    Dir.mktmpdir("rubernetes-native-hooks-") do |directory|
      lower = File.join(directory, "lower")
      FileUtils.mkdir_p(File.join(lower, "bin"))
      FileUtils.cp("/usr/bin/busybox", File.join(lower, "bin", "busybox"), preserve: true)
      sandbox_root = File.join(directory, "sandboxes")
      sandbox_id = "hooks-#{Process.pid}-#{SecureRandom.hex(4)}"
      log = File.join(directory, "hooks.log")
      runtime = Rubernetes::Runtime::Native.new(
        profile: :l3, l3: true,
        adapters: Linux::NativeAdapters.for_profile(profile: :l3, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup"),
        sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup", log_root: File.join(directory, "logs"),
        journal_path: File.join(directory, "journal.jsonl"),
        security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"}
      )
      image_bytes = "verified-hooks-image"
      sandbox = runtime.run_sandbox(
        {"id" => sandbox_id, "image_bytes" => image_bytes,
         "image_digest" => "sha256:#{Digest::SHA256.hexdigest(image_bytes)}", "lowerdirs" => [lower]},
        request_id: sandbox_id
      )
      pid_of = %(sed -n 's/.*"pid":\\([0-9]*\\).*/\\1/p')
      host = lambda do |stage, script|
        {"hookName" => stage, "path" => "/bin/sh", "env" => [], "args" => ["sh", "-c", "state=$(cat); #{script} >> #{log}"]}
      end
      hooks = [
        host.call("createRuntime", %(echo "createRuntime $(readlink /proc/$(echo "$state" | #{pid_of})/ns/net)")),
        host.call("createContainer", %(echo "createContainer $(readlink /proc/self/ns/net)")),
        {"hookName" => "startContainer", "path" => "/bin/busybox", "env" => [],
         "args" => ["busybox", "sh", "-c", "cat > /start.state"]},
        host.call("poststart", %(echo "poststart $(echo "$state" | #{pid_of})")),
        host.call("poststop", %(echo "poststop"))
      ]
      container = runtime.create_container(sandbox, {
                                             "id" => "main", "rootfs_path" => lower, "cdi_hooks" => hooks,
                                             "command" => ["/bin/busybox", "sh", "-c", "cat /start.state; echo; readlink /proc/self/ns/net; sleep 30"]
                                           })
      runtime.start_container(container)
      output = Timeout.timeout(5) do
        text = +""
        text << runtime.logs(container).to_s until text.lines.length >= 2 || (sleep(0.1) && false)
        text
      end
      state_line, workload_netns = output.lines(chomp: true)

      assert_equal "created", JSON.parse(state_line)["status"]
      lines = File.readlines(log, chomp: true)

      assert_equal ["createRuntime #{workload_netns}", "createContainer #{workload_netns}"], lines.first(2)
      refute_equal File.readlink("/proc/self/ns/net"), workload_netns, "the Pod has its own network namespace"
      assert_match(/\Apoststart \d+\z/, lines[2])

      runtime.stop_sandbox(sandbox, timeout: 2)
      runtime.remove_sandbox(sandbox)

      assert_equal "poststop", File.readlines(log, chomp: true).last
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
