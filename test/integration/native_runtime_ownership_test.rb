# frozen_string_literal: true

# Native ownership integration tests.
# Specification references: spec/node/runtime.md §5.8.3, §5.8.4, §5.8.10
# and spec/verification/testing.md §8.7 (L2/L3).  These tests exercise real
# forked workloads, pid identity, cgroup placement, and durable request replay;
# they do not use recording process or cgroup adapters.

require_relative "../test_helper"
require "rubernetes/platform/linux/native_adapters"
require "rubernetes/platform/linux/process_supervisor"
require "rubernetes/runtime/native"
require "digest"
require "securerandom"
require "tmpdir"
require "timeout"

class NativeRuntimeOwnershipTest < Minitest::Test
  Linux = Rubernetes::Platform::Linux
  NativeAdapters = Linux::NativeAdapters

  # The workload joins its leaf before running while the durable wrapper
  # stays outside its limits and has its own process identity.
  def test_actual_workload_joins_the_real_cgroup_without_its_wrapper
    cgroup = NativeAdapters::CgroupAdapter.new(root: "/sys/fs/cgroup")

    assert_predicate(cgroup, :available?)
    pod_id = "m2-owner-#{Process.pid}-#{SecureRandom.hex(4)}"
    cgroup_handle = cgroup.create(qos: "besteffort", pod_id: pod_id, container_id: "workload",
                                  identity: "cgroup:#{pod_id}:workload")
    namespace = Object.new
    security = NativeAdapters::SecurityAdapter.new
    process_adapter = NativeAdapters::ProcessGateAdapter.new(
      namespace_adapter: namespace,
      security: Linux::Security.new(adapter: security)
    )
    supervisor = Linux::ProcessSupervisor.new(
      process_adapter: process_adapter,
      pidfd_adapter: NativeAdapters::PidfdAdapter.new,
      cgroup: cgroup,
      log_directory: Dir.mktmpdir("m2-owner-logs-")
    )
    procs = cgroup.open_procs(cgroup_handle)
    handle = supervisor.spawn(command: ["/bin/sh", "-c", "cat /proc/self/cgroup; sleep 30"],
                              security_plan: unconfined_plan,
                              cgroup: cgroup_handle, cgroup_procs: procs, id: "process-#{pod_id}", oom_score_adj: 501)
    procs.close

    population_path = File.join(cgroup_handle.path, "cgroup.procs")

    assert_empty File.readlines(population_path)
    supervisor.release_gate(handle)
    observed = supervisor.handles.fetch(handle.id)

    refute_equal(observed.pid, observed.workload_pid)
    assert_operator(observed.workload_pid, :>, 0)
    members = File.readlines(population_path, chomp: true).map(&:to_i)

    assert_includes members, observed.workload_pid
    refute_includes members, observed.pid
    assert_equal "501", File.read("/proc/#{observed.workload_pid}/oom_score_adj").strip
    refute_equal "501", File.read("/proc/#{observed.pid}/oom_score_adj").strip
    expected_cgroup = "0::#{cgroup_handle.path.delete_prefix("/sys/fs/cgroup")}"
    wait_until(timeout: 1.0) { supervisor.logs(handle).include?(expected_cgroup) }

    assert_includes supervisor.logs(handle), expected_cgroup
    assert_operator(observed.workload_start_time.to_i, :>, 0)
    assert_match(/\Asha256:[0-9a-f]{64}\z/, observed.workload_executable_digest)
    assert_equal("clone3", observed.workload_creation_method)
    assert_equal(Linux::Clone3::CLONE_PIDFD,
                 observed.workload_clone_flags & Linux::Clone3::CLONE_PIDFD)
  ensure
    procs&.close unless procs&.closed?
    begin
      supervisor&.stop(handle, timeout: 1.0)
    rescue StandardError
      nil
    end
    begin
      supervisor&.close(handle)
    rescue StandardError
      nil
    end
    begin
      cgroup&.remove(cgroup_handle, force: true)
    rescue StandardError
      nil
    end
  end

  # Requirement: the PID namespace holder is owned by the agent supervisor;
  # killing the agent must not strand a PID 1 namespace.  This is a real
  # unshare/fork test, not an adapter simulation.
  def test_sigkill_of_agent_kills_the_pid_namespace_holder
    skip "PID namespace ownership test requires root" unless Process.uid.zero?
    low_level = NativeAdapters::NamespaceAdapter.new
    begin
      low_level.validate_native_capabilities!
    rescue StandardError => error
      skip "native PID namespace capability unavailable: #{error.message}"
    end
    begin
      reader, writer = IO.pipe
      orchestrator_pid = Process.fork do
        reader.close
        plan = Rubernetes::Runtime::Native::Namespace::Plan.new(
          namespaces: [:pid].freeze, shared: [].freeze, host: [].freeze,
          user_mapping: nil, hostname: nil
        )
        handle = Thread.new do
          low_level.create(plan: plan, id: "m2-holder-#{Process.pid}", identity: "namespace:m2-holder-#{Process.pid}")
        end.value
        writer.write([
          handle.pid,
          handle.creation_method == "clone3" ? 1 : 0,
          handle.clone_flags
        ].pack("Q<Q<Q<"))
        writer.flush
        sleep 60
      ensure
        writer.close unless writer.closed?
      end
      writer.close
      holder_pid, clone3_creation, clone_flags = Timeout.timeout(5) { reader.read(24).unpack("Q<Q<Q<") }
      reader.close

      assert_equal(1, clone3_creation)
      assert_equal(Linux::Clone3::CLONE_PIDFD,
                   clone_flags & Linux::Clone3::CLONE_PIDFD)
      assert_equal(Linux::Clone3::CLONE_NEWPID,
                   clone_flags & Linux::Clone3::CLONE_NEWPID)
      assert_path_exists("/proc/#{holder_pid}/ns/pid", "the holder must survive retirement of its creator thread")

      Process.kill(Signal.list.fetch("KILL"), orchestrator_pid)
      Process.wait(orchestrator_pid)
      wait_until(timeout: 3.0) { !File.exist?("/proc/#{holder_pid}") }

      refute_path_exists("/proc/#{holder_pid}", "PID namespace holder survived agent SIGKILL")
    ensure
      reader&.close unless reader&.closed?
      writer&.close unless writer&.closed?
      begin
        Process.kill(Signal.list.fetch("KILL"), orchestrator_pid) if orchestrator_pid && File.exist?("/proc/#{orchestrator_pid}")
      rescue Errno::ESRCH
        nil
      end
      begin
        Process.wait(orchestrator_pid, Process::WNOHANG) if orchestrator_pid
      rescue Errno::ECHILD
        nil
      end
      begin
        Process.kill(Signal.list.fetch("KILL"), holder_pid) if holder_pid && File.exist?("/proc/#{holder_pid}")
      rescue Errno::ESRCH
        nil
      end
    end
  end

  # Requirement: after the agent is recreated, every adopted process,
  # namespace, cgroup, and workspace is checked against its durable kernel
  # identity before the running container is exposed again.
  def test_restart_reconstructs_real_kernel_ownership_before_cleanup
    skip "native restart reconstruction requires root" unless Process.uid.zero?
    begin
      directory = Dir.mktmpdir("m2-reconstruct-")
      sandbox_root = File.join(directory, "sandboxes")
      adapters = NativeAdapters.for_profile(
        profile: :kernel_isolation, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup"
      )
      options = {
        profile: :kernel_isolation, adapters: adapters, sandbox_root: sandbox_root,
        cgroup_root: "/sys/fs/cgroup", journal_path: File.join(directory, "journal.wal"),
        log_root: File.join(directory, "logs"),
        security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"}
      }
      first = Rubernetes::Runtime::Native.new(**options)
      sandbox_id = "m2-reconstruct-#{Process.pid}-#{SecureRandom.hex(4)}"
      image_bytes = "verified-reconstruction-image"
      sandbox = first.run_sandbox(
        {"id" => sandbox_id, "image_bytes" => image_bytes,
         "image_digest" => "sha256:#{Digest::SHA256.hexdigest(image_bytes)}"},
        request_id: "reconstruct-sandbox"
      )
      container = first.create_container(
        sandbox, {"id" => "app", "command" => ["/bin/sh", "-c", "sleep 30"]},
        request_id: "reconstruct-create"
      )
      first.start_container(container, request_id: "reconstruct-start")
      observed = first.resource_inventory

      second = Rubernetes::Runtime::Native.new(**options, log_root: File.join(directory, "logs-restarted"))
      unreadable = observed.map do |resource|
        next resource unless resource["kind"] == "workspace"

        resource.merge("metadata" => resource.fetch("metadata").merge("live" => false, "unverifiable" => true))
      end
      assert_raises(Rubernetes::Runtime::RecoveryRequired) { second.recover(observer: -> { unreadable }) }
      assert_equal("running", first.container_status(container).fetch("state"))

      report = second.recover(observer: -> { observed })

      assert_empty(report.to_h.fetch("errors"))
      assert_equal(:running, second.sandbox(sandbox_id).state)
      restored = second.container_status(container)

      assert_equal("running", restored.fetch("state"))
      assert_operator(restored.fetch("process").fetch("workload_pid"), :>, 0)
      assert_match(/\Asha256:[0-9a-f]{64}\z/, restored.fetch("process").fetch("workload_executable_digest"))

      second.stop_sandbox(sandbox_id, timeout: 2)
      second.remove_sandbox(sandbox_id)

      refute(second.resource_inventory.any? { |entry| entry.fetch("id").to_s.start_with?(sandbox_id) })
    ensure
      begin
        second&.stop_sandbox(sandbox_id, timeout: 1) if second && second.sandboxes.any?
        second&.remove_sandbox(sandbox_id) if second && second.sandboxes.any?
      rescue StandardError
        nil
      end
      begin
        first&.stop_sandbox(sandbox_id, timeout: 1) if first && first.sandboxes.any?
        first&.remove_sandbox(sandbox_id) if first && first.sandboxes.any?
      rescue StandardError
        nil
      end
    end
  end

  # A container that exits between the kernel snapshot and its adoption must
  # not fail the restart: recovery observes again and treats the sandbox as
  # the dead operation it now is.
  def test_restart_survives_a_container_that_exits_after_the_snapshot
    skip "native restart reconstruction requires root" unless Process.uid.zero?
    begin
      directory = Dir.mktmpdir("m2-stale-snapshot-")
      sandbox_root = File.join(directory, "sandboxes")
      adapters = NativeAdapters.for_profile(profile: :kernel_isolation, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup")
      options = {
        profile: :kernel_isolation, adapters: adapters, sandbox_root: sandbox_root,
        cgroup_root: "/sys/fs/cgroup", journal_path: File.join(directory, "journal.wal"),
        log_root: File.join(directory, "logs"),
        security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"}
      }
      first = Rubernetes::Runtime::Native.new(**options)
      sandbox_id = "m2-stale-#{Process.pid}-#{SecureRandom.hex(4)}"
      image_bytes = "verified-stale-snapshot-image"
      sandbox = first.run_sandbox(
        {"id" => sandbox_id, "image_bytes" => image_bytes, "image_digest" => "sha256:#{Digest::SHA256.hexdigest(image_bytes)}"},
        request_id: "stale-sandbox"
      )
      container = first.create_container(sandbox, {"id" => "app", "command" => ["/bin/sh", "-c", "sleep 30"]}, request_id: "stale-create")
      first.start_container(container, request_id: "stale-start")
      stale = first.resource_inventory
      workload = first.container_status(container).fetch("process").fetch("workload_pid")
      Process.kill("KILL", workload)
      wait_until(timeout: 5) { !File.exist?("/proc/#{workload}") }

      second = Rubernetes::Runtime::Native.new(**options, log_root: File.join(directory, "logs-restarted"))
      kernel = Rubernetes::Runtime::Native::KernelObserver.new(ledger: second.ledger)
      observations = 0
      observer = lambda do
        observations += 1
        observations == 1 ? stale : kernel.list_resources
      end

      second.recover(observer: observer)

      assert_operator observations, :>=, 2, "a stale snapshot must be replaced by a fresh observation"
      refute(second.sandboxes.any? { |entry| entry.fetch("id") == sandbox_id && entry.fetch("state").to_s == "running" })
    ensure
      [second, first].each do |runtime|
        next unless runtime&.sandboxes&.any?

        runtime.stop_sandbox(sandbox_id, timeout: 1)
        runtime.remove_sandbox(sandbox_id)
      rescue StandardError
        nil
      end
    end
  end

  # Requirement: PDEATHSIG must cover the actual workload when the agent
  # wrapper is SIGKILLed, while the wrapper remains a subreaper for descendants.
  # Mutation target: removing either PDEATHSIG or subreaper setup.
  def test_sigkill_of_wrapper_kills_the_actual_workload
    adapter = NativeAdapters::ProcessGateAdapter.new(
      namespace_adapter: Object.new,
      security: Linux::Security.new(adapter: NativeAdapters::SecurityAdapter.new)
    )
    process = adapter.spawn(command: ["/bin/sh", "-c", "sleep 30"], security_plan: unconfined_plan)
    gate = process.fetch(:gate)
    adapter.release_gate(gate)
    workload_pid = gate.workload_pid

    refute_nil(workload_pid)
    refute_equal(process.fetch(:pid), workload_pid)

    Process.kill(Signal.list.fetch("KILL"), process.fetch(:pid))
    wait_until(timeout: 3.0) { !File.exist?("/proc/#{workload_pid}") }

    refute_path_exists("/proc/#{workload_pid}", "actual workload survived wrapper SIGKILL")
  ensure
    begin
      Process.kill(Signal.list.fetch("KILL"), process.fetch(:pid)) if process && File.exist?("/proc/#{process.fetch(:pid)}")
    rescue Errno::ESRCH
      nil
    end
    begin
      Process.kill(Signal.list.fetch("KILL"), workload_pid) if workload_pid && File.exist?("/proc/#{workload_pid}")
    rescue Errno::ESRCH
      nil
    end
    begin
      adapter&.wait(pid: process.fetch(:pid), timeout: 1.0) if process
    rescue StandardError
      nil
    end
  end

  def test_committed_wrapper_keeps_its_streams_and_exit_status_after_agent_sigkill
    Dir.mktmpdir("native-wrapper-handoff-") do |directory|
      marker = File.join(directory, "complete")
      reader, writer = IO.pipe
      agent = fork do
        reader.close
        # The test measures closure of the original OS descriptors.
        # rubocop:disable Style/GlobalStdStream
        STDOUT.reopen(writer)
        STDERR.reopen(writer)
        writer.close
        supervisor = handoff_supervisor(directory)
        workload = supervisor.spawn(id: "handoff", durable: true, security_plan: unconfined_plan,
                                    command: ["/bin/sh", "-c", 'echo before; while [ ! -e "$1" ]; do sleep 0.02; done; echo after; exit 37', "sh", marker])
        running = supervisor.release_gate(workload)
        exit!(1) unless supervisor.commit(running)

        STDOUT.puts(JSON.generate(running.to_h))
        STDOUT.flush
        # rubocop:enable Style/GlobalStdStream
        Process.kill("KILL", Process.pid)
      end
      writer.close
      payload = Timeout.timeout(5) { reader.read }
      _, status = Process.waitpid2(agent)

      assert_equal Signal.list.fetch("KILL"), status.termsig
      identity = JSON.parse(payload)
      restored = handoff_supervisor(directory)
      handle = restored.adopt(metadata: identity)

      assert_equal identity.fetch("workload_pid"), handle.workload_pid
      File.write(marker, "complete")

      assert_equal 37, restored.wait(handle, timeout: 5).exit_status
      assert_equal "before\nafter\n", restored.logs(handle)
    ensure
      File.write(marker, "complete") if marker
      reader&.close
      writer&.close unless writer&.closed?
      restored&.close(handle) if handle
      Process.waitpid(agent, Process::WNOHANG) if agent && !status
    end
  end

  def test_restart_retires_verified_mounted_workspaces_left_by_a_dead_sandbox
    skip "native restart reconstruction requires root" unless Process.uid.zero?

    with_retired_namespace do |sandbox, container, options|
      fresh = Rubernetes::Runtime::Native.new(**options)
      observer = Rubernetes::Runtime::Native::KernelObserver.new(ledger: fresh.ledger)
      holder = sandbox.namespace.adapter_handle
      initial = observer.list_resources

      assert_equal %w[namespace workspace workspace], initial.map { |entry| entry["kind"] }.sort
      assert(initial.all? { |entry| entry.dig("metadata", "live") == true })

      mismatched = initial.map { |entry| entry["kind"] == "namespace" ? entry.merge("identity" => "wrong") : entry }
      report = fresh.recover(observer: -> { mismatched }).to_h

      refute_empty report.fetch("identity_mismatch")
      assert_nil IO.for_fd(holder.pidfd, autoclose: false).wait_readable(0)

      assert_empty fresh.recover(observer: observer).to_h.fetch("errors")
      assert_equal "Stopped", fresh.ledger.operation(sandbox.id).state
      assert_empty fresh.ledger.resources(owner: sandbox.identity)
      assert IO.for_fd(holder.pidfd, autoclose: false).wait_readable(2)
      refute_path_exists sandbox.workspace.root
      refute_path_exists container.workspace.root
    end
  end

  # Requirement: create/start/stop/remove request IDs are durable and replay
  # without repeating effects, including a retry after the remove response.
  # Mutation target: deleting request WAL records or replaying a completed op.
  def test_container_requests_are_durable_and_idempotent
    Dir.mktmpdir("m2-owner-journal-") do |directory|
      path = File.join(directory, "runtime.wal")
      first = Rubernetes::Runtime::Native.new(
        profile: :pure,
        journal: Rubernetes::Runtime::Native::RollbackJournal.new(path)
      )
      sandbox = first.run_sandbox({"id" => "owner-sandbox", "request_id" => "owner-sandbox-request"})
      container = first.create_container(sandbox, {"id" => "app", "command" => ["/bin/true"]}, request_id: "owner-create")
      duplicate = first.create_container(sandbox, {"id" => "app", "command" => ["/bin/true"]}, request_id: "owner-create")

      assert_equal(container.id, duplicate.id)

      first.start_container(container, request_id: "owner-start")
      first.start_container(container, request_id: "owner-start")
      first.stop_container(container, request_id: "owner-stop")
      first.stop_container(container, request_id: "owner-stop")

      assert(first.remove_container(container, request_id: "owner-remove"))
      assert(first.remove_container(container, request_id: "owner-remove"))

      reopened = Rubernetes::Runtime::Native::RollbackJournal.new(path)
      ledger = Rubernetes::Runtime::Native::OwnershipLedger.new(journal: reopened)
      requests = ledger.requests.to_h { |record| [record.fetch("id"), record] }

      %w[owner-create owner-start owner-stop owner-remove].each do |request_id|
        assert_equal("Completed", requests.fetch(request_id).fetch("state"))
      end
    end
  end

  # Regression: a post-effect proof refresh may update metadata, but it must
  # never turn into a second owner or permit an identity/owner swap.
  def test_ledger_metadata_refresh_preserves_same_owner_and_identity
    Dir.mktmpdir("m2-owner-refresh-") do |directory|
      journal_path = File.join(directory, "ownership.wal")
      ledger = Rubernetes::Runtime::Native::OwnershipLedger.new(
        journal: Rubernetes::Runtime::Native::RollbackJournal.new(journal_path)
      )
      operation = ledger.begin_operation(
        operation_id: "metadata-refresh", owner: "sandbox:metadata-refresh:#{"a" * 16}",
        config_digest: "config", request_id: "metadata-refresh-request"
      )
      ledger.claim(operation_id: operation.id, kind: "workspace", id: "metadata-refresh",
                   identity: "workspace:metadata-refresh", metadata: {"mounted" => false})
      refreshed = ledger.claim(operation_id: operation.id, kind: "workspace", id: "metadata-refresh",
                               identity: "workspace:metadata-refresh", metadata: {"mounted" => true, "mount_id" => 41})

      assert_equal(true, refreshed.metadata.fetch("mounted"))
      assert_equal(41, refreshed.metadata.fetch("mount_id"))

      replayed = Rubernetes::Runtime::Native::OwnershipLedger.new(
        journal: Rubernetes::Runtime::Native::RollbackJournal.new(journal_path)
      )
      replayed_resource = replayed.resources.fetch(0)
      replayed_metadata = replayed_resource.fetch(:metadata)

      assert_equal(true, replayed_metadata.fetch("mounted"))
      assert_equal(41, replayed_metadata.fetch("mount_id"))

      error = assert_raises(StandardError) do
        ledger.claim(operation_id: operation.id, kind: "workspace", id: "metadata-refresh",
                     identity: "workspace:reused", metadata: {})
      end
      assert_equal("Rubernetes::Runtime::OwnershipConflict", error.class.name)
      other = ledger.begin_operation(
        operation_id: "other-operation", owner: "sandbox:other:#{"b" * 16}",
        config_digest: "config", request_id: "other-request"
      )
      error = assert_raises(StandardError) do
        ledger.claim(operation_id: other.id, kind: "workspace", id: "metadata-refresh",
                     identity: "workspace:metadata-refresh", metadata: {})
      end
      assert_equal("Rubernetes::Runtime::OwnershipConflict", error.class.name)
    end
  end

  private

  def with_retired_namespace
    Dir.mktmpdir("native-retired-namespace-") do |directory|
      sandbox_root = File.join(directory, "sandboxes")
      options = {profile: :kernel_isolation, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup",
                 journal_path: File.join(directory, "journal.wal"), log_root: File.join(directory, "logs"),
                 security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"}}
      adapters = NativeAdapters.for_profile(profile: :kernel_isolation, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup")
      runtime = Rubernetes::Runtime::Native.new(**options, adapters: adapters)
      bytes = "retired-namespace-image"
      sandbox_id = "native-retired-#{SecureRandom.hex(6)}"
      sandbox_id = runtime.run_sandbox({"id" => sandbox_id, "image_bytes" => bytes, "image_digest" => "sha256:#{Digest::SHA256.hexdigest(bytes)}"})
      sandbox = runtime.sandbox(sandbox_id)
      lowerdir = File.join(directory, "rootfs")
      Dir.mkdir(lowerdir)
      container = runtime.create_container(sandbox, {"id" => "app", "rootfs_path" => lowerdir})
      adapters.fetch(:cgroup_adapter).remove(container.cgroup, force: true)
      adapters.fetch(:cgroup_adapter).remove(sandbox.cgroup, force: true)
      runtime.ledger.resources(owner: sandbox.identity).select { |entry| entry[:kind] == "cgroup" }.each do |entry|
        runtime.ledger.release(operation_id: sandbox.id, kind: "cgroup", id: entry[:id], identity: entry[:identity], force: true)
      end
      runtime.ledger.transition(operation_id: sandbox.id, to: "StateUnknown")
      fresh_adapters = NativeAdapters.for_profile(profile: :kernel_isolation, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup")
      yield sandbox, container, options.merge(adapters: fresh_adapters)
    ensure
      adapters&.fetch(:namespace_adapter)&.destroy(handle: sandbox.namespace.adapter_handle, id: sandbox.id, identity: sandbox.namespace.identity) if sandbox
    end
  end

  def handoff_supervisor(directory)
    adapter = NativeAdapters::ProcessGateAdapter.new(namespace_adapter: Object.new,
                                                     security: Linux::Security.new(adapter: NativeAdapters::SecurityAdapter.new))
    Linux::ProcessSupervisor.new(process_adapter: adapter, pidfd_adapter: NativeAdapters::PidfdAdapter.new, log_directory: directory)
  end

  def unconfined_plan
    context = Linux::Security::Context.from("seccomp" => "Unconfined")
    probe = Linux::Security::Probe.new(
      architecture: Linux::ABIManifest.current_architecture,
      capabilities: {}, no_new_privs: true, seccomp: true, landlock: true, details: {}
    )
    Linux::Security::Plan.new(context: context, steps: [].freeze, seccomp_program: nil, probe: probe)
  end

  def wait_until(timeout:)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep 0.01
    end
  end
end
