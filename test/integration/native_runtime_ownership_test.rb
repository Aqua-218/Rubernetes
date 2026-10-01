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

  # Requirement: the parent must observe the actual workload PID, not the
  # wrapper PID, and the workload must be in the cgroup before gate release.
  # Mutation target: removing cgroup inheritance or reporting the wrapper PID.
  def test_actual_workload_is_attached_to_the_real_cgroup_before_release
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
    handle = supervisor.spawn(command: ["/bin/sh", "-c", "sleep 30"],
                              security_plan: unconfined_plan,
                              cgroup: cgroup_handle, id: "process-#{pod_id}")

    # The wrapper is the only process that exists before the gate.  Its cgroup
    # membership is inherited by the final workload child.
    cgroup.attach(cgroup_handle, pid: handle.pid)
    supervisor.release_gate(handle)
    observed = supervisor.handles.fetch(handle.id)

    refute_equal(observed.pid, observed.workload_pid)
    assert_operator(observed.workload_pid, :>, 0)
    assert_includes(File.readlines(File.join(cgroup_handle.path, "cgroup.procs"), chomp: true).map(&:to_i), observed.workload_pid)
    assert_operator(observed.workload_start_time.to_i, :>, 0)
    assert_match(/\Asha256:[0-9a-f]{64}\z/, observed.workload_executable_digest)
    assert_equal("clone3", observed.workload_creation_method)
    assert_equal(Linux::Clone3::CLONE_PIDFD,
                 observed.workload_clone_flags & Linux::Clone3::CLONE_PIDFD)
  ensure
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
        handle = low_level.create(plan: plan, id: "m2-holder-#{Process.pid}", identity: "namespace:m2-holder-#{Process.pid}")
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

  # Requirement: after the agent is recreated, every adopted process,
  # namespace, cgroup, and workspace is checked against its durable kernel
  # identity before the running container is exposed again.
  def test_restart_reconstructs_real_kernel_ownership_before_cleanup
    skip "native restart reconstruction requires root" unless Process.uid.zero?
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
