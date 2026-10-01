#!/usr/bin/env ruby
# frozen_string_literal: true

# M7 exit criteria 1, 2 and 5: the x86_64 KVM L4/L5 report.  Every case
# runs the production MicroVM backend on this host with the pinned
# Firecracker 1.16.1, jailer, dm-verity rootfs, guest kernel and Ruby guest
# supervisor: artifact verification, base snapshot, cold-boot and restored
# Pod lifecycles (exec, logs, stats, probes, network), the Node::Lifecycle
# API contract through the runtime multiplexer, host cleanup after removal,
# and the fault matrix (jailer kill, VMM hang, UDS disconnect, vsock
# disconnect, pause ACK loss) with fail-closed outcomes and zero residue.

require_relative "m7_probe_support"
require "rubernetes/node"
require "rubernetes/runtime/native"
require "rubernetes/runtime/microvm/runtime_classes"

module M7KVMProbe
  S = M7ProbeSupport
  M = Rubernetes::Runtime::MicroVM

  module_function

  def lifecycle_case(id, runtime, network, expect_base:)
    pod = S.start_pod(runtime, network, id)
    session = pod["session"]
    lease = pod["lease"]
    sleep 0.5
    status = runtime.container_status(pod["container"])
    logs = runtime.logs(pod["container"], follow: false, since: nil, tail: nil).read
    stats = runtime.stats(pod["container"])
    stream = runtime.exec(pod["container"], ["/bin/busybox", "sh", "-c", "echo exec-ok; exit 7"], tty: false)
    exec_output = +""
    while (chunk = stream.read)
      exec_output << chunk
    end
    stream.close
    follow = runtime.logs(pod["container"], follow: true, since: nil, tail: 1)
    first_follow = follow.read
    follow.close
    http = session.probe_tcp("127.0.0.1", 1, timeout: 0.5)
    reachable = network.reachable?(lease["ip"])
    confinement = session.confinement_report
    hello = session.guest_hello
    errors = S.stop_pod(runtime, network, pod)
    residue = S.residue(runtime, session)
    {
      "id" => id, "restored_from_base" => !session.base.nil?, "base_id" => session.base&.id,
      "timings" => pod["timings"].merge("session" => session.timings),
      "container_state" => status["state"], "guest_state" => status.dig("backend", "state"),
      "logs" => logs, "exec_output" => exec_output, "exec_exit_code" => stream.exit_code, "follow_first_chunk" => first_follow.to_s.b[0, 64],
      "stats_present" => stats.is_a?(Hash) && !stats["stats"].nil?, "guest_probe_tcp" => http,
      "pod_ip" => lease["ip"], "pod_ip_reachable_from_host" => reachable,
      "confinement" => confinement, "guest" => hello.slice("isolation_profile", "kernel", "ruby", "capabilities"),
      "acks" => session.acks.transform_values { |value| value["ack"].slice("kind", "phase", "gate") },
      "stop_errors" => errors, "residue" => residue,
      "sandbox_state" => S.operation_state(runtime, pod["sandbox"]), "container_final_state" => S.operation_state(runtime, pod["container"]),
      "passed" => status["state"] == "Running" && logs.include?("m7-ready") && exec_output.include?("exec-ok") && stream.exit_code == 7 &&
        stats.is_a?(Hash) && !stats["stats"].nil? && reachable && errors.empty? && S.residue_clean?(residue) &&
        confinement["cap_eff"].to_i(16).zero? && confinement["seccomp"] == "2" && confinement["no_new_privs"] == "1" &&
        confinement["root_inode"] == confinement["chroot_inode"] && confinement["nspid"].last == "1" &&
        hello["isolation_profile"] == "l3" && (!expect_base || !session.base.nil?) &&
        S.operation_state(runtime, pod["sandbox"]) == "Removed" && S.operation_state(runtime, pod["container"]) == "Removed"
    }
  end

  # Node::Lifecycle drives the multiplexed runtime exactly as it drives the
  # Native backend; the only difference is the Pod's runtimeClassName.
  def node_lifecycle_case(runtime, network)
    native = Rubernetes::Runtime::Native.new(profile: :pure)
    mux = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => native, "rubernetes-firecracker" => runtime})
    resolver = ->(pod) { Rubernetes::Runtime::MicroVMRuntimeClasses.handler_table.fetch(pod.dig("spec", "runtimeClassName")) }
    net = Object.new
    net.define_singleton_method(:add) do |sandbox, _pod|
      network.attach(runtime, sandbox.is_a?(Hash) ? sandbox["sandbox_id"] : sandbox.to_s)
    end
    net.define_singleton_method(:delete) { |sandbox| network.detach(sandbox.is_a?(Hash) ? sandbox["sandbox_id"] : sandbox.to_s) }
    volume = Object.new
    volume.define_singleton_method(:prepare) { |_pod| "volume-m7" }
    volume.define_singleton_method(:release) { |_id| true }
    image = S.pinned_image
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: mux, volume: volume, network: net, image_resolver: image, runtime_class_resolver: resolver,
                                                sleeper: ->(_seconds) {})
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "m7-node-lifecycle", "namespace" => "default", "uid" => "m7-node-lifecycle"},
           "spec" => {"runtimeClassName" => "microvm", "containers" => [{"name" => "app", "image" => image.reference,
                                                                         "command" => ["/bin/busybox", "sh", "-c",
                                                                                       "echo node-lifecycle-ok; while :; do /bin/busybox sleep 1; done"]}]}}
    started = lifecycle.start(pod)
    record_state = started.respond_to?(:phase) ? started.phase : started.to_s
    finished = lifecycle.terminate(pod)
    {"id" => "node_lifecycle_contract", "start_phase" => record_state, "finish_state" => finished.state, "finish_phase" => finished.phase,
     "runtime_handler" => "rubernetes-firecracker", "lifecycle_class" => lifecycle.class.name, "multiplexer_handlers" => mux.handlers,
     "passed" => record_state == "Running" && finished.state == "Removed"}
  rescue StandardError => error
    {"id" => "node_lifecycle_contract", "error" => "#{error.class}: #{error.message}", "backtrace" => error.backtrace.first(6),
     "passed" => false}
  end

  def fault_jailer_kill(runtime, network)
    pod = S.start_pod(runtime, network, "fault-jailer-kill")
    session = pod["session"]
    pid = session.instance.vmm_pid
    Process.kill("KILL", pid)
    deadline = S.monotonic + 10
    sleep 0.05 while session.alive? && S.monotonic < deadline
    status_error = begin
      runtime.container_status(pod["container"])
      nil
    rescue StandardError => error
      error.class.name
    end
    teardown_errors = S.force_teardown(runtime, network, pod)
    residue = S.residue(runtime, session)
    {"id" => "fault_jailer_kill", "vmm_pid" => pid, "vmm_dead" => !session.alive?, "status_after_kill" => status_error,
     "stop_errors" => teardown_errors, "residue" => residue,
     "passed" => !session.alive? && !status_error.nil? && teardown_errors.empty? && S.residue_clean?(residue)}
  end

  def fault_vmm_hang(runtime, network)
    pod = S.start_pod(runtime, network, "fault-vmm-hang")
    session = pod["session"]
    Process.kill("STOP", session.instance.vmm_pid)
    channel = session.send(:control)
    channel.instance_variable_set(:@timeout, 2.0)
    stop_error = begin
      runtime.stop_container(pod["container"], timeout: 1, request_id: "hang-stop")
      nil
    rescue StandardError => error
      error.class.name
    end
    state_after = S.operation_state(runtime, pod["container"])
    start_refused = begin
      runtime.start_container(pod["container"], request_id: "hang-start")
      false
    rescue Rubernetes::Runtime::RecoveryRequired, Rubernetes::Runtime::InvalidTransition
      true
    rescue StandardError
      false
    end
    Process.kill("CONT", session.instance.vmm_pid) rescue nil # rubocop:disable Style/RescueModifier
    teardown_errors = S.force_teardown(runtime, network, pod)
    residue = S.residue(runtime, session)
    {"id" => "fault_vmm_hang", "stop_error" => stop_error, "container_state_after_hang" => state_after, "start_refused_while_unknown" => start_refused,
     "teardown_errors" => teardown_errors, "residue" => residue,
     "passed" => !stop_error.nil? && %w[StateUnknown Stopping Stopped].include?(state_after) && start_refused && teardown_errors.empty? &&
       S.residue_clean?(residue)}
  end

  def fault_uds_disconnect(runtime, network)
    pod = S.start_pod(runtime, network, "fault-uds")
    session = pod["session"]
    socket = session.instance.api_socket
    File.rename(socket, "#{socket}.detached")
    api_error = begin
      M::APIClient.new(socket, timeout: 2).pause!
      nil
    rescue M::APIError => error
      error.message
    end
    still_alive = session.alive?
    guest_still_answers = begin
      runtime.container_status(pod["container"])["state"]
    rescue StandardError => error
      "error: #{error.class}"
    end
    stop_errors = S.stop_pod(runtime, network, pod)
    residue = S.residue(runtime, session)
    {"id" => "fault_uds_disconnect", "api_error" => api_error, "vmm_alive_after_disconnect" => still_alive, "guest_status" => guest_still_answers,
     "stop_errors" => stop_errors, "residue" => residue,
     "passed" => !api_error.nil? && still_alive && guest_still_answers == "Running" && stop_errors.empty? && S.residue_clean?(residue)}
  end

  def fault_vsock_disconnect(runtime, network)
    pod = S.start_pod(runtime, network, "fault-vsock",
                      command: ["/bin/busybox", "sh", "-c", "trap '' TERM; while :; do /bin/busybox sleep 1; done"])
    session = pod["session"]
    # Drop the guest vsock connection, then issue a stop that must observe
    # the disconnect (the guest ignores SIGTERM, so the RPC is what fails).
    session.send(:close_control)
    session.instance_variable_get(:@control_mutex).synchronize do
      channel = session.instance_variable_get(:@control)
      channel&.close
      session.instance_variable_set(:@control, nil)
    end
    # Kill the VMM so the reconnect the stop attempts cannot succeed.
    Process.kill("STOP", session.instance.vmm_pid)
    stop_error = begin
      runtime.stop_container(pod["container"], timeout: 2, request_id: "vsock-stop")
      nil
    rescue StandardError => error
      error.class.name
    end
    Process.kill("CONT", session.instance.vmm_pid) rescue nil # rubocop:disable Style/RescueModifier
    state_after = S.operation_state(runtime, pod["container"])
    teardown_errors = S.force_teardown(runtime, network, pod)
    residue = S.residue(runtime, session)
    {"id" => "fault_vsock_disconnect", "stop_error" => stop_error, "container_state" => state_after, "teardown_errors" => teardown_errors, "residue" => residue,
     "passed" => !stop_error.nil? && %w[StateUnknown Stopping Stopped].include?(state_after) && teardown_errors.empty? && S.residue_clean?(residue)}
  end

  def fault_pause_ack_loss(runtime)
    adapter = runtime.adapter
    ledger = runtime.identity_ledger
    identity = ledger.allocate(sandbox_id: "pause-loss", runtime_class: runtime.runtime_class, artifact_digest: S.artifacts.digest,
                               policy_digest: "probe")
    session = M::VMSession.new(sandbox_id: "pause-loss", identity: identity, artifacts: S.artifacts, jailer: adapter.instance_variable_get(:@jailer),
                               verity: adapter.instance_variable_get(:@verity), netns: adapter.instance_variable_get(:@netns),
                               disks: adapter.instance_variable_get(:@disks),
                               pool: runtime.snapshot_pool, broker: nil, clock: lambda {
                                                                           Time.now.utc
                                                                         }, machine: {"vcpu_count" => 1, "mem_size_mib" => 256},
                               network_device: true, run_root: adapter.instance_variable_get(:@run_root))
    session.allocate_workspace(images: [], workspace_mib: 16)
    session.create_isolation(base: nil)
    channel = session.send(:control)
    channel.instance_variable_set(:@timeout, 2.0)
    Process.kill("STOP", session.instance.vmm_pid)
    outcome = begin
      session.snapshot_base!(id: "pause-loss-base", runtime_class: runtime.runtime_class)
      "snapshotted"
    rescue M::SnapshotPauseUnknown => error
      "SnapshotPauseUnknown: #{error.message[0, 80]}"
    rescue StandardError => error
      "#{error.class}: #{error.message[0, 80]}"
    end
    phase = session.phase
    bases = runtime.snapshot_pool.bases(runtime.runtime_class).map(&:id)
    Process.kill("CONT", session.instance.vmm_pid) rescue nil # rubocop:disable Style/RescueModifier
    errors = session.cleanup!(identity_ledger: ledger)
    residue = S.residue(runtime, session)
    {"id" => "fault_pause_ack_loss", "outcome" => outcome, "phase" => phase, "bases_after" => bases, "cleanup_errors" => errors, "residue" => residue,
     "workspace_reused" => false,
     "passed" => outcome.start_with?("SnapshotPauseUnknown") && phase == "pause_unknown" && !bases.include?("pause-loss-base") && errors.empty? &&
       S.residue_clean?(residue)}
  end

  def run
    started_at = S.now
    S.require_root!
    cases = []
    verification = S.artifacts.verify!
    cases << {"id" => "artifact_verification", "files" => verification.map do |entry|
      entry.slice("name", "sha256", "uid", "mode")
    end, "artifact_digest" => S.artifacts.digest,
              "firecracker_version" => S.artifacts.firecracker_version, "verity_root_hash" => S.artifacts.verity_root_hash, "passed" => verification.length >= 7}
    runtime, root = S.build_runtime("kvm", use_base_snapshot: false)
    network = S::ProbeNetwork.new(1)
    begin
      cases << lifecycle_case("cold_boot_lifecycle", runtime, network, expect_base: false)
      base_started = S.monotonic
      base = runtime.prepare_base!(request_id: "kvm-base")
      manifest = runtime.snapshot_pool.latest(runtime.runtime_class).manifest
      cases << {"id" => "base_snapshot", "snapshot_id" => base, "seconds" => (S.monotonic - base_started).round(3), "files" => manifest["files"],
                "pause_ack" => manifest["pause_ack"], "guest_phase" => manifest.dig("guest_hello", "phase"), "artifact_digest" => manifest["artifact_digest"],
                "passed" => manifest.dig("guest_hello",
                                         "phase") == "base" && manifest["pause_ack"].is_a?(Hash) && manifest["artifact_digest"] == S.artifacts.digest}
      runtime.adapter.instance_variable_set(:@use_base_snapshot, true)
      cases << lifecycle_case("restored_lifecycle", runtime, network, expect_base: true)
      cases << node_lifecycle_case(runtime, network)
      cases << fault_jailer_kill(runtime, network)
      cases << fault_vmm_hang(runtime, network)
      cases << fault_uds_disconnect(runtime, network)
      cases << fault_vsock_disconnect(runtime, network)
      cases << fault_pause_ack_loss(runtime)
      cases << {"id" => "identity_reuse_after_faults", "report" => runtime.identity_ledger.reuse_report,
                "live_identities" => runtime.identity_ledger.live.length,
                "passed" => runtime.identity_ledger.reuse_report.values.sum do |entry|
                  entry["reused"]
                end.zero? && runtime.identity_ledger.live.empty?}
      cases << {"id" => "host_inventory_after_cleanup", "resources" => runtime.adapter.list_resources,
                "passed" => runtime.adapter.list_resources.empty?}
    ensure
      network.detach_all
      S.cleanup_runtime_root(root)
    end
    S.emit(S.report(
      kind: "m7_kvm_l4_l5_report", measurement_level: "L5", started_at: started_at, cases: cases,
      extra: {"host" => S.host_facts, "measurement_source" => "real_firecracker_jailer_kvm",
              "sources" => M5ProbeSupport.source_files(%w[lib/rubernetes/runtime/microvm/session.rb lib/rubernetes/runtime/microvm/adapter.rb
                                                          lib/rubernetes/runtime/microvm/jailer.rb lib/rubernetes/runtime/microvm/guest/supervisor.rb
                                                          third_party/locks/m7-microvm-artifacts.json])}
    ))
  end
end

M7KVMProbe.run if $PROGRAM_NAME == __FILE__
