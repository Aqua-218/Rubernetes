#!/usr/bin/env ruby
# frozen_string_literal: true

# M7 exit criterion 4: the guest/host attack matrix.  A live guest attempts,
# from inside the microVM, to reach the jailer root, the host filesystem,
# another VM's vsock, an unlisted host vsock port, another tenant's
# network and its own read-only rootfs; the host verifies the VMM's
# confinement from the kernel's view, rejects spoofed and stale identity
# ACKs, and the restricted class is shown to have no network device.  Every
# attempt is a real syscall in a real guest against real host state.

require_relative "m7_probe_support"

module M7AttackProbe
  S = M7ProbeSupport
  M = Rubernetes::Runtime::MicroVM

  module_function

  def run
    started_at = S.now
    S.require_root!
    cases = []
    runtime, root = S.build_runtime("attack", use_base_snapshot: false)
    restricted, restricted_root = S.build_runtime("attack-restricted", restricted: true, use_base_snapshot: false)
    network = S::ProbeNetwork.new(2)
    other_network = S::ProbeNetwork.new(3)
    begin
      victim = S.start_pod(runtime, other_network, "attack-victim")
      attacker = S.start_pod(runtime, network, "attack-source")
      session = attacker["session"]
      victim_session = victim["session"]
      host_paths = [S::LOCK, session.instance.chroot, session.instance.api_socket,
                    File.join(S::ROOT, "lib/rubernetes/runtime/microvm/session.rb")]
      targets = {"other_cid" => victim_session.identity.fields["guest_cid"], "unlisted_port" => 9999,
                 "other_tenant_ip" => victim["lease"]["ip"], "other_tenant_port" => 80,
                 "host_ip" => network.gateway, "host_port" => 22, "host_paths" => host_paths}
      matrix = session.attack_matrix(targets)
      expected_denied = %w[rootfs_write raw_block_write jailer_root other_vm_vsock host_vsock_unlisted_port other_tenant_network
                           host_filesystem shared_host_mounts]
      denied = expected_denied.select { |key| matrix.dig(key, "outcome") == "denied" }
      cases << {"id" => "guest_attack_matrix", "targets" => targets, "matrix" => matrix, "expected_denied" => expected_denied, "denied" => denied,
                "host_filesystem" => matrix["host_filesystem"], "passed" => denied == expected_denied}
      confinement = session.confinement_report
      jail_root = session.instance.chroot
      jail_listing = Dir.glob(File.join(jail_root, "**", "*"),
                              File::FNM_DOTMATCH).select { |path| File.file?(path) || File.blockdev?(path) || File.chardev?(path) }
        .map { |path| path.delete_prefix("#{jail_root}/") }.sort
      forbidden_in_jail = jail_listing.select { |path| path.end_with?(".pem", ".key", "kubeconfig") || path.include?("secret") }
      cases << {"id" => "host_confinement", "confinement" => confinement, "jail_files" => jail_listing, "forbidden_in_jail" => forbidden_in_jail,
                "passed" => confinement["uid"] == [session.uid] && confinement["cap_eff"].to_i(16).zero? && confinement["seccomp"] == "2" &&
                            confinement["no_new_privs"] == "1" && confinement["root_inode"] == confinement["chroot_inode"] &&
                            confinement["mount_namespace"] != confinement["host_mount_namespace"] &&
                            confinement["network_namespace"] != confinement["host_network_namespace"] &&
                            confinement["nspid"].last == "1" && forbidden_in_jail.empty?}
      # Spoofed / stale ACKs from a malicious guest are rejected by the host.
      key = [session.identity.fields["vsock_session_key"]].pack("H*")
      good = session.acks["gate.open"]
      spoofed = good.merge("ack" => good["ack"].merge("vm_id" => victim_session.vm_id))
      stale = victim_session.acks["gate.open"]
      rejections = {}
      [["spoofed_vm_id", spoofed], ["stale_other_vm_ack", stale], ["wrong_nonce", good.merge("ack" => good["ack"].merge("nonce" => "0" * 32))],
       ["forged_signature", good.merge("signature" => "0" * 64)]].each do |name, response|
        rejections[name] = begin
          session.send(:verify_ack!, response, "gate.open", good["ack"]["nonce"])
          "accepted"
        rescue M::IdentityError => error
          "rejected: #{error.message[0, 60]}"
        end
      end
      cases << {"id" => "identity_ack_forgery", "rejections" => rejections, "signature_key_bytes" => key.bytesize,
                "passed" => rejections.values.all? { |value| value.start_with?("rejected") }}
      # The broker refuses unknown operations and unbound identities.
      broker = runtime.broker
      broker_results = {}
      broker_results["unknown_operation"] = begin
        broker.handle(session.vm_id, "broker.request", {"operation" => "shell.exec", "params" => {"cmd" => "id"}})
        "allowed"
      rescue M::PolicyError => error
        "denied: #{error.message[0, 60]}"
      end
      broker_results["unbound_vm"] = begin
        broker.handle("vm-unknown", "broker.request", {"operation" => "time.now", "params" => {}})
        "allowed"
      rescue M::PolicyError => error
        "denied: #{error.message[0, 60]}"
      end
      broker_results["not_permitted_operation"] = begin
        broker.handle(session.vm_id, "broker.request", {"operation" => "dns.resolve", "params" => {"name" => "example.com"}})
        "allowed"
      rescue M::PolicyError => error
        "denied: #{error.message[0, 60]}"
      end
      cases << {"id" => "broker_fail_closed", "results" => broker_results, "passed" => broker_results.values.all? do |value|
        value.start_with?("denied")
      end}
      # Restricted class: no NIC at all.
      restricted_pod = S.start_pod(restricted, nil, "attack-restricted")
      restricted_hello = restricted_pod["session"].guest_hello
      restricted_matrix = restricted_pod["session"].attack_matrix({"other_cid" => 3, "unlisted_port" => 9999})
      cases << {"id" => "restricted_no_network_device", "interfaces" => restricted_matrix["network_interfaces"], "guest" => restricted_hello.slice("isolation_profile", "phase"),
                "passed" => restricted_matrix["network_interfaces"] == ["lo"] && restricted_hello["isolation_profile"] == "l3"}
      stop_errors = S.stop_pod(restricted, nil,
                               restricted_pod) + S.stop_pod(runtime, network, attacker) + S.stop_pod(runtime, other_network, victim)
      leftovers = runtime.adapter.list_resources + restricted.adapter.list_resources
      cases << {"id" => "cleanup", "errors" => stop_errors, "resources" => leftovers,
                "live_identities" => (runtime.identity_ledger.live + restricted.identity_ledger.live).map do |record|
                  record.fields.slice("vm_id", "sandbox_id", "workspace_id")
                end,
                "passed" => stop_errors.empty? && leftovers.empty?}
    ensure
      network.detach_all
      other_network.detach_all
      S.cleanup_runtime_root(root)
      S.cleanup_runtime_root(restricted_root)
    end
    S.emit(S.report(
      kind: "m7_guest_host_attack_matrix", measurement_level: "L5", started_at: started_at, cases: cases,
      extra: {"host" => S.host_facts, "measurement_source" => "real_guest_syscalls_and_host_procfs",
              "sources" => M5ProbeSupport.source_files(%w[lib/rubernetes/runtime/microvm/guest/supervisor.rb lib/rubernetes/runtime/microvm/jailer.rb
                                                          lib/rubernetes/runtime/microvm/broker.rb lib/rubernetes/runtime/microvm/session.rb])}
    ))
  end
end

M7AttackProbe.run if $PROGRAM_NAME == __FILE__
