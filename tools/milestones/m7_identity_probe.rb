#!/usr/bin/env ruby
# frozen_string_literal: true

# M7 exit criterion 3: every snapshot clone receives a new identity.  Eight
# Pods are restored from the same base snapshot; the identity ledger and
# the guests' signed ACKs are collected and every rotated field must be
# unique across all clones and across the ledger's whole history.

require_relative "m7_probe_support"

module M7IdentityProbe
  S = M7ProbeSupport
  M = Rubernetes::Runtime::MicroVM
  CLONES = Integer(ENV.fetch("RUBERNETES_M7_IDENTITY_CLONES", "8"))
  FIELDS = %w[vm_id subject_id capability_id request_id vsock_uds_path vsock_session_key vsock_nonce entropy hostname machine_id mac_address workspace_id
              credential_id policy_digest policy_generation jail_uid guest_cid ip].freeze

  module_function

  def run
    started_at = S.now
    S.require_root!
    cases = []
    runtime, root = S.build_runtime("identity", use_base_snapshot: false)
    network = S::ProbeNetwork.new(4)
    begin
      runtime.prepare_base!(request_id: "identity-base")
      base = runtime.snapshot_pool.latest(runtime.runtime_class).id
      runtime.adapter.instance_variable_set(:@use_base_snapshot, true)
      clones = []
      CLONES.times do |index|
        pod = S.start_pod(runtime, network, "clone-#{index}")
        session = pod["session"]
        guest_view = session.acks.dig("identity.apply", "ack")
        fields = session.identity.fields.slice(*FIELDS).merge("guest_identity_digest" => guest_view["identity_digest"],
                                                              "boot_nonce" => guest_view["boot_nonce"])
        session.probe_tcp("127.0.0.1", 1, timeout: 0.2) && nil
        clones << {"index" => index, "base" => session.base&.id, "fields" => fields, "ack_vm_id" => guest_view["vm_id"]}
        errors = S.stop_pod(runtime, network, pod)
        clones.last["stop_errors"] = errors
      end
      reused = {}
      FIELDS.each do |field|
        values = clones.map { |clone| clone["fields"][field] }.compact
        duplicates = values.tally.select { |_value, count| count > 1 }.keys
        reused[field] = duplicates
      end
      cases << {"id" => "clone_identities", "clones" => CLONES, "base" => base, "records" => clones, "reused_values" => reused,
                "all_restored_from_base" => clones.all? { |clone| clone["base"] == base },
                "passed" => clones.length == CLONES && clones.all? do |clone|
                  clone["base"] == base && clone["stop_errors"].empty? && clone["ack_vm_id"] == clone["fields"]["vm_id"]
                end &&
                            reused.values.all?(&:empty?)}
      report = runtime.identity_ledger.reuse_report
      cases << {"id" => "ledger_history_reuse", "report" => report, "records" => runtime.identity_ledger.all.length,
                "passed" => report.values.sum { |entry| entry["reused"] }.zero?}
      # A replayed identity ACK from an earlier clone must not be accepted by a later one.
      pod = S.start_pod(runtime, network, "clone-verify")
      session = pod["session"]
      stale_response = {
        "ack" => clones.first["fields"].slice("vm_id").merge("kind" => "gate.open", "nonce" => "n",
                                                             "policy_digest" => clones.first["fields"]["policy_digest"]), "signature" => "0" * 64
      }
      stale_rejected = begin
        session.send(:verify_ack!, stale_response, "gate.open", "n")
        false
      rescue M::IdentityError
        true
      end
      # Policy generation and revocation epoch are re-issued: a bumped epoch invalidates the older capability.
      runtime.identity_ledger.revoke!
      revoked = begin
        runtime.broker.handle(session.vm_id, "broker.request", {"operation" => "time.now", "params" => {}})
        "allowed"
      rescue M::PolicyError => error
        "denied: #{error.message[0, 60]}"
      end
      S.stop_pod(runtime, network, pod)
      cases << {"id" => "stale_ack_and_revocation", "stale_ack_rejected" => stale_rejected, "after_revoke" => revoked,
                "passed" => stale_rejected && revoked.start_with?("denied")}
    ensure
      network.detach_all
      S.cleanup_runtime_root(root)
    end
    S.emit(S.report(
      kind: "m7_identity_ledger", measurement_level: "L4", started_at: started_at, cases: cases,
      extra: {"host" => S.host_facts, "rotated_fields" => FIELDS, "measurement_source" => "real_snapshot_restores",
              "sources" => M5ProbeSupport.source_files(%w[lib/rubernetes/runtime/microvm/identity.rb lib/rubernetes/runtime/microvm/session.rb lib/rubernetes/runtime/microvm/snapshot_pool.rb])}
    ))
  end
end

M7IdentityProbe.run if $PROGRAM_NAME == __FILE__
