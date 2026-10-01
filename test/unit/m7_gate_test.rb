# frozen_string_literal: true

require "digest"
require "json"
require "fileutils"
require "tmpdir"
require "time"
require_relative "../test_helper"
require_relative "../../tools/milestones/m7_gate"

class M7GateTest < Minitest::Test
  def base_manifest(status: "COMPLETE")
    now = Time.now.utc.iso8601
    {"schema_version" => 3, "milestone" => "M7", "status" => status, "input_sha256" => "0" * 64, "input_file_count" => 1,
     "input_stable" => true, "host" => {"architecture" => "x86_64", "kernel" => "test", "ruby" => RUBY_DESCRIPTION},
     "started_at" => now, "finished_at" => now,
     "input_capture" => {"stable" => true, "start" => {"sha256" => "0" * 64, "file_count" => 1}, "finish" => {"sha256" => "0" * 64, "file_count" => 1}},
     "git_metadata_capture" => {"stable" => true, "start_paths" => [], "finish_paths" => [], "count" => 0},
     "commands" => [{"name" => "fixture", "command" => ["fixture"], "started_at" => now, "finished_at" => now, "exit_status" => 0}],
     "artifacts" => [], "subjects" => [],
     "result_counts" => {"commands" => 1, "command_failures" => 0, "artifacts" => 0, "subjects" => 0, "reports" => 5, "source_files" => 1}}
  end

  def test_missing_manifest_fails_closed
    result = M7Gate.evaluate(File.join(Dir.tmpdir, "rubernetes-m7-missing-#{Process.pid}.json"))

    refute result.fetch("passed")
    assert_operator result.fetch("error_count"), :>, 0
  end

  def test_m7_requires_the_complete_m6_chain_and_every_report
    Dir.mktmpdir("rubernetes-m7-gate") do |directory|
      path = File.join(directory, "manifest.json")
      File.write(path, JSON.generate(base_manifest))
      result = M7Gate.evaluate(path)

      refute result.fetch("passed")
      errors = result.fetch("errors")

      assert(errors.any? { |error| error.include?("M6") })
      M7Gate::REPORTS.each_value do |specification|
        assert errors.any? { |error| error.include?(specification.fetch(:names).first) }, specification.inspect
      end
    end
  end

  def report(kind, cases, extra = {})
    {"schema_version" => 1, "milestone" => "M7", "kind" => kind, "input_sha256" => "0" * 64, "input_file_count" => 1,
     "available" => true, "status" => "COMPLETE", "passed" => true, "cases" => cases, "case_count" => cases.length,
     "passed_count" => cases.count { |c| c["passed"] }, "failed_count" => cases.count { |c| !c["passed"] },
     "host" => host_facts, "sources" => sources}.merge(extra)
  end

  def host_facts
    lock = JSON.parse(File.read(File.expand_path("../../third_party/locks/m7-microvm-artifacts.json", __dir__)))
    {"kernel" => "6.8", "kvm" => true, "vhost_vsock" => true, "cpu_virtualization" => "svm",
     "artifacts" => {"firecracker_version" => "1.16.1", "verity_root_hash" => lock.dig("verity", "root_hash"), "digest" => "a" * 64}}
  end

  def sources
    [{"path" => "lib/rubernetes/runtime/microvm/session.rb",
      "sha256" => Digest::SHA256.file(File.expand_path("../../lib/rubernetes/runtime/microvm/session.rb", __dir__)).hexdigest}]
  end

  def identity
    {"input_sha256" => "0" * 64, "input_file_count" => 1}
  end

  def clean_residue
    {"jail_exists" => false, "vmm_alive" => false, "netns_exists" => false, "verity_active" => false, "workspace_exists" => false, "cgroup_exists" => false,
     "identity_live" => false, "resources_listed" => []}
  end

  def confinement
    {"uid" => [200_000], "cap_eff" => "0000000000000000", "seccomp" => "2", "no_new_privs" => "1", "nspid" => %w[123 1], "root_inode" => 7, "chroot_inode" => 7,
     "mount_namespace" => "mnt:[1]", "host_mount_namespace" => "mnt:[2]", "network_namespace" => "net:[3]", "host_network_namespace" => "net:[4]"}
  end

  def kvm_cases
    lifecycle = {"passed" => true, "confinement" => confinement, "guest" => {"isolation_profile" => "l3"}, "pod_ip_reachable_from_host" => true,
                 "residue" => clean_residue, "sandbox_state" => "Removed", "container_final_state" => "Removed"}
    M7Gate::KVM_REQUIRED.map do |id|
      base = {"id" => id, "passed" => true}
      case id
      when "cold_boot_lifecycle" then base.merge(lifecycle)
      when "restored_lifecycle" then base.merge(lifecycle).merge("restored_from_base" => true)
      when "fault_vmm_hang" then base.merge("container_state_after_hang" => "StateUnknown", "start_refused_while_unknown" => true,
                                            "residue" => clean_residue)
      when "fault_pause_ack_loss" then base.merge("outcome" => "SnapshotPauseUnknown: no ack", "phase" => "pause_unknown",
                                                  "residue" => clean_residue)
      when /\Afault_/ then base.merge("residue" => clean_residue)
      when "identity_reuse_after_faults" then base.merge("report" => {"vm_id" => {"reused" => 0}})
      when "host_inventory_after_cleanup" then base.merge("resources" => [])
      when "node_lifecycle_contract" then base.merge("start_phase" => "Running", "finish_state" => "Removed",
                                                     "lifecycle_class" => "Rubernetes::Node::Lifecycle")
      else base
      end
    end
  end

  def test_kvm_report_accepts_a_complete_measurement_and_rejects_residue_and_missing_confinement
    errors = []
    M7Gate.send(:validate_report, "kvm",
                report("m7_kvm_l4_l5_report", kvm_cases, "measurement_level" => "L5", "measurement_source" => "real_firecracker_jailer_kvm"),
                "m7_kvm_l4_l5_report", identity, errors)

    assert_empty errors

    cases = kvm_cases
    cases.find { |entry| entry["id"] == "fault_jailer_kill" }["residue"]["jail_exists"] = true
    cases.find { |entry| entry["id"] == "cold_boot_lifecycle" }["confinement"]["seccomp"] = "0"
    errors = []
    M7Gate.send(:validate_report, "kvm", report("m7_kvm_l4_l5_report", cases, "measurement_level" => "L5", "measurement_source" => "real_firecracker_jailer_kvm"),
                "m7_kvm_l4_l5_report", identity, errors)

    assert errors.any? { |error| error.include?("fault_jailer_kill must leave no residue") }, errors.inspect
    assert errors.any? { |error| error.include?("seccomp") }, errors.inspect

    errors = []
    M7Gate.send(:validate_report, "kvm", report("m7_kvm_l4_l5_report", kvm_cases, "measurement_level" => "L3", "measurement_source" => "simulated"),
                "m7_kvm_l4_l5_report", identity, errors)

    assert errors.any? { |error| error.include?("L5") } && errors.any? { |error| error.include?("real Firecracker") }, errors.inspect
  end

  def test_attack_matrix_requires_every_denial
    matrix = M7Gate::ATTACK_DENIED.to_h { |key| [key, {"outcome" => "denied"}] }.merge("host_filesystem" => {"outcome" => "denied"})
    cases = [
      {"id" => "guest_attack_matrix", "passed" => true, "matrix" => matrix},
      {"id" => "host_confinement", "passed" => true, "forbidden_in_jail" => []},
      {"id" => "identity_ack_forgery", "passed" => true,
       "rejections" => {"a" => "rejected", "b" => "rejected", "c" => "rejected", "d" => "rejected"}},
      {"id" => "broker_fail_closed", "passed" => true},
      {"id" => "restricted_no_network_device", "passed" => true, "interfaces" => ["lo"]},
      {"id" => "cleanup", "passed" => true}
    ]
    errors = []
    M7Gate.send(:validate_report, "attacks", report("m7_guest_host_attack_matrix", cases, "measurement_level" => "L5"),
                "m7_guest_host_attack_matrix", identity, errors)

    assert_empty errors
    matrix["other_vm_vsock"] = {"outcome" => "allowed"}
    errors = []
    M7Gate.send(:validate_report, "attacks", report("m7_guest_host_attack_matrix", cases, "measurement_level" => "L5"),
                "m7_guest_host_attack_matrix", identity, errors)

    assert errors.any? { |error| error.include?("other_vm_vsock must be denied") }, errors.inspect
  end

  def test_identity_ledger_rejects_reuse
    records = Array.new(8) { |index| {"fields" => M7Gate::IDENTITY_FIELDS.to_h { |field| [field, "#{field}-#{index}"] }} }
    reused = M7Gate::IDENTITY_FIELDS.to_h { |field| [field, []] }
    cases = [
      {"id" => "clone_identities", "passed" => true, "clones" => 8, "records" => records, "reused_values" => reused,
       "all_restored_from_base" => true},
      {"id" => "ledger_history_reuse", "passed" => true, "report" => {"vm_id" => {"reused" => 0}}},
      {"id" => "stale_ack_and_revocation", "passed" => true, "stale_ack_rejected" => true, "after_revoke" => "denied: revoked"}
    ]
    errors = []
    M7Gate.send(:validate_report, "identity", report("m7_identity_ledger", cases, "measurement_level" => "L4"), "m7_identity_ledger",
                identity, errors)

    assert_empty errors
    records[1]["fields"]["guest_cid"] = records[0]["fields"]["guest_cid"]
    errors = []
    M7Gate.send(:validate_report, "identity", report("m7_identity_ledger", cases, "measurement_level" => "L4"), "m7_identity_ledger",
                identity, errors)

    assert errors.any? { |error| error.include?("guest_cid") }, errors.inspect
  end

  def test_snapshot_corpus_rejects_a_started_corrupt_vm
    cases = M7Gate::SNAPSHOT_REQUIRED.map do |id|
      if %w[pristine_restore restore_after_corpus].include?(id)
        {"id" => id, "passed" => true, "outcome" => "started"}
      else
        {"id" => id, "passed" => true, "outcome" => "SnapshotCorruption: digest", "vmm_processes_after" => 0, "live_identities_after" => 0,
         "resources_after" => []}
      end
    end
    errors = []
    M7Gate.send(:validate_report, "snapshots", report("m7_snapshot_corruption_corpus", cases, "measurement_level" => "L4"),
                "m7_snapshot_corruption_corpus", identity, errors)

    assert_empty errors
    cases.find { |entry| entry["id"] == "mem_bit_flip_middle" }["outcome"] = "started"
    errors = []
    M7Gate.send(:validate_report, "snapshots", report("m7_snapshot_corruption_corpus", cases, "measurement_level" => "L4"),
                "m7_snapshot_corruption_corpus", identity, errors)

    assert errors.any? { |error| error.include?("mem_bit_flip_middle started a VM") }, errors.inspect
  end

  def test_latency_bound_is_enforced_against_raw_samples
    samples = Array.new(20) { |index| {"index" => index, "total" => 0.9 + (index * 0.01), "base" => "base-1"} }
    totals = samples.map { |sample| sample["total"] }.sort
    p95 = totals[((totals.length - 1) * 0.95).round]
    entry = {"id" => "pod_start_from_base_snapshot", "passed" => true, "samples" => 20, "raw_samples" => samples, "p95_seconds" => p95,
             "bound_seconds" => 1.5}
    errors = []
    M7Gate.send(:validate_report, "latency", report("m7_startup_latency_samples", [entry], "measurement_level" => "L4"),
                "m7_startup_latency_samples", identity, errors)

    assert_empty errors
    slow = samples.map { |sample| sample.merge("total" => sample["total"] + 1.0) }
    slow_totals = slow.map { |sample| sample["total"] }.sort
    entry = entry.merge("raw_samples" => slow, "p95_seconds" => slow_totals[((slow_totals.length - 1) * 0.95).round])
    errors = []
    M7Gate.send(:validate_report, "latency", report("m7_startup_latency_samples", [entry], "measurement_level" => "L4"),
                "m7_startup_latency_samples", identity, errors)

    assert errors.any? { |error| error.include?("exceeds 1.5s") }, errors.inspect
    entry = entry.merge("p95_seconds" => 0.1)
    errors = []
    M7Gate.send(:validate_report, "latency", report("m7_startup_latency_samples", [entry], "measurement_level" => "L4"),
                "m7_startup_latency_samples", identity, errors)

    assert errors.any? { |error| error.include?("must match the raw samples") }, errors.inspect
  end

  def test_host_binding_requires_kvm_and_the_pinned_artifacts
    document = report("m7_identity_ledger", [{"id" => "x", "passed" => true}], "measurement_level" => "L4")
    document["host"]["kvm"] = false
    document["host"]["artifacts"]["verity_root_hash"] = "b" * 64
    errors = []
    M7Gate.send(:validate_host, "identity", document, errors)

    assert errors.any? { |error| error.include?("KVM host") }, errors.inspect
    assert errors.any? { |error| error.include?("verity root hash") }, errors.inspect
  end
end
