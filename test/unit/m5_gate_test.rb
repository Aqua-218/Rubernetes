# frozen_string_literal: true

require "json"
require "fileutils"
require "tmpdir"
require "time"
require "digest"
require_relative "../test_helper"
require_relative "../../tools/milestones/m5_gate"

class M5GateTest < Minitest::Test
  def base_manifest(status: "COMPLETE")
    now = Time.now.utc.iso8601
    {"schema_version" => 3, "milestone" => "M5", "status" => status, "input_sha256" => "0" * 64, "input_file_count" => 1,
     "input_stable" => true, "host" => {"architecture" => "x86_64", "kernel" => "test", "ruby" => RUBY_DESCRIPTION},
     "started_at" => now, "finished_at" => now,
     "input_capture" => {"stable" => true, "start" => {"sha256" => "0" * 64, "file_count" => 1}, "finish" => {"sha256" => "0" * 64, "file_count" => 1}},
     "git_metadata_capture" => {"stable" => true, "start_paths" => [], "finish_paths" => [], "count" => 0},
     "commands" => [{"name" => "fixture", "command" => ["fixture"], "started_at" => now, "finished_at" => now, "exit_status" => 0}],
     "artifacts" => [], "subjects" => [],
     "result_counts" => {"commands" => 1, "command_failures" => 0, "artifacts" => 0, "subjects" => 0, "reports" => 6, "source_files" => 1}}
  end

  def test_missing_manifest_fails_closed
    result = M5Gate.evaluate(File.join(Dir.tmpdir, "rubernetes-m5-missing-#{Process.pid}.json"))
    refute result.fetch("passed")
    assert_operator result.fetch("error_count"), :>, 0
  end

  def test_m5_requires_the_complete_m4_chain_and_every_report
    Dir.mktmpdir("rubernetes-m5-gate") do |directory|
      path = File.join(directory, "manifest.json")
      File.write(path, JSON.generate(base_manifest))
      result = M5Gate.evaluate(path)
      refute result.fetch("passed")
      errors = result.fetch("errors")
      assert errors.any? { |error| error.include?("M4") }
      M5Gate::REPORTS.each_value do |specification|
        assert errors.any? { |error| error.include?(specification.fetch(:names).first) }, specification.inspect
      end
    end
  end

  def test_non_x86_64_host_is_rejected
    Dir.mktmpdir("rubernetes-m5-gate") do |directory|
      path = File.join(directory, "manifest.json")
      manifest = base_manifest
      manifest["host"]["architecture"] = "aarch64"
      File.write(path, JSON.generate(manifest))
      assert M5Gate.evaluate(path).fetch("errors").any? { |error| error.include?("x86_64") }
    end
  end

  def report(kind, cases, extra = {})
    {"schema_version" => 1, "milestone" => "M5", "kind" => kind, "input_sha256" => "0" * 64, "input_file_count" => 1,
     "available" => true, "status" => "COMPLETE", "passed" => true, "cases" => cases, "case_count" => cases.length,
     "passed_count" => cases.count { |c| c["passed"] }, "failed_count" => cases.count { |c| !c["passed"] }}.merge(extra)
  end

  def test_fault_matrix_rejects_lost_writes_and_non_process_provenance
    errors = []
    cases = [
      {"id" => "3_nodes_1_failures", "passed" => true, "measurement_source" => "simulation", "acknowledged_writes" => 120, "lost_acknowledged_writes" => 1, "rto_seconds" => 0.5, "replica_state_identical" => true},
      {"id" => "5_nodes_2_failures", "passed" => true, "measurement_source" => "real_processes_sigkill", "acknowledged_writes" => 120, "lost_acknowledged_writes" => 0, "rto_seconds" => 61, "replica_state_identical" => true},
      {"id" => "membership_change_leader_loss", "passed" => true, "measurement_source" => "real_processes_sigkill", "split_brain" => true},
      {"id" => "snapshot_install_leader_loss", "passed" => true, "measurement_source" => "real_processes_sigkill", "snapshot_installs_on_new_node" => 0}
    ]
    M5Gate.send(:validate_report, "fault_matrix", report("m5_fault_matrix", cases), "m5_fault_matrix", {"input_sha256" => "0" * 64, "input_file_count" => 1}, errors)
    %w[real\ processes lost\ acknowledged exceeded split\ brain real\ snapshot\ install].each do |fragment|
      assert errors.any? { |error| error.include?(fragment) }, "#{fragment}: #{errors.inspect}"
    end
  end

  def test_corruption_corpus_requires_fail_closed_and_real_tmpfs
    errors = []
    cases = M5Gate::CORRUPTION_REQUIRED.map { |id| {"id" => id, "passed" => true, "fail_closed" => id != "wal_torn_tail", "error" => "X"} }
    cases.find { |c| c["id"] == "wal_disk_full_tmpfs" }.merge!("measurement_level" => "L1", "durable_entries_after_reopen" => 3, "acknowledged_entries" => 4)
    M5Gate.send(:validate_report, "corruption", report("m5_corruption_corpus", cases), "m5_corruption_corpus", {"input_sha256" => "0" * 64, "input_file_count" => 1}, errors)
    assert errors.any? { |error| error.include?("wal_torn_tail did not fail closed") }, errors.inspect
    assert errors.any? { |error| error.include?("real size-limited tmpfs") }, errors.inspect
    assert errors.any? { |error| error.include?("lost acknowledged entries") }, errors.inspect
  end

  def test_rto_rpo_requires_zero_rpo_and_sixty_second_recovery
    errors = []
    main = {"id" => "quorum_loss_two_of_three_apiservers", "passed" => true, "measurement_source" => "real_apiserver_and_controller_manager_processes",
            "rpo_objects" => 0, "lost_acknowledged_writes" => 0, "read_resumed_seconds" => 1.0, "write_resumed_seconds" => 70.0,
            "control_loop_resumed_seconds" => 2.0, "write_during_outage" => {"acknowledged" => true}, "readyz_during_outage" => true,
            "control_loop_reconciled_before_fault" => true, "acknowledged_before_fault" => 40, "replica_object_counts" => [40, 40, 39]}
    M5Gate.send(:validate_report, "rto_rpo", report("m5_rto_rpo_report", [main]), "m5_rto_rpo_report", {"input_sha256" => "0" * 64, "input_file_count" => 1}, errors)
    %w[write_resumed_seconds acknowledged\ during\ quorum\ loss readyz same\ object\ count].each do |fragment|
      assert errors.any? { |error| error.include?(fragment) }, "#{fragment}: #{errors.inspect}"
    end
  end

  def test_ownership_requires_every_component_and_exactly_once_reexecution
    errors = []
    cases = [{"id" => "raft_store_create", "component" => "raft_store", "effect" => "create", "passed" => true,
              "request_loss_classification" => "request_loss", "response_loss_classification" => "response_loss",
              "request_loss_effect_count" => 2, "response_loss_retry_effect_count" => 0, "measurement_source" => "real_raft_cluster_tls"}]
    M5Gate.send(:validate_report, "ownership", report("m5_resource_ownership_ledger", cases, "effect_points" => []), "m5_resource_ownership_ledger", {"input_sha256" => "0" * 64, "input_file_count" => 1}, errors)
    assert errors.any? { |error| error.include?("missing component native_runtime") }, errors.inspect
    assert errors.any? { |error| error.include?("exactly once") }, errors.inspect
    assert errors.any? { |error| error.include?("enumerate its effect points") }, errors.inspect
  end

  def test_linearizability_requires_faults_oracle_and_raw_histories
    errors = []
    histories = (1..10).map do |seed|
      events = [{"type" => "invoke"}] * 11 + [{"type" => "ok"}] * 11
      {"id" => "history-#{seed}", "passed" => true, "linearizable" => true, "events" => {"invoke" => 11, "ok" => 11},
       "history" => events, "history_sha256" => M34EvidenceSupport.canonical_document_digest(events)}
    end
    cases = [{"id" => "lean_sequential_oracle", "passed" => true, "compared_operations" => 480, "mismatches" => 0},
             {"id" => "fault_coverage", "passed" => true, "faults" => {"partition" => 1}}] + histories
    M5Gate.send(:validate_report, "linearizability", report("m5_linearizability_histories", cases), "m5_linearizability_histories", {"input_sha256" => "0" * 64, "input_file_count" => 1}, errors)
    assert errors.any? { |error| error.include?("never exercised clock_jump") }, errors.inspect
    refute errors.any? { |error| error.include?("digest mismatch") }, errors.inspect
  end
end
