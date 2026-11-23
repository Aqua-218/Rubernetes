# frozen_string_literal: true

require "cgi"
require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/milestones/m8_integrity_probe"

class K7EvidenceTest < Minitest::Test
  Evidence = Conformance::K7Evidence
  Contract = Conformance::K7Contract
  START = Time.utc(2026, 11, 20, 0, 0, 0)

  def test_complete_labels_cannot_hide_two_unperformed_stages
    stages = Contract::STAGE_IDS.map { |id| complete_stage(id) }
    stages[2].merge!("status" => "INCOMPLETE", "passed" => false, "exit_status" => 2)
    stages[3].merge!("status" => "INCOMPLETE", "passed" => false, "exit_status" => 2)
    report = {"stages" => stages}
    verdict = Evidence.verify(report, {"exit_status" => 0}, directory: "/unused")

    refute verdict.fetch("passed")
    assert_equal 7, verdict.fetch("completed_stages")
    assert_includes verdict.fetch("detail"), "release_upgrade, rollback"

    lane = report.merge("lane" => "K7", "status" => "INCOMPLETE", "passed" => false)
    outcome = M8IntegrityProbe.k7_outcome([{"runId" => "unit", "lanes" => [lane]}])

    assert_equal [false, 7, 9], outcome.values_at("passed", "completed_stages", "expected_stages")
  end

  def test_complete_label_with_obsolete_inventory_is_rejected
    report = complete_report
    report["state_inventory_sha256"] = "0" * 64
    verdict = Evidence.verify(report, {}, directory: "/unused")

    refute verdict.fetch("passed")
    assert_includes verdict.fetch("detail"), "current API state inventory"
  end

  def test_archive_rechecks_stage_originals_and_hashes_instead_of_trusting_the_lane
    Dir.mktmpdir do |run|
      directory = File.join(run, "k7")
      report, execution, manifest, lane = write_unit_fixtures(run, directory)

      assert Evidence.verify(report, execution, directory: directory).fetch("passed")
      assert Evidence.archived(manifest, lane, root: run).fetch("passed")

      File.write(File.join(directory, "backup_restore", "k1-smoke.xml"), "tampered")
      verdict = Evidence.archived(manifest, lane, root: run)

      refute verdict.fetch("passed")
      assert_includes verdict.fetch("detail"), "backup_restore/k1-smoke.xml"
    end
  end

  def test_a_failing_k5_original_is_rejected_even_if_the_digest_is_correct
    Dir.mktmpdir do |run|
      directory = File.join(run, "k7")
      report, execution = write_unit_fixtures(run, directory)
      file = File.join(directory, "backup_restore", "differential.json")
      altered = JSON.parse(File.read(file))
      altered.fetch("cases").last["matches"] = false
      report.fetch("stages").last.fetch("checks").fetch("k5_differential")["report_sha256"] = write_json(file, altered)
      verdict = Evidence.verify(report, execution, directory: directory)

      refute verdict.fetch("passed")
      assert_includes verdict.fetch("detail"), "did not record matching expected responses"
    end
  end

  def test_k5_response_uses_canonical_json_and_the_recorded_cbor_mode
    report = differential_report("readback", START)
    verifier = Conformance::K5Evidence

    assert verifier.verify(report, cbor_enabled: false).fetch("passed")
    refute verifier.verify(report, cbor_enabled: true).fetch("passed")

    first = report.fetch("cases").first
    first["rubernetes_sha256"] = Digest::SHA256.hexdigest(JSON.generate(first.fetch("rubernetes")))
    verdict = verifier.verify(report, cbor_enabled: false)

    refute verdict.fetch("passed")
    assert_includes verdict.fetch("detail"), "invalid normalized response digest"
  end

  private

  def complete_stage(id)
    {"id" => id, "status" => "COMPLETE", "passed" => true, "operation_passed" => true, "exit_status" => 0, "data_loss" => [], "stuck_operations" => []}
  end

  def operation_evidence
    digest_names = {"rubernetes-apiserver" => "a" * 64}
    target_digests = {"rubernetes-apiserver" => "b" * 64}
    transition = {"from_version" => "0.1.0", "to_version" => "1.0.0", "from_binaries" => digest_names, "to_binaries" => target_digests,
                  "checkpoint_uid" => "unit-checkpoint", "checkpoint_revision" => "20"}
    voters = %w[control-0 control-1 control-2]
    leadership = {"lease" => "lease", "holder_before" => "old", "holder_after" => "new"}
    {
      "memory_to_raft" => {"from" => "memory", "to" => "raft", "raft_voters" => voters.take(1), "seed_revision" => 1, "memory_snapshot_round_trip" => true},
      "single_to_three_node" => {"from_voters" => voters.take(1), "to_voters" => voters, "checked_replicas" => voters},
      "release_upgrade" => transition,
      "rollback" => transition.merge("from_version" => "1.0.0", "to_version" => "0.1.0", "from_binaries" => target_digests, "to_binaries" => digest_names),
      "apiserver_rolling_restart" => {"restarted" => voters.map { |voter| "apiserver-#{voter}" }},
      "controller_leader_loss" => leadership.merge("renewed_at" => (START + 51).iso8601),
      "scheduler_leader_loss" => leadership.merge("renewed_at" => (START + 61).iso8601),
      "worker_reboot" => {"worker" => "unit-worker", "worker_uid" => "unit-node", "boot_id_before" => "old-boot", "boot_id_after" => "new-boot"},
      "backup_restore" => {"restored_replica" => "apiserver-control-0", "restored_snapshot_revision" => 33, "checkpoint_uid" => "unit-checkpoint"}
    }
  end

  def complete_report
    inventory = {"objects" => 12, "sha256" => "9" * 64}
    evidence = operation_evidence
    stages = Contract::STAGE_IDS.map.with_index do |id, index|
      started = START + (index * 10)
      complete_stage(id).merge("started_at" => started.iso8601(6), "finished_at" => (started + 9).iso8601(6),
                               "reversible" => %w[memory_to_raft release_upgrade].include?(id), "evidence" => evidence.fetch(id),
                               "api_inventory" => {"before" => inventory, "after" => inventory})
    end
    {"kind" => "k7_upgrade_and_recovery", "generated_at" => (START + 90).iso8601,
     "state_inventory_sha256" => Contract.state_inventory_sha256, "state_inventory_stable" => true,
     "stages" => stages, "baseline_missing" => [], "baseline_objects" => 12, "baseline_pods" => 1, "baseline_ready_pods" => 1,
     "baseline_attached_volumes" => 1, "data_loss" => [], "stuck_operations" => [], "irreversible_migrations" => []}
  end

  def command(argv, started, finished)
    {"command" => argv, "exit_status" => 0, "timed_out" => false, "started_at" => started.iso8601, "finished_at" => finished.iso8601}
  end

  def write_json(path, body)
    File.write(path, JSON.generate(body))
    Digest::SHA256.file(path).hexdigest
  end

  # These deliberately tiny unit inputs exercise the verifier without a cluster.
  def write_unit_fixtures(run, directory)
    FileUtils.mkdir_p(directory)
    report = complete_report
    argv = %W[ruby k7_lifecycle.rb --kubeconfig target --output #{directory} --oracle-kubeconfig oracle]
    execution = command(argv, START, START + 91)
    report.fetch("stages").each { |stage| write_checks(directory, stage) }
    write_json(File.join(directory, Evidence::REPORT), report)
    write_json(File.join(directory, Evidence::COMMAND), execution)
    artifacts = Dir.glob(File.join(directory, "**", "*")).select { |path| File.file?(path) }.map do |path|
      {"path" => path.delete_prefix("#{run}/"), "sha256" => Digest::SHA256.file(path).hexdigest}
    end
    times = {"startedAt" => START.iso8601, "finishedAt" => (START + 91).iso8601}
    manifest = times.merge("_path" => File.join(run, "manifest.json"), "runId" => "unit-fixture", "artifacts" => artifacts,
                           "sourceCommit" => Conformance::Lock.source_commit, "rubernetesSourceStable" => true,
                           "rubernetesCommit" => "unit-source", "rubernetesCommitAfter" => "unit-source")
    lane = times.merge("status" => "COMPLETE", "passed" => true, "artifacts" => artifacts,
                       "stages" => report.fetch("stages"), "baseline_missing" => [])
    [report, execution, manifest, lane]
  end

  def write_checks(directory, stage)
    id = stage.fetch("id")
    path = File.join(directory, id)
    FileUtils.mkdir_p(path)
    started = Time.iso8601(stage.fetch("started_at"))
    junit = File.join(path, "k1-smoke.xml")
    cases = Contract::SMOKE_SPECS.map { |name| {"id" => name, "status" => "passed"} }
    testcases = cases.map { |entry| %(<testcase status="passed" name="[It] #{CGI.escapeHTML(entry.fetch("id"))} [unit]"/>) }.join
    File.write(junit, "<testsuite>#{testcases}</testsuite>")
    smoke = ["e2e.test", "--provider=skeleton", "--kubeconfig", "target", "--kubectl-path", "kubectl-v1.36.2",
             "--ginkgo.focus=#{Contract.smoke_focus}", "--ginkgo.junit-report=#{junit}", "--ginkgo.no-color"]
    differential = %W[ruby k5_differential.rb --kubeconfig target --oracle-kubeconfig oracle --output #{path}]
    ok = {"status" => "COMPLETE", "passed" => true}
    differential_command = command(differential, started + 4, started + 6)
    stage["checks"] = {
      "k1_smoke" => ok.merge("cases" => cases, "namespaces_cleaned_up" => true, "binary_sha256" => "f" * 64,
                             "junit_sha256" => Digest::SHA256.file(junit).hexdigest,
                             "command_sha256" => write_json(File.join(path, "k1-smoke-command.json"), command(smoke, started + 1, started + 3))),
      "k5_differential" => ok.merge("command_sha256" => write_json(File.join(path, "k5-differential-command.json"), differential_command),
                                    "report_sha256" => write_json(File.join(path, "differential.json"), differential_report(id, started + 5)))
    }
  end

  def differential_report(id, time)
    fixture = "k5-#{Digest::SHA256.hexdigest(id)[0, 16]}"
    observations = Conformance::K5Differential.observables(cbor_enabled: false)
    comparisons = observations.map do |observable|
      name = observable.fetch("id")
      peer = differential_response(observable, fixture)
      sha256 = Digest::SHA256.hexdigest(Rubernetes::Schema::Codec.canonical_json(peer))
      {"id" => name, "matches" => true, "expected_responses" => true, "rubernetes" => peer, "kubernetes" => peer,
       "rubernetes_sha256" => sha256, "kubernetes_sha256" => sha256}
    end
    {"schema_version" => 1, "kind" => "k5_api_wire_differential", "fixture" => fixture, "generated_at" => time.iso8601, "differences" => [],
     "observables" => comparisons.length, "matching" => comparisons.length, "cases" => comparisons,
     "attestation" => {"oracle_commit" => Conformance::Lock.source_commit, "target_default_namespace_uid" => "target", "oracle_default_namespace_uid" => "oracle"}}
  end

  def differential_response(observable, fixture)
    errors = {"apply_configmap_conflict" => "conflict with fixture: .data.a", "unknown_field_strict" => "strict decoding error: unknown field dataz",
              "missing_object" => "NotFound", "invalid_object" => "metadata.name: Invalid value"}
    id = observable.fetch("id")
    error = errors[id]
    body = %w[create_configmap get_configmap].include?(id) ? {"metadata" => {"name" => fixture}} : {"z" => "last", "a" => "first"}
    {"exit_status" => error ? 1 : 0, "body" => body, "error" => [error].compact}.merge(observable.slice("http_status", "content_type"))
  end
end
