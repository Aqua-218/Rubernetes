# frozen_string_literal: true

require "digest"
require "json"
require "open3"
require "rbconfig"
require "tmpdir"
require "time"
require_relative "../test_helper"
require_relative "../../tools/milestones/m2_gate"
require_relative "../../tools/milestones/m2_probe_support"

class M2GateTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  GATE = File.join(ROOT, "tools/milestones/m2_gate.rb")

  def test_gate_rejects_a_bundle_without_the_cumulative_m0_and_m1_chain
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      errors = JSON.parse(stdout).fetch("errors")

      assert_includes errors, "COMPLETE M0 evidence is required for cumulative M2 completion"
      assert_includes errors, "COMPLETE M1 evidence is required for cumulative M2 completion"
    end
  end

  def test_gate_rejects_an_unavailable_required_x86_64_profile
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "runtime-report.json")
      report = JSON.parse(File.read(report_path))
      report.fetch("profiles").find do |profile|
        profile.fetch("architecture") == "x86_64"
      end.merge!("available" => false, "status" => "INCOMPLETE", "passed" => false)
      report["passed"] = false
      report["status"] = "INCOMPLETE"
      report["failure_count"] = 1
      write_json(report_path, report)
      update_artifact(manifest_path, "runtime-report.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      errors = JSON.parse(stdout).fetch("errors")

      assert(errors.any? { |error| error.include?("runtime profile 0 must be available") })
      assert(errors.any? { |error| error.include?("runtime report status must be PASS") })
    end
  end

  def test_gate_does_not_require_an_arm_profile
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      errors = JSON.parse(stdout).fetch("errors")

      refute(errors.any? { |error| error.match?(/aarch64|arm64/i) })
      refute(errors.any? { |error| error.include?("architecture profiles") })
      refute(errors.any? { |error| error.include?("required_architectures") })
    end
  end

  def test_gate_rejects_skip_retry_and_unclassified_adapter_evidence
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "oci-attack-corpus.json")
      report = JSON.parse(File.read(report_path))
      report["retry_count"] = 1
      report["unexpected_skip_count"] = 1
      report["unclassified_count"] = 1
      report["failure_count"] = 3
      report["passed"] = false
      report["status"] = "INCOMPLETE"
      write_json(report_path, report)
      update_artifact(manifest_path, "oci-attack-corpus.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      errors = JSON.parse(stdout).fetch("errors")

      assert_includes errors, "attacks report retry_count must be zero"
      assert_includes errors, "attacks report unexpected_skip_count must be zero"
      assert_includes errors, "attacks report unclassified_count must be zero"
    end
  end

  def test_gate_rejects_a_ledger_that_does_not_cover_all_1000_cycles
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "resource-ledger.json")
      report = JSON.parse(File.read(report_path))
      report["cycles"] = []
      report["cycle_count"] = 0
      report["passed"] = false
      report["status"] = "INCOMPLETE"
      report["failure_count"] = 1
      write_json(report_path, report)
      update_artifact(manifest_path, "resource-ledger.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      assert_includes JSON.parse(stdout).fetch("errors"), "resource ledger must contain exactly 1000 cycles"
    end
  end

  def test_gate_rejects_a_lifecycle_trace_with_an_illegal_transition
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "pod-lifecycle-trace.json")
      report = JSON.parse(File.read(report_path))
      event = report.fetch("trace").first
      event["from"] = "New"
      event["to"] = "Running"
      report["trace_sha256"] = Digest::SHA256.hexdigest(JSON.generate(report.fetch("trace")))
      report["passed"] = false
      report["status"] = "INCOMPLETE"
      report["failure_count"] = 1
      write_json(report_path, report)
      update_artifact(manifest_path, "pod-lifecycle-trace.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      assert_includes JSON.parse(stdout).fetch("errors"), "Pod lifecycle event operation-1/0 transition is not allowed"
    end
  end

  def test_gate_rejects_artifact_digest_tampering_and_unstable_capture
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      File.write(File.join(directory, "runtime-report.json"), "tampered\n")
      manifest = JSON.parse(File.read(manifest_path))
      manifest["input_stable"] = false
      manifest["input_capture"]["stable"] = false
      write_json(manifest_path, manifest)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      errors = JSON.parse(stdout).fetch("errors")

      assert_includes errors, "source input must remain stable during evidence capture"
      assert_includes errors, "artifact digest mismatch runtime-report.json"
    end
  end

  def test_gate_recomputes_the_canonical_report_digest
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "runtime-report.json")
      report = JSON.parse(File.read(report_path))
      report.fetch("adapter")["name"] = "forged-adapter"
      write_json(report_path, report)
      update_artifact(manifest_path, "runtime-report.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      assert_includes JSON.parse(stdout).fetch("errors"), "runtime report report_sha256 does not match canonical content"
    end
  end

  def test_gate_requires_lifecycle_sigkill_and_subresource_measurements
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "pod-lifecycle-trace.json")
      report = JSON.parse(File.read(report_path))
      report.delete("sigkill_matrix")
      report.delete("subresource_e2e")
      report.delete("subresource_e2e_sha256")
      write_json(report_path, report)
      update_artifact(manifest_path, "pod-lifecycle-trace.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      errors = JSON.parse(stdout).fetch("errors")

      assert_includes errors, "Pod lifecycle sigkill_matrix is required"
      assert_includes errors, "Pod lifecycle subresource_e2e is required"
    end
  end

  def test_gate_rejects_synthetic_sigkill_measurements_and_requires_production_agent_identity
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "pod-lifecycle-trace.json")
      report = JSON.parse(File.read(report_path))
      report.fetch("sigkill_matrix").each do |entry|
        entry["measurement_source"] = "fork+Process.kill"
        entry.delete("native_agent")
        entry["evidence_sha256"] = M2Gate.canonical_document_digest(entry, excluded_keys: ["evidence_sha256"])
      end
      write_json(report_path, report)
      update_artifact(manifest_path, "pod-lifecycle-trace.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      errors = JSON.parse(stdout).fetch("errors")

      assert(errors.any? { |error| error.include?("measurement must come from production Native L3 Node Agent SIGKILL") })
      assert(errors.any? { |error| error.include?("Native Node Agent restart evidence is required") })
    end
  end

  def test_gate_rejects_native_sigkill_evidence_without_real_workload_wal_and_kernel_observer
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "pod-lifecycle-trace.json")
      report = JSON.parse(File.read(report_path))
      entry = report.fetch("sigkill_matrix").first
      entry.delete("actual_workload")
      entry.delete("kernel_observer")
      entry["native_wal_path"] = "/tmp/runtime.wal"
      entry["evidence_sha256"] = M2Gate.canonical_document_digest(entry, excluded_keys: ["evidence_sha256"])
      write_json(report_path, report)
      update_artifact(manifest_path, "pod-lifecycle-trace.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      errors = JSON.parse(stdout).fetch("errors")

      assert(errors.any? { |error| error.include?("must replay the exact Native ownership WAL") })
      assert(errors.any? { |error| error.include?("actual Native workload evidence is required") })
      assert(errors.any? { |error| error.include?("independent kernel observer evidence is required") })
    end
  end

  def test_gate_rejects_subresource_flow_that_bypasses_agent_sync_loop_watch
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "pod-lifecycle-trace.json")
      report = JSON.parse(File.read(report_path))
      flow = report.fetch("apply_lifecycle_native_flow")
      flow["node_agent_class"] = "Struct"
      flow["watch_event_count"] = 0
      flow["lifecycle_started_from_watch"] = false
      write_json(report_path, report)
      update_artifact(manifest_path, "pod-lifecycle-trace.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      errors = JSON.parse(stdout).fetch("errors")

      assert_includes errors, "Pod lifecycle flow must use Node::Agent"
      assert_includes errors, "Pod lifecycle must be started from the Agent watch path"
    end
  end

  def test_gate_rejects_a_kernel_workload_reported_as_fork_created
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "kernel-inventory.json")
      report = JSON.parse(File.read(report_path))
      object = report.fetch("architectures").first.fetch("objects").find { |entry| entry["kind"] == "child_security" }
      child = JSON.parse(object.fetch("active"))
      child["creation_method"] = "fork"
      object["active"] = JSON.generate(child)
      object["active_sha256"] = Digest::SHA256.hexdigest(object.fetch("active"))
      write_json(report_path, report)
      update_artifact(manifest_path, "kernel-inventory.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      assert_includes JSON.parse(stdout).fetch("errors"),
                      "kernel inventory profile 0 actual workload must use clone3 with CLONE_PIDFD and CLONE_NEWPID"
    end
  end

  def test_gate_rejects_lifecycle_evidence_without_an_external_kubernetes_oracle
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "pod-lifecycle-trace.json")
      report = JSON.parse(File.read(report_path))
      report.delete("lifecycle_oracle")
      write_json(report_path, report)
      update_artifact(manifest_path, "pod-lifecycle-trace.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      assert_includes JSON.parse(stdout).fetch("errors"), "Pod lifecycle Kubernetes semantic oracle evidence is missing"
    end
  end

  def test_gate_requires_a_content_addressed_runtime_lifecycle_formal_report
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "pod-lifecycle-trace.json")
      report = JSON.parse(File.read(report_path))
      report["formal_claims"] = ["RuntimeLifecycle"]
      report["report_sha256"] = M2Gate.canonical_document_digest(report, excluded_keys: ["report_sha256"])
      write_json(report_path, report)
      update_artifact(manifest_path, "pod-lifecycle-trace.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      assert_includes JSON.parse(stdout).fetch("errors"),
                      "RuntimeLifecycle formal report is missing (expected formal-report.json)"
    end
  end

  def test_gate_rejects_production_provenance_marked_as_a_self_comparison
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "runtime-report.json")
      report = JSON.parse(File.read(report_path))
      provenance = report.fetch("provenance")
      provenance["self_comparison"] = true
      provenance["provenance_sha256"] = M2Gate.canonical_document_digest(provenance, excluded_keys: ["provenance_sha256"])
      write_json(report_path, report)
      update_artifact(manifest_path, "runtime-report.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      assert_includes JSON.parse(stdout).fetch("errors"), "runtime report provenance must not be a self-comparison"
    end
  end

  def test_gate_rejects_a_lifecycle_oracle_marked_as_a_self_comparison
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "pod-lifecycle-trace.json")
      report = JSON.parse(File.read(report_path))
      provenance = report.fetch("lifecycle_oracle").fetch("provenance")
      provenance["self_comparison"] = true
      provenance["provenance_sha256"] = M2Gate.canonical_document_digest(provenance, excluded_keys: ["provenance_sha256"])
      write_json(report_path, report)
      update_artifact(manifest_path, "pod-lifecycle-trace.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      assert_includes JSON.parse(stdout).fetch("errors"),
                      "Pod lifecycle Kubernetes semantic oracle provenance must not be a self-comparison"
    end
  end

  def test_gate_rejects_semantics_comparison_that_claims_native_lifecycle_provenance
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "pod-lifecycle-trace.json")
      report = JSON.parse(File.read(report_path))
      comparison = report.fetch("lifecycle_oracle").fetch("comparisons").first
      comparison["actual_source"] = "rubernetes_native_lifecycle"
      comparison["actual_provenance"]["source"] = "rubernetes_native_lifecycle"
      write_json(report_path, report)
      update_artifact(manifest_path, "pod-lifecycle-trace.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      errors = JSON.parse(stdout).fetch("errors")

      assert_includes errors, "Pod lifecycle Kubernetes semantic oracle comparison 0 actual source must be #{M2Gate::LIFECYCLE_SEMANTICS_ACTUAL_SOURCE}"
      assert_includes errors, "Pod lifecycle Kubernetes semantic oracle comparison case init_sidecar_app_order actual source must be " \
                              "#{M2Gate::LIFECYCLE_SEMANTICS_ACTUAL_SOURCE}"
    end
  end

  def test_gate_rejects_a_cycle_reuse_count_that_is_not_zero_and_not_aggregated
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "resource-ledger.json")
      report = JSON.parse(File.read(report_path))
      report.fetch("cycles").first["resource_reuse_count"] = 1
      write_json(report_path, report)
      update_artifact(manifest_path, "resource-ledger.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      errors = JSON.parse(stdout).fetch("errors")

      assert_includes errors, "resource ledger cycle 1 resource reuse count must be zero"
      assert_includes errors, "resource ledger aggregate resource reuse count must equal cycle counts"
    end
  end

  def test_gate_recomputes_each_cycle_active_inventory_digest
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "resource-ledger.json")
      report = JSON.parse(File.read(report_path))
      report.fetch("cycles").first["active_inventory_sha256"] = "0" * 64
      write_json(report_path, report)
      update_artifact(manifest_path, "resource-ledger.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      assert_includes JSON.parse(stdout).fetch("errors"),
                      "resource ledger cycle 1 active_inventory_sha256 must match the raw active inventory"
    end
  end

  def test_gate_rejects_duplicate_raw_inventory_before_aggregation
    Dir.mktmpdir("rubernetes-m2-gate-") do |directory|
      manifest_path = write_bundle(directory)
      report_path = File.join(directory, "pod-lifecycle-trace.json")
      report = JSON.parse(File.read(report_path))
      duplicate = Marshal.load(Marshal.dump(report.fetch("sigkill_matrix").first.fetch("inventory_before").first))
      report.fetch("sigkill_matrix").first.fetch("inventory_before") << duplicate
      write_json(report_path, report)
      update_artifact(manifest_path, "pod-lifecycle-trace.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate status, :success?
      assert_empty stderr
      errors = JSON.parse(stdout).fetch("errors")

      assert(errors.any? { |error| error.include?("duplicate raw inventory identities") })
    end
  end

  def test_m2_source_identity_excludes_only_anchored_generator_temp_directories
    Dir.mktmpdir("rubernetes-source-identity-") do |directory|
      File.write(File.join(directory, "source.rb"), "source\n")
      Dir.mkdir(File.join(directory, "a11-generated.u1BHO1"))
      File.write(File.join(directory, "a11-generated.u1BHO1", "generated.rb"), "temporary\n")
      Dir.mkdir(File.join(directory, "a11-generated.bad"))
      File.write(File.join(directory, "a11-generated.bad", "source.rb"), "tracked\n")
      File.write(File.join(directory, "a11-generated.u1BHO1x"), "tracked-file\n")

      entries = M2ProbeSupport.source_identity(directory).fetch("entries").map { |entry| entry.fetch("path") }

      refute_includes entries, "a11-generated.u1BHO1/generated.rb"
      assert_includes entries, "a11-generated.bad/source.rb"
      assert_includes entries, "a11-generated.u1BHO1x"
    end
  end

  private

  def write_bundle(directory)
    input_sha256 = Digest::SHA256.hexdigest("source/example.rb\0#{Digest::SHA256.hexdigest("example")}\n")
    input_file_count = 1
    write_json(directory, "source-inventory.json", {
                 "schema_version" => 1,
                 "milestone" => "M2",
                 "kind" => "m2_source_inventory",
                 "input_sha256" => input_sha256,
                 "input_file_count" => input_file_count,
                 "input_stable" => true,
                 "entries" => [{"path" => "source/example.rb", "sha256" => Digest::SHA256.hexdigest("example"), "bytes" => 7}]
               })
    write_json(directory, "runtime-report.json", runtime_report(input_sha256, input_file_count))
    write_json(directory, "oci-attack-corpus.json", attack_report(input_sha256, input_file_count))
    write_json(directory, "pod-lifecycle-trace.json", lifecycle_report(input_sha256, input_file_count))
    write_json(directory, "resource-ledger.json", ledger_report(input_sha256, input_file_count))
    write_json(directory, "kernel-inventory.json", kernel_report(input_sha256, input_file_count))

    timestamp = Time.now.utc.iso8601(6)
    artifacts = Dir.children(directory).sort.map do |name|
      path = File.join(directory, name)
      {"path" => name, "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
    end
    manifest = {
      "schema_version" => 3,
      "milestone" => "M2",
      "status" => "COMPLETE",
      "host" => {"architecture" => "x86_64", "kernel" => "test-kernel", "ruby" => RUBY_DESCRIPTION},
      "input_sha256" => input_sha256,
      "input_file_count" => input_file_count,
      "input_stable" => true,
      "input_capture" => {"stable" => true, "start" => {"sha256" => input_sha256, "file_count" => 1},
                          "finish" => {"sha256" => input_sha256, "file_count" => 1}},
      "git_metadata_capture" => {"stable" => true, "start_paths" => [], "finish_paths" => [], "count" => 0},
      "started_at" => timestamp,
      "finished_at" => timestamp,
      "commands" => [{"name" => "m2_fixture", "command" => ["fixture"], "started_at" => timestamp, "finished_at" => timestamp,
                      "exit_status" => 0}],
      "prior_milestones" => {},
      "result_counts" => {"commands" => 1, "command_failures" => 0, "artifacts" => artifacts.length, "subjects" => 0, "reports" => 5,
                          "source_files" => 1},
      "artifacts" => artifacts,
      "subjects" => []
    }
    path = File.join(directory, "manifest.json")
    write_json(path, manifest)
    path
  end

  def report_base(input_sha256, input_file_count, kind)
    adapter_name = {
      "m2_runtime_profiles" => "m2-runtime-probe",
      "m2_oci_attack_corpus" => "m2-attack-probe",
      "m2_pod_lifecycle_trace" => "m2-lifecycle-probe",
      "m2_resource_ledger" => "m2-ledger-probe",
      "m2_kernel_inventory" => "m2-kernel-probe"
    }.fetch(kind)
    adapter = {"name" => adapter_name, "version" => "1", "runner_sha256" => Digest::SHA256.hexdigest("fixture")}
    timestamp = Time.now.utc.iso8601(6)
    measurement_source = {
      "m2_runtime_profiles" => "production_native_runtime",
      "m2_oci_attack_corpus" => "production_image_layer_extractor",
      "m2_pod_lifecycle_trace" => "production_native_lifecycle",
      "m2_resource_ledger" => "production_native_l3_cycles",
      "m2_kernel_inventory" => "production_native_kernel"
    }.fetch(kind)
    provenance = {
      "source_sha256" => input_sha256,
      "source_file_count" => input_file_count,
      "mode" => "production",
      "self_comparison" => false,
      "measurement_source" => measurement_source,
      "runner_sha256" => adapter.fetch("runner_sha256"),
      "command" => ["ruby", "m2_fixture.rb"],
      "command_kind" => "ruby_probe",
      "process_id" => Process.pid,
      "measurement_id" => "fixture-#{kind}-#{Process.pid}",
      "started_at" => timestamp,
      "finished_at" => timestamp
    }
    provenance["provenance_sha256"] = M2Gate.canonical_document_digest(provenance, excluded_keys: ["provenance_sha256"])
    {
      "schema_version" => 1,
      "milestone" => "M2",
      "kind" => kind,
      "adapter" => adapter,
      "input_sha256" => input_sha256,
      "input_file_count" => input_file_count,
      "input_stable" => true,
      "attempt_count" => 1,
      "retry_count" => 0,
      "unexpected_skip_count" => 0,
      "unclassified_count" => 0,
      "flake_count" => 0,
      "failure_count" => 0,
      "passed" => true,
      "status" => "PASS",
      "errors" => [],
      "measurement_level" => "L3",
      "measurement_source" => measurement_source,
      "provenance" => provenance
    }
  end

  def runtime_report(sha, count)
    levels = M2Gate::REQUIRED_LEVELS.map do |level|
      evidence = if level == "L3"
                   {"details" => {"native_workload" => {"passed" => true, "measurement_source" => "production_native_l3",
                                                        "runtime_class" => "Rubernetes::Runtime::Native",
                                                        "adapter_class" => "Rubernetes::Platform::Linux::NativeAdapters"}}}
                 end
      {"level" => level, "status" => "PASS", "passed" => true, "attempt_count" => 1, "failure_count" => 0, "unexpected_skip_count" => 0,
       "unclassified_count" => 0, "evidence_sha256" => Digest::SHA256.hexdigest(level.to_s), "evidence" => evidence}.compact
    end
    profiles = M2Gate::REQUIRED_ARCHITECTURES.map do |architecture|
      {"architecture" => architecture, "available" => true, "status" => "PASS", "passed" => true, "profile_sha256" => Digest::SHA256.hexdigest(architecture),
       "levels" => levels}
    end
    finalize_report(report_base(sha, count, "m2_runtime_profiles").merge(
      "required_architectures" => M2Gate::REQUIRED_ARCHITECTURES,
      "profiles" => profiles
    ))
  end

  def attack_report(sha, count)
    cases = M2Gate::REQUIRED_ATTACKS.map do |attack|
      {"id" => attack, "category" => attack, "status" => "PASS", "passed" => true, "attempt_count" => 1, "fail_closed" => true,
       "measurement_source" => "production_image_layer_extractor", "adapter_class" => "Rubernetes::Image::LayerExtractor",
       "observable_sha256" => Digest::SHA256.hexdigest(attack)}
    end
    finalize_report(report_base(sha, count, "m2_oci_attack_corpus").merge("cases" => cases, "coverage_count" => 4, "case_count" => 4))
  end

  def lifecycle_report(sha, count)
    digest = Digest::SHA256.hexdigest("config")
    states = %w[New Validated ImagePinned WorkspaceAllocated IsolationCreated ResourcesAttached WorkloadStopped Running Stopping Stopped
                Removed]
    trace = states.each_cons(2).map.with_index do |(from, to), index|
      {"operation_id" => "operation-1", "from" => from, "to" => to, "timestamp" => Time.at(index).utc.iso8601(6),
       "config_digest" => digest, "owned_resources" => [], "fsynced" => true}
    end
    document = report_base(sha, count, "m2_pod_lifecycle_trace").merge(
      "trace" => trace,
      "trace_sha256" => Digest::SHA256.hexdigest(JSON.generate(trace)),
      "failure_injection_count" => 4,
      "live_leak_count" => 0,
      "orphan_count" => 0,
      "resource_kinds" => M2Gate::REQUIRED_RESOURCE_KINDS,
      "inventory_measurement" => fixture_inventory,
      "sigkill_matrix" => fixture_sigkill_matrix,
      "subresource_e2e" => fixture_subresource_e2e,
      "subresource_e2e_sha256" => M2Gate.canonical_document_digest(fixture_subresource_e2e),
      "lifecycle_semantics_measurement_source" => M2Gate::LIFECYCLE_SEMANTICS_ACTUAL_SOURCE,
      "apply_lifecycle_native_flow" => {
        "apply_preceded_lifecycle" => true,
        "node_lifecycle_class" => "Rubernetes::Node::Lifecycle",
        "node_agent_class" => "Rubernetes::Node::Agent",
        "sync_loop_class" => "Rubernetes::Node::SyncLoop",
        "watch_source_class" => "M2ProbeSupport::NativeAgentAPI",
        "watch_event_count" => 2,
        "watch_resource_version" => "2",
        "agent_registered" => true,
        "lifecycle_started_from_watch" => true,
        "runtime_class" => "Rubernetes::Runtime::Native",
        "finish_state" => "Removed",
        "measurement_source" => "production_native_lifecycle"
      },
      "lifecycle_semantics_matrix" => fixture_lifecycle_semantics,
      "lifecycle_semantics_matrix_sha256" => M2Gate.canonical_document_digest(fixture_lifecycle_semantics),
      "oracle_difference_count" => 0,
      "lifecycle_oracle" => fixture_lifecycle_oracle
    )
    finalize_report(document)
  end

  def ledger_report(sha, count)
    inventory = fixture_inventory
    cycles = (1..1000).map do |cycle|
      active = M2Gate::REQUIRED_RESOURCE_KINDS.map do |kind|
        {"kind" => kind, "id" => "fixture-cycle-#{cycle}-#{kind}",
         "identity" => "fixture-cycle-identity-#{cycle}-#{kind}", "owner" => "fixture-cycle-owner-#{cycle}",
         "metadata" => {"managed_by" => "fixture-cycle", "live" => true}}
      end
      residual = []
      {"cycle" => cycle, "cycle_id" => format("m2-native-cycle-%04d", cycle),
       "measurement_id" => format("m2-native-cycle-%04d", cycle),
       "operations" => %w[create start stop delete], "status" => "PASS", "passed" => true,
       "attempt_count" => 1, "live_leak_count" => 0, "orphan_count" => 0,
       "resource_reuse_count" => 0, "resource_count" => active.length,
       "released_resource_count" => active.length, "resource_kinds" => M2Gate::REQUIRED_RESOURCE_KINDS,
       "active_inventory" => active, "active_inventory_sha256" => M2Gate.canonical_document_digest(active),
       "active_inventory_count" => active.length, "active_inventory_kinds" => M2Gate::REQUIRED_RESOURCE_KINDS,
       "residual_inventory" => residual, "residual_inventory_sha256" => M2Gate.canonical_document_digest(residual),
       "residual_inventory_count" => 0, "residual_inventory_kinds" => [],
       "kernel_identity_sha256" => M2Gate.canonical_document_digest(active),
       "kernel_identity_source" => "production_native_l3_kernel_inventory",
       "measurement_source" => "production_native_l3_cycles"}
    end
    cycle_inventory = fixture_cycle_inventory(cycles)
    cycles.each do |cycle|
      cycle["inventory_measurement_id"] = cycle_inventory.fetch("measurement_id")
      cycle["active_inventory_measurement_id"] = cycle_inventory.fetch("measurement_id")
    end
    effects = M2Gate::REQUIRED_EFFECT_POINTS.map { |name| {"name" => name, "injected_count" => 1, "live_leak_count" => 0, "measurement_source" => "production_native_effect_injection"} }
    canonical_payload = {
      "cycle_count" => 1000,
      "cycles" => cycles,
      "effect_points" => effects,
      "failure_injection_count" => 4,
      "live_leak_count" => 0,
      "orphan_count" => 0,
      "resource_reuse_count" => 0
    }
    document = report_base(sha, count, "m2_resource_ledger").merge(
      canonical_payload,
      "ledger_sha256" => M2Gate.canonical_document_digest(canonical_payload),
      "resource_kinds" => M2Gate::REQUIRED_RESOURCE_KINDS,
      "inventory_measurement" => inventory,
      "cycle_inventory_measurement" => cycle_inventory,
      "sigkill_matrix" => fixture_sigkill_matrix
    )
    finalize_report(document)
  end

  def kernel_report(sha, count)
    profiles = M2Gate::REQUIRED_ARCHITECTURES.map do |architecture|
      child = JSON.generate(
        "pid" => 12_345,
        "start_time" => "12345",
        "executable_digest" => "sha256:#{"c" * 64}",
        "creation_method" => "clone3",
        "clone_flags" => M2Gate::CLONE_PIDFD | M2Gate::CLONE_NEWPID
      )
      objects = [
        {"kind" => "namespace", "identity" => "#{architecture}-ns", "before" => "present", "active" => "present", "after" => "present",
         "measurement_source" => "production_native_adapter", "active_sha256" => Digest::SHA256.hexdigest("present")},
        {"kind" => "child_security", "identity" => "#{architecture}:native-workload", "before" => "parent", "active" => child,
         "after" => "parent", "measurement_source" => "production_native_adapter", "active_sha256" => Digest::SHA256.hexdigest(child)}
      ]
      {"architecture" => architecture, "available" => true, "status" => "PASS", "passed" => true,
       "profile_sha256" => Digest::SHA256.hexdigest(architecture), "objects" => objects,
       "inventory_sha256" => M2Gate.canonical_kernel_inventory_digest(objects), "baseline_sha256" => Digest::SHA256.hexdigest("baseline-#{architecture}"),
       "final_sha256" => Digest::SHA256.hexdigest("final-#{architecture}"), "difference_count" => 0, "live_leak_count" => 0, "orphan_count" => 0}
    end
    finalize_report(report_base(sha, count, "m2_kernel_inventory").merge(
      "required_architectures" => M2Gate::REQUIRED_ARCHITECTURES,
      "architectures" => profiles
    ))
  end

  def fixture_inventory(measurement_source: "production_native_agent_sigkill")
    before = fixture_sigkill_resources(victim_live: false)
    after = fixture_guard_resources
    before_keys = before.map { |entry| "#{entry.fetch("kind")}:#{entry.fetch("id")}" }
    after_keys = after.map { |entry| "#{entry.fetch("kind")}:#{entry.fetch("id")}" }
    diff = {
      "added" => (after_keys - before_keys).sort,
      "removed" => (before_keys - after_keys).sort,
      "retained" => (after_keys & before_keys).sort
    }
    {
      "source" => "real_adapter",
      "measurement_source" => measurement_source,
      "measurement_id" => "fixture-inventory-#{Process.pid}",
      "before" => before,
      "after" => after,
      "diff" => diff,
      "inventory_diff_sha256" => M2Gate.canonical_document_digest({"before" => before, "after" => after, "diff" => diff}),
      "resource_kinds" => M2Gate::REQUIRED_RESOURCE_KINDS,
      "required_resource_kinds" => M2Gate::REQUIRED_RESOURCE_KINDS,
      "missing_resource_kinds" => [],
      "profile_status" => "PASS",
      "live_leak_count" => 0,
      "orphan_count" => 0,
      "live_wrong_deletion_count" => 0
    }
  end

  def fixture_cycle_inventory(cycles = nil)
    unless cycles
      return fixture_inventory(measurement_source: "production_native_l3_cycles").merge(
        "measurement_id" => "fixture-cycle-inventory-#{Process.pid}",
        "cycle_count" => 1000,
        "adapter_class" => "Rubernetes::Platform::Linux::NativeAdapters"
      )
    end

    before = cycles.flat_map { |cycle| cycle.fetch("active_inventory") }
    after = cycles.flat_map { |cycle| cycle.fetch("residual_inventory") }
    before_keys = before.map { |entry| "#{entry.fetch("kind")}:#{entry.fetch("id")}" }
    after_keys = after.map { |entry| "#{entry.fetch("kind")}:#{entry.fetch("id")}" }
    diff = {"added" => (after_keys - before_keys).sort, "removed" => (before_keys - after_keys).sort,
            "retained" => (after_keys & before_keys).sort}
    {"source" => "real_adapter", "measurement_source" => "production_native_l3_cycles",
     "measurement_id" => "fixture-cycle-inventory-#{Process.pid}", "before" => before, "after" => after,
     "diff" => diff, "inventory_diff_sha256" => M2Gate.canonical_document_digest({"before" => before, "after" => after, "diff" => diff}),
     "resource_kinds" => M2Gate::REQUIRED_RESOURCE_KINDS, "required_resource_kinds" => M2Gate::REQUIRED_RESOURCE_KINDS,
     "missing_resource_kinds" => [], "profile_status" => "PASS", "live_leak_count" => 0,
     "orphan_count" => 0, "live_wrong_deletion_count" => 0, "cycle_count" => cycles.length,
     "adapter_class" => "Rubernetes::Platform::Linux::NativeAdapters"}
  end

  def fixture_sigkill_matrix
    inventory = fixture_inventory
    M2Gate::REQUIRED_EFFECT_POINTS.map.with_index do |effect, index|
      target_pid = Process.pid + 100
      workload_pid = target_pid + 1
      at_kill = fixture_sigkill_resources(victim_live: true)
      evidence = {
        "effect_point" => effect,
        "crash_checkpoint" => {"native_state" => "running", "actual_operation" => "container.start"},
        "signal" => "SIGKILL",
        "target_pid" => target_pid,
        "target_start_time" => (10_000 + index).to_s,
        "measurement_id" => "fixture-sigkill-#{effect}-#{index}",
        "wal_path" => "/tmp/#{effect}/native-agent.wal",
        "native_wal_path" => "/tmp/#{effect}/native-agent.wal",
        "wal_kind" => "rubernetes_native_ownership_ledger",
        "wal_changed" => true,
        "restart_pid" => Process.pid,
        "restart_process" => "fork",
        "kill_observed" => true,
        "restart_observed" => true,
        "wal_replayed" => true,
        "replayed_operation_state" => "Stopped",
        "replayed_request_ids" => {
          "sigkill-#{effect}-create" => true,
          "sigkill-#{effect}-start" => true
        },
        "actual_workload" => {
          "pid" => workload_pid,
          "start_time" => "11000",
          "command" => ["/bin/busybox", "sleep", "3600"],
          "executable_digest" => "sha256:#{"a" * 64}",
          "cgroup_path" => "/sys/fs/cgroup/rubernetes/besteffort/fixture/workload",
          "cgroup_membership" => ["0::/rubernetes/besteffort/fixture/workload"],
          "pid_namespace" => "pid:[4026533000]",
          "mount_namespace" => "mnt:[4026533001]",
          "workload_pidfd" => 8,
          "workload_pidfd_link" => "anon_inode:[pidfd]",
          "creation_method" => "clone3",
          "clone_flags" => M2Gate::CLONE_PIDFD | M2Gate::CLONE_NEWPID
        },
        "kernel_observer" => {
          "external" => true,
          "observer_pid" => Process.pid,
          "inventory_at_kill" => at_kill,
          "inventory_at_kill_sha256" => M2Gate.canonical_document_digest(at_kill)
        },
        "wait_status" => {"signaled" => true, "signal" => "SIGKILL", "exit_status" => nil},
        "wal_before_sha256" => Digest::SHA256.hexdigest("wal-before-#{effect}"),
        "wal_after_sha256" => Digest::SHA256.hexdigest("wal-after-#{effect}"),
        "inventory_before" => inventory.fetch("before"),
        "inventory_after" => inventory.fetch("after"),
        "inventory_before_sha256" => M2Gate.canonical_document_digest(inventory.fetch("before")),
        "inventory_after_sha256" => M2Gate.canonical_document_digest(inventory.fetch("after")),
        "live_wrong_deletion_count" => 0,
        "dead_residual_count" => 0,
        "measurement_source" => "production_native_agent_sigkill",
        "native_agent" => {
          "ready" => true,
          "registered" => true,
          "agent_pid" => Process.pid,
          "agent_start_time" => "12000",
          "agent_process_identity" => "process:node-agent:#{Process.pid}:12000",
          "agent_class" => "Rubernetes::Node::Agent",
          "sync_loop_class" => "Rubernetes::Node::SyncLoop",
          "lifecycle_class" => "Rubernetes::Node::Lifecycle",
          "runtime_class" => "Rubernetes::Runtime::Native",
          "runtime_profile" => "l3",
          "recovery" => {
            "ready" => true,
            "errors" => [],
            "blocked" => [],
            "runtime" => {"identity_mismatch" => [], "orphans" => [], "cleaned_orphans" => []}
          }
        }
      }
      evidence["evidence_sha256"] = M2Gate.canonical_document_digest(evidence, excluded_keys: ["evidence_sha256"])
      evidence
    end
  end

  def fixture_guard_resources
    [{
      "kind" => "process",
      "id" => "fixture-guard-process",
      "identity" => "fixture-guard-process-identity",
      "owner" => "fixture-guard-owner",
      "metadata" => {"managed_by" => "fixture-observer", "observer_role" => "guard", "live" => true}
    }]
  end

  def fixture_sigkill_resources(victim_live:)
    workload_pid = Process.pid + 101
    digest = Digest::SHA256.hexdigest("fixture-mountinfo")
    resources = M2Gate::REQUIRED_RESOURCE_KINDS.map do |kind|
      metadata = {
        "managed_by" => "fixture-observer",
        "observer_role" => "victim",
        "live" => victim_live
      }
      if kind == "mount"
        metadata.merge!("filesystem" => "overlay", "mountinfo" => "1 0 0:1 / /fixture rw - overlay overlay rw",
                        "mountinfo_sha256" => digest)
      end
      if kind == "process"
        metadata.merge!("pid" => workload_pid, "start_time" => 11_000,
                        "command" => ["/bin/busybox", "sleep", "3600"],
                        "executable_digest" => "sha256:#{"a" * 64}")
      end
      {
        "kind" => kind,
        "id" => "fixture-victim-#{kind}",
        "identity" => "fixture-victim-identity-#{kind}",
        "owner" => "fixture-victim-owner",
        "metadata" => metadata
      }
    end
    resources << {
      "kind" => "namespace",
      "id" => "fixture-victim-namespace-holder",
      "identity" => "fixture-victim-namespace-holder-identity",
      "owner" => "fixture-victim-owner",
      "metadata" => {
        "managed_by" => "fixture-observer",
        "observer_role" => "victim",
        "live" => victim_live,
        "creation_method" => "clone3",
        "clone_flags" => M2Gate::CLONE_PIDFD | M2Gate::CLONE_NEWNS | M2Gate::CLONE_NEWPID
      }
    }
    resources + fixture_guard_resources
  end

  def fixture_lifecycle_semantics
    M2Gate::REQUIRED_LIFECYCLE_SEMANTICS.map do |name|
      payload = {"name" => name, "expected" => {"fixture" => name}, "observed" => {"fixture" => name},
                 "actual_provenance" => fixture_semantics_provenance(name), "passed" => true}
      payload["evidence_sha256"] = M2Gate.canonical_document_digest(payload)
      payload
    end
  end

  def fixture_semantics_provenance(name)
    M2Gate::LIFECYCLE_SEMANTICS_PROVENANCE.fetch(name).merge(
      "source" => M2Gate::LIFECYCLE_SEMANTICS_ACTUAL_SOURCE
    )
  end

  def fixture_lifecycle_oracle
    runner = Digest::SHA256.hexdigest("fixture-lifecycle-oracle-runner")
    seed = Digest::SHA256.hexdigest("fixture-lifecycle-oracle-seed")
    provenance = {
      "kind" => M2Gate::KUBERNETES_SEMANTICS_ORACLE_KIND,
      "mode" => "external",
      "self_comparison" => false,
      "implementation" => "fixture external Kubernetes lifecycle oracle",
      "source" => {
        "version" => M2Gate::KUBERNETES_VERSION,
        "commit" => M2Gate::KUBERNETES_SOURCE_COMMIT,
        "tag" => M2Gate::KUBERNETES_VERSION,
        "apiserver_image" => "registry.k8s.io/kube-apiserver@sha256:#{"a" * 64}",
        "etcd_image" => "registry.k8s.io/etcd@sha256:#{"b" * 64}",
        "network_isolated" => true
      },
      "runner_sha256" => runner,
      "request_seed_sha256" => seed
    }
    provenance["provenance_sha256"] = M2Gate.canonical_document_digest(provenance, excluded_keys: ["provenance_sha256"])
    {
      "executed" => true,
      "kubernetes_version" => M2Gate::KUBERNETES_VERSION,
      "source_commit" => M2Gate::KUBERNETES_SOURCE_COMMIT,
      "runner_sha256" => runner,
      "request_seed_sha256" => seed,
      "comparison_count" => M2Gate::REQUIRED_LIFECYCLE_SEMANTICS.length,
      "missing_comparison_count" => 0,
      "provenance" => provenance,
      "comparisons" => M2Gate::REQUIRED_LIFECYCLE_SEMANTICS.map do |name|
        digest = Digest::SHA256.hexdigest("lifecycle:#{name}")
        {"id" => name, "attempt_count" => 1, "passed" => true, "expected_source" => "kubernetes_external", "actual_source" => M2Gate::LIFECYCLE_SEMANTICS_ACTUAL_SOURCE, "actual_provenance" => fixture_semantics_provenance(name), "expected_sha256" => digest, "actual_sha256" => digest}
      end
    }
  end

  def fixture_subresource_e2e
    M2Gate::REQUIRED_SUBRESOURCES.to_h do |name|
      [name, {"requested" => true, "observed" => true, "passed" => true, "request_id" => "fixture-#{name}", "response_sha256" => Digest::SHA256.hexdigest("response-#{name}")}]
    end
  end

  def finalize_report(report)
    report["report_sha256"] = M2Gate.canonical_document_digest(report, excluded_keys: ["report_sha256"])
    report
  end

  def write_json(path_or_directory, value_or_name, value = nil)
    path = value.nil? ? path_or_directory : File.join(path_or_directory, value_or_name)
    document = value.nil? ? value_or_name : value
    File.write(path, JSON.pretty_generate(document) << "\n")
  end

  def update_artifact(manifest_path, name, path)
    manifest = JSON.parse(File.read(manifest_path))
    artifact = manifest.fetch("artifacts").find { |entry| entry.fetch("path") == name }
    artifact["sha256"] = Digest::SHA256.file(path).hexdigest
    artifact["bytes"] = File.size(path)
    write_json(manifest_path, manifest)
  end

  def run_gate(manifest_path)
    Open3.capture3(RbConfig.ruby, GATE, manifest_path, chdir: ROOT)
  end
end
