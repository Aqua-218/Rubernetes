# frozen_string_literal: true

require "digest"
require "etc"
require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "tmpdir"
require "time"
require_relative "../test_helper"
require_relative "../../tools/milestones/m1_gate"
require_relative "../../tools/milestones/m0_gate"
require_relative "../../tools/milestones/m1_probe_support"

class M1GateTest < Minitest::Test
  class << self
    attr_accessor :fixture_gem_path
  end

  ROOT = File.expand_path("../..", __dir__)
  GATE = File.join(ROOT, "tools/milestones/m1_gate.rb")
  JSON_LIMIT_BYTES = M1Gate::MAX_JSON_BYTES
  M0_EXECUTABLES = %w[
    rubectl
    rubernetes-apiserver
    rubernetes-controller-manager
    rubernetes-scheduler
    rubernetes-agent
    rubernetes-proxy
  ].freeze
  M0_PROBES = %w[
    abi_manifest
    clone3_pid_namespace_mount_proc_pidfd_wait
    netlink_ack
    bpf_verifier
    kvm_capability
    errno_clone3
    errno_pidfd
    errno_mount
    errno_netlink
    errno_bpf
    errno_kvm
    errno_namespace_exec
    source_input_stability
  ].freeze
  M0_ERRNO = {
    "errno_clone3" => ["clone3", "intentional:clone3"],
    "errno_pidfd" => ["pidfd_open", "intentional:pidfd"],
    "errno_mount" => ["mount", "intentional:mount"],
    "errno_netlink" => ["netlink_ack", "intentional:netlink"],
    "errno_bpf" => ["bpf(BPF_PROG_LOAD)", "intentional:bpf"],
    "errno_kvm" => ["kvm_probe", "intentional:kvm"],
    "errno_namespace_exec" => ["execve", "intentional:namespace-exec"]
  }.freeze

  def test_gate_accepts_a_complete_content_addressed_bundle
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)

      stdout, stderr, status = run_gate(manifest_path)

      assert_predicate(status, :success?, stdout)
      assert_empty(stderr)
      assert_equal(true, JSON.parse(stdout).fetch("passed"))
    end
  end

  def test_gate_requires_the_full_api_surface_corpus_in_addition_to_operations
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      report_path = File.join(directory, "api-differential.json")
      report = JSON.parse(File.read(report_path))
      report.delete("api_surface")
      File.write(report_path, JSON.pretty_generate(report) << "\n")
      update_artifact_digest(manifest_path, "api-differential.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert_includes(JSON.parse(stdout).fetch("errors"), "API corpus-driven surface matrix is required")
    end
  end

  def test_gate_rejects_an_unexpected_semantic_header_exclusion
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      report_path = File.join(directory, "api-differential.json")
      report = JSON.parse(File.read(report_path))
      observation = report.fetch("operations").first.fetch("header_observation").fetch("expected")
      observation.fetch("excluded") << "x-kubernetes-test"
      observation.fetch("compared").delete("x-kubernetes-test")
      File.write(report_path, JSON.pretty_generate(report) << "\n")
      update_artifact_digest(manifest_path, "api-differential.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      errors = JSON.parse(stdout).fetch("errors")

      assert(errors.any? { |error| error.include?("excludes an unexpected header") })
      assert(errors.any? { |error| error.include?("hides a semantic header") })
    end
  end

  def test_gate_validates_every_surface_observation_field_and_digest
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      report_path = File.join(directory, "api-differential.json")
      report = JSON.parse(File.read(report_path))
      oracle = report.fetch("api_surface").fetch("gvr_matrix").first.fetch("oracle")
      oracle.fetch("fields").delete("kind")
      File.write(report_path, JSON.pretty_generate(report) << "\n")
      update_artifact_digest(manifest_path, "api-differential.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      errors = JSON.parse(stdout).fetch("errors")

      assert(errors.any? { |error| error.include?("fields must contain exactly the API surface fields") })
      assert(errors.any? { |error| error.include?("digest does not match fields") })
    end
  end

  def test_gate_rejects_a_missing_required_report
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      File.delete(File.join(directory, "roundtrip-report.json"))

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      errors = JSON.parse(stdout).fetch("errors")

      assert(errors.any? { |error| error.include?("missing artifact roundtrip-report.json") })
    end
  end

  def test_gate_rejects_an_artifact_digest_mismatch
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      File.write(File.join(directory, "generation-diff.json"), "{}\n")

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert_includes(JSON.parse(stdout).fetch("errors"), "artifact digest mismatch generation-diff.json")
    end
  end

  def test_gate_rejects_a_report_from_a_different_source_input
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      report_path = File.join(directory, "roundtrip-report.json")
      report = JSON.parse(File.read(report_path))
      report["input_sha256"] = "b" * 64
      File.write(report_path, JSON.pretty_generate(report) << "\n")
      update_artifact_digest(manifest_path, "roundtrip-report.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert_includes(JSON.parse(stdout).fetch("errors"), "roundtrip report input_sha256 must match manifest")
    end
  end

  def test_gate_rejects_an_unstable_capture
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      manifest = JSON.parse(File.read(manifest_path))
      manifest["input_stable"] = false
      manifest["input_capture"]["stable"] = false
      File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      errors = JSON.parse(stdout).fetch("errors")

      assert(errors.any? { |error| error.include?("source input must remain stable") })
      assert(errors.any? { |error| error.include?("input_capture must record a stable capture") })
    end
  end

  def test_gate_rejects_an_artifact_symlink_that_resolves_outside_the_bundle
    Dir.mktmpdir("rubernetes-m1-gate-") do |parent_directory|
      directory = File.join(parent_directory, "bundle")
      outside_path = File.join(parent_directory, "outside.json")
      Dir.mkdir(directory)
      File.write(outside_path, "outside")
      manifest_path = write_valid_evidence(directory)
      symlink_path = File.join(directory, "escaped.json")
      File.symlink(outside_path, symlink_path)
      add_artifact(manifest_path, "escaped.json", symlink_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert_includes(JSON.parse(stdout).fetch("errors"), "artifact escapes evidence directory escaped.json")
    end
  end

  def test_gate_rejects_duplicate_manifest_artifact_paths
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      manifest = JSON.parse(File.read(manifest_path))
      manifest["artifacts"] << manifest.fetch("artifacts").first.dup
      manifest["result_counts"]["artifacts"] += 1
      File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert(JSON.parse(stdout).fetch("errors").any? { |error| error.include?("duplicate artifact path") })
    end
  end

  def test_gate_rejects_missing_artifact_digest_and_byte_count
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      manifest = JSON.parse(File.read(manifest_path))
      artifact = manifest.fetch("artifacts").find { |entry| entry.fetch("path") == "api-differential.json" }
      artifact.delete("sha256")
      artifact.delete("bytes")
      File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      errors = JSON.parse(stdout).fetch("errors")

      assert(errors.any? { |error| error.include?("artifact api-differential.json must have a SHA-256 digest") })
      assert(errors.any? { |error| error.include?("artifact api-differential.json must have a non-negative byte count") })
    end
  end

  def test_gate_rejects_invalid_json_without_emitting_a_parser_backtrace
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      report_path = File.join(directory, "roundtrip-report.json")
      File.write(report_path, "{invalid json\n")
      update_artifact_digest(manifest_path, "roundtrip-report.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      errors = JSON.parse(stdout).fetch("errors")

      assert(errors.any? { |error| error.include?("roundtrip report is not valid JSON") })
      refute_includes(stdout, "backtrace")
    end
  end

  def test_gate_rejects_json_over_the_machine_readable_size_limit
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      report_path = File.join(directory, "roundtrip-report.json")
      File.write(report_path, "{\"payload\":\"#{"x" * JSON_LIMIT_BYTES}\"}\n")
      update_artifact_digest(manifest_path, "roundtrip-report.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert_includes(JSON.parse(stdout).fetch("errors"), "roundtrip report exceeds the #{JSON_LIMIT_BYTES}-byte JSON limit")
    end
  end

  def test_gate_rejects_duplicate_json_object_keys
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      report_path = File.join(directory, "api-differential.json")
      File.write(report_path, '{"schema_version":1,"schema_version":1}\n')
      update_artifact_digest(manifest_path, "api-differential.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert(JSON.parse(stdout).fetch("errors").any? { |error| error.include?("api report is not valid JSON") })
    end
  end

  def test_gate_rejects_report_kind_schema_and_inventory_count_spoofing
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      report_path = File.join(directory, "corpus-coverage.json")
      report = JSON.parse(File.read(report_path))
      report["kind"] = "m1_fake_report"
      report["gvk"]["registered_items"] = ["v1/Service"]
      File.write(report_path, JSON.pretty_generate(report) << "\n")
      update_artifact_digest(manifest_path, "corpus-coverage.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      errors = JSON.parse(stdout).fetch("errors")

      assert_includes(errors, "corpus report kind must be m1_corpus_coverage")
      refute(errors.any? { |error| error.include?("expected and registered item sets differ") }, "wrong kind must stop semantic parsing")
    end

    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      report_path = File.join(directory, "corpus-coverage.json")
      report = JSON.parse(File.read(report_path))
      report["gvk"]["registered_items"] = ["v1/Service"]
      File.write(report_path, JSON.pretty_generate(report) << "\n")
      update_artifact_digest(manifest_path, "corpus-coverage.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert_includes(JSON.parse(stdout).fetch("errors"), "corpus gvk expected and registered item sets differ")
    end
  end

  def test_gate_rejects_generation_roundtrip_and_api_count_spoofing
    mutations = [
      ["generation-diff.json", lambda { |report|
        report["runs"] = [report.fetch("runs").first]
      }, "generation report must record exactly two generation runs"],
      ["roundtrip-report.json", lambda { |report|
        report["cases"] = report.fetch("cases").first(3)
      }, "roundtrip case count does not match case entries"],
      ["api-differential.json", lambda { |report|
        report["operations"] = report.fetch("operations").first(4)
      }, "API operation count does not match operation entries"]
    ]
    mutations.each do |name, mutation, expected_error|
      Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
        manifest_path = write_valid_evidence(directory)
        report_path = File.join(directory, name)
        report = JSON.parse(File.read(report_path))
        mutation.call(report)
        File.write(report_path, JSON.pretty_generate(report) << "\n")
        update_artifact_digest(manifest_path, name, report_path)

        stdout, stderr, status = run_gate(manifest_path)

        refute_predicate(status, :success?)
        assert_empty(stderr)
        assert_includes(JSON.parse(stdout).fetch("errors"), expected_error)
      end
    end
  end

  def test_gate_rejects_source_inventory_entries_from_excluded_roots
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      inventory_path = File.join(directory, "source-inventory.json")
      inventory = JSON.parse(File.read(inventory_path))
      inventory.fetch("entries").first["path"] = "build/generated.rb"
      File.write(inventory_path, JSON.pretty_generate(inventory) << "\n")
      update_artifact_digest(manifest_path, "source-inventory.json", inventory_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert(JSON.parse(stdout).fetch("errors").any? { |error| error.include?("source inventory entry 0 path is invalid") })
    end
  end

  def test_gate_rejects_retry_skip_and_unclassified_evidence
    mutations = [
      ["roundtrip-report.json", "retry_count", 1, "roundtrip report retry count must be zero"],
      ["api-differential.json", "unexpected_skip_count", 1, "api report unexpected skip count must be zero"],
      ["kubectl-transcript.json", "unclassified_count", 1, "kubectl report unclassified count must be zero"]
    ]
    mutations.each do |name, key, value, expected_error|
      Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
        manifest_path = write_valid_evidence(directory)
        report_path = File.join(directory, name)
        report = JSON.parse(File.read(report_path))
        report[key] = value
        File.write(report_path, JSON.pretty_generate(report) << "\n")
        update_artifact_digest(manifest_path, name, report_path)

        stdout, stderr, status = run_gate(manifest_path)

        refute_predicate(status, :success?)
        assert_empty(stderr)
        assert_includes(JSON.parse(stdout).fetch("errors"), expected_error)
      end
    end

    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      manifest = JSON.parse(File.read(manifest_path))
      manifest.fetch("commands") << manifest.fetch("commands").first.dup
      manifest["result_counts"]["commands"] += 1
      File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert(JSON.parse(stdout).fetch("errors").any? { |error| error.include?("duplicate command name") })
    end
  end

  def test_gate_rejects_a_kubectl_retry_or_failed_operation_hidden_by_passed_flag
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      report_path = File.join(directory, "kubectl-transcript.json")
      report = JSON.parse(File.read(report_path))
      report.fetch("operations").first["exit_status"] = 1
      report.fetch("operations").first["passed"] = true
      report.fetch("operations").first["attempt_count"] = 2
      File.write(report_path, JSON.pretty_generate(report) << "\n")
      update_artifact_digest(manifest_path, "kubectl-transcript.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      errors = JSON.parse(stdout).fetch("errors")

      assert_includes(errors, "kubectl operation 0 did not pass")
      assert_includes(errors, "kubectl operation 0 must run exactly once")
    end
  end

  def test_gate_rejects_roundtrip_and_api_reports_without_executed_kubernetes_oracles
    %w[roundtrip-report.json api-differential.json].each do |name|
      Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
        manifest_path = write_valid_evidence(directory)
        report_path = File.join(directory, name)
        report = JSON.parse(File.read(report_path))
        report.fetch("oracle")["executed"] = false
        report.fetch("oracle")["comparison_count"] = 0
        report.fetch("oracle")["missing_comparison_count"] = 1
        File.write(report_path, JSON.pretty_generate(report) << "\n")
        update_artifact_digest(manifest_path, name, report_path)

        stdout, stderr, status = run_gate(manifest_path)

        refute_predicate(status, :success?)
        assert_empty(stderr)
        label = name.start_with?("roundtrip") ? "roundtrip" : "API"
        errors = JSON.parse(stdout).fetch("errors")

        assert_includes(errors, "#{label} Kubernetes oracle was not executed")
        assert_includes(errors, "#{label} Kubernetes oracle missing comparison count must be zero")
      end
    end
  end

  def test_gate_rejects_a_roundtrip_report_without_external_semantic_oracle
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      report_path = File.join(directory, "roundtrip-report.json")
      report = JSON.parse(File.read(report_path))
      report.delete("semantic_oracle")
      File.write(report_path, JSON.pretty_generate(report) << "\n")
      update_artifact_digest(manifest_path, "roundtrip-report.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert_includes(JSON.parse(stdout).fetch("errors"), "roundtrip semantic Kubernetes oracle evidence is missing")
    end
  end

  def test_gate_keeps_an_incomplete_validation_applicability_criterion_incomplete
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      report_path = File.join(directory, "roundtrip-report.json")
      report = JSON.parse(File.read(report_path))
      criterion = report.fetch("semantic_oracle").fetch("validation_criterion")
      criterion["status"] = "INCOMPLETE"
      criterion["applicable_count"] = 769
      criterion["not_applicable_count"] = 1
      criterion["ledger"][0]["applicable"] = false
      criterion["ledger"][0]["reason"] = "upstream source has no validation registration"
      File.write(report_path, JSON.pretty_generate(report) << "\n")
      update_artifact_digest(manifest_path, "roundtrip-report.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert_includes(JSON.parse(stdout).fetch("errors"), "roundtrip semantic Kubernetes oracle validation criterion remains INCOMPLETE")
    end
  end

  def test_validation_gate_rejects_an_invalid_strategy_marked_passed
    criterion = {
      "status" => "COMPLETE",
      "applicable_count" => 1,
      "not_applicable_count" => 0,
      "ledger" => [{"id" => "schema-0", "applicable" => true, "reason" => nil, "mode" => "strategy",
                    "source_paths" => ["test/validation.go"]}]
    }
    comparison = validation_oracle_evidence(["schema-0"], criterion).fetch("comparisons").fetch(0)
    comparison.fetch("operations").fetch("invalid")["accepted"] = false
    comparison.fetch("operations").fetch("invalid")["expected_accepted"] = true
    comparison.fetch("operations").fetch("invalid")["expectation_matches"] = false
    comparison["passed"] = true

    errors = []
    M1Gate.send(:validate_validation_operations, comparison, errors, "test validation comparison")

    assert(errors.any? { |error| error.include?("passed must bind to completed operations") })
  end

  def test_gate_rejects_an_external_oracle_marked_as_a_self_comparison
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      report_path = File.join(directory, "api-differential.json")
      report = JSON.parse(File.read(report_path))
      provenance = report.fetch("oracle").fetch("provenance")
      provenance["self_comparison"] = true
      provenance["provenance_sha256"] = M1Gate.canonical_document_digest(provenance)
      File.write(report_path, JSON.pretty_generate(report) << "\n")
      update_artifact_digest(manifest_path, "api-differential.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert_includes(JSON.parse(stdout).fetch("errors"), "API Kubernetes oracle provenance must not be a self-comparison")
    end
  end

  def test_source_identity_excludes_only_anchored_generator_temp_directories
    Dir.mktmpdir("rubernetes-source-identity-") do |directory|
      File.write(File.join(directory, "source.rb"), "source\n")
      Dir.mkdir(File.join(directory, "a11-generated.u1BHO1"))
      File.write(File.join(directory, "a11-generated.u1BHO1", "generated.rb"), "temporary\n")
      Dir.mkdir(File.join(directory, "a11-generated.bad"))
      File.write(File.join(directory, "a11-generated.bad", "source.rb"), "tracked\n")
      File.write(File.join(directory, "a11-generated.u1BHO1x"), "tracked-file\n")
      Dir.mkdir(File.join(directory, "nested"))
      Dir.mkdir(File.join(directory, "nested", "a11-generated.u1BHO1"))
      File.write(File.join(directory, "nested", "a11-generated.u1BHO1", "source.rb"), "tracked\n")

      entries = M1ProbeSupport.source_identity(directory).fetch("entries").map { |entry| entry.fetch("path") }

      refute_includes(entries, "a11-generated.u1BHO1/generated.rb")
      assert_includes(entries, "a11-generated.bad/source.rb")
      assert_includes(entries, "a11-generated.u1BHO1x")
      assert_includes(entries, "nested/a11-generated.u1BHO1/source.rb")
    end
  end

  def test_surface_helpers_cover_the_registry_and_wire_each_schema_contract
    registry_document = M1ProbeSupport.parse_json(File.join(ROOT, "generated/schema/registry.json"))
    server, _store, _document = M1ProbeSupport.build_api_server
    canonical = M1ProbeSupport.canonical_discovery_surface
    runtime = M1ProbeSupport.runtime_surface_entries(registry_document)

    assert_equal M1Gate::API_SURFACE_GVK_COUNT, registry_document.fetch("gvks").length
    assert_equal M1Gate::API_SURFACE_GVR_COUNT, canonical.length
    assert_equal M1Gate::API_SURFACE_GVR_COUNT, runtime.length
    assert_equal(
      registry_document.fetch("gvrs").map { |entry| entry.fetch("identifier") }.sort,
      runtime.map { |entry| M1ProbeSupport.surface_identifier(entry) }.sort
    )
    assert(runtime.all? { |entry| entry.fetch("schema_contract_present") == true })
    assert_equal registry_document.fetch("resources").length, server.registry.resources.length
    assert(server.registry.resources.all? { |resource| resource.schema.respond_to?(:validate) && resource.schema.respond_to?(:default) })
  end

  def test_gate_rejects_missing_or_different_input_m0_evidence
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      manifest = JSON.parse(File.read(manifest_path))
      manifest.delete("prior_milestones")
      File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert_includes JSON.parse(stdout).fetch("errors"),
                      "COMPLETE M0 evidence is required for cumulative M1 completion"
    end

    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      m0_path = File.join(directory, "m0", "manifest.json")
      m0_manifest = JSON.parse(File.read(m0_path))
      m0_manifest["input_sha256"] = "b" * 64
      File.write(m0_path, JSON.pretty_generate(m0_manifest) << "\n")
      update_artifact_digest(manifest_path, "m0/manifest.json", m0_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert_includes JSON.parse(stdout).fetch("errors"), "M0 evidence must use the same source input as M1"
    end
  end

  # A Git checkout is allowed: the capture only has to be stable.
  def test_gate_accepts_a_stable_git_metadata_capture_and_rejects_an_unstable_one
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      manifest = JSON.parse(File.read(manifest_path))
      manifest["git_metadata_capture"] = {
        "stable" => true,
        "start_paths" => ["vendor/example/.git"],
        "finish_paths" => ["vendor/example/.git"],
        "count" => 1
      }
      File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")
      stdout, stderr, status = run_gate(manifest_path)

      assert_predicate(status, :success?, stdout)
      assert_empty(stderr)

      manifest["git_metadata_capture"]["finish_paths"] = []
      File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")
      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert_includes JSON.parse(stdout).fetch("errors"), "git metadata changed during evidence capture"
    end
  end

  def test_gate_rejects_an_api_oracle_mismatch_hidden_by_a_zero_alias
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      report_path = File.join(directory, "api-differential.json")
      report = JSON.parse(File.read(report_path))
      report["oracle_difference_count"] = 1
      File.write(report_path, JSON.pretty_generate(report) << "\n")
      update_artifact_digest(manifest_path, "api-differential.json", report_path)

      stdout, stderr, status = run_gate(manifest_path)

      refute_predicate(status, :success?)
      assert_empty(stderr)
      assert_includes JSON.parse(stdout).fetch("errors"), "API oracle difference count must be zero"
    end
  end

  def test_command_line_gate_matches_the_in_process_report
    Dir.mktmpdir("rubernetes-m1-gate-") do |directory|
      manifest_path = write_valid_evidence(directory)
      stdout, stderr, status = run_gate_cli(manifest_path)
      in_process_stdout, _in_process_stderr, in_process_status = run_gate(manifest_path)

      assert_empty(stderr)
      assert_equal(in_process_status.success?, status.success?)
      cli = JSON.parse(stdout)
      in_process = JSON.parse(in_process_stdout)

      %w[passed milestone error_count errors].each { |key| assert_equal(in_process.fetch(key), cli.fetch(key), key) }
    end
  end

  private

  def write_valid_evidence(directory)
    source_entries = current_source_entries
    input_sha256 = Digest::SHA256.hexdigest(
      source_entries.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
    )
    input_file_count = source_entries.length
    write_json(directory, "source-inventory.json", source_inventory(input_sha256, input_file_count))
    write_json(directory, "corpus-coverage.json", corpus_report(input_sha256, input_file_count))
    write_json(directory, "generation-diff.json", generation_report(input_sha256, input_file_count))
    write_json(directory, "roundtrip-report.json", roundtrip_report(input_sha256, input_file_count))
    write_json(directory, "api-differential.json", api_report(input_sha256, input_file_count))
    write_json(directory, "kubectl-transcript.json", kubectl_report(input_sha256, input_file_count))
    prior_m0 = write_m0_evidence(directory, input_sha256, input_file_count)

    artifact_entries = Dir.glob(File.join(directory, "**/*")).select { |path| File.file?(path) }.sort.map do |path|
      name = path.delete_prefix("#{directory}/")
      {"path" => name, "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
    end
    timestamp = Time.now.utc.iso8601(6)
    commands = ["m0_gate", *REPORT_NAMES.map { |name| "m1_#{name}" }].map do |name|
      {
        "name" => name,
        "command" => ["adapter", name],
        "started_at" => timestamp,
        "finished_at" => timestamp,
        "exit_status" => 0
      }
    end
    identity = {"sha256" => input_sha256, "file_count" => input_file_count}
    manifest = {
      "schema_version" => 3,
      "milestone" => "M1",
      "status" => "COMPLETE",
      "host" => {"architecture" => "x86_64", "kernel" => "test-kernel", "ruby" => RUBY_DESCRIPTION},
      "input_sha256" => input_sha256,
      "input_file_count" => input_file_count,
      "input_stable" => true,
      "input_capture" => {"stable" => true, "start" => identity, "finish" => identity},
      "git_metadata_capture" => {"stable" => true, "start_paths" => [], "finish_paths" => [], "count" => 0},
      "started_at" => timestamp,
      "finished_at" => timestamp,
      "commands" => commands,
      "prior_milestones" => {"M0" => prior_m0},
      "result_counts" => {
        "commands" => commands.length,
        "command_failures" => 0,
        "artifacts" => artifact_entries.length,
        "subjects" => 0,
        "reports" => 5,
        "source_files" => input_file_count
      },
      "artifacts" => artifact_entries,
      "subjects" => []
    }
    manifest_path = File.join(directory, "manifest.json")
    File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")
    manifest_path
  end

  def write_m0_evidence(directory, input_sha256, input_file_count)
    m0_directory = File.join(directory, "m0")
    FileUtils.mkdir_p(m0_directory)
    timestamp = Time.now.utc.iso8601(6)
    source_entries = current_source_entries
    current_identity = Digest::SHA256.hexdigest(
      source_entries.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
    )
    unless current_identity == input_sha256 && source_entries.length == input_file_count
      raise "M0 fixture source input changed while building"
    end

    commands = m0_command_records(m0_directory, timestamp, source_entries)
    FileUtils.cp(current_gem_path, File.join(m0_directory, "rubernetes-0.1.0.gem"))
    write_json(m0_directory, "source-inventory.json", {
                 "schema_version" => 1, "kind" => "m0_source_inventory", "input_sha256" => input_sha256,
                 "input_file_count" => input_file_count, "entries" => source_entries
               })
    write_json(m0_directory, "gem-build.json", commands.first)

    subjects = m0_subjects(m0_directory)
    write_json(m0_directory, "executables.json", m0_executable_report(subjects, timestamp, m0_directory))
    native_entries = source_entries.select { |entry| entry.fetch("path").match?(%r{\Aext/rubernetes_linux/.*\.(?:c|cc|h)\z}) }
    write_json(m0_directory, "native-boundary-scan.json", {
                 "schema_version" => 2,
                 "kind" => "native_boundary_scan",
                 "command" => [RbConfig.ruby, "tools/milestones/native_boundary_scan.rb", "--output",
                               File.join(m0_directory, "native-boundary-scan.json")],
                 "output_path" => File.join(m0_directory, "native-boundary-scan.json"),
                 "tool_path" => "tools/milestones/native_boundary_scan.rb",
                 "tool_sha256" => Digest::SHA256.file(File.join(ROOT, "tools/milestones/native_boundary_scan.rb")).hexdigest,
                 "started_at" => timestamp,
                 "finished_at" => timestamp,
                 "host" => {"sysname" => Etc.uname[:sysname], "release" => Etc.uname[:release], "machine" => Etc.uname[:machine],
                            "ruby" => RUBY_DESCRIPTION},
                 "source_files" => native_entries,
                 "policy_branch_count" => 0,
                 "retry_count" => 0,
                 "authorization_count" => 0,
                 "state_machine_count" => 0,
                 "findings" => [],
                 "passed" => true
               })
    write_json(m0_directory, "abi-probe-x86_64.json", m0_abi_probe(input_sha256, timestamp, subjects, m0_directory))
    write_m0_junit(m0_directory, commands, source_entries)

    artifact_entries = %w[abi-probe-x86_64.json executables.json gem-build.json junit.xml native-boundary-scan.json
                          source-inventory.json].sort.map do |name|
      path = File.join(m0_directory, name)
      {"path" => name, "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
    end
    m0_manifest_path = File.join(m0_directory, "manifest.json")
    File.write(
      m0_manifest_path,
      JSON.pretty_generate(
        "schema_version" => 3,
        "milestone" => "M0",
        "status" => "COMPLETE",
        "host" => {"architecture" => RbConfig::CONFIG.fetch("host_cpu").sub("arm64", "aarch64").sub("amd64", "x86_64"),
                   "kernel" => Etc.uname[:release], "sysname" => Etc.uname[:sysname], "ruby" => RUBY_DESCRIPTION},
        "input_sha256" => input_sha256,
        "input_file_count" => input_file_count,
        "input_stable" => true,
        "input_capture" => {"stable" => true, "start" => {"sha256" => input_sha256, "file_count" => input_file_count},
                            "finish" => {"sha256" => input_sha256, "file_count" => input_file_count}},
        "started_at" => timestamp,
        "finished_at" => timestamp,
        "commands" => commands,
        "result_counts" => {"commands" => commands.length, "command_failures" => 0, "artifacts" => artifact_entries.length,
                            "subjects" => subjects.length, "architecture_profiles" => 1, "source_files" => input_file_count},
        "artifacts" => artifact_entries,
        "subjects" => subjects
      ) << "\n"
    )
    # In-process evaluation of the fixture's M0 gate (same module the CLI runs; the
    # CLI itself is covered by test_command_line_gate_matches_the_in_process_report).
    # Output bytes match `puts JSON.pretty_generate(result)` so the recorded digest is
    # the one the CLI would produce.
    gate_result = M0Gate.evaluate(m0_manifest_path)
    gate_stdout = JSON.pretty_generate(gate_result) + "\n"
    raise "test M0 fixture gate failed: #{gate_stdout}" unless gate_result.fetch("passed")

    gate_result_path = File.join(m0_directory, "gate-result.json")
    File.write(gate_result_path, gate_stdout)
    {
      "manifest_path" => "m0/manifest.json",
      "manifest_sha256" => Digest::SHA256.file(m0_manifest_path).hexdigest,
      "gate_result_path" => "m0/gate-result.json",
      "gate_result_sha256" => Digest::SHA256.file(gate_result_path).hexdigest,
      "input_sha256" => input_sha256,
      "input_file_count" => input_file_count,
      "gate_passed" => true
    }
  end

  # One fixture gem per process: its content is a function of the tree, which every
  # test asserts unchanged; rebuilding it per test cost 1.6 s x 29.
  def current_gem_path
    self.class.fixture_gem_path ||= begin
      # The M0 gate requires the gem subject at exactly build/rubernetes-0.1.0.gem.
      # rake test:parallel builds it once before the run and sets
      # RUBERNETES_TEST_FIXTURE_GEM_PREBUILT so concurrent gate processes share one
      # immutable file; plain `rake test` builds it here as before.
      path = File.join(ROOT, "build/rubernetes-0.1.0.gem")
      unless ENV["RUBERNETES_TEST_FIXTURE_GEM_PREBUILT"] == "1" && File.file?(path)
        FileUtils.mkdir_p(File.dirname(path))
        stdout, stderr, status = Open3.capture3("gem", "build", "rubernetes.gemspec", "--output", path, chdir: ROOT)
        raise "current M0 fixture gem build failed: #{stdout}#{stderr}" unless status.success?
      end

      path
    end
  end

  def authoritative_minitest_inventory
    @authoritative_minitest_inventory ||= begin
      stdout, stderr, status = Open3.capture3(RbConfig.ruby, "tools/milestones/m0_test_inventory.rb", chdir: ROOT)
      raise "Minitest inventory discovery failed: #{stderr}" unless status.success?

      JSON.parse(stdout)
    end
  end

  def m0_command_records(directory, timestamp, source_entries)
    values = {
      "gem_build" => ["gem", "build", "rubernetes.gemspec", "--output", File.join(directory, "rubernetes-0.1.0.gem")],
      "rake_test" => %w[bundle exec rake test],
      "executables" => [RbConfig.ruby, "tools/milestones/executables_probe.rb", "--output", File.join(directory, "executables.json")],
      "native_boundary_scan" => [RbConfig.ruby, "tools/milestones/native_boundary_scan.rb", "--output",
                                 File.join(directory, "native-boundary-scan.json")],
      "rbs_validate" => ["bundle", "exec", "rbs", "-I", "sig", "-I", "generated/rbs", "validate"],
      "kernel_probe_x86_64" => [RbConfig.ruby, "-I#{File.join(ROOT, "build/ext/rubernetes_linux")}", "tools/milestones/m0_kernel_probe.rb",
                                "--output", File.join(directory, "abi-probe-x86_64.json")]
    }
    test_entries = source_entries.select { |entry| entry.fetch("path").match?(%r{\Atest/.*_test\.rb\z}) }
    test_inventory_content = test_entries.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
    tool_paths = {
      "gem_build" => "rubernetes.gemspec",
      "rake_test" => "Gemfile",
      "executables" => "tools/milestones/executables_probe.rb",
      "native_boundary_scan" => "tools/milestones/native_boundary_scan.rb",
      "rbs_validate" => "Gemfile",
      "kernel_probe_x86_64" => "tools/milestones/m0_kernel_probe.rb"
    }
    values.map do |name, command|
      environment = if name == "rake_test"
                      {
                        "RUBERNETES_JUNIT" => File.join(directory, "junit.xml"),
                        "RUBERNETES_JUNIT_COMMAND_SHA256" => Digest::SHA256.hexdigest(JSON.generate(command)),
                        "RUBERNETES_JUNIT_TEST_PATTERN" => "test/**/*_test.rb",
                        "RUBERNETES_JUNIT_TEST_INVENTORY_SHA256" => Digest::SHA256.hexdigest(test_inventory_content),
                        "RUBERNETES_JUNIT_TEST_INVENTORY_COUNT" => test_entries.length.to_s
                      }
                    else
                      {}
                    end
      tool = tool_paths.fetch(name)
      {
        "name" => name,
        "command" => command,
        "started_at" => timestamp,
        "finished_at" => timestamp,
        "exit_status" => 0,
        "stdout" => if name == "rake_test"
                      "#{authoritative_minitest_inventory.fetch("testcase_count")} runs, 0 assertions, 0 failures, 0 errors, 0 skips\n"
                    elsif name == "gem_build"
                      "  Successfully built RubyGem\n  Name: rubernetes\n  Version: 0.1.0\n  File: rubernetes-0.1.0.gem\n"
                    else
                      ""
                    end,
        "stderr" => "",
        "environment" => environment,
        "tool_path" => tool,
        "tool_sha256" => Digest::SHA256.file(File.join(ROOT, tool)).hexdigest
      }
    end
  end

  def m0_subjects(directory)
    source_paths = M0_EXECUTABLES.map { |name| "exe/#{name}" }
    source_paths.concat(["generated/platform/linux/abi/x86_64.json", "build/ext/rubernetes_linux/rubernetes_linux.so",
                         "build/rubernetes-0.1.0.gem"])
    source_paths.map do |source_path|
      source = source_path == "build/rubernetes-0.1.0.gem" ? current_gem_path : File.join(ROOT, source_path)
      relative = "subjects/#{source_path == "build/rubernetes-0.1.0.gem" ? "rubernetes-0.1.0.gem" : File.basename(source_path)}"
      FileUtils.mkdir_p(File.dirname(File.join(directory, relative)))
      FileUtils.cp(source, File.join(directory, relative))
      evidence_entry(directory, relative).merge("source_path" => source_path)
    end
  end

  def m0_executable_report(subjects, timestamp, directory)
    subject_index = subjects.to_h { |subject| [subject.fetch("source_path"), subject] }
    results = M0_EXECUTABLES.product(%w[--help --version]).map do |executable, option|
      {
        "executable" => executable,
        "option" => option,
        "command" => [RbConfig.ruby, "-I#{ROOT}/lib", "#{ROOT}/exe/#{executable}", "--config", "/unreadable/m0-side-effect-sentinel",
                      option],
        "started_at" => timestamp,
        "finished_at" => timestamp,
        "exit_status" => 0,
        "stdout" => "#{executable} output\n",
        "stderr" => "",
        "binary_sha256" => subject_index.fetch("exe/#{executable}").fetch("sha256"),
        "passed" => true
      }
    end
    {
      "schema_version" => 1,
      "kind" => "m0_executables",
      "command" => [RbConfig.ruby, "tools/milestones/executables_probe.rb", "--output", File.join(directory, "executables.json")],
      "output_path" => File.join(directory, "executables.json"),
      "tool_path" => "tools/milestones/executables_probe.rb",
      "tool_sha256" => Digest::SHA256.file(File.join(ROOT, "tools/milestones/executables_probe.rb")).hexdigest,
      "started_at" => timestamp,
      "finished_at" => timestamp,
      "host" => {"sysname" => Etc.uname[:sysname], "release" => Etc.uname[:release], "machine" => Etc.uname[:machine],
                 "ruby" => RUBY_DESCRIPTION},
      "count" => results.length,
      "failure_count" => 0,
      "results" => results
    }
  end

  def m0_abi_probe(input_sha256, timestamp, subjects, directory)
    abi_subject = subjects.find { |entry| entry.fetch("source_path") == "generated/platform/linux/abi/x86_64.json" }
    native_subject = subjects.find { |entry| entry.fetch("source_path") == "build/ext/rubernetes_linux/rubernetes_linux.so" }
    native_sources = current_source_entries.select { |entry| entry.fetch("path").match?(%r{\Aext/rubernetes_linux/.*\.(?:c|cc|h|rb)\z}) }
    native_content = native_sources.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
    results = M0_PROBES.map do |name|
      result = if name == "abi_manifest"
                 {"manifest" => "generated/platform/linux/abi/x86_64.json", "manifest_sha256" => abi_subject.fetch("sha256"),
                  "manifest_bytes" => abi_subject.fetch("bytes"), "mismatch_count" => 0}
               elsif name == "clone3_pid_namespace_mount_proc_pidfd_wait"
                 {"pid" => 1234, "pidfd" => 9, "exit_status" => 0, "ps_pids" => [1], "ps_output" => "  1 ps\n"}
               elsif name == "netlink_ack"
                 {"sequence" => 60_000, "message_types" => [16]}
               elsif name == "bpf_verifier"
                 {"fd" => 5, "verifier_log" => "processed 2 insns"}
               elsif name == "kvm_capability"
                 {"api_version" => 12, "capabilities" => {"3" => 1, "9" => 64}}
               elsif name == "source_input_stability"
                 {"sha256" => input_sha256, "file_count" => current_source_entries.length}
               elsif M0_ERRNO.key?(name)
                 operation, resource_id = M0_ERRNO.fetch(name)
                 {"errno" => 22, "errno_name" => "EINVAL", "operation" => operation, "resource_id" => resource_id,
                  "details" => {}, "message" => "Invalid argument - #{operation}; resource=#{resource_id}"}
               else
                 {"observed" => true}
               end
      {"name" => name, "started_at" => timestamp, "finished_at" => timestamp, "passed" => true, "result" => result}
    end
    {
      "schema_version" => 2,
      "kind" => "m0_abi_probe",
      "architecture" => "x86_64",
      "input_sha256" => input_sha256,
      "input_file_count" => current_source_entries.length,
      "input_stable" => true,
      "command" => [RbConfig.ruby, "-I#{File.join(ROOT, "build/ext/rubernetes_linux")}", "tools/milestones/m0_kernel_probe.rb", "--output",
                    File.join(directory, "abi-probe-x86_64.json")],
      "output_path" => File.join(directory, "abi-probe-x86_64.json"),
      "tool_path" => "tools/milestones/m0_kernel_probe.rb",
      "tool_sha256" => Digest::SHA256.file(File.join(ROOT, "tools/milestones/m0_kernel_probe.rb")).hexdigest,
      "started_at" => timestamp,
      "finished_at" => timestamp,
      "probe_count" => results.length,
      "host" => {"sysname" => Etc.uname[:sysname], "release" => Etc.uname[:release], "machine" => Etc.uname[:machine],
                 "ruby" => RUBY_DESCRIPTION},
      "native_extension" => {
        "path" => "build/ext/rubernetes_linux/rubernetes_linux.so",
        "loaded_feature" => "build/ext/rubernetes_linux/rubernetes_linux.so",
        "sha256" => native_subject.fetch("sha256"),
        "bytes" => native_subject.fetch("bytes"),
        "source_sha256" => Digest::SHA256.hexdigest(native_content),
        "source_file_count" => native_sources.length,
        "source_files" => native_sources
      },
      "failure_count" => 0,
      "results" => results
    }
  end

  def write_m0_junit(directory, commands, source_entries)
    test_entries = source_entries.select { |entry| entry.fetch("path").match?(%r{\Atest/.*_test\.rb\z}) }
    test_inventory_content = test_entries.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
    testcases = authoritative_minitest_inventory.fetch("testcases").map { |item| [item.fetch("classname"), item.fetch("name")] }
    status_inventory = testcases.map { |classname, name| "#{classname}\0#{name}\0passed\n" }.sort.join
    identity_inventory = testcases.sort.map { |classname, name| "#{classname}\0#{name}\n" }.join
    attributes = {
      "name" => "rubernetes",
      "tests" => testcases.length,
      "failures" => 0,
      "errors" => 0,
      "skipped" => 0,
      "reporter_path" => "test/support/junit_reporter.rb",
      "reporter_sha256" => Digest::SHA256.file(File.join(ROOT, "test/support/junit_reporter.rb")).hexdigest,
      "testcase_inventory_sha256" => Digest::SHA256.hexdigest(status_inventory),
      "testcase_inventory_count" => testcases.length,
      "registered_testcase_inventory_sha256" => Digest::SHA256.hexdigest(identity_inventory),
      "registered_testcase_inventory_count" => testcases.length,
      "executed_testcase_inventory_sha256" => Digest::SHA256.hexdigest(identity_inventory),
      "inventory_complete" => true,
      "command_sha256" => Digest::SHA256.hexdigest(JSON.generate(commands.find do |entry|
        entry.fetch("name") == "rake_test"
      end.fetch("command"))),
      "test_pattern" => "test/**/*_test.rb",
      "test_inventory_sha256" => Digest::SHA256.hexdigest(test_inventory_content),
      "test_inventory_count" => test_entries.length
    }
    serialized_attributes = attributes.map { |key, value| %(#{key}="#{value}") }.join(" ")
    cases = testcases.map { |classname, name| %(<testcase classname="#{classname}" name="#{name}" time="0.001000"/>) }.join
    File.write(File.join(directory, "junit.xml"), %(<testsuite #{serialized_attributes}>#{cases}</testsuite>))
  end

  def evidence_entry(directory, relative)
    path = File.join(directory, relative)
    {"path" => relative, "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
  end

  def current_source_entries
    paths = Dir.glob(File.join(ROOT, "**/*"), File::FNM_DOTMATCH).select do |path|
      relative = path.delete_prefix("#{ROOT}/")
      if relative.empty? || relative.match?(%r{\A(?:\.git|artifacts|build|pkg|tmp|\.bundle)(?:/|\z)|\Aa11-generated\.[A-Za-z0-9]{6,}/|\Aapps/[^/]+/(?:log|tmp|storage)/})
        next false
      end

      # Another test's scratch (excluded above) can vanish between glob and lstat.
      begin
        File.lstat(path).file?
      rescue Errno::ENOENT
        false
      end
    end.sort
    paths.map do |path|
      {"path" => path.delete_prefix("#{ROOT}/"), "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
    end
  end

  def source_inventory(input_sha256, input_file_count)
    entries = current_source_entries
    {
      "schema_version" => 1,
      "kind" => "m1_source_inventory",
      "input_sha256" => input_sha256,
      "input_file_count" => input_file_count,
      "input_stable" => true,
      "entries" => entries
    }
  end

  def corpus_report(input_sha256, input_file_count)
    report_base(input_sha256, input_file_count, "m1_corpus_coverage").merge(
      "gvk" => coverage_items(321, "gvk"),
      "gvr" => coverage_items(153, "gvr"),
      "failure_count" => 0
    )
  end

  def generation_report(input_sha256, input_file_count)
    tree_sha256 = Digest::SHA256.hexdigest("generated-tree")
    report_base(input_sha256, input_file_count, "m1_generation_diff").merge(
      "runs" => [{"id" => "first", "tree_sha256" => tree_sha256}, {"id" => "second", "tree_sha256" => tree_sha256}],
      "canonical_tree_sha256" => tree_sha256,
      "byte_differences" => [],
      "canonical_differences" => [],
      "byte_diff_count" => 0,
      "canonical_diff_count" => 0,
      "missing_count" => 0,
      "unexpected_count" => 0,
      "failure_count" => 0
    )
  end

  def roundtrip_report(input_sha256, input_file_count)
    case_ids = Array.new(770) { |index| "schema-#{index}" }
    semantic = semantic_oracle_evidence(case_ids)
    report_base(input_sha256, input_file_count, "m1_roundtrip_report").merge(
      "gvk_count" => 311,
      "case_count" => 770,
      "registry_gvk_count" => 321,
      "protobuf_expected_supported_count" => 770,
      "protobuf_supported_count" => 770,
      "protobuf_unsupported_count" => 1,
      "protobuf_unsupported_types" => [{"id" => "io.k8s.apimachinery.pkg.version.Info", "reason" => "upstream has no generated.proto"}],
      "gvks" => Array.new(311) { |index| {"id" => "gvk-#{index}"} },
      "cases" => case_ids.map do |id|
        {
          "id" => id,
          "passed" => true,
          "attempt_count" => 1,
          "json_roundtrip" => true,
          "protobuf_roundtrip" => true,
          "unknown_field" => true,
          "defaulting" => true,
          "validation" => true,
          "semantic_oracle" => true
        }
      end,
      "oracle" => oracle_evidence(case_ids, kind: M1Gate::KUBERNETES_PROTOBUF_ORACLE_KIND),
      "validation_oracle" => validation_oracle_evidence(case_ids, semantic.fetch("validation_criterion")),
      "semantic_oracle" => semantic,
      "unknown_field_mismatch_packet" => unknown_field_mismatch_packet_evidence(case_ids),
      "failure_count" => 0,
      "json_roundtrip_failures" => 0,
      "protobuf_roundtrip_failures" => 0,
      "unknown_field_failures" => 0,
      "defaulting_failures" => 0,
      "validation_failures" => 0,
      "oracle_difference_count" => 0,
      "semantic_difference_count" => 0
    )
  end

  def api_report(input_sha256, input_file_count)
    surface = api_surface_fixture
    operations = M1Gate::REQUIRED_API_OPERATION_INVENTORY.each_with_index.map do |inventory, index|
      api_operation_fixture(inventory, index)
    end
    report_base(input_sha256, input_file_count, "m1_api_differential").merge(
      "operation_count" => operations.length,
      "passed_count" => operations.length,
      "operations" => operations,
      "header_policy" => M1Gate::HEADER_EXCLUSION_ALLOWLIST,
      "header_policy_sha256" => M1Gate.canonical_document_digest(M1Gate::HEADER_EXCLUSION_ALLOWLIST),
      "api_surface" => surface,
      "oracle" => oracle_evidence(operations, kind: M1Gate::KUBERNETES_API_ORACLE_KIND),
      "failure_count" => 0,
      "unexpected_skip_count" => 0,
      "unclassified_count" => 0,
      "difference_count" => 0,
      "oracle_difference_count" => 0,
      "self_check_difference_count" => 0,
      "status_mismatch_count" => 0,
      "header_mismatch_count" => 0,
      "status_body_mismatch_count" => 0,
      "defaulting_mismatch_count" => 0,
      "validation_mismatch_count" => 0,
      "ownership_mismatch_count" => 0,
      "watch_failure_count" => 0
    )
  end

  def api_operation_fixture(inventory, _index)
    headers = {"content-type" => "application/json", "x-kubernetes-test" => "semantic"}
    packet = {
      "status" => 200,
      "headers" => headers,
      "body" => {},
      "ownership" => []
    }
    expected = JSON.parse(JSON.generate(packet))
    actual = JSON.parse(JSON.generate(packet))
    expected_digest = M1Gate.canonical_document_digest(expected)
    request = inventory.fetch("request")
    {
      "id" => inventory.fetch("id"),
      "method" => inventory.fetch("method"),
      "path" => inventory.fetch("path"),
      "request" => request,
      "request_sha256" => M1Gate.canonical_document_digest(request),
      "oracle_status" => 200,
      "rubernetes_status" => 200,
      "status_matches" => true,
      "header_matches" => true,
      "body_matches" => true,
      "status_body_matches" => true,
      "defaulting_matches" => true,
      "validation_matches" => true,
      "ownership_matches" => true,
      "watch_matches" => true,
      "resource_version_causality_matches" => true,
      "expected_sha256" => expected_digest,
      "actual_sha256" => M1Gate.canonical_document_digest(actual),
      "header_observation" => {
        "expected" => header_observation_fixture(all: headers),
        "actual" => header_observation_fixture(all: headers)
      },
      "resource_version_observation" => nil,
      "attempt_count" => 1,
      "differences" => [],
      "oracle_observable" => expected,
      "rubernetes_observable" => actual,
      "passed" => true
    }
  end

  def api_surface_fixture
    registry = M1ProbeSupport.parse_json(File.join(ROOT, "generated/schema/registry.json"))
    gvr_ids = registry.fetch("gvrs").map { |entry| entry.fetch("identifier") }
    gvk_ids = registry.fetch("gvks").map { |entry| entry.fetch("identifier") }
    pinned = M1Gate.send(:pinned_surface_expectations, [])
    runtime_rows = M1ProbeSupport.runtime_surface_entries(registry)
    runtime_by_gvr = runtime_rows.to_h { |row| [M1ProbeSupport.surface_identifier(row), row] }
    gvr_matrix = gvr_ids.map do |id|
      expected = pinned.fetch("gvr").fetch(id)
      runtime = runtime_by_gvr.fetch(id)
      fields = runtime.slice(*M1Gate::API_SURFACE_FIELDS)
      disabled = M1Gate::DEFAULT_OFF_GVR_IDS.include?(id)
      {
        "id" => id,
        "attempt_count" => 1,
        "passed" => true,
        "availability" => disabled ? "not_served_default" : "served",
        "availability_reason" => disabled ? M1Gate::DEFAULT_OFF_REASON : nil,
        "expected" => expected,
        "oracle" => disabled ? absent_surface_observation : surface_observation(expected),
        "rubernetes" => disabled ? absent_surface_observation : surface_observation(expected)
      }.merge(fields)
    end
    type_index = registry.fetch("types").to_h { |entry| [entry.fetch("schema"), entry] }
    runtime_by_gvk = {}
    runtime_rows.each do |row|
      id = M1ProbeSupport.identifier(row.fetch("group", ""), row.fetch("version"), row.fetch("kind"))
      runtime_by_gvk[id] ||= row
      next if row.fetch("listKind", "").empty?

      list_row = row.merge(
        "kind" => row.fetch("listKind"), "listKind" => "", "singular" => "",
        "subresources" => [], "shortNames" => [], "categories" => []
      )
      list_id = M1ProbeSupport.identifier(list_row.fetch("group", ""), list_row.fetch("version"), list_row.fetch("kind"))
      runtime_by_gvk[list_id] ||= list_row
    end
    gvk_matrix = gvk_ids.map do |id|
      registry_entry = registry.fetch("gvks").find { |entry| entry.fetch("identifier") == id }
      expected = pinned.fetch("gvk")[id]
      disabled = M1Gate::DEFAULT_OFF_GVK_IDS.include?(id)
      runtime = runtime_by_gvk[id]
      schema_present = M1ProbeSupport.schema_contract_present?(registry_entry.fetch("schema"), type_index: type_index)
      fields = if runtime
                 runtime.slice(*M1Gate::API_SURFACE_FIELDS)
               else
                 group, version, kind = id.split("/", 3)
                 {
                   "group" => group == "core" ? "" : group,
                   "version" => version,
                   "resource" => "",
                   "kind" => kind,
                   "scope" => "",
                   "plural" => "",
                   "singular" => "",
                   "verbs" => [],
                   "subresources" => [],
                   "shortNames" => [],
                   "categories" => [],
                   "listKind" => "",
                   "schema_contract_present" => schema_present
                 }
               end
      fields["group"] = registry_entry.fetch("group", "").to_s
      fields["version"] = registry_entry.fetch("version").to_s
      fields["kind"] = registry_entry.fetch("kind").to_s
      fields["schema_contract_present"] = schema_present
      {
        "id" => id,
        "attempt_count" => 1,
        "passed" => true,
        "availability" => disabled ? "not_served_default" : "served",
        "availability_reason" => disabled ? M1Gate::DEFAULT_OFF_REASON : nil,
        "expected_present" => !expected.nil?,
        "oracle_present" => !expected.nil? && !disabled,
        "rubernetes_present" => !expected.nil? && !disabled,
        "expected" => expected,
        "oracle" => expected.nil? || disabled ? absent_surface_observation : surface_observation(expected),
        "rubernetes" => expected.nil? || disabled ? absent_surface_observation : surface_observation(expected),
        "schema_contract_applicable" => registry_entry["schema"].is_a?(String) && !registry_entry["schema"].empty?
      }.merge(fields)
    end
    endpoints = M1Gate.send(:pinned_discovery_endpoint_inventory).map do |endpoint|
      path = endpoint.fetch("path")
      default_off = M1Gate::DEFAULT_OFF_DISCOVERY_PATHS.include?(path)
      source_path = endpoint.fetch("source_path")
      body = if default_off
               M1Gate.send(:canonical_discovery_value, M1Gate.send(:default_off_discovery_body, path))
             else
               source_file = File.join(ROOT, source_path)
               document = M1ProbeSupport.parse_json(source_file)
               M1Gate.send(:default_profile_discovery_value, path: source_file, document: document, endpoint: path)
             end
      body = M1Gate.send(:canonical_discovery_value, body)
      sha = M1Gate.send(:canonical_discovery_digest, body)
      {
        "id" => path,
        "path" => path,
        "source_path" => source_path,
        "attempt_count" => 1,
        "availability" => default_off ? "not_served_default" : "served",
        "availability_reason" => default_off ? M1Gate::DEFAULT_OFF_REASON : nil,
        "oracle_status" => default_off ? 404 : 200,
        "rubernetes_status" => default_off ? 404 : 200,
        "expected_source" => "pinned_kubernetes_discovery",
        "oracle_source" => "kubernetes_external",
        "rubernetes_source" => "rubernetes",
        "comparison_scope" => "full_semantic",
        "expected_sha256" => sha,
        "oracle_sha256" => sha,
        "rubernetes_sha256" => sha,
        "expected_body" => body,
        "oracle_body" => body,
        "rubernetes_body" => body,
        "header_matches" => true,
        "header_observation" => {
          "expected" => header_observation_fixture,
          "actual" => header_observation_fixture
        },
        "passed" => true
      }
    end
    {
      "registry_gvk_count" => M1Gate::API_SURFACE_GVK_COUNT,
      "registry_gvr_count" => M1Gate::API_SURFACE_GVR_COUNT,
      "discovery_endpoint_count" => M1Gate::API_SURFACE_ENDPOINT_COUNT,
      "feature_profile" => {
        "name" => M1Gate::DEFAULT_PROFILE,
        "feature_gates" => {
          "MutatingAdmissionPolicy" => true,
          "ClusterTrustBundle" => false,
          "PodCertificateRequest" => false,
          "CoordinatedLeaderElection" => false,
          "MultiCIDRServiceAllocator" => true,
          "DynamicResourceAllocation" => true,
          "GenericWorkload" => false,
          "VolumeAttributesClass" => true,
          "StorageVersionMigrator" => false,
          "StorageVersionAPI" => false
        },
        "default_off_gvr_ids" => M1Gate::DEFAULT_OFF_GVR_IDS,
        "default_off_gvk_ids" => M1Gate::DEFAULT_OFF_GVK_IDS,
        "default_off_discovery_paths" => M1Gate::DEFAULT_OFF_DISCOVERY_PATHS,
        "reason" => M1Gate::DEFAULT_OFF_REASON
      },
      "registry_gvk_ids" => gvk_ids,
      "registry_gvr_ids" => gvr_ids,
      "discovery_endpoints" => endpoints,
      "gvk_matrix" => gvk_matrix,
      "gvr_matrix" => gvr_matrix,
      "oracle_missing_count" => 0,
      "rubernetes_missing_count" => 0,
      "duplicate_count" => 0,
      "unexpected_count" => 0,
      "endpoint_difference_count" => 0,
      "difference_count" => 0,
      "schema_contract_missing_count" => 0,
      "passed" => true
    }
  end

  def surface_observation(fields)
    {
      "present" => true,
      "fields" => fields,
      "sha256" => M1Gate.canonical_document_digest(fields)
    }
  end

  def absent_surface_observation
    {"present" => false, "fields" => nil, "sha256" => nil}
  end

  def header_observation_fixture(all: nil)
    all ||= {
      "content-type" => "application/json",
      "date" => "2026-01-01T00:00:00Z",
      "x-kubernetes-test" => "semantic"
    }
    compared = all.reject { |name, _value| name == "date" }
    {
      "all" => all,
      "compared" => compared,
      "excluded" => all.key?("date") ? ["date"] : [],
      "all_sha256" => M1Gate.canonical_document_digest(all),
      "compared_sha256" => M1Gate.canonical_document_digest(compared)
    }
  end

  def kubectl_report(input_sha256, input_file_count)
    report_base(input_sha256, input_file_count, "m1_kubectl_transcript").merge(
      "operation_count" => REQUIRED_OPERATIONS.length,
      "failure_count" => 0,
      "unexpected_skip_count" => 0,
      "unclassified_count" => 0,
      "operations" => REQUIRED_OPERATIONS.map do |operation|
        record = {"operation" => operation, "exit_status" => 0, "passed" => true, "attempt_count" => 1, "command" => ["kubectl", operation]}
        if operation == "apply-invalid"
          record.merge!("exit_status" => 1, "expected_exit_status" => 1,
                        "stderr" => "error: unknown field \"dataz\"")
        end
        record
      end
    )
  end

  def report_base(input_sha256, input_file_count, kind)
    {
      "schema_version" => 1,
      "kind" => kind,
      "input_sha256" => input_sha256,
      "input_file_count" => input_file_count,
      "input_stable" => true,
      "retry_count" => 0,
      "unexpected_skip_count" => 0,
      "unclassified_count" => 0,
      "flake_count" => 0,
      "passed" => true
    }
  end

  def oracle_evidence(ids, kind:)
    return api_oracle_evidence(ids) if kind == M1Gate::KUBERNETES_API_ORACLE_KIND

    seed = Digest::SHA256.hexdigest("m1-oracle-seed")
    runner = Digest::SHA256.hexdigest("test-oracle-runner")
    source = if [M1Gate::KUBERNETES_PROTOBUF_ORACLE_KIND, M1Gate::KUBERNETES_SEMANTICS_ORACLE_KIND].include?(kind)
               {
                 "version" => M1Gate::KUBERNETES_VERSION,
                 "commit" => M1Gate::KUBERNETES_SOURCE_COMMIT,
                 "tag" => M1Gate::KUBERNETES_VERSION,
                 "root" => "/tmp/kubernetes-v1.36.2",
                 "tree_clean" => true
               }
             else
               {
                 "version" => M1Gate::KUBERNETES_VERSION,
                 "commit" => M1Gate::KUBERNETES_SOURCE_COMMIT,
                 "tag" => M1Gate::KUBERNETES_VERSION,
                 "apiserver_image" => "registry.k8s.io/kube-apiserver@sha256:#{"a" * 64}",
                 "etcd_image" => "registry.k8s.io/etcd@sha256:#{"b" * 64}",
                 "network_isolated" => true
               }
             end
    provenance = {
      "kind" => kind,
      "mode" => "external",
      "self_comparison" => false,
      "implementation" => "test external Kubernetes oracle",
      "source" => source,
      "runner_sha256" => runner,
      "request_seed_sha256" => seed
    }
    provenance["provenance_sha256"] = M1Gate.canonical_document_digest(provenance)
    {
      "executed" => true,
      "kubernetes_version" => M1Gate::KUBERNETES_VERSION,
      "source_commit" => M1Gate::KUBERNETES_SOURCE_COMMIT,
      "runner_sha256" => runner,
      "request_seed_sha256" => seed,
      "comparison_count" => ids.length,
      "missing_comparison_count" => 0,
      "provenance" => provenance,
      "comparisons" => ids.map do |id|
        digest = Digest::SHA256.hexdigest("observable:#{id}")
        {
          "id" => id,
          "attempt_count" => 1,
          "passed" => true,
          "expected_source" => "kubernetes_external",
          "actual_source" => "rubernetes",
          "expected_sha256" => digest,
          "actual_sha256" => digest
        }
      end
    }
  end

  def api_oracle_evidence(operations)
    stream = M1Gate.send(:expected_api_request_stream, operations)
    stream_digest = M1Gate.canonical_document_digest(stream)
    records = api_container_execution_fixture
    execution_digest = M1Gate.canonical_document_digest(records)
    source_files = %w[tools/milestones/m1_api_probe.rb tools/milestones/m1_kubernetes_oracle.rb].map do |relative|
      path = File.join(ROOT, relative)
      {"path" => relative, "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
    end
    runner_material = {
      "source_files" => source_files,
      "pinned_images" => {
        "kube_apiserver" => M1Gate::KUBE_APISERVER_IMAGE,
        "etcd" => M1Gate::ETCD_IMAGE
      },
      "container_execution_sha256" => execution_digest
    }
    runner_digest = M1Gate.canonical_document_digest(runner_material)
    source = {
      "version" => M1Gate::KUBERNETES_VERSION,
      "commit" => M1Gate::KUBERNETES_SOURCE_COMMIT,
      "tag" => M1Gate::KUBERNETES_VERSION,
      "apiserver_image" => M1Gate::KUBE_APISERVER_IMAGE,
      "etcd_image" => M1Gate::ETCD_IMAGE,
      "network_isolated" => true
    }
    provenance = {
      "kind" => M1Gate::KUBERNETES_API_ORACLE_KIND,
      "mode" => "external",
      "self_comparison" => false,
      "implementation" => "isolated Kubernetes kube-apiserver and etcd",
      "source" => source,
      "runner_sha256" => runner_digest,
      "request_seed_sha256" => stream_digest
    }
    provenance["provenance_sha256"] = M1Gate.canonical_document_digest(provenance)
    {
      "executed" => true,
      "kubernetes_version" => M1Gate::KUBERNETES_VERSION,
      "source_commit" => M1Gate::KUBERNETES_SOURCE_COMMIT,
      "kube_apiserver_image" => M1Gate::KUBE_APISERVER_IMAGE,
      "etcd_image" => M1Gate::ETCD_IMAGE,
      "runner_sha256" => runner_digest,
      "request_seed_sha256" => stream_digest,
      "container_execution" => records,
      "container_execution_sha256" => execution_digest,
      "runner_material" => runner_material,
      "request_stream" => stream,
      "request_stream_sha256" => stream_digest,
      "request_sequence" => "configmap-v1",
      "comparison_count" => operations.length,
      "missing_comparison_count" => 0,
      "provenance" => provenance,
      "comparisons" => operations.map do |operation|
        {
          "id" => operation.fetch("id"),
          "attempt_count" => 1,
          "passed" => true,
          "expected_source" => "kubernetes_external",
          "actual_source" => "rubernetes",
          "expected_sha256" => operation.fetch("expected_sha256"),
          "actual_sha256" => operation.fetch("actual_sha256")
        }
      end
    }
  end

  def api_container_execution_fixture
    kube = M1Gate::KUBE_APISERVER_IMAGE
    etcd = M1Gate::ETCD_IMAGE
    commands = [
      ["docker", "image", "inspect", kube, "--format", "{{json .RepoDigests}}", JSON.generate([kube])],
      ["docker", "image", "inspect", etcd, "--format", "{{json .RepoDigests}}", JSON.generate([etcd])],
      ["docker", "network", "create", "--label", "rubernetes.m1.oracle=true", "rubernetes-m1-oracle-net-fixture", ""],
      ["docker", "run", "--detach", "--name", "rubernetes-m1-oracle-etcd-fixture", "--network", "rubernetes-m1-oracle-net-fixture", etcd,
       "--name", "m1-oracle", ""],
      ["docker", "exec", "rubernetes-m1-oracle-etcd-fixture", "/usr/local/bin/etcdctl", "--endpoints=http://127.0.0.1:2379", "endpoint",
       "health", ""],
      ["docker", "run", "--detach", "--name", "rubernetes-m1-oracle-api-fixture", "--network", "rubernetes-m1-oracle-net-fixture", kube,
       "--secure-port=6443", ""],
      ["docker", "port", "rubernetes-m1-oracle-api-fixture", "6443/tcp", ""]
    ]
    commands.map.with_index do |command, index|
      stdout = command.pop
      {
        "sequence" => index,
        "argv" => command,
        "stdout" => stdout,
        "stderr" => "",
        "exit_status" => 0
      }
    end
  end

  def semantic_oracle_evidence(ids)
    oracle = oracle_evidence(ids, kind: M1Gate::KUBERNETES_SEMANTICS_ORACLE_KIND)
    oracle["source_root"] = "/tmp/kubernetes-v1.36.2"
    oracle["source_tree_clean"] = true
    oracle["validation_criterion"] = {
      "status" => "COMPLETE",
      "applicable_count" => ids.length,
      "not_applicable_count" => 0,
      "ledger" => ids.map do |id|
        {"id" => id, "applicable" => true, "reason" => nil, "mode" => "strategy", "source_paths" => ["test/validation.go"]}
      end
    }
    oracle["comparisons"] = ids.map do |id|
      json_observation = {
        "accepted" => true,
        "canonical_sha256" => Digest::SHA256.hexdigest("json-canonical:#{id}"),
        "unknown_accepted" => true,
        "unknown_canonical_sha256" => Digest::SHA256.hexdigest("json-unknown-canonical:#{id}"),
        "unknown_field_preserved" => false,
        "strict_unknown_accepted" => false
      }
      json_digest = M1Gate.canonical_document_digest(json_observation)
      json_dimension = {
        "applicable" => true,
        "reason" => nil,
        "expected_sha256" => json_digest,
        "actual_sha256" => json_digest,
        "expected_source" => "kubernetes_external",
        "actual_source" => "rubernetes",
        "expected" => json_observation,
        "actual" => json_observation,
        "matches" => true,
        "expected_observation" => {
          "raw_sha256" => Digest::SHA256.hexdigest("json-raw:#{id}"),
          "canonical_sha256" => Digest::SHA256.hexdigest("json-canonical:#{id}"),
          "unknown_raw_sha256" => Digest::SHA256.hexdigest("json-unknown-raw:#{id}"),
          "unknown_canonical_sha256" => Digest::SHA256.hexdigest("json-unknown-canonical:#{id}")
        },
        "actual_observation" => {
          "raw_sha256" => Digest::SHA256.hexdigest("ruby-json-raw:#{id}"),
          "canonical_sha256" => Digest::SHA256.hexdigest("ruby-json-canonical:#{id}"),
          "unknown_raw_sha256" => Digest::SHA256.hexdigest("ruby-json-unknown-raw:#{id}"),
          "unknown_canonical_sha256" => Digest::SHA256.hexdigest("ruby-json-unknown-canonical:#{id}")
        }
      }
      defaulting = Digest::SHA256.hexdigest("defaulting:#{id}")
      validation_observation = {
        "applicable" => true,
        "accepted" => true,
        "errors" => [],
        "missing_accepted" => true,
        "missing_errors" => []
      }
      validation = M1Gate.canonical_document_digest(validation_observation)
      defaulting_observation = {"applicable" => false, "reason" => "test fixture has no defaulting entrypoint"}
      {
        "id" => id,
        "attempt_count" => 1,
        "passed" => true,
        "json" => json_dimension,
        "json_expected_source" => "kubernetes_external",
        "json_actual_source" => "rubernetes",
        "json_expected_sha256" => json_digest,
        "json_actual_sha256" => json_digest,
        "defaulting" => {
          "applicable" => false,
          "reason" => defaulting_observation["reason"],
          "expected_sha256" => defaulting,
          "actual_sha256" => defaulting,
          "expected_source" => "kubernetes_external",
          "actual_source" => "rubernetes",
          "expected" => defaulting_observation,
          "actual" => defaulting_observation,
          "matches" => true
        },
        "defaulting_expected_source" => "kubernetes_external",
        "defaulting_actual_source" => "rubernetes",
        "validation_expected_source" => "kubernetes_external",
        "validation_actual_source" => "rubernetes",
        "defaulting_expected_sha256" => defaulting,
        "defaulting_actual_sha256" => defaulting,
        "defaulting_applicable" => false,
        "defaulting_reason" => defaulting_observation["reason"],
        "validation" => {
          "applicable" => true,
          "reason" => nil,
          "expected_sha256" => validation,
          "actual_sha256" => validation,
          "expected_source" => "kubernetes_external",
          "actual_source" => "rubernetes",
          "expected" => validation_observation,
          "actual" => validation_observation,
          "matches" => true
        },
        "validation_applicable" => true,
        "validation_reason" => nil,
        "validation_expected_sha256" => validation,
        "validation_actual_sha256" => validation
      }
    end
    oracle
  end

  def validation_oracle_evidence(ids, criterion)
    oracle = oracle_evidence(ids, kind: M1Gate::KUBERNETES_SEMANTICS_ORACLE_KIND)
    oracle["source_root"] = "/tmp/kubernetes-v1.36.2"
    oracle["source_tree_clean"] = true
    oracle.delete("validation_criterion")
    oracle["validation_criterion_sha256"] = M1Gate.canonical_document_digest(criterion)
    empty_errors = M1Gate.canonical_document_digest([])
    oracle["error_catalog"] = {empty_errors => []}
    oracle["comparisons"] = ids.map do |id|
      operations = M1Gate::REQUIRED_VALIDATION_OPERATIONS.to_h do |operation_name|
        [
          operation_name,
          {
            "completed" => true,
            "accepted" => true,
            "error" => nil,
            "expected_accepted" => true,
            "expectation_matches" => true,
            "errors" => [],
            "error_count" => 0,
            "errors_sha256" => empty_errors,
            "field_paths" => []
          }
        ]
      end
      {
        "id" => id,
        "passed" => true,
        "applicable" => true,
        "owner_schema" => "io.test.v1.Test",
        "target_path" => [],
        "source_paths" => ["test/validation.go"],
        "operations" => operations,
        "operation_observation_sha256" => M1Gate.canonical_document_digest(
          M1Gate::REQUIRED_VALIDATION_OPERATIONS.map { |operation_name| operations.fetch(operation_name) }
        )
      }
    end
    oracle
  end

  def unknown_field_mismatch_packet_evidence(ids)
    {
      "executed" => true,
      "comparison_count" => ids.length,
      "mismatch_count" => 0,
      "non_comparable_count" => 0,
      "groups" => [],
      "by_type" => [],
      "non_comparable_by_type" => [],
      "production_codec_fix_packet" => {
        "status" => "NOT_REQUIRED",
        "not_applied" => true,
        "target_files" => ["lib/rubernetes/schema/codec.rb"],
        "behavior" => "No unknown-field mismatch was present in this synthetic gate fixture.",
        "verification" => "Use the external M1 semantic report for production evidence."
      }
    }
  end

  def coverage_items(count, prefix)
    identifiers = Array.new(count) { |index| "#{prefix}-#{index}" }
    {
      "expected_count" => count,
      "registered_count" => count,
      "expected_items" => identifiers,
      "registered_items" => identifiers,
      "duplicate_count" => 0,
      "missing_count" => 0,
      "unexpected_count" => 0
    }
  end

  def write_json(directory, name, value)
    File.write(File.join(directory, name), JSON.pretty_generate(value) << "\n")
  end

  def update_artifact_digest(manifest_path, name, path)
    manifest = JSON.parse(File.read(manifest_path))
    artifact = manifest.fetch("artifacts").find { |entry| entry.fetch("path") == name }
    artifact["sha256"] = Digest::SHA256.file(path).hexdigest
    artifact["bytes"] = File.size(path)
    File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")
  end

  def add_artifact(manifest_path, name, path)
    manifest = JSON.parse(File.read(manifest_path))
    manifest.fetch("artifacts") << {
      "path" => name,
      "sha256" => Digest::SHA256.file(path).hexdigest,
      "bytes" => File.size(path)
    }
    manifest["result_counts"]["artifacts"] += 1
    File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")
  end

  # The gate under test runs in-process (M1Gate.evaluate is exactly what the CLI
  # calls); the triple mirrors Open3.capture3 so assertions read the same.  A fresh
  # interpreter per evaluation cost ~20 s x 30 evaluations; the CLI wrapper itself
  # is exercised once by test_command_line_gate_matches_the_in_process_report.
  GateStatus = Struct.new(:exitstatus) do
    def success? = exitstatus.zero?
  end

  def run_gate(manifest_path)
    output = M1Gate.evaluate(manifest_path)
    [JSON.pretty_generate(output) + "\n", "", GateStatus.new(output.fetch("passed") ? 0 : 1)]
  end

  def run_gate_cli(manifest_path)
    Open3.capture3(RbConfig.ruby, GATE, manifest_path, chdir: ROOT)
  end

  REPORT_NAMES = %w[corpus generation roundtrip api kubectl].freeze
  REQUIRED_OPERATIONS = M1Gate::REQUIRED_OPERATIONS
  REQUIRED_API_OPERATIONS = M1Gate::REQUIRED_API_OPERATIONS
end
