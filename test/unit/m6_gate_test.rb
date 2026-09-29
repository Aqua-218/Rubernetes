# frozen_string_literal: true

require "json"
require "fileutils"
require "tmpdir"
require "time"
require "digest"
require_relative "../test_helper"
require_relative "../../tools/milestones/m6_gate"

class M6GateTest < Minitest::Test
  def base_manifest(status: "COMPLETE")
    now = Time.now.utc.iso8601
    {"schema_version" => 3, "milestone" => "M6", "status" => status, "input_sha256" => "0" * 64, "input_file_count" => 1,
     "input_stable" => true, "host" => {"architecture" => "x86_64", "kernel" => "test", "ruby" => RUBY_DESCRIPTION},
     "started_at" => now, "finished_at" => now,
     "input_capture" => {"stable" => true, "start" => {"sha256" => "0" * 64, "file_count" => 1}, "finish" => {"sha256" => "0" * 64, "file_count" => 1}},
     "git_metadata_capture" => {"stable" => true, "start_paths" => [], "finish_paths" => [], "count" => 0},
     "commands" => [{"name" => "fixture", "command" => ["fixture"], "started_at" => now, "finished_at" => now, "exit_status" => 0}],
     "artifacts" => [], "subjects" => [],
     "result_counts" => {"commands" => 1, "command_failures" => 0, "artifacts" => 0, "subjects" => 0, "reports" => 6, "source_files" => 1}}
  end

  def test_missing_manifest_fails_closed
    result = M6Gate.evaluate(File.join(Dir.tmpdir, "rubernetes-m6-missing-#{Process.pid}.json"))
    refute result.fetch("passed")
    assert_operator result.fetch("error_count"), :>, 0
  end

  def test_m6_requires_the_complete_m5_chain_and_every_report
    Dir.mktmpdir("rubernetes-m6-gate") do |directory|
      path = File.join(directory, "manifest.json")
      File.write(path, JSON.generate(base_manifest))
      result = M6Gate.evaluate(path)
      refute result.fetch("passed")
      errors = result.fetch("errors")
      assert errors.any? { |error| error.include?("M5") }
      M6Gate::REPORTS.each_value do |specification|
        assert errors.any? { |error| error.include?(specification.fetch(:names).first) }, specification.inspect
      end
    end
  end

  def test_non_x86_64_host_is_rejected
    Dir.mktmpdir("rubernetes-m6-gate") do |directory|
      path = File.join(directory, "manifest.json")
      manifest = base_manifest
      manifest["host"]["architecture"] = "aarch64"
      File.write(path, JSON.generate(manifest))
      assert M6Gate.evaluate(path).fetch("errors").any? { |error| error.include?("x86_64") }
    end
  end

  def report(kind, cases, extra = {})
    {"schema_version" => 1, "milestone" => "M6", "kind" => kind, "input_sha256" => "0" * 64, "input_file_count" => 1,
     "available" => true, "status" => "COMPLETE", "passed" => true, "cases" => cases, "case_count" => cases.length,
     "passed_count" => cases.count { |c| c["passed"] }, "failed_count" => cases.count { |c| !c["passed"] }}.merge(extra)
  end

  def sources
    [{"path" => "lib/rubernetes/api/server.rb", "sha256" => Digest::SHA256.file(File.expand_path("../../lib/rubernetes/api/server.rb", __dir__)).hexdigest}]
  end

  def oracle
    {"executed" => true, "kubernetes_version" => "v1.36.2", "source_commit" => "abc", "kube_apiserver_image" => "registry.k8s.io/kube-apiserver@sha256:1",
     "etcd_image" => "registry.k8s.io/etcd@sha256:2", "container_execution" => [{"argv" => ["docker", "run"]}]}
  end

  def manifest_identity
    {"input_sha256" => "0" * 64, "input_file_count" => 1}
  end

  def test_differential_with_divergent_observations_is_rejected
    cases = M6Gate::CRD_REQUIRED.map { |id| {"id" => id, "passed" => true, "oracle" => {"status" => 200}, "rubernetes" => {"status" => 200}} }
    cases.find { |entry| entry["id"] == "create_ok" }["rubernetes"] = {"status" => 201}
    errors = []
    M6Gate.send(:validate_report, "crd", report("m6_crd_aggregation_differential", cases, "measurement_level" => "differentially_tested", "oracle" => oracle, "sources" => sources),
                "m6_crd_aggregation_differential", manifest_identity, errors)
    assert errors.any? { |error| error.include?("create_ok") && error.include?("differ") }
  end

  def test_differential_without_oracle_execution_is_rejected
    cases = M6Gate::WEBHOOK_REQUIRED.map { |id| {"id" => id, "passed" => true, "oracle" => {"status" => 201}, "rubernetes" => {"status" => 201}} }
    errors = []
    M6Gate.send(:validate_report, "webhook", report("m6_webhook_differential", cases, "measurement_level" => "differentially_tested", "docker_gateway" => "172.17.0.1", "sources" => sources),
                "m6_webhook_differential", manifest_identity, errors)
    assert errors.any? { |error| error.include?("oracle") }
  end

  def test_feature_gate_profile_with_differences_is_rejected
    cases = M6Gate::FEATURE_PROFILES.map { |id| {"id" => id, "passed" => true, "difference_count" => 0, "differences" => [], "documents_compared" => 60} }
    cases.first["difference_count"] = 1
    cases << {"id" => "gate_corpus", "passed" => true, "gate_count" => 225}
    errors = []
    M6Gate.send(:validate_report, "feature_gate", report("m6_feature_gate_matrix", cases, "measurement_level" => "differentially_tested",
                                                          "profiles" => {"default" => [], "all-beta" => [], "alpha-apis" => []}, "sources" => sources),
                "m6_feature_gate_matrix", manifest_identity, errors)
    assert errors.any? { |error| error.include?("profile-default") }
  end

  def test_fuzz_summary_with_a_panic_is_rejected
    cases = Array.new(110) { |index| {"id" => "random-#{index}", "passed" => true} }
    %w[body-invalid_utf8-post body-oversized-post body-duplicate_keys-post body-deep_nesting-post negotiation-0 path-1].each { |id| cases << {"id" => id, "passed" => true} }
    6.times { |index| cases << {"id" => "bypass-#{index}", "passed" => true} }
    errors = []
    M6Gate.send(:validate_report, "fuzz", report("m6_fuzz_summary", cases, "measurement_level" => "integration_tested", "seed" => 1, "panics" => 1, "hangs" => 0,
                                                  "policy_bypasses" => 0, "crash_corpus" => [], "sources" => sources),
                "m6_fuzz_summary", manifest_identity, errors)
    assert errors.any? { |error| error.include?("panics") }
  end

  def test_security_trace_with_wrong_stage_order_is_rejected
    cases = M6Gate::SECURITY_REQUIRED.map { |id| {"id" => id, "passed" => true, "status" => 403, "www_authenticate" => "Bearer", "events" => 7} }
    order = cases.find { |entry| entry["id"] == "stage_order_create" }
    order["observed"] = M6Gate::SECURITY_STAGE_ORDER.reverse
    order["expected"] = M6Gate::SECURITY_STAGE_ORDER
    cases.find { |entry| entry["id"] == "invalid_credentials_stop_at_authentication" }["status"] = 401
    errors = []
    M6Gate.send(:validate_report, "security", report("m6_security_pipeline_trace", cases, "measurement_level" => "integration_tested",
                                                      "specified_order" => Array.new(13) { |index| "stage#{index}" }, "sources" => sources),
                "m6_security_pipeline_trace", manifest_identity, errors)
    assert errors.any? { |error| error.include?("stage order") }
  end

  def test_source_digest_mismatch_is_rejected
    cases = [{"id" => "gate_corpus", "passed" => true, "gate_count" => 225}] + M6Gate::FEATURE_PROFILES.map { |id| {"id" => id, "passed" => true, "difference_count" => 0, "differences" => [], "documents_compared" => 60} }
    errors = []
    M6Gate.send(:validate_report, "feature_gate", report("m6_feature_gate_matrix", cases, "measurement_level" => "differentially_tested",
                                                          "profiles" => {"default" => [], "all-beta" => [], "alpha-apis" => []},
                                                          "sources" => [{"path" => "lib/rubernetes/api/server.rb", "sha256" => "1" * 64}]),
                "m6_feature_gate_matrix", manifest_identity, errors)
    assert errors.any? { |error| error.include?("digest does not match") }
  end
end
