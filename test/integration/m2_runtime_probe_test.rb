# frozen_string_literal: true

require "json"
require "open3"
require "rbconfig"
require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/milestones/m2_gate"
require_relative "../../tools/milestones/m2_kubernetes_lifecycle_oracle"

class M2ProbesTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  PROBES = %w[runtime attack lifecycle ledger kernel].freeze

  def test_m2_probes_report_real_effect_evidence_and_fail_closed_without_l3
    # The three probes are independent processes (own temp roots; the shared image
    # cache writes blobs and stages atomically), so they run concurrently and are
    # asserted in order afterwards.
    names = %w[attack lifecycle ledger]
    outcomes = names.map { |name| Thread.new { run_probe(name) } }.map(&:value)
    names.zip(outcomes).each do |name, (report, stderr, status)|
      assert_empty stderr
      case name
      when "attack"
        assert_predicate status, :success?, "#{name} probe should execute its implementation"
        assert_equal true, report.fetch("passed")
        assert_equal "PASS", report.fetch("status")
        assert_empty report.fetch("errors")
        assert_equal M2Gate::REQUIRED_ATTACKS, report.fetch("cases").map { |entry| entry.fetch("id") }
        assert(report.fetch("cases").all? { |entry| entry.fetch("fail_closed") })
      when "lifecycle"
        # The CNI lock (third_party/locks/m2-lifecycle-cni.json) is present, so
        # the external Kubernetes oracle is never BLOCKED. With the pinned
        # source checkout configured it must execute on the real v1.36.2 node;
        # otherwise it must name the missing input instead of fabricating.
        oracle = report.fetch("lifecycle_oracle")
        refute_equal "BLOCKED", oracle.fetch("status")
        refute_includes report.fetch("errors"), M2KubernetesLifecycleOracle::CNI_LOCK_BLOCKER
        assert_equal M2KubernetesLifecycleOracle::REQUIRED_CASES, oracle.fetch("comparisons").map { |entry| entry.fetch("id") } if oracle.fetch("executed")
        if ENV.fetch("RUBERNETES_M2_KUBERNETES_SOURCE", "").empty?
          refute_predicate status, :success?, "#{name} must fail closed without the pinned Kubernetes source checkout"
          assert_equal false, oracle.fetch("executed")
          assert_equal "INCOMPLETE", oracle.fetch("status")
          assert(oracle.fetch("errors").any? { |error| error.include?("RUBERNETES_M2_KUBERNETES_SOURCE") }, oracle.fetch("errors").inspect)
        else
          assert_equal true, oracle.fetch("executed"), oracle.fetch("errors").inspect
          assert_includes %w[PASS FAIL], oracle.fetch("status")
          assert(oracle.fetch("comparisons").all? { |entry| M2KubernetesLifecycleOracle.valid_digest?(entry["expected_sha256"]) }, "Kubernetes observables must be digested")
          assert_equal oracle.fetch("passed"), oracle.fetch("comparisons").all? { |entry| entry.fetch("passed") }
          assert_equal report.fetch("passed"), status.success?
        end
        assert_operator report.fetch("trace").length, :>, 0
        assert_equal 0, report.fetch("live_leak_count")
        assert_equal 0, report.fetch("orphan_count")
        assert_empty M2Gate::REQUIRED_RESOURCE_KINDS - report.fetch("resource_kinds")
        assert_equal M2Gate::REQUIRED_RESOURCE_KINDS, report.fetch("inventory_measurement").fetch("required_resource_kinds")
        assert_empty report.fetch("inventory_measurement").fetch("missing_resource_kinds")
        assert_equal "PASS", report.fetch("inventory_measurement").fetch("profile_status")
        assert_equal M2Gate::REQUIRED_EFFECT_POINTS, report.fetch("sigkill_matrix").map { |entry| entry.fetch("effect_point") }
        assert(report.fetch("sigkill_matrix").all? do |entry|
          entry.fetch("kill_observed") && entry.fetch("restart_observed") && entry.fetch("wal_replayed") &&
            entry.fetch("wait_status").fetch("signal") == "SIGKILL" &&
            entry.fetch("live_wrong_deletion_count").zero? && entry.fetch("dead_residual_count").zero?
        end)
        assert(report.fetch("subresource_e2e").values.all? { |entry| entry.fetch("passed") })
      when "ledger"
        if report.fetch("l3_available")
          assert_predicate status, :success?, "#{name} should pass only with complete L3 evidence"
        else
          refute_predicate status, :success?, "#{name} must fail closed without L3 kernel evidence"
          assert(report.fetch("errors").any? { |error| error.start_with?("L3 ") })
        end
        assert_equal report.fetch("l3_available"), report.fetch("passed")
        assert_equal expected_ledger_cycles, report.fetch("cycle_count")
        assert_equal 4, report.fetch("failure_injection_count")
        assert_equal 0, report.fetch("live_leak_count")
        assert_equal 0, report.fetch("orphan_count")
        assert_empty M2Gate::REQUIRED_RESOURCE_KINDS - report.fetch("resource_kinds")
        assert_equal M2Gate::REQUIRED_RESOURCE_KINDS, report.fetch("inventory_measurement").fetch("required_resource_kinds")
        assert_empty report.fetch("inventory_measurement").fetch("missing_resource_kinds")
        assert_equal "PASS", report.fetch("inventory_measurement").fetch("profile_status")
        assert_equal report.fetch("cycle_inventory_measurement").fetch("measurement_id"), report.fetch("cycles").first.fetch("inventory_measurement_id")
        assert_equal expected_ledger_cycles, report.fetch("cycle_inventory_measurement").fetch("cycle_count")
        assert_equal "Rubernetes::Platform::Linux::NativeAdapters", report.fetch("cycle_inventory_measurement").fetch("adapter_class")
        assert_equal M2Gate::REQUIRED_EFFECT_POINTS, report.fetch("sigkill_matrix").map { |entry| entry.fetch("effect_point") }
        assert(report.fetch("sigkill_matrix").all? { |entry| entry.fetch("dead_residual_count").zero? })
      end
    end

    %w[runtime kernel].each do |name|
      report, stderr, status = run_probe(name)

      assert_empty stderr
      profiles = report.fetch(name == "runtime" ? "profiles" : "architectures")
      profile = profiles.fetch(0)
      if profile.fetch("available")
        assert_predicate status, :success?, "#{name} probe should pass with complete x86_64 host evidence"
        assert_equal true, report.fetch("passed")
        assert_equal "PASS", report.fetch("status")
        assert_empty report.fetch("errors")
      else
        refute_predicate status, :success?, "#{name} probe must fail closed without complete x86_64 host evidence"
        assert_equal false, report.fetch("passed")
        assert_equal "INCOMPLETE", report.fetch("status")
        refute_empty report.fetch("errors")
      end
    end
  end

  def test_runtime_and_kernel_probes_only_require_x86_64
    runtime, _stderr, _status = run_probe("runtime")
    kernel, _stderr, _status = run_probe("kernel")

    assert_equal ["x86_64"], runtime.fetch("required_architectures")
    assert_equal ["x86_64"], kernel.fetch("required_architectures")
    assert_equal ["x86_64"], runtime.fetch("profiles").map { |profile| profile.fetch("architecture") }
    assert_equal ["x86_64"], kernel.fetch("architectures").map { |profile| profile.fetch("architecture") }
    if kernel.fetch("architectures").first.fetch("available")
      assert_operator kernel.fetch("architectures").first.fetch("objects").length, :>, 0
    end
    refute(runtime.fetch("profiles").any? { |profile| profile.fetch("skip") })
    refute(kernel.fetch("architectures").any? { |profile| profile.fetch("skip") })
  end

  def test_probe_refuses_a_changed_input_identity_before_running
    report, _stderr, status = run_probe("runtime", "RUBERNETES_M2_INPUT_SHA256" => "0" * 64, "RUBERNETES_M2_INPUT_FILE_COUNT" => "1")

    refute_predicate status, :success?
    assert_equal false, report.fetch("input_stable")
    assert_includes report.fetch("errors"), "source input changed before probe execution"
  end

  def test_evidence_runner_marks_missing_chain_and_profiles_incomplete
    Dir.mktmpdir("rubernetes-m2-evidence-") do |directory|
      stdout, stderr, status = Open3.capture3(
        RbConfig.ruby,
        File.join(ROOT, "tools/milestones/m2_evidence.rb"),
        "--output-root",
        directory,
        "--run-id",
        "missing-chain",
        chdir: ROOT
      )

      refute_predicate status, :success?
      assert_empty stderr
      result = JSON.parse(stdout)
      assert_equal false, result.fetch("passed")
      manifest = JSON.parse(File.read(File.join(directory, "missing-chain", "manifest.json")))
      assert_equal "INCOMPLETE", manifest.fetch("status")
      assert_equal manifest.fetch("input_capture").fetch("stable"), manifest.fetch("input_stable")
      assert_equal 5, manifest.fetch("result_counts").fetch("reports")
      assert_operator manifest.fetch("result_counts").fetch("command_failures"), :>, 0
    end
  end

  private

  # 1000 unless the fast lane shortened the ledger probe (see M2LedgerProbe.cycle_count).
  def expected_ledger_cycles
    Integer(ENV.fetch("RUBERNETES_M2_LEDGER_CYCLES", "1000"), 10)
  end

  def run_probe(name, environment = {})
    path = File.join(ROOT, "tools/milestones/m2_#{name}_probe.rb")
    stdout, stderr, status = Open3.capture3(environment, RbConfig.ruby, path, chdir: ROOT)
    [JSON.parse(stdout), stderr, status]
  end
end
