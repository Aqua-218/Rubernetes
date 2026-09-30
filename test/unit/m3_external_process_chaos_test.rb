# frozen_string_literal: true

require "minitest/autorun"

require_relative "../../tools/milestones/m3_gate"
require_relative "../conformance/kubernetes/m3_control_plane_chaos/runner"

class M3ExternalProcessChaosTest < Minitest::Test
  def request(suite = "m3-control-plane-leader-chaos")
    {"schema_version" => 1, "suite" => suite, "scenario" => "leader-loss",
     "components" => %w[controller-manager scheduler]}
  end

  def test_missing_durable_api_returns_the_exact_blocker
    report = M3ControlPlaneChaosRunner.blocked_report(request)

    assert_equal "BLOCKED", report.fetch("status")
    assert_equal M3ControlPlaneChaosRunner::BLOCKER, report.fetch("blocker")
    assert_equal [M3ControlPlaneChaosRunner::BLOCKER], report.fetch("errors")
    assert_equal false, report.fetch("executed")
  end

  def test_gate_requires_runtime_process_lease_effect_and_trace_provenance
    document = {
      "chaos" => {
        "executed" => true,
        "status" => "PASS",
        "runner" => {"runner_sha256" => "a" * 64, "command" => ["chaos-runner"], "process_id" => 1,
                     "mode" => "external", "self_comparison" => false, "implementation" => "runner.rb",
                     "started_at" => Time.now.utc.iso8601, "finished_at" => Time.now.utc.iso8601},
        "processes" => [{"pid" => 2, "start_time" => 3, "observed_exit" => true, "exit_status" => 0}],
        "events" => [{"id" => "acquire", "observed_at" => Time.now.utc.iso8601, "observation" => {"pid" => 2}}],
        "trace" => [], "effect_ids" => [], "lease_observations" => [], "component_runs" => []
      }
    }
    errors = []

    M3Gate.send(:validate_process_chaos, document, errors, "leader-loss process chaos", %w[acquire])

    assert(errors.any? { |error| error.include?("namespace") })
    assert(errors.any? { |error| error.include?("lease observations") })
    assert(errors.any? { |error| error.include?("effect IDs") })
    assert(errors.any? { |error| error.include?("separate controller-manager and scheduler") })
  end

  def test_blocked_process_chaos_preserves_blocker_in_gate_diagnostics
    blocker = M3ControlPlaneChaosRunner::BLOCKER
    document = {"chaos" => {"executed" => true, "status" => "BLOCKED", "blocker" => blocker}}
    errors = []

    M3Gate.send(:validate_process_chaos, document, errors, "leader-loss process chaos", %w[acquire])

    assert_equal [blocker], errors
  end

  def test_chaos_probes_use_real_external_process_runner_contract
    leader_source = File.read(File.expand_path("../../tools/milestones/m3_leader_probe.rb", __dir__))
    queue_source = File.read(File.expand_path("../../tools/milestones/m3_queue_probe.rb", __dir__))
    runner_source = File.read(File.expand_path("../conformance/kubernetes/m3_control_plane_chaos/runner.rb", __dir__))

    [leader_source, queue_source].each do |source|
      code = source.lines.reject { |line| line.lstrip.start_with?("#") }.join

      refute_match(/MemoryStore|Object\.new|LeaseElector\.new/, code)
      assert_match(/external_process/, code)
    end
    assert_match(/Process\.spawn/, runner_source)
    assert_match(/signal:\s*"KILL"/, runner_source)
    assert_match(/namespace_snapshot/, runner_source)
    assert_match(/raw_trace_sha256/, runner_source)
  end

  def test_builtin_backend_claims_worker_restart_scope_without_m5_claims
    capabilities = M3ControlPlaneChaosRunner::BUILT_IN_CAPABILITIES

    assert_equal "project_owned_apiserver_memorystore", capabilities.fetch("backend")
    M3ControlPlaneChaosRunner::REQUIRED_CAPABILITIES.each do |capability|
      assert_equal true, capabilities.fetch(capability)
    end
    assert_equal "worker_restart", capabilities.fetch("capability_scope")
    assert_equal true, capabilities.fetch("worker_restart_durable")
    assert_equal false, capabilities.fetch("m5_disk_durable")
    assert_equal false, capabilities.fetch("m5_api_ha")
    assert_empty M3ControlPlaneChaosRunner.capability_errors(capabilities,
                                                             request("m3-control-plane-queue-chaos").merge("scenario" => "watch-queue-chaos"))
  end

  # Requirement: a stale holder and a dead/recycled PID cannot satisfy
  # recovery. Mutation target: accepting the restarted logical identity alone
  # must fail this assertion.
  def test_recovery_rejects_stale_lease_without_live_generation_transition
    harness = M3ControlPlaneChaosRunner::Harness.allocate
    harness.define_singleton_method(:latest_lease_object) do |*_args, **_kwargs|
      {"metadata" => {"resourceVersion" => "7"}, "spec" => {"holderIdentity" => "old", "renewTime" => "2026-01-01T00:00:00Z"}}
    end
    harness.define_singleton_method(:process_alive?) { |_record| false }
    harness.define_singleton_method(:wait_until) { |timeout:, &block| block.call }
    record = {"identity" => "old", "pid" => 999_999, "start_time" => 1, "generation" => "old:999999:1"}
    result = harness.send(:wait_for_recovery, [record], record, lease_name: "m3", started_at: M3ControlPlaneChaosRunner.monotonic_time,
                                                                old_identity: "old", old_lease: {"metadata" => {"resourceVersion" => "7"}, "spec" => {"holderIdentity" => "old", "renewTime" => "2026-01-01T00:00:00Z"}})

    assert_equal false, result.fetch("recovered")
  end
end
