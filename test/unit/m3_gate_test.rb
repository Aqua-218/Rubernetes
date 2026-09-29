# frozen_string_literal: true

require "json"
require "minitest/autorun"
require "tmpdir"
require_relative "../../tools/milestones/m2_gate"
require_relative "../../tools/milestones/m3_gate"

class M3GateTest < Minitest::Test
  def test_source_exclusions_match_the_m0_to_m2_rule
    excluded = ->(path) do
      M3Gate::SOURCE_EXCLUDED_ROOTS.include?(path.split("/", 2).first) ||
        M3Gate::SOURCE_EXCLUDED_PATTERNS.any? { |pattern| pattern.match?(path) }
    end

    assert(excluded.call("a11-generated.u1BHO1/generated.rb"))
    assert(excluded.call("artifacts/milestones/M0/x.json"))
    refute(excluded.call("a11-generated.bad/source.rb"))
    refute(excluded.call("a11-generated.u1BHO1x"))
    refute(excluded.call("nested/a11-generated.u1BHO1/source.rb"))
    assert_equal(M3Gate::SOURCE_EXCLUDED_PATTERNS, M2Gate::SOURCE_EXCLUDED_PATTERNS)
    assert_equal(M3Gate::SOURCE_EXCLUDED_ROOTS, M2Gate::SOURCE_EXCLUDED_ROOTS)
  end

  def test_missing_manifest_fails_closed
    result = M3Gate.evaluate(File.join(Dir.tmpdir, "rubernetes-m3-missing-#{Process.pid}.json"))

    refute result.fetch("passed")
    assert_operator result.fetch("error_count"), :>, 0
  end

  def test_duplicate_json_keys_are_rejected
    Dir.mktmpdir("rubernetes-m3-gate") do |directory|
      path = File.join(directory, "manifest.json")
      File.write(path, '{"schema_version":3,"schema_version":3}')

      result = M3Gate.evaluate(path)

      refute result.fetch("passed")
      assert result.fetch("errors").any? { |error| error.include?("valid JSON") }
    end
  end

  def test_incomplete_manifest_cannot_claim_complete
    Dir.mktmpdir("rubernetes-m3-gate") do |directory|
      path = File.join(directory, "manifest.json")
      File.write(path, JSON.generate("schema_version" => 3, "milestone" => "M3", "status" => "COMPLETE"))

      result = M3Gate.evaluate(path)

      refute result.fetch("passed")
      assert result.fetch("errors").any? { |error| error.include?("input_sha256") || error.include?("prior") }
    end
  end

  def test_scheduler_rejects_self_digest_and_boolean_observables
    digest = "a" * 64
    cases = %w[filter score tie_break preemption binding volume_binding].map do |id|
      {"id" => id, "name" => id, "passed" => true, "attempt_count" => 1,
       "evidence_sha256" => digest, "actual_observable" => true, "expected_observable" => true,
       "measurement_source" => "production_module"}
    end
    plugins = [{"id" => "plugin", "name" => "plugin", "measurement_source" => "production_module", "passed" => true}]
    document = {"cases" => cases, "plugins" => plugins,
                "oracle" => {"executed" => true, "version" => M3Gate::KUBERNETES_VERSION,
                             "source_commit" => M3Gate::KUBERNETES_SOURCE_COMMIT, "runner_sha256" => digest,
                             "runner" => {"runner_sha256" => digest, "version" => M3Gate::KUBERNETES_VERSION,
                                          "source_commit" => M3Gate::KUBERNETES_SOURCE_COMMIT,
                                          "command" => ["m3_scheduler_probe.rb"], "process_id" => 1,
                                          "started_at" => Time.now.utc.iso8601, "finished_at" => Time.now.utc.iso8601},
                             "comparison_count" => 6,
                             "comparisons" => cases.map { |entry| entry.merge("expected_sha256" => digest, "actual_sha256" => digest) }},
                "failure_count" => 0, "difference_count" => 0, "filter_mismatch_count" => 0,
                "score_mismatch_count" => 0, "tie_break_mismatch_count" => 0,
                "preemption_mismatch_count" => 0, "binding_mismatch_count" => 0,
                "unexpected_skip_count" => 0, "unclassified_count" => 0}
    errors = []

    M3Gate.send(:validate_scheduler, document, errors)

    assert errors.any? { |error| error.include?("structured") || error.include?("independent") || error.include?("digest") }
  end

  def test_controller_registry_rejects_corpus_controller_fallback
    entries = M3Gate::REQUIRED_CONTROLLER_NAMES.map do |name|
      {"id" => name, "name" => name, "passed" => true, "attempt_count" => 1,
       "owns_declared" => true, "reconcile_declared" => true,
       "measurement_source" => "production_module",
       "implementation_class" => "Rubernetes::Controller::CorpusController",
       "uses_corpus_controller" => true}
    end
    document = {"required_controller_names" => M3Gate::REQUIRED_CONTROLLER_NAMES,
                "registered_controller_names" => M3Gate::REQUIRED_CONTROLLER_NAMES,
                "controllers" => entries, "duplicate_count" => 0, "missing_count" => 0,
                "unexpected_count" => 0, "unregistered_count" => 0, "failure_count" => 0}
    errors = []

    M3Gate.send(:validate_controller_registry, document, errors)

    assert errors.any? { |error| error.include?("CorpusController") }
  end

  # Requirement: duplicate registration must be rejected by the production
  # DuplicateControllerError type, not merely by any rescued StandardError.
  # Mutation target: accepting RuntimeError as proof of duplicate rejection.
  def test_controller_registry_rejects_an_unexpected_duplicate_exception
    entries = M3Gate::REQUIRED_CONTROLLER_NAMES.map do |name|
      {"id" => name, "name" => name, "passed" => true, "attempt_count" => 1,
       "owns_declared" => true, "reconcile_declared" => true,
       "measurement_source" => "production_module",
       "implementation_class" => "Rubernetes::Controller::#{name.tr("-", "_").capitalize}Controller",
       "implementation_present" => true, "uses_corpus_controller" => false}
    end
    document = {"required_controller_names" => M3Gate::REQUIRED_CONTROLLER_NAMES,
                "registered_controller_names" => M3Gate::REQUIRED_CONTROLLER_NAMES,
                "controllers" => entries, "duplicate_count" => 0, "missing_count" => 0,
                "unexpected_count" => 0, "unregistered_count" => 0, "failure_count" => 0,
                "duplicate_exception_class" => "RuntimeError", "duplicate_check_passed" => false}
    errors = []

    M3Gate.send(:validate_controller_registry, document, errors)

    assert errors.any? { |error| error.include?("DuplicateControllerError") }
    assert errors.any? { |error| error.include?("duplicate registration check") }
  end

  def test_leader_loss_rejects_boolean_only_process_chaos
    now = Time.now.utc.iso8601
    trace = %w[acquire loss fence recovery].map { |id| {"id" => id, "event" => id, "passed" => true, "attempt_count" => 1} }
    document = {"trace" => trace, "double_side_effect_count" => 0, "duplicate_side_effect_count" => 0,
                "stale_side_effect_count" => 0, "quorum_recovered" => true, "recovery_seconds" => 1.0,
                "failure_count" => 0, "unexpected_skip_count" => 0, "unclassified_count" => 0,
                "chaos" => {"executed" => true,
                            "runner" => {"runner_sha256" => "b" * 64, "command" => ["chaos-runner"],
                                         "process_id" => 2, "started_at" => now, "finished_at" => now},
                            "processes" => [], "events" => []}}
    errors = []

    M3Gate.send(:validate_leader, document, errors)

    assert errors.any? { |error| error.include?("process observation") || error.include?("event inventory") }
  end

  def test_workload_differential_requires_the_full_matrix_and_structured_observables
    document = {"workload_types" => M3Gate::REQUIRED_WORKLOAD_TYPES,
                "operations" => M3Gate::REQUIRED_WORKLOAD_OPERATIONS,
                "cases" => [{"id" => "deployment:rollout", "passed" => true,
                             "attempt_count" => 1, "measurement_source" => "production_module",
                             "actual_observable" => true, "expected_observable" => true}],
                "difference_count" => 0, "workload_mismatch_count" => 0}
    errors = []

    M3Gate.send(:validate_workload, document, errors)

    assert errors.any? { |error| error.include?("case inventory") }
    assert errors.any? { |error| error.include?("structured") || error.include?("oracle") }
  end

  # Requirement: idempotency evidence must bind API mutations, events,
  # provider calls, and a durable journal. Mutation target: deleting any one
  # inventory must make the gate reject the report.
  def test_idempotency_rejects_store_only_observables
    first = {"store" => [], "step" => {}, "queue" => {}, "foreign" => true}
    second = Marshal.load(Marshal.dump(first))
    errors = []

    M3Gate.send(:validate_idempotency_effect_inventory, first, second, errors, 0)

    assert errors.any? { |error| error.include?("api_mutations") }
    assert errors.any? { |error| error.include?("durable") }
  end

  # Requirement: replay safety is semantic, not an effect-id/generation
  # comparison. Mutation target: changing only generation, effect_id, or
  # payload must not let two writes with one effect_key pass.
  def test_idempotency_rejects_generation_changed_semantic_api_replay
    first_entry = api_mutation("generation-one", "effect-one", "a" * 64)
    second_entry = api_mutation("generation-two", "effect-two", "b" * 64)
    first = observable_for("first", [first_entry, second_entry])
    second = observable_for("second", [])
    errors = []

    M3Gate.send(:validate_idempotency_effect_inventory, first, second, errors, 0)

    assert errors.any? { |error| error.include?("duplicate semantic API effect keys") }
  end

  # Requirement: each replay journal slice must independently prove zero
  # events and provider calls. Mutation target: checking API mutations alone.
  def test_idempotency_rejects_second_run_event_and_provider_side_effects
    event = {"kind" => "controller_event", "effect_key" => "controller-manager|default/m3|reconcile",
             "event_sha256" => "a" * 64}
    provider = {"kind" => "provider_event", "effect_key" => "controller-manager|default/m3|provider:record",
                "provider" => "Provider", "operation" => "record"}
    first = observable_for("first", [])
    second = observable_for("second", [event, provider])
    errors = []

    M3Gate.send(:validate_idempotency_effect_inventory, first, second, errors, 0)

    assert errors.any? { |error| error.include?("replay must not append controller events") }
    assert errors.any? { |error| error.include?("replay must not append provider calls") }
  end

  def test_idempotency_step_gate_requires_leader_success_and_no_pending_retry
    observable = {"step" => {"leader_execution" => false, "follower" => true,
                              "reconciled" => 0, "reconcile_success" => false,
                              "step_error_class" => "RuntimeError", "pending_retry" => true,
                              "follower_noop" => true}}
    errors = []

    M3Gate.send(:validate_idempotency_step_observable, observable, errors, 0, "first")

    assert errors.any? { |error| error.include?("leader execution") }
    assert errors.any? { |error| error.include?("reconcile exactly once") }
    assert errors.any? { |error| error.include?("pending retry") }
  end

  def test_controller_registry_rejects_wrong_authoritative_gvk_binding
    require_relative "../../lib/rubernetes"
    registry = Rubernetes::Controller.build_default_registry
    corpus = Rubernetes::Controller::BuiltinControllerCorpus
    entries = M3Gate::REQUIRED_CONTROLLER_NAMES.map do |name|
      definition = registry.fetch(name)
      binding = M3Gate.controller_registry_binding(definition, corpus.fetch(name))
      {"id" => name, "name" => name, "passed" => true, "attempt_count" => 1,
       "owns_declared" => true, "reconcile_declared" => true,
       "measurement_source" => "production_module", "implementation_class" => definition.implementation_name,
       "implementation_present" => true, "uses_corpus_controller" => false,
       "binding" => binding, "metadata_digest" => binding["metadata_digest"],
       "binding_digest" => binding["binding_digest"]}
    end
    entries.first["binding"]["authoritative_corpus"]["descriptor"]["kind"] = "WrongKind"
    document = {"required_controller_names" => M3Gate::REQUIRED_CONTROLLER_NAMES,
                "registered_controller_names" => M3Gate::REQUIRED_CONTROLLER_NAMES,
                "controllers" => entries, "startup_validation" => {"attempt_count" => 1, "passed" => true,
                "exception_class" => nil, "error" => nil}, "duplicate_count" => 0,
                "missing_count" => 0, "unexpected_count" => 0, "unregistered_count" => 0,
                "failure_count" => 0, "binding_failure_count" => 0,
                "duplicate_exception_class" => "Rubernetes::Controller::DuplicateControllerError",
                "duplicate_check_passed" => true}
    errors = []

    M3Gate.send(:validate_controller_registry, document, errors)

    assert errors.any? { |error| error.include?("authoritative descriptor/GVK") }
  end

  def test_external_execution_requires_built_in_transcript_and_pinned_source
    errors = []
    document = {"executed" => true, "runner_sha256" => "a" * 64, "input_payload" => {}, "external_document_sha256" => "b" * 64}

    M3Gate.send(:validate_external_execution, document, {}, {"runner_source" => "/tmp/fake.rb", "runner_sha256" => "a" * 64}, errors, "scheduler oracle")

    assert errors.any? { |error| error.include?("transcript") || error.include?("argv") }
    assert errors.any? { |error| error.include?("runner source") }
  end

  private

  def api_mutation(generation, effect_id, object_sha256)
    {"kind" => "api_mutation", "reconcile_key" => "apps/v1/deployments/default/m3",
     "effect_type" => "update", "action" => "update",
     "effect_key" => "controller-manager|apps/v1/deployments/default/m3|update",
     "generation" => generation, "effect_id" => effect_id,
     "object_sha256" => object_sha256, "response_sha256" => "c" * 64}
  end

  def observable_for(run, raw_entries)
    snapshot = {"raw_entries" => raw_entries}
    inventory = M3Gate.send(:recompute_idempotency_inventory, raw_entries)
    snapshot["raw_entry_count"] = raw_entries.length
    snapshot["raw_sha256"] = M3Gate.canonical_document_digest(raw_entries)
    %w[effect_ids effect_id_counts effect_signature_counts api_effect_key_counts api_mutation_count event_count provider_call_count
        event_effect_key_counts provider_effect_key_counts event_signatures event_signature_counts
        provider_call_signatures provider_call_signature_counts].each { |key| snapshot[key] = inventory.fetch(key) }
    snapshot["inventory"] = inventory
    {"store" => [], "api_mutations" => inventory.fetch("api_mutations"),
     "events" => inventory.fetch("events"), "provider_calls" => inventory.fetch("provider_calls"),
     "durable_journal" => {"run" => run, "before" => {}, "after" => inventory, "raw_snapshot" => snapshot}}
  end
end
