# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/milestones/m2_lifecycle_trace_support"
require_relative "../../tools/verification/m2_runtime_trace_verifier"

class M2LifecycleTraceSupportTest < Minitest::Test
  DIGEST = "sha256:#{"a" * 64}".freeze

  def record(sequence, operation_id, event, payload)
    {"sequence" => sequence, "operation_id" => operation_id, "event" => event, "payload" => payload,
     "timestamp" => "2026-09-05T00:00:#{format("%02d", sequence)}Z", "previous_digest" => nil,
     "digest" => Digest::SHA256.hexdigest(sequence.to_s)}
  end

  def transition(sequence, operation_id, from, to)
    record(sequence, operation_id, "state_transition", {"from" => from, "to" => to, "config_digest" => DIGEST})
  end

  def journal(id)
    seq = 0
    next_seq = -> { seq += 1 }
    [
      record(next_seq.call, id, "operation_started", {"config_digest" => DIGEST}),
      transition(next_seq.call, id, "New", "Validated"),
      transition(next_seq.call, id, "Validated", "ImagePinned"),
      record(next_seq.call, id, "resource_claimed", {"kind" => "workspace", "id" => id}),
      transition(next_seq.call, id, "ImagePinned", "WorkspaceAllocated"),
      record(next_seq.call, id, "resource_claimed", {"kind" => "namespace", "id" => id}),
      transition(next_seq.call, id, "WorkspaceAllocated", "IsolationCreated"),
      record(next_seq.call, id, "resource_claimed", {"kind" => "cgroup", "id" => id}),
      transition(next_seq.call, id, "IsolationCreated", "ResourcesAttached"),
      transition(next_seq.call, id, "ResourcesAttached", "WorkloadStopped"),
      record(next_seq.call, id, "resource_claimed", {"kind" => "cgroup", "id" => "#{id}:main"}),
      record(next_seq.call, id, "resource_claimed", {"kind" => "process", "id" => "#{id}:main"}),
      transition(next_seq.call, id, "WorkloadStopped", "Running"),
      transition(next_seq.call, id, "Running", "Stopping"),
      transition(next_seq.call, id, "Stopping", "Stopped"),
      record(next_seq.call, id, "resource_released", {"kind" => "process", "id" => "#{id}:main"}),
      record(next_seq.call, id, "resource_released", {"kind" => "cgroup", "id" => "#{id}:main"}),
      record(next_seq.call, id, "resource_released", {"kind" => "cgroup", "id" => id}),
      record(next_seq.call, id, "resource_released", {"kind" => "namespace", "id" => id}),
      record(next_seq.call, id, "resource_released", {"kind" => "workspace", "id" => id}),
      transition(next_seq.call, id, "Stopped", "Removed")
    ]
  end

  def facets(id)
    entries = [
      {"kind" => "temp", "id" => "#{id}:root"}, {"kind" => "temp", "id" => "#{id}:upper"},
      {"kind" => "temp", "id" => "#{id}:work"}, {"kind" => "mount", "id" => "#{id}:77"},
      {"kind" => "ns", "id" => "#{id}:mnt"}, {"kind" => "ns", "id" => "#{id}:pid"},
      {"kind" => "pidfd", "id" => "#{id}:namespace"}, {"kind" => "pidfd", "id" => "#{id}:workload"}
    ]
    M2LifecycleTraceSupport.facets_from_entries(entries, sandbox_id: id, container_ids: ["main"])
  end

  def test_replayed_trace_satisfies_the_runtime_trace_verifier
    trace = M2LifecycleTraceSupport.trace_from_journal(journal("sb"), facets: facets("sb"))
    report = Rubernetes::Verification::M2RuntimeTraceVerifier.new({"trace" => trace}).verify

    assert_equal [], report["violations"]
    assert report["success"]
    running = trace.find { |event| event["to"] == "Running" }
    kinds = running["after"]["owned_resources"].map { |key| key.split(":", 2).first }.uniq.sort

    assert_equal %w[cgroup mount ns pidfd process temp], kinds
    assert_equal true, running["after"]["live_process"]
    stopping = trace.find { |event| event["to"] == "Stopping" }

    assert_equal false, stopping["after"]["live_process"]
    assert_equal false, stopping["after"]["result"]
    removed = trace.find { |event| event["to"] == "Removed" }

    assert_equal [], removed["after"]["owned_resources"]
    assert_equal removed["before"]["released"], removed["after"]["released"]
    assert_equal running["after"]["claim_order"].reverse, removed["after"]["released"]
  end

  def test_facets_attach_to_the_owning_ledger_claim
    mapped = facets("sb")

    assert_equal %w[temp:sb:root temp:sb:upper temp:sb:work], mapped["temp:sb"]
    assert_equal %w[mount:sb:77 ns:sb:mnt ns:sb:pid pidfd:sb:namespace], mapped["ns:sb"]
    assert_equal %w[pidfd:sb:workload], mapped["process:sb:main"]
  end

  def test_release_before_stopped_is_reported_by_the_verifier
    id = "sb"
    records = journal(id)
    early = records.index { |entry| entry["event"] == "state_transition" && entry["payload"]["to"] == "Stopping" }
    release = records.find { |entry| entry["event"] == "resource_released" && entry["payload"]["kind"] == "process" }
    records.delete(release)
    records.insert(early, release)
    trace = M2LifecycleTraceSupport.trace_from_journal(records, facets: facets(id))
    report = Rubernetes::Verification::M2RuntimeTraceVerifier.new({"trace" => trace}).verify

    refute report["success"]
    assert_includes report["violations"].map { |entry| entry["code"] }, "cleanup_before_stop"
  end
end
