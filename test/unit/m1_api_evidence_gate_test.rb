# frozen_string_literal: true

require "json"
require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/milestones/m1_gate"

class M1ApiEvidenceGateTest < Minitest::Test
  def test_initial_watch_causality_is_derived_from_event_and_list_revisions
    valid = initial_watch_trace(event_rv: "7", list_rv: "8", claimed: true)
    forged = initial_watch_trace(event_rv: "9", list_rv: "8", claimed: true)

    assert(M1Gate.send(:valid_resource_version_trace?, valid))
    refute(M1Gate.send(:valid_resource_version_trace?, forged))

    errors = []
    packet = {"resourceVersion_causality" => M1Gate.send(:resource_version_signature, forged)}
    observation = {
      "expected" => forged,
      "actual" => forged,
      "expected_sha256" => M1Gate.canonical_document_digest(forged),
      "actual_sha256" => M1Gate.canonical_document_digest(forged)
    }
    M1Gate.send(
      :validate_resource_version_observation,
      {"resource_version_observation" => observation}, packet, packet, errors, "hostile initial-watch"
    )

    assert(errors.any? { |error| error.include?("validity is not derived from raw revisions") })
  end

  def test_header_observation_cannot_hide_a_semantic_header_behind_fresh_digests
    observation = header_pair({"content-type" => "application/json"})
    forged = observation.fetch("expected")
    forged.fetch("all")["cache-control"] = "private"
    forged["all_sha256"] = M1Gate.canonical_document_digest(forged.fetch("all"))
    errors = []

    M1Gate.send(:validate_header_observation_pair, observation, errors, "hostile headers")

    assert(errors.any? { |error| error.include?("hides a semantic header") })
  end

  def test_exact_request_stream_binds_both_watch_start_revisions
    operations = M1Gate::REQUIRED_API_OPERATION_INVENTORY.map do |inventory|
      next inventory unless inventory.fetch("id") == "watch"

      inventory.merge(
        "resource_version_observation" => {
          "actual" => {"start_resourceVersion" => "17"},
          "expected" => {"start_resourceVersion" => "29"}
        }
      )
    end
    stream = M1Gate.send(:expected_api_request_stream, operations)

    expected_length = (M1Gate::API_SURFACE_ENDPOINT_COUNT + 1 + 2 + M1Gate::REQUIRED_API_OPERATION_INVENTORY.length) * 2
    assert_equal(172, expected_length)
    assert_equal(expected_length, stream.length)
    assert_equal((0...expected_length).to_a, stream.map { |entry| entry.fetch("sequence") })
    watch = stream.select do |entry|
      entry.dig("request", "path") == M1Gate::API_COLLECTION_PATH &&
        entry.dig("request", "query", "watch") == "true" &&
        entry.dig("request", "query", "sendInitialEvents").nil? &&
        entry.dig("request", "query").key?("resourceVersion")
    end
    assert_equal(%w[17 29], watch.map { |entry| entry.dig("request", "query", "resourceVersion") })
    assert(watch.all? { |entry| entry.fetch("request_sha256") == M1Gate.canonical_document_digest(entry.fetch("request")) })
  end

  def test_surface_expected_fields_are_recomputed_from_pinned_discovery
    errors = []
    pinned = M1Gate.send(:pinned_surface_expectations, errors)
    assert_empty(errors)
    assert_equal(153, pinned.fetch("gvr").length)
    assert_equal(194, pinned.fetch("gvk").length)

    id = "core/v1/configmaps"
    expected = pinned.fetch("gvr").fetch(id)
    observed = expected.merge("schema_contract_present" => true)
    entry = observed.merge(
      "id" => id,
      "attempt_count" => 1,
      "passed" => true,
      "availability" => "served",
      "availability_reason" => nil,
      "expected_present" => true,
      "oracle_present" => true,
      "rubernetes_present" => true,
      "expected" => expected,
      "oracle" => presence(expected),
      "rubernetes" => presence(expected)
    )
    valid_errors = []
    M1Gate.send(
      :validate_surface_matrix, [entry], [id], valid_errors, "GVR",
      require_applicability: false, pinned_expected_by_id: {id => expected}
    )
    assert_empty(valid_errors)

    forged = JSON.parse(JSON.generate(entry))
    forged.fetch("expected")["scope"] = "Cluster"
    forged.fetch("oracle")["fields"]["scope"] = "Cluster"
    forged.fetch("oracle")["sha256"] = M1Gate.canonical_document_digest(forged.dig("oracle", "fields"))
    forged.fetch("rubernetes")["fields"]["scope"] = "Cluster"
    forged.fetch("rubernetes")["sha256"] = M1Gate.canonical_document_digest(forged.dig("rubernetes", "fields"))
    hostile_errors = []
    M1Gate.send(
      :validate_surface_matrix, [forged], [id], hostile_errors, "GVR",
      require_applicability: false, pinned_expected_by_id: {id => expected}
    )
    assert(hostile_errors.any? { |error| error.include?("expected fields differ from pinned discovery") })
  end

  def test_default_off_discovery_preserves_both_upstream_404_shapes
    server, = M1ProbeSupport.build_api_server

    known_group_version = server.call(
      method: "GET", path: "/apis/admissionregistration.k8s.io/v1alpha1"
    )
    assert_equal(404, known_group_version.status)
    assert_equal("application/json", known_group_version.headers.fetch("content-type"))
    assert_equal(M1Gate::DISCOVERY_STATUS_NOT_FOUND_BODY, known_group_version.body)

    absent_group = server.call(method: "GET", path: "/apis/internal.apiserver.k8s.io/v1alpha1")
    assert_equal(404, absent_group.status)
    assert_equal("text/plain; charset=utf-8", absent_group.headers.fetch("content-type"))
    assert_equal("nosniff", absent_group.headers.fetch("x-content-type-options"))
    assert_equal(M1Gate::DISCOVERY_NOT_FOUND_BODY, absent_group.body)
  end

  # M1 completion rule: source input must remain content-identical for the
  # complete probe, including path, digest, and file count.
  def test_probe_report_fails_closed_when_source_changes_during_probe
    with_source_fixture do |directory, path|
      report = M1ProbeSupport.probe_report("m1_test_probe", root: directory) do
        File.binwrite(path, "changed\n")
        {"passed" => true}
      end

      refute(report.fetch("passed"))
      refute(report.fetch("input_stable"))
      refute(report.fetch("input_capture").fetch("stable"))
      assert(report.fetch("errors").any? { |error| error.include?("source input changed during probe execution") })
      refute_equal(
        report.dig("input_capture", "start", "entries"),
        report.dig("input_capture", "finish", "entries")
      )
    end
  end

  # M1 completion rule: a byte mutation must be detected even when filesystem
  # size and mtime are deliberately preserved by an adversarial writer.
  def test_probe_report_detects_same_size_mtime_preserving_byte_mutation
    with_source_fixture do |directory, path|
      before = File.stat(path)
      original_bytes = File.size(path)
      report = M1ProbeSupport.probe_report("m1_test_probe", root: directory) do
        File.binwrite(path, "bravo")
        File.utime(before.atime, before.mtime, path)
        assert_equal(original_bytes, File.size(path))
        assert_equal(before.mtime, File.stat(path).mtime)
        {"passed" => true}
      end

      refute(report.fetch("passed"))
      refute(report.fetch("input_stable"))
      assert(report.fetch("errors").any? { |error| error.include?("source input changed during probe execution") })
      start_entry = report.dig("input_capture", "start", "entries").first
      finish_entry = report.dig("input_capture", "finish", "entries").first
      assert_equal(start_entry.fetch("bytes"), finish_entry.fetch("bytes"))
      refute_equal(start_entry.fetch("sha256"), finish_entry.fetch("sha256"))
    end
  end

  # M1 completion rule: restoring the original bytes must not erase evidence
  # that a file was rewritten during the probe.
  def test_probe_report_rejects_byte_mutation_that_is_restored_before_finish
    with_source_fixture do |directory, path|
      original = File.binread(path)
      before = File.stat(path)
      report = M1ProbeSupport.probe_report("m1_restore_probe", root: directory) do
        File.binwrite(path, "bravo")
        File.utime(before.atime, before.mtime, path)
        File.binwrite(path, original)
        File.utime(before.atime, before.mtime, path)
        {"passed" => true}
      end

      refute(report.fetch("passed"))
      refute(report.fetch("input_stable"))
      assert_equal(
        report.dig("input_capture", "start", "entries"),
        report.dig("input_capture", "finish", "entries")
      )
      refute_equal(
        report.dig("input_capture", "start", "stability_metadata"),
        report.dig("input_capture", "finish", "stability_metadata")
      )
    end
  end

  # M1 completion rule: path additions, removals, and renames are all source
  # input changes, regardless of whether the aggregate file count is restored.
  def test_probe_report_detects_add_delete_and_rename_mutations
    mutations = {
      "add" => lambda do |directory, _path|
        File.write(File.join(directory, "added.rb"), "added\n")
      end,
      "delete" => lambda do |_directory, path|
        File.delete(path)
      end,
      "rename" => lambda do |directory, path|
        File.rename(path, File.join(directory, "renamed.rb"))
      end
    }

    mutations.each do |name, mutation|
      with_source_fixture do |directory, path|
        report = M1ProbeSupport.probe_report("m1_#{name}_probe", root: directory) do
          mutation.call(directory, path)
          {"passed" => true}
        end

        refute(report.fetch("passed"), name)
        refute(report.fetch("input_stable"), name)
        refute_equal(
          report.dig("input_capture", "start", "entries"),
          report.dig("input_capture", "finish", "entries"),
          name
        )
      end
    end
  end

  # M1 completion rule: a change between the two end-capture phases is not
  # retried into a new identity; it fails closed as an unstable snapshot.
  def test_stable_source_identity_rejects_mutation_between_capture_phases
    with_source_fixture do |directory, path|
      error = assert_raises(M1ProbeSupport::ProbeError) do
        M1ProbeSupport.stable_source_identity(directory, between_snapshots: lambda do
          File.binwrite(path, "bravo")
        end)
      end

      assert_includes(error.message, "stable inventory snapshot")
    end
  end

  private

  def with_source_fixture
    Dir.mktmpdir("rubernetes-m1-source-") do |directory|
      path = File.join(directory, "tracked.rb")
      File.binwrite(path, "alpha")
      yield(directory, path)
    end
  end

  def initial_watch_trace(event_rv:, list_rv:, claimed:)
    {
      "mode" => "initial-watch",
      "response_status" => 200,
      "events" => [
        {"type" => "ADDED", "resourceVersion" => event_rv, "initial_events_end" => false},
        {"type" => "BOOKMARK", "resourceVersion" => list_rv, "initial_events_end" => true}
      ],
      "list_resourceVersion" => list_rv,
      "valid" => claimed
    }
  end

  def header_pair(headers)
    packet = {
      "all" => headers.dup,
      "compared" => headers.dup,
      "excluded" => [],
      "all_sha256" => M1Gate.canonical_document_digest(headers),
      "compared_sha256" => M1Gate.canonical_document_digest(headers)
    }
    {"expected" => JSON.parse(JSON.generate(packet)), "actual" => JSON.parse(JSON.generate(packet))}
  end

  def presence(fields)
    {"present" => true, "fields" => fields, "sha256" => M1Gate.canonical_document_digest(fields)}
  end
end
