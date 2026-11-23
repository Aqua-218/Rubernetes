# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/milestones/m8_gate"
require_relative "../../tools/milestones/m8_selection_probe"

class M8K3EvidenceTest < Minitest::Test
  Evidence = M8K3Evidence
  Lock = Evidence::Lock
  Build = Evidence::Build
  INTERNAL = Conformance::K3InternalContractIndex
  REQUIRED_IDS = ["[sig-example] accepts network policy", "[sig-example] reconciles a Job"].freeze
  STARTED = "2026-11-20T04:10:00Z"
  FINISHED = "2026-11-20T04:11:00Z"

  def test_complete_original_joins_current_ledger_junit_and_replacement_observations
    with_campaign do |fixture|
      verdict = verify(fixture)

      assert verdict.fetch("passed"), verdict.inspect
      assert_equal 2, verdict.fetch("verified_required")
      assert_equal 1, verdict.fetch("verified_replacements")
    end
  end

  def test_archive_moves_without_requiring_the_binary_or_old_paths
    with_campaign do |fixture|
      Dir.mktmpdir("moved-k3-archive-") do |new_root|
        File.unlink(fixture.fetch(:binary))
        FileUtils.mv(fixture.fetch(:root), new_root)
        verdict = verify(fixture.merge(run_root: new_root, binary: nil))

        assert verdict.fetch("passed"), verdict.inspect
      end
    end
  end

  def test_matching_local_filename_and_sha_without_build_receipt_are_insufficient
    with_campaign(archived_build: false) do |fixture|
      verdict = verify(fixture)

      refute verdict.fetch("passed")
      assert_includes verdict.fetch("detail"), "requires a matching build receipt"
    end
  end

  def test_legacy_archive_can_use_local_executable_with_original_build_stdout
    with_campaign(archived_build: false) do |fixture|
      target = {"target" => "e2e.test", "installed" => true, "exit_status" => 0,
                "sha256" => Digest::SHA256.file(fixture.fetch(:binary)).hexdigest}
      File.write("#{fixture.fetch(:binary)}.build.json", raw_receipt(target))
      Build.stub(:go_platform, Build::PLATFORM) do
        verdict = verify(fixture)

        assert verdict.fetch("passed"), verdict.inspect
      end
    end
  end

  def test_wrong_build_platform_cannot_be_replaced_by_a_local_executable
    with_campaign(archived_build: "linux/arm64") do |fixture|
      verdict = verify(fixture)

      refute verdict.fetch("passed")
      assert_includes verdict.fetch("detail"), "requires a matching build receipt"
    end
  end

  def test_matching_pass_counts_cannot_replace_exact_ledger_selection
    with_campaign(selected: REQUIRED_IDS.take(1)) do |fixture|
      verdict = verify(fixture)

      refute verdict.fetch("passed")
      assert_includes verdict.fetch("detail"), "selected 1 of 2 required ledger IDs"
    end
  end

  def test_selection_with_full_count_but_duplicate_id_cannot_pass
    with_campaign(selected: [REQUIRED_IDS.first, REQUIRED_IDS.first]) do |fixture|
      verdict = verify(fixture)

      refute verdict.fetch("passed")
      assert_includes verdict.fetch("detail"), "1 duplicate"
    end
  end

  def test_recorded_pass_cannot_replace_a_skipped_original_junit_case
    with_campaign(skipped: REQUIRED_IDS.last) do |fixture|
      verdict = verify(fixture)

      refute verdict.fetch("passed")
      assert_includes verdict.fetch("detail"), "did not pass every selected ID"
      assert_includes verdict.fetch("detail"), "skipped"
    end
  end

  def test_original_failing_suite_cannot_be_promoted_by_passing_cases
    with_campaign(suite_succeeded: false) do |fixture|
      verdict = verify(fixture)

      refute verdict.fetch("passed")
      assert_includes verdict.fetch("detail"), "original JUnit suite did not succeed"
    end
  end

  def test_replacement_pass_without_observations_cannot_satisfy_the_ledger
    with_campaign(replacement_observations: {}) do |fixture|
      verdict = verify(fixture)

      refute verdict.fetch("passed")
      assert_includes verdict.fetch("detail"), "has no passing original"
    end
  end

  def test_digest_mismatch_rejects_the_campaign
    with_campaign do |fixture|
      path = File.join(fixture.fetch(:root), "k3/chunk-000/junit_01.xml")
      File.open(path, "a") { |file| file << "\n" }
      verdict = verify(fixture)

      refute verdict.fetch("passed")
      assert_includes verdict.fetch("detail"), "does not match its recorded SHA-256"
    end
  end

  def test_gate_rejects_summary_with_no_original_campaign
    errors = []
    summary = {"id" => Evidence::CASE, "passed" => true, "status" => "verified", "required" => 5147, "verified_required" => 5147}
    M8Gate.send(:validate_selection, {"counts" => {"required" => 5147}}, [summary], errors)

    assert_includes errors, "K3 must verify the original full campaign: K3 requires a hash-pinned campaign manifest"
  end

  def test_probe_cannot_report_pass_without_a_k3_run
    verdict = M8SelectionProbe.k3_campaign([{"lanes" => [{"lane" => "K4", "passed" => true}]}], "{}")

    refute verdict.fetch("passed")
    assert_equal "no K3 campaign is recorded", verdict.fetch("detail")
  end

  private

  def verify(fixture)
    Evidence::Campaign.new(fixture.fetch(:reference), ledger_bytes: fixture.fetch(:ledger_bytes),
                                                      run_root: fixture.fetch(:run_root), binary: fixture.fetch(:binary)).verify
  end

  def with_campaign(selected: REQUIRED_IDS, skipped: nil, suite_succeeded: true, replacement_observations: {"metric_observed" => true},
                    archived_build: Build::PLATFORM)
    Dir.mktmpdir("m8-k3-archive-") do |run_root|
      root = File.join(run_root, "campaign")
      FileUtils.mkdir_p(root)
      binary = File.join(root, "e2e.test")
      File.binwrite(binary, "unit test only")
      File.chmod(0o755, binary)
      ledger_bytes = JSON.generate(ledger)
      profile = Lock.profiles.fetch("profiles").first
      selection = {"chunks" => [selected], "ledger_sha256" => Digest::SHA256.hexdigest(ledger_bytes),
                   "profile" => profile.fetch("name"), "kubernetes_tag" => Lock.kubernetes.dig("source", "tag"),
                   "binary_path" => binary, "binary_sha256" => Digest::SHA256.file(binary).hexdigest}

      entries = record_originals(root, selection, skipped, suite_succeeded, replacement_observations, archived_build)
      manifest_path = File.join(root, "manifest.json")
      File.write(manifest_path, JSON.generate(manifest(profile, entries)))
      reference = {"path" => "campaign/manifest.json", "sha256" => Digest::SHA256.file(manifest_path).hexdigest}
      yield(root: root, run_root: run_root, reference: reference, ledger_bytes: ledger_bytes, binary: binary)
    end
  end

  def raw_receipt(target)
    JSON.generate("schema_version" => 1, "kind" => Build::KIND, "commit" => Lock.source_commit, "passed" => true, "targets" => [target])
  end

  def ledger
    replacement = INTERNAL::CASES.first
    tests = REQUIRED_IDS.map { |id| {"id" => id, "classification" => "required"} }
    tests << {"id" => replacement.first, "classification" => "implementation-internal", "external_contract" => true,
              "reason" => "Direct datastore process interaction", "replacement_test" => INTERNAL::RUNNER, "replacement_case" => replacement.last}
    {"source" => {"kubernetes_tag" => Lock.kubernetes.dig("source", "tag"), "spec_count" => tests.length},
     "counts" => {"required" => REQUIRED_IDS.length, "implementation-internal" => 1}, "tests" => tests}
  end

  def record_originals(root, selection, skipped, suite_succeeded, replacement_observations, archived_build)
    lane = File.join(root, "k3")
    chunks = File.join(lane, "chunk-000")
    FileUtils.mkdir_p(chunks)
    ids = selection.fetch("chunks").first
    if archived_build
      target = {"target" => "e2e.test", "installed" => true, "exit_status" => 0,
                "sha256" => selection.fetch("binary_sha256"), "platform" => archived_build,
                "source_commit" => Lock.source_commit, "source_clean" => true, "command" => Build::COMMAND}
      File.write(File.join(lane, Build::ARTIFACT), raw_receipt(target))
    end
    File.write(File.join(lane, "upstream-selection.json"), JSON.generate(selection))
    File.write(File.join(lane, "e2e-command-000.json"), JSON.generate(command(selection, chunks)))
    %w[stdout stderr].each do |stream|
      Zlib::GzipWriter.open(File.join(lane, "e2e-command-000.#{stream}.gz")) { |gzip| gzip.write("") }
    end
    File.write(File.join(chunks, "junit_01.xml"), junit(ids, skipped, suite_succeeded))
    File.write(File.join(lane, "internal-replacements-command.json"), JSON.generate(replacement_command(replacement_observations)))
    Dir.glob(File.join(lane, "**/*")).select { |path| File.file?(path) }.map do |path|
      {"path" => path, "sha256" => Digest::SHA256.file(path).hexdigest}
    end
  end

  def manifest(profile, entries)
    lane = {"lane" => "K3", "passed" => true, "status" => "COMPLETE", "startedAt" => STARTED, "finishedAt" => FINISHED,
            "artifacts" => entries.reject { |entry| entry.fetch("path").end_with?("junit_01.xml") }}
    {"suite" => "K0-K7-kubernetes-compatibility", "runId" => "k3-test-run",
     "profile" => profile.fetch("name"), "profileDefinition" => profile, "platform" => "linux/amd64",
     "rubernetesCommit" => "b" * 40, "rubernetesCommitAfter" => "b" * 40, "rubernetesSourceStable" => true,
     "sourceCommit" => Lock.source_commit, "inputsLock" => Lock::KUBERNETES.delete_prefix("#{Lock::ROOT}/"),
     "startedAt" => STARTED, "finishedAt" => FINISHED, "lanes" => [lane], "artifacts" => entries}
  end

  def command(selection, chunks)
    {"command" => [selection.fetch("binary_path"), "--provider=skeleton", "--kubeconfig", "/fixture/kubeconfig",
                   "--kubectl-path", "/fixture/kubectl-v1.36.2",
                   "--ginkgo.focus=#{Evidence::K3.focus_pattern(selection.fetch("chunks").first)}", "--report-dir=#{chunks}"],
     "exit_status" => 0, "timed_out" => false, "started_at" => STARTED, "finished_at" => FINISHED,
     "stdout_artifact" => "e2e-command-000.stdout.gz", "stderr_artifact" => "e2e-command-000.stderr.gz"}
  end

  def junit(ids, skipped, suite_succeeded)
    cases = ids.map { |id| %(<testcase name="[It] #{id}" status="#{id == skipped ? "skipped" : "passed"}"/>) }.join
    %(<testsuites><testsuite><properties><property name="SuiteSucceeded" value="#{suite_succeeded}"/></properties>#{cases}</testsuite></testsuites>)
  end

  def replacement_command(observations)
    id, key = INTERNAL::CASES.first
    result = {"id" => id, "replacement_case" => key, "passed" => true, "observations" => observations}
    {"command" => [RbConfig.ruby, File.join(Lock::ROOT, INTERNAL::RUNNER), key],
     "exit_status" => 0, "timed_out" => false, "stdout" => JSON.generate("results" => [result])}
  end
end
