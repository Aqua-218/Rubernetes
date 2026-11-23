# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/milestones/m8_conformance_probe"

class M8ConformanceProbeTest < Minitest::Test
  Lock = Conformance::Lock
  JUnit = Conformance::K1Evidence
  Ginkgo = Conformance::K1GinkgoReport
  Profiles = Lock.profiles.fetch("profiles")
  Configuration = Lock.profiles.merge("conformance" => {"expected_tests" => 2})
  CODENAMES = ["[sig-api-machinery] sample A & B [Conformance]", "[sig-node] sample B [Conformance]"].freeze
  Definition = YAML.dump(CODENAMES.map { |name| {"codename" => name} }).freeze
  REVISION = "a" * 40

  def test_three_recent_independent_runs_clear_old_failure_and_incomplete_history
    in_fixture do
      earlier = [attempt("zz-first-failure", 1, status: "FAILED"),
                 attempt("zz-next-incomplete", 2, status: "INCOMPLETE")]
      complete = Profiles.each_with_index.flat_map do |profile, index|
        Array.new(3) { |offset| attempt("recent-#{index}-#{offset}", 3 + (index * 3) + offset, profile: profile) }
      end
      report = evaluate([*complete.reverse, *earlier])

      assert report.fetch("passed"), report.fetch("cases").reject { |entry| entry["passed"] }.inspect
      assert_equal 9, run_cases(report).size
      assert_equal([3, 3, 3], Profiles.map { |profile| streak(report, profile).fetch("clean_streak") })
      history = report.fetch("k1_earlier_runs").fetch(Profiles.first.fetch("name"))

      assert_equal(%w[INCOMPLETE FAILED], history.map { |run| run.fetch("recorded_status") })
    end
  end

  def test_identical_manifest_copies_count_once_with_relocated_originals
    in_fixture do
      original = attempt("relocated-run", 1)
      copies = %w[another-directory yet-another-directory].map do |label|
        original.merge("_path" => File.join(@directory, label, "manifest.json"))
      end
      report = evaluate([*copies, original])
      profile = streak(report)

      assert_equal 1, profile.fetch("runs")
      assert_equal 1, profile.fetch("clean_streak")
      assert_equal [original.fetch("runId")], profile.fetch("run_ids")
      assert_equal(["verified"], run_cases(report).map { |entry| entry.fetch("status") })
      assert_equal original.fetch("_path"), run_cases(report).first.fetch("manifest")
      refute profile.fetch("passed")
    end
  end

  def test_same_original_reports_under_distinct_run_ids_do_not_count
    in_fixture do
      original = attempt("original", 1)
      replay = original.merge("runId" => "relabelled-original")
      report = evaluate([original, replay])

      assert_equal 2, streak(report).fetch("runs")
      assert_equal 0, streak(report).fetch("clean_streak")
      assert_equal(%w[duplicate_evidence duplicate_evidence], run_cases(report).map { |entry| entry.fetch("status") })
    end
  end

  def test_conflicting_manifests_for_the_same_run_id_are_unclean
    in_fixture do
      original = attempt("original", 1)
      conflict = original.merge("rubernetesCommit" => "b" * 40)
      report = evaluate([original, conflict])

      assert_equal 1, streak(report).fetch("runs")
      assert_equal(["conflicting_run_id"], run_cases(report).map { |entry| entry.fetch("status") })
      assert_equal 0, streak(report).fetch("clean_streak")
    end
  end

  def test_an_attempt_with_missing_or_modified_originals_occupies_its_history_position
    in_fixture do
      records = Array.new(4) { |offset| attempt("run-#{offset}", offset + 1) }
      target = records.fetch(2)
      original = artifact_path(target, M8K1Evidence::JUNIT)
      bytes = File.binread(original)
      File.unlink(original)

      report = evaluate(records)

      assert_equal 1, streak(report).fetch("clean_streak")
      assert_equal(%w[verified missing_evidence verified], run_cases(report).map { |entry| entry.fetch("status") })

      File.binwrite(original, bytes + "\n")

      report = evaluate(records)

      assert_equal 1, streak(report).fetch("clean_streak")
      assert_equal(%w[verified invalid_evidence verified], run_cases(report).map { |entry| entry.fetch("status") })
      assert_match(/does not match its recorded SHA-256/, run_cases(report).fetch(1).fetch("detail"))
    end
  end

  def test_recorded_totals_and_codenames_must_match_the_original_join
    in_fixture do
      run = attempt("run", 1)
      lane = run.fetch("lanes").first
      lane.fetch("summary").delete("failed")
      lane.fetch("codenames")["executed_count"] = 1
      report = evaluate([run])

      assert_match(/do not match the original reports/, run_cases(report).first.fetch("detail"))
      refute report.fetch("cases").find { |entry| entry.fetch("id").start_with?("k1_codename_join-") }.fetch("passed")
      assert_equal 0, streak(report).fetch("clean_streak")
    end
  end

  def test_original_reports_cannot_certify_a_run_with_source_changes
    in_fixture do
      run = attempt("run", 1)
      run["rubernetesCommitAfter"] = "b" * 40
      run["rubernetesSourceStable"] = false
      report = evaluate([run])

      assert_match(/source changed/, run_cases(report).first.fetch("detail"))
      assert_equal 0, streak(report).fetch("clean_streak")
    end
  end

  def test_latest_runs_for_all_profiles_must_certify_the_same_release_revision
    in_fixture do
      other_profile = Profiles.fetch(1)
      previous = Array.new(3) { |offset| attempt("other-#{offset}", offset + 1, profile: other_profile) }
      release = "sha256:#{"b" * 64}"
      latest = attempt("latest-release", 4, revision: release)
      report = evaluate([*previous, latest])

      assert_equal release, streak(report).fetch("release_cohort")
      assert_equal 1, streak(report).fetch("clean_streak")
      assert_equal 0, streak(report, other_profile).fetch("clean_streak")
      refute report.fetch("passed")
    end
  end

  def test_accepts_equivalent_hydrophone_argv_with_a_namespace_and_mixed_flag_forms
    in_fixture do
      run = attempt("run", 1)
      argv = hydrophone_command(run.fetch("lanes").first).fetch("command")
      executable, _, kubeconfig, _, _, image, _, busybox, _, _, report, _, output = argv
      rewrite_command(run, ["ip", "netns", "exec", "fixture", executable, "--parallel=1",
                            "--output-dir", output, "--conformance=true", "--busybox-image=#{busybox}",
                            "--kubeconfig=#{kubeconfig}", report, "--conformance-image", image])

      report = evaluate([run])

      assert_equal(["verified"], run_cases(report).map { |entry| entry.fetch("status") })
    end
  end

  def test_rejects_filters_unknown_flags_duplicate_or_missing_flags_and_wrong_parallelism
    in_fixture do
      run = attempt("run", 1)
      argv = hydrophone_command(run.fetch("lanes").first).fetch("command")
      options = [
        [*argv, "--focus", "one case"],
        [*argv, "--skip=one case"],
        [*argv, "--unknown"],
        [*argv, "--parallel=1"],
        argv.take(argv.length - 2),
        argv.map { |arg| arg == "1" ? "2" : arg }
      ]

      options.each do |command|
        rewrite_command(run, command)

        assert_equal ["invalid_evidence"], run_cases(evaluate([run])).map { |entry| entry.fetch("status") }, command.inspect
      end
    end
  end

  private

  def in_fixture(&)
    Dir.mktmpdir("m8-conformance-probe") do |directory|
      @directory = directory
      definition = {"sha256" => Digest::SHA256.hexdigest(Definition), "test_count" => CODENAMES.length}
      Lock.stub(:conformance_definition, definition, &)
    end
  end

  def evaluate(runs)
    k2 = {"lanes" => [{"lane" => "K2", "status" => "COMPLETE", "passed" => true}]}
    M8ConformanceProbe.evaluate(manifests: [*runs, k2], configuration: Configuration)
  end

  def run_cases(report)
    report.fetch("cases").select { |entry| entry.fetch("id").start_with?("k1_totals-") }
  end

  def streak(report, profile = Profiles.first)
    report.fetch("cases").find { |entry| entry.fetch("id") == "k1_consecutive_clean-#{profile.fetch("name")}" }
  end

  def attempt(label, order, profile: Profiles.first, revision: REVISION, status: "COMPLETE")
    start = Time.utc(2026, 11, 20) + (order * 60)
    finish = start + 30
    name = profile.fetch("name")
    path = File.join(@directory, label, "manifest.json")
    lane = {"lane" => "K1", "status" => status, "passed" => status == "COMPLETE", "profile" => name,
            "startedAt" => start.iso8601, "finishedAt" => finish.iso8601}
    manifest = {"_path" => path, "runId" => "run-#{order}", "profile" => name, "profileDefinition" => profile,
                "sourceCommit" => Lock.source_commit, "rubernetesCommit" => revision, "platform" => "linux/amd64",
                "inputsLock" => Lock::KUBERNETES.delete_prefix("#{Lock::ROOT}/"),
                "startedAt" => start.iso8601, "finishedAt" => finish.iso8601, "lanes" => [lane]}
    write_original_reports(manifest, lane, order) if status == "COMPLETE"
    manifest
  end

  def write_original_reports(manifest, lane, seed)
    definition = artifact_path(manifest, "k1/conformance-definition.yaml")
    command = artifact_path(manifest, "k1/hydrophone-command.json")
    stdout = artifact_path(manifest, "k1/hydrophone.stdout.gz")
    junit = artifact_path(manifest, M8K1Evidence::JUNIT)
    ginkgo = artifact_path(manifest, M8K1Evidence::GINKGO)
    FileUtils.mkdir_p(File.dirname(junit))
    File.write(definition, Definition)
    File.write(command, JSON.generate(hydrophone_command(lane)))
    Zlib::GzipWriter.open(stdout) { |file| file.write("finished Conformance run\n") }
    write_suite(junit, ginkgo, seed)

    summary, codenames, cases = Zlib::GzipReader.open(stdout) { |log| JUnit.junit(junit, codenames: CODENAMES, stdout: log) }
    lane.merge!("summary" => summary, "codenames" => codenames, "ginkgo" => Ginkgo.join(ginkgo, cases, expected: CODENAMES.length))
    directory = File.dirname(manifest.fetch("_path"))
    artifacts = [definition, command, stdout, junit, ginkgo].map do |path|
      {"path" => "/original/chroot/run/#{path.delete_prefix("#{directory}/")}", "sha256" => Lock.digest_file(path)}
    end
    lane["artifacts"] = artifacts
    manifest["artifacts"] = artifacts
  end

  def artifact_path(manifest, name)
    File.join(File.dirname(manifest.fetch("_path")), name)
  end

  def hydrophone_command(lane)
    command = ["/tools/hydrophone", "--kubeconfig", "/fixture/kubeconfig", "--conformance",
               "--conformance-image", Lock.reference_by_digest(Lock.kubernetes.fetch("conformance_image")),
               "--busybox-image", Lock.reference_by_digest(Lock.support_images.fetch("busybox")),
               "--parallel", "1", Ginkgo::FLAG, "--output-dir", "/original/chroot/run/k1/hydrophone"]
    {"command" => command, "exit_status" => 0, "timed_out" => false, "stdout_artifact" => "hydrophone.stdout.gz",
     "started_at" => lane.fetch("startedAt"), "finished_at" => lane.fetch("finishedAt")}
  end

  def rewrite_command(manifest, argv)
    name = "k1/hydrophone-command.json"
    path = artifact_path(manifest, name)
    lane = manifest.fetch("lanes").first
    File.write(path, JSON.generate(hydrophone_command(lane).merge("command" => argv)))
    [manifest, lane].each do |entry|
      entry.fetch("artifacts").find { |artifact| artifact.fetch("path").end_with?(name) }["sha256"] = Lock.digest_file(path)
    end
  end

  def write_suite(junit, ginkgo, seed)
    config = {"FocusStrings" => [JUnit::FOCUS], "SkipStrings" => [], "FocusFiles" => [], "SkipFiles" => [],
              "LabelFilter" => "", "SemVerFilter" => "", "FlakeAttempts" => 0, "DryRun" => false,
              "ParallelTotal" => 1, "RandomSeed" => seed}
    specs = CODENAMES.map do |name|
      {"ContainerHierarchyTexts" => [], "LeafNodeText" => name,
       "LeafNodeType" => "It", "State" => "passed", "NumAttempts" => 1}
    end
    report = {"SuiteConfig" => config, "SuiteSucceeded" => true, "SuiteHasProgrammaticFocus" => false, "SpecReports" => specs}
    Zlib::GzipWriter.open(ginkgo) { |file| file.write(JSON.generate([report])) }

    xml = REXML::Document.new
    suite = xml.add_element("testsuite", {"tests" => CODENAMES.length.to_s})
    properties = suite.add_element("properties")
    config.merge(report.slice("SuiteSucceeded", "SuiteHasProgrammaticFocus")).each do |key, value|
      properties.add_element("property", {"name" => key, "value" => value.is_a?(Array) ? value.join(",") : value.to_s})
    end
    CODENAMES.each { |name| suite.add_element("testcase", {"name" => "[It] #{name}", "status" => "passed"}) }
    File.open(junit, "w") { |file| xml.write(file) }
  end
end
