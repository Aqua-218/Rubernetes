# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/conformance/lanes"
require_relative "../../tools/conformance/k6_corpus"
require_relative "../../tools/milestones/m8_corpus_probe"
require_relative "../../tools/milestones/m8_gate"

class K6EvidenceTest < Minitest::Test
  Evidence = Conformance::K6Evidence
  ClientEvidence = Conformance::K6ClientEvidence
  Lanes = Conformance::Lanes
  CorpusProbe = M8CorpusProbe
  CORPUS = YAML.safe_load_file(Conformance::K6Corpus::CORPUS)
  MATRIX = YAML.safe_load_file(Conformance::K6Corpus::CLIENTS)
  PROJECTS = [CORPUS.fetch("projects").find { |project| project.fetch("name") == "jaeger-operator" }].freeze
  CORPUS_DIGEST = "b" * 64

  def test_standalone_evidence_load_checks_image_and_chart_observations
    pin = PROJECTS.first
    project = {"name" => pin.fetch("name"), "images" => image_readback(pin), "preparation" => chart_readbacks(pin)}
    input = JSON.generate([project, pin, CORPUS.fetch("repositories")])
    evidence_path = File.join(Lanes::ROOT, "tools/conformance/k6_evidence.rb")
    check = <<~RUBY
      project, pin, repositories = JSON.parse($stdin.read)
      Conformance::K6Evidence.check_image_observations!(project, pin)
      Conformance::K6Evidence.check_chart_preparation!(project, pin, repositories)
    RUBY
    _output, error, status = Open3.capture3(RbConfig.ruby, "-r", evidence_path, "-e", check, stdin_data: input)

    assert_predicate status, :success?, error
  end

  def test_a_passing_client_placeholder_cannot_replace_the_pinned_matrix
    report = corpus_report(PROJECTS, CORPUS_DIGEST)
    report["clients"] = [{"id" => "arbitrary-client", "passed" => true}]

    verdict = Evidence.verify(report, execution, projects: PROJECTS, corpus_sha256: CORPUS_DIGEST)

    refute verdict.fetch("passed")
    assert_includes verdict.fetch("detail"), "complete pinned client matrix"
  end

  def test_a_passing_project_summary_requires_chart_and_image_readbacks
    report = corpus_report(PROJECTS, CORPUS_DIGEST)
    project = report.fetch("projects").first
    preparation = project.delete("preparation")
    verdict = Evidence.verify(report, execution, projects: PROJECTS, corpus_sha256: CORPUS_DIGEST)

    refute verdict.fetch("passed")
    assert_includes verdict.fetch("detail"), "chart preparation evidence"

    project["preparation"] = preparation
    project.delete("images")
    verdict = Evidence.verify(report, execution, projects: PROJECTS, corpus_sha256: CORPUS_DIGEST)

    refute verdict.fetch("passed")
    assert_includes verdict.fetch("detail"), "running image observations"
    assert_nil Evidence.check_project!(project, Time.iso8601(timestamp(2)), Time.iso8601(timestamp(40)))
  end

  def test_missing_kubectl_verbs_or_a_zero_diff_exit_are_rejected
    report = corpus_report(PROJECTS, CORPUS_DIGEST)
    verbs = report.fetch("clients").first.fetch("verbs")
    missing = verbs.shift
    verdict = Evidence.verify(report, execution, projects: PROJECTS, corpus_sha256: CORPUS_DIGEST)

    refute verdict.fetch("passed")
    assert_includes verdict.fetch("detail"), "operation inventory"

    verbs.unshift(missing)
    verbs.find { |row| row["verb"] == "diff" }["exit_status"] = 0
    verdict = Evidence.verify(report, execution, projects: PROJECTS, corpus_sha256: CORPUS_DIGEST)

    refute verdict.fetch("passed")
    assert_includes verdict.fetch("detail"), "invalid kubectl diff execution"
  end

  def test_full_run_checks_prerequisite_digest_and_the_running_image_readback
    report = corpus_report(PROJECTS, CORPUS_DIGEST)
    project = report.fetch("projects").first
    prerequisite = project.fetch("preparation").find { |row| row["id"] == "chart-cert-manager" }
    digest = prerequisite.fetch("observed_sha256")
    prerequisite["observed_sha256"] = "0" * 64
    verdict = Evidence.verify(report, execution, projects: PROJECTS, corpus_sha256: CORPUS_DIGEST)

    refute verdict.fetch("passed")
    assert_includes verdict.fetch("detail"), "chart-cert-manager preparation does not match"

    prerequisite["observed_sha256"] = digest
    image = project.fetch("images").fetch("images").first
    image["image_id"] = "sha256:#{"0" * 64}"
    verdict = Evidence.verify(report, execution, projects: PROJECTS, corpus_sha256: CORPUS_DIGEST)

    refute verdict.fetch("passed")
    assert_includes verdict.fetch("detail"), "running image observation does not match"
  end

  def test_client_go_and_tool_rows_must_attest_their_checks
    report = corpus_report(PROJECTS, CORPUS_DIGEST)
    client_go = report.fetch("clients").find { |row| row.fetch("id").start_with?("client-go-") }
    client_go["interfaces"] = client_go.fetch("interfaces").except("dynamic")
    verdict = Evidence.verify(report, execution, projects: PROJECTS, corpus_sha256: CORPUS_DIGEST)

    refute verdict.fetch("passed")
    assert_includes verdict.fetch("detail"), "discovery/dynamic/typed evidence is incomplete"

    client_go["interfaces"] = ClientEvidence::INTERFACES
    helm = report.fetch("clients").find { |row| row.fetch("id").start_with?("helm-") }
    helm.fetch("steps").delete_at(2)
    verdict = Evidence.verify(report, execution, projects: PROJECTS, corpus_sha256: CORPUS_DIGEST)

    refute verdict.fetch("passed")
    assert_includes verdict.fetch("detail"), "tool step inventory is incomplete"
  end

  def test_watch_only_image_rows_need_a_complete_stream_receipt
    report = corpus_report(PROJECTS, CORPUS_DIGEST)
    images = report.fetch("projects").first.fetch("images")
    images.fetch("images").first.merge!("observation" => "watch", "pod_uid" => "hook-uid", "resource_version" => "42",
                                        "watch_event" => "DELETED", "stage" => "uninstall")
    images["watch"] = {"status" => "complete", "errors" => []}

    assert Evidence.verify(report, execution, projects: PROJECTS, corpus_sha256: CORPUS_DIGEST).fetch("passed")

    images.fetch("watch")["status"] = "incomplete"
    verdict = Evidence.verify(report, execution, projects: PROJECTS, corpus_sha256: CORPUS_DIGEST)

    refute verdict.fetch("passed")
    assert_includes verdict.fetch("detail"), "running image watch evidence is incomplete"
  end

  def test_a_complete_manifest_requires_a_hash_bound_corpus_and_fresh_runtime_proof
    Dir.mktmpdir do |directory|
      report = corpus_report(PROJECTS, CORPUS_DIGEST)
      manifest = archive(directory, report)

      verdict = CorpusProbe.executed_case([manifest], PROJECTS, CORPUS_DIGEST)

      assert verdict.fetch("passed")
      assert_equal 1, verdict.fetch("runtime_verified_runs")

      report.fetch("projects").first.fetch("runtime_residue")["post_uninstall_at"] = timestamp(16)
      stale = archive(directory, report)
      verdict = CorpusProbe.executed_case([stale], PROJECTS, CORPUS_DIGEST)

      refute verdict.fetch("passed")
      assert_match(/does not bracket/, verdict.fetch("detail"))

      clean = archive(directory, corpus_report(PROJECTS, CORPUS_DIGEST))
      File.write(File.join(directory, "k6", Evidence::REPORT), JSON.generate(report))
      verdict = CorpusProbe.executed_case([clean], PROJECTS, CORPUS_DIGEST)

      refute verdict.fetch("passed")
      assert_match(/SHA-256/, verdict.fetch("detail"))
    end
  end

  def test_a_legacy_lane_and_a_current_smoke_report_with_no_runtime_measurement_are_not_k6_passes
    Dir.mktmpdir do |directory|
      report = corpus_report(PROJECTS, CORPUS_DIGEST)
      report.fetch("projects").first.delete("runtime_residue")
      old = archive(directory, report)
      verdict = CorpusProbe.executed_case([old], PROJECTS, CORPUS_DIGEST)

      refute verdict.fetch("passed")
      assert_equal "COMPLETE", verdict.fetch("observations").first.fetch("recorded_status")

      current = corpus_report(PROJECTS, CORPUS_DIGEST)
      current.fetch("projects").first.fetch("runtime_residue")["workers"]["worker-1"] = "unmeasured"
      verdict = CorpusProbe.executed_case([archive(directory, current)], PROJECTS, CORPUS_DIGEST)

      refute verdict.fetch("passed")
      assert_match(/runtime cleanup or project stages are incomplete/, verdict.fetch("detail"))
    end
  end

  def test_normal_k6_lane_records_and_checks_the_corpus_results
    Dir.mktmpdir do |directory|
      corpus = CORPUS.merge("projects" => PROJECTS)
      load_yaml = YAML.method(:safe_load_file)
      pinned_inputs = ->(path) { path == Lanes::K6::CORPUS ? corpus : load_yaml.call(path) }
      capture = lambda do |_command|
        digest = Digest::SHA256.file(Lanes::K6::CORPUS).hexdigest
        File.write(File.join(directory, Evidence::REPORT), JSON.generate(corpus_report(PROJECTS, digest)))
        execution
      end
      result = YAML.stub(:safe_load_file, pinned_inputs) do
        Lanes.stub(:corpus_shape, {"satisfies_minimums" => true}) do
          Lanes.stub(:cluster_reachable?, true) do
            Lanes.stub(:capture, capture) { Lanes::K6.run(options: {kubeconfig: "fixture"}, profile: {}, directory: directory) }
          end
        end
      end

      assert_equal "COMPLETE", result.fetch("status")
      assert_equal 1, result.fetch("runtime_evidence").fetch("verified_projects")
      assert(result.fetch("artifacts").any? { |entry| entry.fetch("path").end_with?(Evidence::REPORT) })
    end
  end

  def test_m8_gate_rejects_imported_corpus_reports_that_only_record_complete
    summary = {"id" => "corpus_minimums", "total" => PROJECTS.length}
    old = {"id" => "k6_executed", "passed" => true}
    errors = []
    M8Gate.send(:validate_corpus, {}, [summary, old], errors)

    assert_includes errors, "K6 must record runtime cleanup verification for the full corpus"

    Dir.mktmpdir do |directory|
      manifest = archive(directory, corpus_report(PROJECTS, CORPUS_DIGEST))
      verified = CorpusProbe.executed_case([manifest], PROJECTS, CORPUS_DIGEST)
      errors = []
      M8Gate.send(:validate_corpus, {}, [summary, verified], errors)

      refute_includes errors, "K6 must record runtime cleanup verification for the full corpus"
    end
  end

  private

  def timestamp(offset)
    (Time.utc(2026, 11, 20) + offset).iso8601
  end

  def execution
    {"command" => %w[ruby tools/conformance/k6_corpus.rb --kubeconfig fixture --output /chroot/evidence/relocated/k6],
     "exit_status" => 0, "timed_out" => false, "started_at" => timestamp(1), "finished_at" => timestamp(50)}
  end

  def corpus_report(projects, digest)
    rows = projects.map do |project|
      stages = Evidence::STAGES.each_with_index.map do |stage, index|
        {"stage" => stage, "passed" => true, "started_at" => timestamp(10 + index), "finished_at" => timestamp(10 + index)}
      end
      runtime = {"status" => "clean", "passed" => true, "workers" => {"worker-0" => "measured"},
                 "baseline_at" => timestamp(9), "post_uninstall_at" => timestamp(35), "observed_pod_uids" => ["pod-id"],
                 "residue" => [], "unattributed" => [], "errors" => []}
      project.slice("name", "source_commit").merge("api_passed" => true, "passed" => true, "stages" => stages, "runtime_residue" => runtime,
                                                   "preparation" => chart_readbacks(project), "images" => image_readback(project))
    end
    {"schema_version" => 1, "kind" => "k6_client_and_project_corpus", "corpus_sha256" => digest, "clients_only" => false, "projects_only" => false,
     "started_at" => timestamp(2), "generated_at" => timestamp(40), "clients" => client_report,
     "failures" => [], "residue" => [], "projects" => rows}
  end

  def client_report
    rows = MATRIX.fetch("kubectl").map { |pin| kubectl_report(pin) }
    rows.concat(MATRIX.fetch("client_go").map do |pin|
      {"id" => ClientEvidence.client_id("client-go", pin), "passed" => true, "module_sum" => pin.fetch("sum"),
       "probe_sha256" => "d" * 64, "interfaces" => ClientEvidence::INTERFACES}
    end)
    rows + %w[helm kustomize].map { |name| tool_report(name) }
  end

  def kubectl_report(pin)
    namespace = "k6-client-aabbccddeeff"
    prefix = ClientEvidence.fixture_prefix("fixture", namespace, kubectl: true)
    binary = "/checkout/#{pin.fetch("path")}"
    verbs = ClientEvidence.kubectl_operations(namespace).map do |name, args|
      receipt = {"verb" => name, "command" => [binary, *prefix, *args], "passed" => true}
      next receipt if ClientEvidence::STREAMS.include?(name)

      receipt.merge("exit_status" => (name == "diff" ? 1 : 0), "stdout_sha256" => "c" * 64)
    end
    cleanup = [binary, *prefix, "delete", "namespace", namespace, "--ignore-not-found", "--wait=true", "--timeout=90s"]
    {"id" => ClientEvidence.client_id("kubectl", pin), "passed" => true, "image" => Conformance::K6ClientVerbs::IMAGE,
     "sha256" => pin.fetch("sha256"), "namespace" => namespace, "verbs" => verbs,
     "setup" => {"command" => [binary, *prefix, "create", "-f", "-"], "exit_status" => 0},
     "cleanup" => {"command" => cleanup, "exit_status" => 0}}
  end

  def tool_report(name)
    pin = MATRIX.fetch(name)
    kubectl = MATRIX.fetch("kubectl").find { |entry| entry["version"] == MATRIX.fetch("target_api_server") }
    steps = ClientEvidence.tool_operations(name, "fixture", "k6-tool-aabbccddeeff", "/unit-fixture").map do |tool, args|
      binary = tool == "kubectl" ? kubectl.fetch("path") : pin.fetch("path")
      result = {"command" => ["/checkout/#{binary}", *args], "passed" => true, "stdout_sha256" => "c" * 64}
      result["exit_status"] = 0 unless tool == "kustomize"
      result
    end
    {"id" => ClientEvidence.client_id(name, pin), "passed" => true, "sha256" => pin.fetch("sha256"), "steps" => steps}
  end

  def chart_readbacks(project)
    Evidence.chart_preparation_pins(project, CORPUS.fetch("repositories")).map do |id, pins|
      pins.merge("id" => id, "passed" => true)
    end
  end

  def image_readback(project)
    lock = project.fetch("images").first
    reference, digest = lock.split("@", 2)
    {"passed" => true, "errors" => [], "images" => [
      {"stage" => "ready", "pod" => "pod", "container" => "container", "reference" => reference,
       "image_id" => reference.split(":", 2).first + "@#{digest}", "lock" => lock, "passed" => true, "manifest_digest" => digest}
    ]}
  end

  def archive(directory, report)
    lane_dir = File.join(directory, "k6")
    FileUtils.mkdir_p(lane_dir)
    artifacts = {Evidence::REPORT => report, Evidence::COMMAND => execution}.map do |name, data|
      path = File.join(lane_dir, name)
      File.write(path, JSON.generate(data))
      {"path" => "/chroot/evidence/relocated/k6/#{name}", "sha256" => Digest::SHA256.file(path).hexdigest}
    end
    lane = {"lane" => "K6", "status" => "COMPLETE", "passed" => true, "startedAt" => timestamp(1),
            "finishedAt" => timestamp(51), "artifacts" => artifacts}
    {"_path" => File.join(directory, "manifest.json"), "startedAt" => timestamp(0), "finishedAt" => timestamp(52),
     "lanes" => [lane], "artifacts" => artifacts}
  end
end
