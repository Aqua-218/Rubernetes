# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/conformance/lanes"
require_relative "../../tools/milestones/m8_gate"
require_relative "../../tools/milestones/m8_selection_probe"

class M8K4EvidenceTest < Minitest::Test
  K4 = Conformance::Lanes::K4
  Lock = Conformance::Lock
  RRO = Conformance::K4RRO

  def test_complete_summary_without_originals_does_not_pass_probe_or_gate
    Dir.mktmpdir do |directory|
      lane = {"lane" => "K4", "status" => "COMPLETE", "passed" => true}
      manifest = {"_path" => File.join(directory, "manifest.json"), "lanes" => [lane]}
      result = M8SelectionProbe.k4_case([manifest])

      refute result.fetch("passed")
      assert_equal "missing_evidence", result.fetch("attempts").first.fetch("status")

      errors = []
      fake = result.merge("passed" => true)
      M8Gate.send(:validate_selection, {"counts" => {"required" => 1}}, [fake], errors)

      assert_includes errors, "K4 requires an original-backed clean run of the pinned Node Conformance inventory"
    end
  end

  def test_archived_originals_with_bound_build_invocation_and_junit_can_pass
    fixture(archive: true, cli_junit: true) do |manifest, lane, _path|
      result = M8SelectionProbe.k4_case([manifest])
      verdict = result.fetch("proof")

      assert result.fetch("passed"), result.inspect
      assert_equal lane.fetch("coverage"), verdict.fetch("coverage")
      assert_equal 11, verdict.fetch("original_sha256").size
      assert M8K4Evidence.proof?(verdict)
      refute M8K4Evidence.proof?(verdict.merge("original_sha256" => verdict.fetch("original_sha256").except("execution.json")))
      refute M8K4Evidence.proof?(verdict.merge("coverage" => verdict.fetch("coverage").merge("passed" => 0)))

      errors = []
      M8Gate.send(:validate_selection, {"counts" => {"required" => 1}}, [result], errors)

      refute errors.any? { |error| error.start_with?("K4 requires") }, errors.inspect

      # A freshly recorded compressed digest does not attest the raw size.
      lane.fetch("artifacts").find { |artifact| artifact.fetch("path").end_with?("/inventory.json.gz") }["uncompressed_bytes"] += 1
      republish_lane(manifest, lane)
      result = M8K4Evidence.verify(manifest, lane)

      refute result.fetch("passed")
      assert_match(/original size differs/, result.fetch("detail"))
    end
  end

  def test_framework_junit_only_historical_layout_and_failed_run_remain_distinct
    fixture do |manifest, lane, _path|
      assert_equal "verified", M8K4Evidence.verify(manifest, lane).fetch("status")
    end

    fixture(failed: true) do |manifest, lane, _path|
      # The historical manifest includes the JUnit as a run artifact only.
      lane.fetch("artifacts").reject! { |artifact| artifact.fetch("path").end_with?("/#{K4::FRAMEWORK_JUNIT}") }
      republish_lane(manifest, lane)
      verdict = M8K4Evidence.verify(manifest, lane)

      refute verdict.fetch("passed")
      assert_equal "failed", verdict.fetch("status")
      assert_equal 0, verdict.dig("coverage", "passed")
    end
  end

  def test_same_count_with_substituted_inventory_is_rejected
    fixture do |manifest, lane, path|
      local = File.join(path, K4::INVENTORY)
      report = JSON.parse(File.binread(local))
      report.first.fetch("SpecReports").first["LeafNodeText"] = "a different upstream test"
      replace_original(manifest, lane, local, report)

      error = M8K4Evidence.verify(manifest, lane)

      refute error.fetch("passed")
      assert_match(/pinned Node Conformance selection/, error.fetch("detail"))
    end
  end

  def test_an_added_node_option_or_retried_test_cannot_supply_clean_proof
    fixture do |manifest, lane, path|
      local = File.join(path, "execution.json")
      report = JSON.parse(File.binread(local))
      report.fetch("command") << "--ginkgo.focus=volume"
      replace_original(manifest, lane, local, report)

      error = M8K4Evidence.verify(manifest, lane)

      refute error.fetch("passed")
      assert_match(/stock flags/, error.fetch("detail"))
    end

    fixture do |manifest, lane, path|
      local = File.join(path, K4::REPORT)
      report = JSON.parse(File.binread(local))
      report.first.fetch("SpecReports").first["NumAttempts"] = 2
      replace_original(manifest, lane, local, report)

      error = M8K4Evidence.verify(manifest, lane)

      refute error.fetch("passed")
      assert_match(/coverage differs/, error.fetch("detail"))
    end
  end

  def test_execution_exit_and_timing_both_matter
    fixture do |manifest, lane, path|
      local = File.join(path, "execution.json")
      report = JSON.parse(File.binread(local)).merge("exit_status" => 1)
      replace_original(manifest, lane, local, report)

      result = M8K4Evidence.verify(manifest, lane)

      refute result.fetch("passed")
      assert_equal "invalid_evidence", result.fetch("status")

      report["started_at"] = timestamp(5)
      replace_original(manifest, lane, local, report)
      result = M8K4Evidence.verify(manifest, lane)

      refute result.fetch("passed")
      assert_match(/timestamps fall outside/, result.fetch("detail"))
    end
  end

  def test_junit_must_join_to_each_stock_spec_outcome
    fixture do |manifest, lane, path|
      local = File.join(path, K4::FRAMEWORK_JUNIT)
      bytes = File.binread(local).sub("Node tests volume", "Node tests replacement")
      replace_original(manifest, lane, local, bytes)

      error = M8K4Evidence.verify(manifest, lane)

      refute error.fetch("passed")
      assert_match(/framework JUnit does not match/, error.fetch("detail"))
    end
  end

  def test_exact_stock_rro_guards_are_counted_as_skips_in_both_directions
    {true => [130, 171], false => [41, 84]}.each do |supported, guards|
      fixture(archive: true, rro: supported) do |manifest, lane, _path|
        result = M8SelectionProbe.k4_case([manifest])
        proof = result.fetch("proof")

        assert result.fetch("passed"), result.inspect
        assert_equal [5, 3], lane.fetch("coverage").values_at("selected", "passed")
        assert_equal(guards, proof.fetch("coverage").fetch("expected_skips").map { |skip| skip.dig("id", "line") })
        assert_equal [supported], proof.fetch("coverage").fetch("expected_skips").map { |skip| skip.fetch("runtime_supports_rro") }.uniq
        assert(RRO::OBSERVATIONS.all? { |name| proof.fetch("original_sha256").key?(name) })
        refute M8K4Evidence.proof?(proof.merge("coverage" => proof.fetch("coverage").merge("passed" => 5)))

        errors = []
        M8Gate.send(:validate_selection, {"counts" => {"required" => 1}}, [result], errors)

        refute errors.any? { |error| error.start_with?("K4 requires") }, errors.inspect

        # Even a well-formed proof cannot be replayed with unavailable originals.
        File.unlink(File.join(File.dirname(manifest.fetch("_path")), "k4", "#{RRO::AFTER}.gz")) if supported
        refute M8K4Evidence.original_matches?(proof) if supported
      end
    end
  end

  def test_rro_skip_requires_same_node_endpoint_and_bracketing_feature_observations
    {
      "changed feature" => ->(capture) { capture["stdout"] = capture["stdout"].sub("true}}", "false}}") },
      "different node" => ->(capture) { capture["stdout"] = capture["stdout"].sub("node-uid", "other-uid") },
      "different endpoint" => ->(capture) { capture.fetch("command")[2] = "--server=https://different:6443" },
      "during the run" => ->(capture) { capture["started_at"] = timestamp(6) },
      "missing default feature" => ->(capture) { capture["stdout"] = capture["stdout"].sub("recursiveReadOnlyMounts", "unrelatedFeature") }
    }.each do |description, edit|
      fixture(rro: true) do |manifest, lane, path|
        original = File.join(path, RRO::AFTER)
        capture = JSON.parse(File.binread(original))
        edit.call(capture)
        replace_original(manifest, lane, original, capture)

        error = M8K4Evidence.verify(manifest, lane)

        refute error.fetch("passed"), description
        assert_match(/coverage differs/, error.fetch("detail"), description)
      end
    end
  end

  def test_rro_proof_cannot_be_reused_under_another_upstream_source
    fixture(rro: true) do |manifest, lane, _path|
      manifest["sourceCommit"] = "d" * 40
      republish_lane(manifest, lane)
      verdict = M8K4Evidence.verify(manifest, lane)

      refute verdict.fetch("passed")
      assert_match(/pinned amd64 build and source/, verdict.fetch("detail"))
    end
  end

  def test_rro_skip_requires_exact_stock_guard_and_both_reciprocal_single_attempt_passes
    {
      "wrong guard location" => [130, ->(spec) { spec.fetch("Failure").fetch("Location")["LineNumber"] = 136 }],
      "ordered skip" => [130, ->(spec) { spec.fetch("Failure")["Message"] = "Spec skipped because an earlier spec in an ordered container failed" }],
      "pending" => [171, ->(spec) { spec["State"] = "pending" }],
      "outside the suite" => [171, ->(spec) { spec["StartTime"] = timestamp(3) }],
      "reciprocal case failed" => [41, ->(spec) { spec["State"] = "failed" }],
      "reciprocal case retried" => [84, ->(spec) { spec["NumAttempts"] = 2 }]
    }.each do |description, (line, edit)|
      fixture(rro: true) do |manifest, lane, path|
        original = File.join(path, K4::REPORT)
        report = JSON.parse(File.binread(original))
        spec = report.first.fetch("SpecReports").find { |entry| entry.dig("LeafNodeLocation", "LineNumber") == line }
        edit.call(spec)
        replace_original(manifest, lane, original, report)

        error = M8K4Evidence.verify(manifest, lane)

        refute error.fetch("passed"), description
        assert_match(/coverage differs/, error.fetch("detail"), description)
      end
    end
  end

  private

  def fixture(archive: false, cli_junit: false, failed: false, rro: nil)
    Dir.mktmpdir do |directory|
      path = File.join(directory, "k4")
      FileUtils.mkdir_p(path)
      dry_run = suite(dry_run: true, failed: false, rro: rro)
      actual = suite(dry_run: false, failed: failed, rro: rro)
      pin = {"label" => "NodeConformance", "inventories" => {"fixture" => K4.inventory_identity(dry_run)}}
      lock = Lock.kubernetes.merge("node_conformance" => pin)
      coverage = Lock.stub(:kubernetes, lock) { K4.compare(dry_run, actual, rro_supported: rro) }
      originals = {
        "node.json" => {"kind" => "Node", "metadata" => {"name" => "worker", "uid" => "node-uid"},
                        "status" => {"nodeInfo" => {"architecture" => "amd64", "operatingSystem" => "linux", "kernelVersion" => "7.0"},
                                     "conditions" => [{"type" => "Ready", "status" => "True"}]}},
        "host.json" => {"hostname" => "worker", "kernel" => "7.0"},
        "build.json" => build, "inventory-execution.json" => capture(dry_run: true, failed: false, cli_junit: cli_junit),
        "execution.json" => capture(dry_run: false, failed: failed, cli_junit: cli_junit),
        K4::INVENTORY => [dry_run], K4::REPORT => [actual], "coverage.json" => coverage,
        K4::FRAMEWORK_JUNIT => junit(actual)
      }
      unless rro.nil?
        originals[RRO::BEFORE] = rro_capture(originals.fetch("node.json"), rro, 2, 3)
        originals[RRO::AFTER] = rro_capture(originals.fetch("node.json"), rro, 7, 8)
      end
      originals[K4::JUNIT] = junit(actual, label: " [NodeConformance]") if cli_junit
      references = originals.map do |name, value|
        artifact = Conformance::Lanes.record(path, name, value)
        archivable = %W[#{K4::REPORT} #{K4::INVENTORY} #{K4::JUNIT} #{K4::FRAMEWORK_JUNIT} inventory-execution.json execution.json] + RRO::OBSERVATIONS
        if archive && archivable.include?(name)
          file = File.join(path, name)
          artifact = Conformance::K4Evidence.retain(file, bytes: File.binread(file))
        end
        artifact.merge("path" => "/old/container/reports/k4/#{File.basename(artifact.fetch("path"))}")
      end
      lane = {"lane" => "K4", "status" => failed ? "FAILED" : "COMPLETE", "passed" => !failed,
              "startedAt" => timestamp(0), "finishedAt" => timestamp(8), "artifacts" => references, "coverage" => coverage}
      manifest = {
        "schemaVersion" => 1, "suite" => "K0-K7-kubernetes-compatibility", "runId" => "fixture",
        "rubernetesCommit" => "a" * 40, "rubernetesCommitAfter" => "a" * 40, "rubernetesSourceStable" => true,
        "platform" => "linux/amd64", "profile" => "linux-amd64-ipv4-native",
        "profileDefinition" => {"name" => "linux-amd64-ipv4-native", "os" => "linux", "architecture" => "amd64"},
        "sourceCommit" => Lock.source_commit, "inputsLock" => "third_party/locks/kubernetes-v1.36.2.json",
        "startedAt" => timestamp(0), "finishedAt" => timestamp(9),
        "_path" => File.join(directory, "manifest.json"), "lanes" => [lane], "artifacts" => references.map(&:dup)
      }
      republish_lane(manifest, lane)

      Lock.stub(:kubernetes, lock) { yield manifest, lane, path }
    end
  end

  def republish_lane(manifest, lane)
    path = File.dirname(manifest.fetch("_path"))
    manifest.fetch("artifacts").reject! { |artifact| artifact.fetch("path").end_with?("/result.json") }
    manifest.fetch("artifacts") << Conformance::Lanes.record(File.join(path, "k4"), "result.json", lane)
    File.binwrite(manifest.fetch("_path"), JSON.generate(manifest.except("_path")))
  end

  def replace_original(manifest, lane, path, document)
    artifact = Conformance::Lanes.record(File.dirname(path), File.basename(path), document)
    [manifest, lane].each do |record|
      reference = record.fetch("artifacts").find { |entry| File.basename(entry.fetch("path")) == File.basename(path) }
      reference["sha256"] = artifact.fetch("sha256")
    end
    republish_lane(manifest, lane)
  end

  def build
    {"source_commit" => Lock.source_commit, "target" => "e2e_node.test", "platform" => "linux/amd64",
     "go" => "go version go1.27.1 linux/amd64", "exit_status" => 0, "installed" => true,
     "sha256" => "b" * 64, "ginkgo_sha256" => "c" * 64,
     "command" => %w[go test -mod=vendor -trimpath -c -o /tools/e2e_node.test ./test/e2e_node],
     "ginkgo_command" => %w[go build -mod=vendor -trimpath -o /tools/ginkgo-k4 github.com/onsi/ginkgo/v2/ginkgo]}
  end

  def suite(dry_run:, failed:, rro:)
    spec = {"LeafNodeType" => "It", "LeafNodeText" => "volume", "ContainerHierarchyTexts" => ["Node tests"],
            "LeafNodeLabels" => ["NodeConformance"], "LeafNodeLocation" => {"FileName" => "node.go", "LineNumber" => 40},
            "State" => failed ? "failed" : "passed", "NumAttempts" => dry_run ? 0 : 1}
    config = {"LabelFilter" => "NodeConformance", "DryRun" => dry_run, "FailOnEmpty" => true, "FailFast" => false,
              "FlakeAttempts" => 0, "MustPassRepeatedly" => 0, "SemVerFilter" => "", "RandomSeed" => 101, "ParallelTotal" => dry_run ? 1 : 8}
    specs = [spec]
    specs.concat(rro_specs(dry_run: dry_run, supported: rro)) unless rro.nil?
    {"SuiteDescription" => "E2eNode Suite", "SuitePath" => "/tools", "SuiteConfig" => config,
     "SuiteSucceeded" => !failed, "SuiteHasProgrammaticFocus" => false,
     "StartTime" => timestamp(dry_run ? 1 : 4, ".1"), "EndTime" => timestamp(dry_run ? 1 : 6, ".4"),
     "PreRunStats" => {"TotalSpecs" => specs.length, "SpecsThatWillRun" => specs.length}, "SpecReports" => specs}
  end

  def rro_specs(dry_run:, supported:)
    [
      [41, 45, true, "should accept recursive read-only mounts"],
      [84, 88, true, "should reject invalid recursive read-only mounts"],
      [130, 135, false, "should accept non-recursive read-only mounts"],
      [171, 176, false, "should reject recursive read-only mounts"]
    ].map do |line, guard, branch, text|
      location = {"FileName" => "k8s.io/kubernetes/test/e2e_node/mount_rro_linux_test.go", "LineNumber" => line}
      condition = branch ? "supports" : "does not support"
      hierarchy = ["[sig-node] Mount recursive read-only [LinuxOnly] [NodeConformance]", "Mount recursive read-only",
                   "when the runtime #{condition} recursive read-only mounts"]
      spec = {"LeafNodeType" => "It", "LeafNodeLocation" => location, "LeafNodeText" => text,
              "ContainerHierarchyTexts" => hierarchy, "State" => "passed", "NumAttempts" => dry_run ? 0 : 1,
              "StartTime" => timestamp(4, ".5"), "EndTime" => timestamp(5)}
      next spec if dry_run || supported == branch

      message = supported ? "runtime supports recursive read-only mounts" : "runtime does not support recursive read-only mounts"
      spec.merge("State" => "skipped", "Failure" => {"Message" => message, "FailureNodeContext" => "leaf-node", "FailureNodeType" => "It",
                                                     "Location" => location.merge("LineNumber" => guard), "FailureNodeLocation" => location})
    end
  end

  def rro_capture(node, supported, started, finished)
    handlers = [{"name" => "", "features" => {"recursiveReadOnlyMounts" => supported}}]
    observed = node.merge("status" => node.fetch("status").merge("runtimeHandlers" => handlers))
    {"command" => %w[/tools/kubectl-v1.36.2 --kubeconfig=/fixture/kubeconfig --server=https://localhost:6443 get --raw /api/v1/nodes],
     "exit_status" => 0, "timed_out" => false, "timeout_seconds" => 30,
     "stdout" => JSON.generate("kind" => "NodeList", "apiVersion" => "v1", "items" => [observed]),
     "stderr" => "", "started_at" => timestamp(started), "finished_at" => timestamp(finished)}
  end

  def capture(dry_run:, failed:, cli_junit:)
    directory = "/old/container/reports/k4"
    args = %W[--conformance=true --start-services=false --prepull-images=false --bearer-token=[redacted]
              --node-name=worker --host=https://localhost:6443 --kubectl-path=/tools/kubectl-v1.36.2 --report-dir=#{directory}]
    report = File.join(directory, dry_run ? K4::INVENTORY : K4::REPORT)
    command = K4.ginkgo_command("/tools/e2e_node.test", args, report, dry_run: dry_run)
    command.reject! { |arg| arg.start_with?("--junit-report=") } unless cli_junit
    {"command" => command, "exit_status" => failed ? 1 : 0, "timed_out" => false,
     "stdout" => "upstream Ginkgo output", "stderr" => "", "elapsed_seconds" => dry_run ? 0.5 : 3.0,
     "started_at" => timestamp(dry_run ? 1 : 4), "finished_at" => timestamp(dry_run ? 1 : 7)}
  end

  def junit(report, label: "")
    succeeded = report.fetch("SuiteSucceeded")
    specs = report.fetch("SpecReports").map do |spec|
      state = spec.fetch("State")
      name = (spec.fetch("ContainerHierarchyTexts") + [spec.fetch("LeafNodeText")]).join(" ")
      outcome = {"failed" => "<failure/>", "skipped" => "<skipped/>"}[state]
      labels = label if spec["LeafNodeLabels"]
      %(<testcase name="[It] #{name}#{labels}" status="#{state}">#{outcome}</testcase>)
    end
    <<~XML
      <testsuites><testsuite name="E2eNode Suite"><properties>
        <property name="SuiteSucceeded" value="#{succeeded}"/>
        <property name="SuiteHasProgrammaticFocus" value="false"/>
        <property name="LabelFilter" value="NodeConformance"/>
        <property name="DryRun" value="false"/>
        <property name="RandomSeed" value="101"/>
      </properties>#{specs.join}</testsuite></testsuites>
    XML
  end

  def timestamp(seconds, fraction = "")
    "2026-11-19T09:55:0#{seconds}#{fraction}Z"
  end
end
