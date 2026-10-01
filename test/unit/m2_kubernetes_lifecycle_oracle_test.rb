# frozen_string_literal: true

require "json"
require "open3"
require "rbconfig"
require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/milestones/m2_kubernetes_lifecycle_oracle"

class M2KubernetesLifecycleOracleTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  RUNNER = File.join(ROOT, "test/conformance/kubernetes/m2_lifecycle_oracle/runner.rb")

  def test_fixture_and_timeline_are_pinned_and_cover_the_required_cases
    fixture = M2KubernetesLifecycleOracle.fixture_document

    assert_equal M2KubernetesLifecycleOracle::KUBERNETES_VERSION, fixture.fetch("kubernetes_version")
    assert_equal M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT, fixture.fetch("source_commit")
    assert_equal M2KubernetesLifecycleOracle::REQUIRED_CASES.sort, fixture.fetch("cases").keys.sort
    refute_empty fixture.fetch("timeline")
  end

  def test_missing_cni_lock_is_an_exact_product_blocker
    status = M2KubernetesLifecycleOracle.cni_lock_status("/tmp/rubernetes-m2-lifecycle-cni-lock-is-absent")

    assert_equal false, status.fetch("available")
    assert_equal M2KubernetesLifecycleOracle::CNI_LOCK_BLOCKER, status.fetch("errors").first
  end

  def test_missing_cni_lock_returns_blocked_without_fabricating_comparisons
    report = M2KubernetesLifecycleOracle.run(
      input: {"sha256" => "a" * 64, "file_count" => 1},
      actual_cases: M2KubernetesLifecycleOracle::REQUIRED_CASES.map { |name| {"name" => name, "observed" => {"name" => name}} },
      cni_lock_path: "/tmp/rubernetes-m2-lifecycle-cni-lock-is-absent"
    )

    assert_equal false, report.fetch("executed")
    assert_equal "BLOCKED", report.fetch("status")
    assert_equal M2KubernetesLifecycleOracle::CNI_LOCK_BLOCKER, report.fetch("blocker")
    assert_empty report.fetch("comparisons")
    assert_nil report.fetch("raw_trace_sha256")
    assert_nil report.fetch("canonical_trace_sha256")
    assert_equal M2KubernetesLifecycleOracle::REQUIRED_CASES.length, report.fetch("missing_comparison_count")
  end

  def test_repository_cni_lock_is_available_and_content_addressed
    status = M2KubernetesLifecycleOracle.cni_lock_status

    assert_equal true, status.fetch("available"), status.fetch("errors").inspect
    lock = status.fetch("lock")

    assert_equal "kindnetd", lock.fetch("plugin")
    assert_equal lock.fetch("image_digest"), lock.fetch("image_reference").split("@sha256:").last
    assert_equal M2KubernetesLifecycleOracle.canonical_digest(lock, excluded_keys: ["lock_sha256"]), lock.fetch("lock_sha256")
  end

  def test_tampered_cni_lock_is_rejected
    lock = JSON.parse(File.read(M2KubernetesLifecycleOracle::CNI_LOCK_PATH))
    lock["image_digest"] = "0" * 64
    Dir.mktmpdir("rubernetes-m2-cni-lock-") do |directory|
      path = File.join(directory, "m2-lifecycle-cni.json")
      File.write(path, JSON.generate(lock))
      status = M2KubernetesLifecycleOracle.cni_lock_status(path)

      assert_equal false, status.fetch("available")
      assert_includes status.fetch("errors"), "CNI lock #{path} image_reference digest must match image_digest"
      assert_includes status.fetch("errors"), "CNI lock #{path} lock_sha256 does not match canonical content"
    end
  end

  def test_runner_never_blocks_with_the_lock_present_and_names_the_missing_checkout
    request = M2KubernetesLifecycleOracle.request_document(
      input: {"sha256" => "b" * 64, "file_count" => 1}
    )
    stdout, stderr, status = Open3.capture3(
      {"RUBERNETES_M2_KUBERNETES_SOURCE" => nil},
      RbConfig.ruby,
      RUNNER,
      stdin_data: JSON.generate(request),
      chdir: ROOT
    )

    assert_equal 1, status.exitstatus
    assert_empty stderr
    document = JSON.parse(stdout)

    assert_equal "INCOMPLETE", document.fetch("status")
    assert_equal false, document.fetch("executed")
    refute_equal "BLOCKED", document.fetch("status")
    assert_includes document.fetch("errors"), "RUBERNETES_M2_KUBERNETES_SOURCE must point to the pinned Kubernetes source checkout"
  end

  def test_kind_and_node_image_locks_are_content_addressed_and_bind_the_same_kind_binary
    kind_lock = JSON.parse(File.read(File.join(ROOT, "third_party/locks/kind-v0.33.0.json")))
    node_lock = JSON.parse(File.read(File.join(ROOT, "third_party/locks/m2-lifecycle-node-image.json")))
    cni_lock = JSON.parse(File.read(M2KubernetesLifecycleOracle::CNI_LOCK_PATH))

    assert_equal M2KubernetesLifecycleOracle.canonical_digest(kind_lock, excluded_keys: ["lock_sha256"]), kind_lock.fetch("lock_sha256")
    assert_equal M2KubernetesLifecycleOracle.canonical_digest(node_lock, excluded_keys: ["lock_sha256"]), node_lock.fetch("lock_sha256")
    assert_equal kind_lock.dig("artifacts", "linux/amd64", "sha256"), node_lock.dig("build", "kind_binary_sha256")
    assert_equal M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT, node_lock.dig("build", "kubernetes", "commit")
    assert_equal M2KubernetesLifecycleOracle::KUBERNETES_VERSION, node_lock.dig("build", "kubernetes", "tag")
    assert M2KubernetesLifecycleOracle.digest_pinned_image?(node_lock.dig("image", "reference"))
    assert M2KubernetesLifecycleOracle.digest_pinned_image?(node_lock.dig("images", "kube_apiserver"))
    assert M2KubernetesLifecycleOracle.digest_pinned_image?(node_lock.dig("images", "etcd"))
    assert_equal node_lock.dig("image", "reference"), cni_lock.fetch("node_image_reference")
    assert_equal node_lock.dig("images", "kindnetd"), cni_lock.fetch("image_reference")
    %w[containerd runc kubelet].each do |name|
      assert M2KubernetesLifecycleOracle.valid_digest?(node_lock.dig("runtime", name, "binary_sha256")), name
    end
    kind_path = File.join(ROOT, kind_lock.fetch("install_path"))
    assert_equal kind_lock.dig("artifacts", "linux/amd64", "sha256"), Digest::SHA256.file(kind_path).hexdigest if File.file?(kind_path)
  end

  def test_contract_observable_schema_covers_every_required_observable_field
    schema = M2KubernetesLifecycleOracle.contract.fetch("observable_schema")

    M2KubernetesLifecycleOracle::REQUIRED_OBSERVABLE_FIELDS.each do |name, fields|
      fields.each { |field| assert schema.fetch(name).key?(field), "#{name}.#{field} must be described by the observable schema" }
    end
  end

  def test_executed_oracle_with_a_real_difference_is_a_fail_not_incomplete
    request, actual_cases, document, lock = valid_external_report_fixture
    actual_cases["graceful_termination_oracle"]["observed"] =
      actual_cases["graceful_termination_oracle"]["observed"].merge("events" => %w[Killing FailedPreStopHook])

    report = normalize_fixture(document, request, actual_cases, lock)

    assert_equal true, report.fetch("executed")
    assert_equal "FAIL", report.fetch("status")
    assert_equal false, report.fetch("passed")
    assert_equal 1, report.fetch("difference_count")
    assert_includes report.fetch("errors"),
                    "external lifecycle oracle case graceful_termination_oracle differs from Rubernetes production semantics"
    comparison = report.fetch("comparisons").find { |entry| entry.fetch("id") == "graceful_termination_oracle" }

    refute_equal comparison.fetch("expected_sha256"), comparison.fetch("actual_sha256")
  end

  def test_request_seed_binds_the_same_fixture_and_operation_timeline
    request = M2KubernetesLifecycleOracle.request_document(
      input: {"sha256" => "c" * 64, "file_count" => 3}
    )

    assert_equal M2KubernetesLifecycleOracle.canonical_digest(request.reject { |key, _|
      key == "request_seed_sha256"
    }), request.fetch("request_seed_sha256")
    assert_equal M2KubernetesLifecycleOracle.canonical_digest(request.fetch("cases")), request.fetch("fixture_sha256")
    assert_equal M2KubernetesLifecycleOracle.canonical_digest(request.fetch("timeline")), request.fetch("timeline_sha256")
  end

  def test_external_report_keeps_runtime_cni_and_trace_provenance_separate_from_native_observations
    request = M2KubernetesLifecycleOracle.request_document(
      input: {"sha256" => "d" * 64, "file_count" => 4}
    )
    actual_cases = M2KubernetesLifecycleOracle::REQUIRED_CASES.to_h do |name|
      fields = M2KubernetesLifecycleOracle::REQUIRED_OBSERVABLE_FIELDS.fetch(name).to_h { |field| [field, field] }
      [name, {"observed" => fields, "actual_provenance" => semantics_provenance(name)}]
    end
    runtime = {
      "containerd" => {"path" => RbConfig.ruby, "version" => "containerd 2.2.1",
                       "binary_sha256" => Digest::SHA256.file(RbConfig.ruby).hexdigest, "identity_method" => "realpath+version+binary_sha256"},
      "runc" => {"path" => RbConfig.ruby, "version" => "runc 1.3.4", "binary_sha256" => Digest::SHA256.file(RbConfig.ruby).hexdigest,
                 "identity_method" => "realpath+version+binary_sha256"}
    }
    cni = {
      "plugin" => "pinned-cni",
      "version" => "1.0.0",
      "source_commit" => "3" * 40,
      "image_reference" => "example/cni@sha256:#{"4" * 64}",
      "image_digest" => "4" * 64,
      "config_sha256" => "5" * 64
    }
    source = {
      "version" => M2KubernetesLifecycleOracle::KUBERNETES_VERSION,
      "commit" => M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT,
      "tag" => M2KubernetesLifecycleOracle::KUBERNETES_VERSION,
      "kubelet_image" => "example/kubelet@sha256:#{"6" * 64}",
      "apiserver_image" => "example/apiserver@sha256:#{"7" * 64}",
      "etcd_image" => "example/etcd@sha256:#{"8" * 64}",
      "runtime" => runtime,
      "cni" => cni,
      "network_isolated" => true
    }
    document = {
      "executed" => true,
      "status" => "PASS",
      "passed" => true,
      "errors" => [],
      "kubernetes_version" => M2KubernetesLifecycleOracle::KUBERNETES_VERSION,
      "source_commit" => M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT,
      "input_sha256" => request["input_sha256"],
      "fixture_sha256" => request["fixture_sha256"],
      "timeline_sha256" => request["timeline_sha256"],
      "request_seed_sha256" => request["request_seed_sha256"],
      "source" => source,
      "runtime" => runtime,
      "cni" => cni,
      "trace" => [{"event" => "running"}],
      "observations" => actual_cases,
      "runner" => {"runner_sha256" => M2KubernetesLifecycleOracle.runner_digest,
                   "command" => M2KubernetesLifecycleOracle.built_in_command}
    }
    report = M2KubernetesLifecycleOracle.normalize_external_report(
      document,
      request: request,
      actual_cases: actual_cases.map { |name, value| {"name" => name}.merge(value) },
      lock_status: {"available" => true, "lock" => cni},
      contract_document: M2KubernetesLifecycleOracle.contract,
      command: M2KubernetesLifecycleOracle.built_in_command,
      raw_trace_sha256: "a" * 64
    )

    assert_equal true, report.fetch("executed")
    assert_equal true, report.fetch("passed")
    assert_equal "a" * 64, report.fetch("raw_trace_sha256")
    assert_equal M2KubernetesLifecycleOracle.canonical_digest(document.fetch("trace")), report.fetch("canonical_trace_sha256")
    assert_equal runtime, report.dig("provenance", "source", "runtime")
    assert_equal cni, report.dig("provenance", "source", "cni")
    assert_equal M2Gate::LIFECYCLE_SEMANTICS_ACTUAL_SOURCE, report.dig("comparisons", 0, "actual_source")
    assert_equal semantics_provenance("init_sidecar_app_order"), report.dig("comparisons", 0, "actual_provenance")
  end

  def test_external_report_does_not_assign_native_provenance_to_unattributed_semantics
    request = M2KubernetesLifecycleOracle.request_document(
      input: {"sha256" => "e" * 64, "file_count" => 5}
    )
    actual_cases = M2KubernetesLifecycleOracle::REQUIRED_CASES.to_h do |name|
      fields = M2KubernetesLifecycleOracle::REQUIRED_OBSERVABLE_FIELDS.fetch(name).to_h { |field| [field, field] }
      [name, {"observed" => fields}]
    end
    report = M2KubernetesLifecycleOracle.normalize_external_report(
      {
        "executed" => true,
        "kubernetes_version" => M2KubernetesLifecycleOracle::KUBERNETES_VERSION,
        "source_commit" => M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT,
        "input_sha256" => request["input_sha256"],
        "fixture_sha256" => request["fixture_sha256"],
        "timeline_sha256" => request["timeline_sha256"],
        "request_seed_sha256" => request["request_seed_sha256"],
        "source" => {"version" => M2KubernetesLifecycleOracle::KUBERNETES_VERSION,
                     "commit" => M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT,
                     "kubelet_image" => "example/kubelet", "apiserver_image" => "example/apiserver",
                     "etcd_image" => "example/etcd", "network_isolated" => true},
        "runtime" => {
          "containerd" => {"version" => "containerd", "binary_sha256" => "1" * 64, "identity_method" => "test"},
          "runc" => {"version" => "runc", "binary_sha256" => "2" * 64, "identity_method" => "test"}
        },
        "cni" => {"plugin" => "pinned-cni", "version" => "1", "source_commit" => "3" * 40,
                  "image_reference" => "example/cni", "image_digest" => "4" * 64, "config_sha256" => "5" * 64},
        "trace" => [{"event" => "running"}],
        "observations" => actual_cases.transform_values { |value| value.fetch("observed") },
        "runner" => {"runner_sha256" => "9" * 64}
      },
      request: request,
      actual_cases: actual_cases,
      lock_status: {"available" => true, "lock" => actual_cases},
      contract_document: M2KubernetesLifecycleOracle.contract,
      command: ["external-runner"],
      raw_trace_sha256: "a" * 64
    )

    assert_equal false, report.fetch("passed")
    assert_nil report.dig("comparisons", 0, "actual_source")
    assert_includes report.fetch("errors"), "Rubernetes lifecycle case init_sidecar_app_order actual provenance is missing"
  end

  def test_external_report_rejects_a_fake_runner_sha_even_when_observations_match
    request, actual_cases, document, lock = valid_external_report_fixture
    document.fetch("runner")["runner_sha256"] = "f" * 64

    report = normalize_fixture(document, request, actual_cases, lock)

    refute report.fetch("passed")
    assert_includes report.fetch("errors"), "external lifecycle oracle runner SHA-256 does not match the real pinned runner"
  end

  def test_external_report_rejects_failed_status_passed_or_errors_claims
    request, actual_cases, document, lock = valid_external_report_fixture
    document["status"] = "PASS"
    document["passed"] = true
    document["errors"] = ["harness reported a failed comparison"]

    report = normalize_fixture(document, request, actual_cases, lock)

    refute report.fetch("passed")
    assert_includes report.fetch("errors"), "external lifecycle oracle reported errors must be empty"
    assert_equal ["harness reported a failed comparison"], report.fetch("external_errors")
  end

  def test_external_report_rejects_an_arbitrary_runner_command
    request, actual_cases, document, lock = valid_external_report_fixture

    report = M2KubernetesLifecycleOracle.normalize_external_report(
      document,
      request: request,
      actual_cases: actual_cases.map { |name, value| {"name" => name}.merge(value) },
      lock_status: {"available" => true, "lock" => lock},
      contract_document: M2KubernetesLifecycleOracle.contract,
      command: [RbConfig.ruby, "/tmp/unlocked-lifecycle-runner.rb"],
      raw_trace_sha256: "a" * 64
    )

    refute report.fetch("passed")
    assert(report.fetch("errors").any? { |error| error.include?("not the built-in pinned runner") })
  end

  def test_lifecycle_probe_matrix_records_production_semantics_and_fake_support_boundaries
    # M2 lifecycle evidence must distinguish in-process policy semantics from
    # the separate Native kernel-effect and SIGKILL evidence paths.
    path = File.join(ROOT, "tools/milestones/m2_lifecycle_probe.rb")
    source = File.read(path).split("\nM2ProbeSupport.run_probe", 2).first
    eval(source, TOPLEVEL_BINDING, path, 1) # rubocop:disable Security/Eval -- loads the probe script under test as a library

    matrix = M2LifecycleProbe.lifecycle_semantics_matrix

    assert_equal M2Gate::REQUIRED_LIFECYCLE_SEMANTICS.sort, matrix.map { |entry| entry.fetch("name") }.sort
    matrix.each do |entry|
      provenance = entry.fetch("actual_provenance")

      assert_equal M2Gate::LIFECYCLE_SEMANTICS_ACTUAL_SOURCE, provenance.fetch("source")
      assert_equal "in_process", provenance.fetch("execution_mode")
      assert_equal false, provenance.fetch("native_effects_executed")
      assert_equal M2Gate::LIFECYCLE_SEMANTICS_PROVENANCE.fetch(entry.fetch("name"))["production_classes"],
                   provenance.fetch("production_classes")
      assert_equal true, entry.fetch("passed")
    end
  end

  private

  def normalize_fixture(document, request, actual_cases, lock)
    M2KubernetesLifecycleOracle.normalize_external_report(
      document,
      request: request,
      actual_cases: actual_cases.map { |name, value| {"name" => name}.merge(value) },
      lock_status: {"available" => true, "lock" => lock},
      contract_document: M2KubernetesLifecycleOracle.contract,
      command: M2KubernetesLifecycleOracle.built_in_command,
      raw_trace_sha256: "a" * 64
    )
  end

  def valid_external_report_fixture
    request = M2KubernetesLifecycleOracle.request_document(
      input: {"sha256" => "1" * 64, "file_count" => 1}
    )
    actual_cases = M2KubernetesLifecycleOracle::REQUIRED_CASES.to_h do |name|
      fields = M2KubernetesLifecycleOracle::REQUIRED_OBSERVABLE_FIELDS.fetch(name).to_h { |field| [field, field] }
      [name, {"observed" => fields, "actual_provenance" => semantics_provenance(name)}]
    end
    runtime_path = RbConfig.ruby
    runtime = {
      "containerd" => {"path" => runtime_path, "version" => "containerd", "binary_sha256" => Digest::SHA256.file(runtime_path).hexdigest,
                       "identity_method" => "realpath+version+binary_sha256"},
      "runc" => {"path" => runtime_path, "version" => "runc", "binary_sha256" => Digest::SHA256.file(runtime_path).hexdigest, "identity_method" => "realpath+version+binary_sha256"}
    }
    cni = {
      "plugin" => "pinned-cni", "version" => "1.0.0", "source_commit" => "2" * 40,
      "image_reference" => "example/cni@sha256:#{"3" * 64}", "image_digest" => "3" * 64,
      "config_sha256" => "4" * 64
    }
    source = {
      "version" => M2KubernetesLifecycleOracle::KUBERNETES_VERSION,
      "commit" => M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT,
      "tag" => M2KubernetesLifecycleOracle::KUBERNETES_VERSION,
      "kubelet_image" => "example/kubelet@sha256:#{"5" * 64}",
      "apiserver_image" => "example/apiserver@sha256:#{"6" * 64}",
      "etcd_image" => "example/etcd@sha256:#{"7" * 64}",
      "runtime" => runtime, "cni" => cni, "network_isolated" => true
    }
    document = {
      "executed" => true, "status" => "PASS", "passed" => true, "errors" => [],
      "kubernetes_version" => M2KubernetesLifecycleOracle::KUBERNETES_VERSION,
      "source_commit" => M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT,
      "input_sha256" => request["input_sha256"], "fixture_sha256" => request["fixture_sha256"],
      "timeline_sha256" => request["timeline_sha256"], "request_seed_sha256" => request["request_seed_sha256"],
      "source" => source, "runtime" => runtime, "cni" => cni, "trace" => [{"event" => "running"}],
      "observations" => actual_cases.transform_values { |value| value.fetch("observed") },
      "runner" => {"runner_sha256" => M2KubernetesLifecycleOracle.runner_digest,
                   "command" => M2KubernetesLifecycleOracle.built_in_command}
    }
    [request, actual_cases, document, cni]
  end

  def semantics_provenance(name)
    M2Gate::LIFECYCLE_SEMANTICS_PROVENANCE.fetch(name).merge(
      "source" => M2Gate::LIFECYCLE_SEMANTICS_ACTUAL_SOURCE
    )
  end
end
