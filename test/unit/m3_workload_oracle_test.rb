# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/milestones/m3_kubernetes_workload_oracle"

class M3WorkloadOracleTest < Minitest::Test
  REQUIRED_CASES = %w[
    daemonset:delete daemonset:rollout daemonset:rollback daemonset:scale
    deployment:delete deployment:rollout deployment:rollback deployment:scale
    cronjob:delete cronjob:rollout cronjob:rollback cronjob:scale
    job:delete job:rollout job:rollback job:scale
    statefulset:delete statefulset:rollout statefulset:rollback statefulset:scale
  ].freeze

  def test_request_requires_the_complete_independent_matrix_and_canonical_stream_digests
    request = valid_request

    assert M3KubernetesWorkloadOracle.verify_request!(request)

    broken = Marshal.load(Marshal.dump(request))
    broken.fetch("cases").fetch("deployment:rollout")["stream_sha256"] = "0" * 64

    error = assert_raises(M3KubernetesWorkloadOracle::Error) do
      M3KubernetesWorkloadOracle.verify_request!(broken)
    end
    assert_match(/stream digest is not canonical/, error.message)
  end

  def test_canonical_observations_replace_runtime_identity_and_timestamps
    value = {
      "metadata" => {
        "uid" => "uid-1", "resourceVersion" => "17",
        "creationTimestamp" => "2026-08-23T12:00:00Z"
      },
      "status" => {"conditions" => [
        {"type" => "Ready", "lastTransitionTime" => "2026-08-23T12:00:01Z"},
        {"type" => "Available", "lastTransitionTime" => "2026-08-23T12:00:02Z"}
      ]}
    }

    canonical = M3KubernetesWorkloadOracle.canonical(value)

    assert_equal "<uid>", canonical.dig("metadata", "uid")
    assert_equal "<resourceVersion>", canonical.dig("metadata", "resourceVersion")
    assert_equal "<timestamp>", canonical.dig("metadata", "creationTimestamp")
    assert_equal "<timestamp>", canonical.dig("status", "conditions", 0, "lastTransitionTime")
    assert_equal "workload-<generated>", M3KubernetesWorkloadOracle.canonical_generated_name("Pod", "workload-7c8qh")
    assert_equal %w[Available Ready], canonical.dig("status", "conditions").map { |condition| condition["type"] }
  end

  def test_canonical_workload_observations_retain_meaningful_pod_semantics
    base = {
      "apiVersion" => "v1", "kind" => "Pod",
      "metadata" => {"name" => "workload-pod", "namespace" => "default"},
      "spec" => {
        "affinity" => {"nodeAffinity" => {"requiredDuringSchedulingIgnoredDuringExecution" => {"nodeSelectorTerms" => []}}},
        "priority" => 10, "restartPolicy" => "OnFailure", "schedulerName" => "custom-scheduler",
        "securityContext" => {"runAsUser" => 1000}, "volumes" => [{"name" => "data", "emptyDir" => {}}],
        "containers" => [{"name" => "app", "image" => "example/app", "volumeMounts" => [{"name" => "data", "mountPath" => "/data"}]}]
      }
    }

    canonical = M3KubernetesWorkloadOracle.canonical_resource(base)

    assert_equal base.dig("spec", "affinity"), canonical.dig("spec", "affinity")
    assert_equal 10, canonical.dig("spec", "priority")
    assert_equal "OnFailure", canonical.dig("spec", "restartPolicy")
    assert_equal "custom-scheduler", canonical.dig("spec", "schedulerName")
    assert_equal({"runAsUser" => 1000}, canonical.dig("spec", "securityContext"))
    assert_equal base.dig("spec", "volumes"), canonical.dig("spec", "volumes")
    assert_equal base.dig("spec", "containers"), canonical.dig("spec", "containers")

    changed = Marshal.load(Marshal.dump(base))
    changed["spec"]["priority"] = 11
    refute_equal M3KubernetesWorkloadOracle.canonical_digest(base), M3KubernetesWorkloadOracle.canonical_digest(changed)
  end

  # Requirement: M3 workload differential canonicalization must retain
  # controller-owned scheduling, security, storage, service-account, and
  # controller identity fields. Mutation target: removing any field from
  # semantic_pod must make this negative corpus collide; this test must fail.
  def test_owned_pod_semantics_and_stateful_ordinals_never_collide
    base = {
      "apiVersion" => "v1", "kind" => "Pod",
      "metadata" => {"name" => "web-0", "namespace" => "default",
                      "labels" => {"apps.kubernetes.io/pod-index" => "0", "statefulset.kubernetes.io/pod-name" => "web-0"},
                      "ownerReferences" => [{"kind" => "StatefulSet", "controller" => true}]},
      "spec" => {"priority" => 10, "preemptionPolicy" => "Never", "serviceAccountName" => "reader",
                 "enableServiceLinks" => false,
                 "tolerations" => [{"key" => "workload", "operator" => "Exists"}],
                 "volumes" => [{"name" => "data", "emptyDir" => {}}],
                 "containers" => [{"name" => "app", "image" => "example/app",
                                   "volumeMounts" => [{"name" => "data", "mountPath" => "/data"}]}]}
    }
    canonical = M3KubernetesWorkloadOracle.canonical_resource(base)
    assert_equal 10, canonical.dig("spec", "priority")
    assert_equal "Never", canonical.dig("spec", "preemptionPolicy")
    assert_equal "reader", canonical.dig("spec", "serviceAccountName")
    assert_equal false, canonical.dig("spec", "enableServiceLinks")
    assert_equal "0", canonical.dig("metadata", "labels", "apps.kubernetes.io/pod-index")
    assert_equal "web-0", canonical.dig("metadata", "labels", "statefulset.kubernetes.io/pod-name")
    assert_equal "web-0", canonical.dig("metadata", "name")

    changed = Marshal.load(Marshal.dump(base))
    changed["spec"]["serviceAccountName"] = "writer"
    refute_equal M3KubernetesWorkloadOracle.canonical_digest(base), M3KubernetesWorkloadOracle.canonical_digest(changed)

    ordinal = Marshal.load(Marshal.dump(base))
    ordinal["metadata"]["name"] = "web-1"
    ordinal["metadata"]["labels"]["apps.kubernetes.io/pod-index"] = "1"
    ordinal["metadata"]["labels"]["statefulset.kubernetes.io/pod-name"] = "web-1"
    refute_equal M3KubernetesWorkloadOracle.canonical_digest(base), M3KubernetesWorkloadOracle.canonical_digest(ordinal)
  end

  def test_runner_provenance_records_source_build_and_no_controller_manager_image
    assert_equal "v1.36.2", M3KubernetesWorkloadOracle::VERSION
    assert_equal "24e2b02af5543d7910c2bb074c7264df5a8f0467", M3KubernetesWorkloadOracle::SOURCE_COMMIT
    assert_match(/@sha256:[0-9a-f]{64}\z/, M3KubernetesWorkloadOracle::KUBE_APISERVER_IMAGE)
    assert_match(/@sha256:[0-9a-f]{64}\z/, M3KubernetesWorkloadOracle::ETCD_IMAGE)
  end

  def test_runner_contract_binds_matrix_provenance_and_no_fixture_policy
    contract_path = File.expand_path("../conformance/kubernetes/m3_workload_oracle/runner_contract.json", __dir__)
    contract = JSON.parse(File.binread(contract_path))

    assert_equal 20, contract.dig("request", "case_count")
    assert_equal true, contract.dig("execution", "controller_manager_source_build_required")
    assert_equal false, contract.dig("output", "expected_fixtures_allowed")
    assert_includes contract.dig("output", "required_provenance"), "input"
  end

  private

  def valid_request
    {
      "kubernetes_version" => M3KubernetesWorkloadOracle::VERSION,
      "source_commit" => M3KubernetesWorkloadOracle::SOURCE_COMMIT,
      "stream_version" => 1,
      "cases" => REQUIRED_CASES.to_h do |id|
        stream = [{"id" => "create", "method" => "POST", "path" => "/api/v1/namespaces"}]
        [id, {"independent" => true, "deadline_seconds" => 30.0,
              "stream" => stream,
              "stream_sha256" => M3KubernetesWorkloadOracle.canonical_digest(stream)}]
      end
    }
  end
end
