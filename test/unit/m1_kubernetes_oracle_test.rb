# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/milestones/m1_kubernetes_oracle"

class M1KubernetesOracleTest < Minitest::Test
  FakeStatus = Struct.new(:success?)

  class FakeRunner
    attr_reader :calls

    def initialize(stdout: "[]", success: true, stderr: "")
      @stdout = stdout
      @success = success
      @stderr = stderr
      @calls = []
    end

    def capture(*argv)
      @calls << argv
      M1KubernetesOracle::CommandResult.new(
        stdout: @stdout,
        stderr: @stderr,
        status: FakeStatus.new(@success)
      )
    end
  end

  def test_oracle_images_and_source_identity_are_exactly_pinned
    assert_equal("v1.36.2", M1KubernetesOracle::KUBERNETES_VERSION)
    assert_equal(
      "24e2b02af5543d7910c2bb074c7264df5a8f0467",
      M1KubernetesOracle::KUBERNETES_SOURCE_COMMIT
    )
    assert_equal(
      "registry.k8s.io/kube-apiserver@sha256:0535dde1a857029209d7effe681c919a1580d2eb24eda4bd122d24e9a372e1b8",
      M1KubernetesOracle::KUBE_APISERVER_IMAGE
    )
    assert_equal(
      "registry.k8s.io/etcd@sha256:397189418d1a00e500c0605ad18d1baf3b541a1004d768448c367e48071622e5",
      M1KubernetesOracle::ETCD_IMAGE
    )
  end

  def test_digest_mismatch_fails_before_any_docker_resource_is_created
    runner = FakeRunner.new(stdout: JSON.generate(["registry.k8s.io/kube-apiserver@sha256:wrong"]))
    cluster = M1KubernetesOracle::DockerCluster.new(command_runner: runner)

    error = assert_raises(M1KubernetesOracle::Error) { cluster.with_client { flunk("must not yield") } }

    assert_match(/digest mismatch/, error.message)
    assert_equal(1, runner.calls.length)
    assert_equal(%w[docker image inspect], runner.calls.first.first(3))
    refute(runner.calls.any? { |argv| argv.first(2) == %w[docker run] })
    refute(runner.calls.any? { |argv| argv.first(3) == %w[docker network create] })
  end

  def test_unavailable_docker_or_image_fails_closed
    runner = FakeRunner.new(success: false, stderr: "docker unavailable")
    cluster = M1KubernetesOracle::DockerCluster.new(command_runner: runner)

    error = assert_raises(M1KubernetesOracle::Error) { cluster.with_client { flunk("must not yield") } }

    assert_match(/required oracle image is unavailable/, error.message)
    assert_equal(1, runner.calls.length)
  end

  def test_cluster_resource_names_are_unique_and_narrowly_prefixed
    first = M1KubernetesOracle::DockerCluster.new
    second = M1KubernetesOracle::DockerCluster.new

    refute_equal(first.network_name, second.network_name)
    refute_equal(first.etcd_name, second.etcd_name)
    refute_equal(first.api_name, second.api_name)
    assert_match(/\Arubernetes-m1-oracle-net-[0-9]+-[0-9a-f]{12}\z/, first.network_name)
    assert_match(/\Arubernetes-m1-oracle-etcd-[0-9]+-[0-9a-f]{12}\z/, first.etcd_name)
    assert_match(/\Arubernetes-m1-oracle-api-[0-9]+-[0-9a-f]{12}\z/, first.api_name)
  end

  def test_resource_normalization_preserves_shape_and_dynamic_value_format
    resource = {
      "apiVersion" => "v1",
      "kind" => "ConfigMap",
      "metadata" => {
        "uid" => "9a960869-6027-4d42-bb20-13cf72d53729",
        "resourceVersion" => "12",
        "creationTimestamp" => "2026-08-22T10:11:12Z",
        "managedFields" => [{"manager" => "ignored"}]
      },
      "immutable" => false
    }

    normalized = M1KubernetesOracle.canonical_resource(resource)

    assert_equal("<uuid>", normalized.dig("metadata", "uid"))
    assert_equal("<positive-integer>", normalized.dig("metadata", "resourceVersion"))
    assert_equal("<timestamp>", normalized.dig("metadata", "creationTimestamp"))
    assert_equal(false, normalized["immutable"])
    refute(normalized.fetch("metadata").key?("managedFields"))
    assert_equal(
      "<invalid-uid>",
      M1KubernetesOracle.canonical_resource({"metadata" => {"uid" => "not-a-uuid"}}).dig("metadata", "uid")
    )
  end

  def test_status_ownership_and_watch_signatures_keep_oracle_observables
    status = {
      "apiVersion" => "v1", "kind" => "Status", "status" => "Failure",
      "message" => "invalid", "reason" => "Invalid", "code" => 422,
      "details" => {"causes" => [{"reason" => "FieldValueRequired", "field" => "metadata.name"}]},
      "ignored" => true
    }
    object = {
      "apiVersion" => "v1", "kind" => "ConfigMap",
      "metadata" => {
        "name" => "demo", "resourceVersion" => "2",
        "managedFields" => [{
          "manager" => "manager-one", "operation" => "Apply", "apiVersion" => "v1",
          "fieldsType" => "FieldsV1", "time" => "2026-08-22T10:11:12Z",
          "fieldsV1" => {"f:data" => {"." => {}, "f:owned" => {}}}
        }]
      },
      "data" => {"owned" => "one"}
    }

    assert_equal(%w[apiVersion code details kind message reason status], M1KubernetesOracle.status_signature(status).keys)
    ownership = M1KubernetesOracle.ownership_signature(object)

    assert_equal(["data", "data.owned"], ownership.first.fetch("fields"))
    assert_equal("<timestamp>", ownership.first.fetch("time"))
    watch = M1KubernetesOracle.watch_signature({"type" => "MODIFIED", "object" => object})

    assert_equal("MODIFIED", watch.first.fetch("type"))
    assert_equal("<positive-integer>", watch.first.dig("object", "metadata", "resourceVersion"))
    assert_equal(ownership, watch.first.fetch("ownership"))
  end
end
