# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/volume"

class ProjectedPodContextTest < Minitest::Test
  NODE = Rubernetes::Node
  VOLUME = Rubernetes::Volume
  VOLUME_NAME = "kube-api-access-test"
  MOUNT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"
  CALLER_ANNOTATION = "example.com/owning-pod"
  TRUST_PEM = Rubernetes::PEM.certificate("trust anchor bytes").freeze
  OWNERSHIP = {"runAsUser" => (Process.uid.zero? ? 12_345 : Process.uid),
               "fsGroup" => (Process.uid.zero? ? 23_456 : Process.gid)}.freeze

  class TokenRequestClient
    attr_reader :requests

    def initialize
      @requests = []
    end

    def create(body, namespace:, api_version:, path:)
      @requests << [body, namespace, api_version, path]
      {"status" => {"token" => "issued-#{@requests.length}", "expirationTimestamp" => "2026-01-02T00:00:00Z"}}
    end
  end

  class InjectedTokenProvider
    def for_pod(pod)
      ->(**) { pod.dig("metadata", "annotations", CALLER_ANNOTATION).to_s }
    end
  end

  class InjectedCertificateProvider
    def credential_bundle(pod, *)
      [pod.dig("metadata", "annotations", CALLER_ANNOTATION).to_s, "-certificate"]
    end

    def version(*) = 1
    def forget_pod(*) = nil
  end

  class FilesystemAdapter < VOLUME::FilesystemAdapter
    def apply_fs_group(**) = true
  end

  def setup
    @root = Dir.mktmpdir("rubernetes-projected-pod-context")
    @now = Time.utc(2026, 1, 1)
    @token_api = TokenRequestClient.new
    @provider = VOLUME::ServiceAccountTokenProvider.new(client: @token_api)
    @previous_certificate_provider = VOLUME::ProjectedBackend.pod_certificate_provider
  end

  def teardown
    @volumes.release(@pod, @handle) if @handle
  ensure
    VOLUME::ProjectedBackend.pod_certificate_provider = @previous_certificate_provider
    FileUtils.remove_entry(@root)
  end

  def get(resource, name, namespace:)
    case [resource, namespace, name]
    when %w[configmaps tenant kube-root-ca.crt] then {"data" => {"ca.crt" => "public root CA"}}
    when ["clustertrustbundles", nil, "tenant-root"] then {"spec" => {"trustBundle" => TRUST_PEM}}
    end
  end

  def test_default_kube_api_access_does_not_record_unrelated_pod_metadata
    prepare(default_sources, annotations: {CALLER_ANNOTATION => "x" * (192 * 1024)})

    sizes = ledger_bytes

    assert_operator sizes.values.sum, :<, 16 * 1024, "projected ledger bytes #{sizes.inspect}"
    assert_equal "issued-1", read_projected("token")
    assert_credential_ownership("token")
    assert_equal "tenant", read_projected("namespace")
    assert_equal "public root CA", read_projected("ca.crt")
    start_node

    assert_equal [VOLUME_NAME], @volumes.rotate_tokens(@pod, @handle)
    assert_equal "issued-2", read_projected("token")
    assert_credential_ownership("token")
    assert_equal "tenant", read_projected("namespace")
    assert_equal "public root CA", read_projected("ca.crt")
    expected = {"apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenRequest",
                "spec" => {"audiences" => [], "expirationSeconds" => 3607,
                           "boundObjectRef" => {"apiVersion" => "v1", "kind" => "Pod", "name" => "client", "uid" => "pod-uid"}}}

    assert_equal [[expected, "tenant", "v1", "/api/v1/namespaces/tenant/serviceaccounts/workload/token"]] * 2, @token_api.requests
  end

  def test_legacy_full_pod_records_reconstruct_owner_and_token_identity
    prepare(default_sources)
    id = @handle.dig("mounts", VOLUME_NAME, "id")
    record = @manager.volume(id)
    legacy = record.spec.except("credentialOwnership").merge("pod" => @pod)
    @manager.volume_store[id] = record.with(spec: legacy)
    start_node

    assert_equal [VOLUME_NAME], @volumes.rotate_tokens(@pod, @handle)
    assert_equal "issued-2", read_projected("token")
    assert_credential_ownership("token")
    assert_equal @token_api.requests.first, @token_api.requests.last
  end

  def test_mixed_trust_bundle_and_token_keep_credential_modes_after_restart
    trust = {"clusterTrustBundle" => {"name" => "tenant-root", "path" => "trust.pem"}}
    prepare(default_sources + [trust], annotations: {CALLER_ANNOTATION => "unrelated-trust-annotation"})
    id = @handle.dig("mounts", VOLUME_NAME, "id")

    assert_equal({"metadata" => {"namespace" => "tenant", "name" => "client", "uid" => "pod-uid"},
                  "spec" => {"serviceAccountName" => "workload"}}, @manager.volume(id).spec.fetch("pod"))
    start_node

    assert_equal [VOLUME_NAME], @volumes.rotate_tokens(@pod, @handle)
    assert_equal TRUST_PEM, read_projected("trust.pem")
    assert_credential_ownership("trust.pem")
    assert_credential_ownership("token")
  end

  def test_run_as_user_without_fs_group_keeps_owner_only_access_on_replay
    owner = OWNERSHIP.fetch("runAsUser")
    prepare(default_sources, security_context: {"runAsUser" => owner})
    start_node

    assert_equal [VOLUME_NAME], @volumes.rotate_tokens(@pod, @handle)
    stat = File.stat(projected_path("token"))

    assert_equal owner, stat.uid
    assert_equal 0o600, stat.mode & 0o777
  end

  def test_injected_token_provider_keeps_the_full_pod_on_replay
    @provider = InjectedTokenProvider.new
    prepare(default_sources, annotations: {CALLER_ANNOTATION => "pod-annotation-value"})

    assert_equal "pod-annotation-value", read_projected("token")
    start_node

    assert_equal [VOLUME_NAME], @volumes.rotate_tokens(@pod, @handle)
    assert_equal "pod-annotation-value", read_projected("token")
  end

  def test_injected_certificate_provider_keeps_the_full_pod_on_replay
    @certificate_provider = InjectedCertificateProvider.new
    certificate = {"podCertificate" => {"signerName" => "example.com/test", "credentialBundlePath" => "certificate"}}
    prepare(default_sources + [certificate], annotations: {CALLER_ANNOTATION => "pod-annotation-value"})

    assert_equal "pod-annotation-value-certificate", read_projected("certificate")
    start_node

    assert_equal [VOLUME_NAME], @volumes.rotate_tokens(@pod, @handle)
    assert_equal "pod-annotation-value-certificate", read_projected("certificate")
  end

  private

  def default_sources
    namespace_item = {"path" => "namespace", "fieldRef" => {"apiVersion" => "v1", "fieldPath" => "metadata.namespace"}}
    [
      {"serviceAccountToken" => {"expirationSeconds" => 3607, "path" => "token"}},
      {"configMap" => {"name" => "kube-root-ca.crt", "items" => [{"key" => "ca.crt", "path" => "ca.crt"}]}},
      {"downwardAPI" => {"items" => [namespace_item]}}
    ]
  end

  def start_node
    @manager = VOLUME::Manager.new(data_dir: @root, token_provider: @provider, mount_adapter: FilesystemAdapter.new, clock: -> { @now }, fsync: true)
    @volumes = NODE::PodVolumes.new(volume: @manager, reader: self, root: File.join(@root, "pods"), clock: -> { @now },
                                    cluster_trust_bundle_projection: true)
    @volumes.pod_certificates = @certificate_provider if @certificate_provider
  end

  def prepare(sources, annotations: {}, security_context: OWNERSHIP)
    start_node
    @pod = {"metadata" => {"namespace" => "tenant", "name" => "client", "uid" => "pod-uid", "annotations" => annotations},
            "spec" => {"serviceAccountName" => "workload", "securityContext" => security_context,
                       "containers" => [{"name" => "app", "volumeMounts" => [{"name" => VOLUME_NAME, "mountPath" => MOUNT_PATH}]}],
                       "volumes" => [{"name" => VOLUME_NAME, "projected" => {"defaultMode" => 0o644, "sources" => sources}}]}}
    @handle = @volumes.prepare(@pod)
  end

  def ledger_bytes
    %w[operations volumes].to_h { |name| [name, Dir[File.join(@root, "#{name}.json.d", "*.json")].sum { |path| File.size(path) }] }
  end

  def projected_path(name)
    File.join(@handle.dig("mounts", VOLUME_NAME, "path"), name)
  end

  def read_projected(name)
    File.read(projected_path(name))
  end

  def assert_credential_ownership(name)
    stat = File.stat(projected_path(name))

    assert_equal(OWNERSHIP.values_at("runAsUser", "fsGroup"), [stat.uid, stat.gid])
    assert_equal 0o640, stat.mode & 0o777
  end
end
