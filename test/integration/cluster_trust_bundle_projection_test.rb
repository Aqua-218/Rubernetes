# frozen_string_literal: true

require_relative "../test_helper"
require "openssl"
require "tmpdir"
require "rubernetes/bootstrap"
require "rubernetes/node"
require "rubernetes/volume"

class ClusterTrustBundleProjectionTest < Minitest::Test
  API = Rubernetes::API
  VOLUME = Rubernetes::Volume
  NODE = Rubernetes::Node
  AUTHORIZATION = Rubernetes::Security::Authorization
  VERSION = "certificates.k8s.io"
  SIGNER = "example.com/signer"
  IDENTITY = {"username" => "system:node:worker", "groups" => %w[system:nodes system:authenticated]}.freeze

  # The node runs its ordinary Kubernetes client, discovery and resource
  # reader against the real API handler. The transport stays in-process.
  class Transport
    attr_reader :paths

    def initialize(server)
      @server = server
      @paths = []
    end

    def request(method, path, body: nil, headers: {}, query: nil)
      @paths << path
      @server.call(API::Request.new(method: method, path: path, body: body, headers: headers, query: query, identity: IDENTITY))
    end
  end

  class FilesystemAdapter < VOLUME::FilesystemAdapter
    def apply_fs_group(**)
      true
    end
  end

  def setup
    @root = Dir.mktmpdir("rubernetes-trust-bundle")
    @manager = VOLUME::Manager.new(data_dir: @root, mount_adapter: FilesystemAdapter.new)
  end

  def teardown
    @volumes.release(@pod, @handle) if @handle
  ensure
    FileUtils.remove_entry(@root)
  end

  def start_api(versions, bundles: true, projection: true)
    @versions = versions
    feature_gates = {"ClusterTrustBundle" => bundles, "ClusterTrustBundleProjection" => projection}
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    runtime_config = %w[v1beta1 v1alpha1].to_h { |version| ["#{VERSION}/#{version}", versions.include?(version)] }
    node_authorizer = AUTHORIZATION::Node.new(graph: Object.new, features: feature_gates)
    authorizer = Object.new
    authorizer.define_singleton_method(:authorize) do |attributes|
      if !attributes.resource_request? || attributes.user.groups.include?("system:masters")
        AUTHORIZATION::Decision.allow
      else
        node_authorizer.authorize(attributes)
      end
    end
    security = Rubernetes::Security::Pipeline.new(authorizer: authorizer)
    @api = API::Server.new(registry: registry, feature_gates: feature_gates, runtime_config: runtime_config, security: security)
    @transport = Transport.new(@api)
    client = Rubernetes::Client::KubernetesClient.new(rest_client: @transport, namespace: "wrong-namespace")
    adapter = NODE::APIClientAdapter.new(client: client, node_name: "worker")
    reader = NODE::ResourceReader.new(client: adapter, ttl: 0)
    lifecycle = NODE::Lifecycle.new(runtime: Object.new, volume: @manager, pod_root: File.join(@root, "pods"),
                                    resource_reader: reader, feature_gates: feature_gates)
    @volumes = lifecycle.pod_volumes
  end

  def test_beta_discovery_precedes_alpha_and_projects_normalized_named_bundle
    start_api(%w[v1beta1 v1alpha1])
    root = certificate(1)
    create_bundle("named", "comment before anchor\n#{root.gsub("\n", "\r\n")}comment after anchor")
    prepare({"name" => "named"})

    assert_equal root, read_bundle
    assert_equal 0o664, File.stat(bundle_path).mode & 0o777
    assert_equal ["/apis/#{VERSION}/v1beta1", "/apis/#{VERSION}/v1beta1/clustertrustbundles/named"], @transport.paths
  end

  def test_discovers_alpha_filters_all_label_operators_and_deduplicates_anchors
    start_api(%w[v1alpha1])
    roots = {alpha: certificate(1), beta: certificate(2), excluded: certificate(3)}
    create_bundle("one", roots[:alpha], signer: SIGNER, labels: {"environment" => "", "level" => "primary", "selected" => ""})
    create_bundle("two", roots[:beta] + roots[:alpha],
                  signer: SIGNER, labels: {"environment" => "", "level" => "secondary", "selected" => "", "revoked" => "no"})
    create_bundle("absent-empty-label", roots[:excluded], signer: SIGNER, labels: {"level" => "primary", "selected" => ""})
    create_bundle("excluded-value", roots[:excluded],
                  signer: SIGNER, labels: {"environment" => "", "level" => "primary", "selected" => "", "revoked" => "yes"})
    create_bundle("excluded-presence", roots[:excluded],
                  signer: SIGNER, labels: {"environment" => "", "level" => "primary", "selected" => "", "old" => ""})
    create_bundle("excluded-missing-label", roots[:excluded], signer: SIGNER, labels: {"environment" => "", "level" => "secondary"})
    create_bundle("wrong-signer", roots[:excluded], signer: "example.com/other", labels: {"environment" => "", "level" => "primary", "selected" => ""})
    selector = {
      "matchLabels" => {"environment" => ""},
      "matchExpressions" => [
        {"key" => "level", "operator" => "In", "values" => %w[primary secondary]},
        {"key" => "revoked", "operator" => "NotIn", "values" => %w[yes]},
        {"key" => "selected", "operator" => "Exists"},
        {"key" => "old", "operator" => "DoesNotExist"}
      ]
    }
    prepare({"signerName" => SIGNER, "labelSelector" => selector})

    assert_equal roots.values_at(:alpha, :beta).map { |pem| OpenSSL::X509::Certificate.new(pem).to_der }.sort, bundle_anchors.sort
    assert_empty @volumes.refresh_contents(@pod, @handle)
    assert_includes @transport.paths, "/apis/#{VERSION}/v1alpha1/clustertrustbundles"
    assert_includes @transport.paths, "/apis/#{VERSION}/v1beta1"
  end

  def test_omitted_selector_matches_nothing_and_empty_selector_matches_signer
    start_api(%w[v1beta1])
    root = certificate(1)
    create_bundle("one", root, signer: SIGNER)

    missing = assert_raises(NODE::PodVolumes::MissingDependency) { prepare({"signerName" => SIGNER}) }

    assert_match(/matched zero ClusterTrustBundles/, missing.message)
    prepare({"signerName" => SIGNER, "labelSelector" => {}})

    assert_equal root, read_bundle
  end

  def test_signer_projection_can_exceed_the_size_limit_of_one_api_object
    start_api(%w[v1beta1])
    limit = 1024 * 1024
    roots = [certificate(1, extension_bytes: 400 * 1024), certificate(2, extension_bytes: 400 * 1024)]
    roots.each_with_index do |root, index|
      assert_operator root.bytesize, :<, limit
      create_bundle("large-#{index}", root, signer: SIGNER)
    end
    prepare({"signerName" => SIGNER, "labelSelector" => {}})

    assert_operator File.size(bundle_path), :>, limit
    expected = roots.map { |pem| Digest::SHA256.hexdigest(OpenSSL::X509::Certificate.new(pem).to_der) }

    assert_equal expected.sort, bundle_anchors.map { |der| Digest::SHA256.hexdigest(der) }.sort
  end

  def test_optional_missing_bundle_publishes_an_empty_file_with_credential_permissions
    start_api(%w[v1beta1])
    uid = Process.uid.zero? ? 12_345 : Process.uid
    gid = Process.uid.zero? ? 12_345 : Process.gid
    spec = {"runAsUser" => uid, "fsGroup" => gid}
    missing = assert_raises(NODE::PodVolumes::MissingDependency) { prepare({"name" => "missing"}, security_context: spec) }

    assert_match(/"missing" not found/, missing.message)
    prepare({"name" => "missing", "optional" => true}, security_context: spec)

    assert_equal "", read_bundle
    stat = File.stat(bundle_path)

    assert_equal [uid, gid, 0o640], [stat.uid, stat.gid, stat.mode & 0o777]
    root = certificate(1)
    create_bundle("missing", root)

    assert_equal ["trust"], @volumes.refresh_contents(@pod, @handle)
    assert_equal root, read_bundle
    stat = File.stat(bundle_path)

    assert_equal [uid, gid, 0o640], [stat.uid, stat.gid, stat.mode & 0o777]
  end

  def test_disabled_node_or_unserved_api_errors_even_if_optional
    start_api(%w[v1beta1], projection: false)
    projection = {"name" => "missing", "optional" => true}

    assert_raises(NODE::PodVolumes::Unsupported) { prepare(projection) }
    assert_empty @transport.paths
    start_api(%w[v1beta1 v1alpha1], bundles: false)
    unavailable = assert_raises(NODE::PodVolumes::MissingDependency) { prepare(projection) }

    assert_match(/no version of the ClusterTrustBundle API is served/, unavailable.message)
  end

  def test_node_authorizer_allows_bundle_reads_when_api_gate_is_on
    user = Rubernetes::Security::UserInfo.from_h(IDENTITY)
    enabled = AUTHORIZATION::Node.new(graph: Object.new, features: {"ClusterTrustBundle" => true})
    disabled = AUTHORIZATION::Node.new(graph: Object.new)
    attrs = AUTHORIZATION::Attributes.new(user: user, verb: "list", api_group: VERSION, resource: "clustertrustbundles")

    assert_predicate enabled.authorize(attrs), :allowed?
    refute_predicate disabled.authorize(attrs), :allowed?
    refute_predicate enabled.authorize(attrs.with_verb("create")), :allowed?
  end

  def test_api_requires_signer_name_prefix_distinct_ca_certificates_and_valid_updates
    start_api(%w[v1beta1])
    root = certificate(1)
    path = "/apis/#{VERSION}/v1beta1/clustertrustbundles"
    body = {"apiVersion" => "#{VERSION}/v1beta1", "kind" => "ClusterTrustBundle", "metadata" => {"name" => "wrong-prefix"},
            "spec" => {"signerName" => SIGNER, "trustBundle" => root}}
    rejected = admin_request("POST", path, body)

    assert_equal 422, rejected.status
    assert_match(/must be named with prefix example.com:signer:/, rejected.body.fetch("message"))
    name = "example.com:signer:valid"
    body["metadata"]["name"] = name
    body["spec"]["trustBundle"] = root * 2
    rejected = admin_request("POST", path, body)

    assert_equal 422, rejected.status
    assert_match(/duplicate trust anchor/, rejected.body.fetch("message"))
    body["spec"]["trustBundle"] = certificate(2, ca: false)
    rejected = admin_request("POST", path, body)

    assert_equal 422, rejected.status
    assert_match(/does not have the CA bit set/, rejected.body.fetch("message"))
    create_bundle("valid", root, signer: SIGNER)
    rejected = admin_request("PATCH", "#{path}/#{name}", {"spec" => {"trustBundle" => "no certificate"}})

    assert_equal 422, rejected.status
    assert_match(/at least one trust anchor must be provided/, rejected.body.fetch("message"))
    updated = admin_request("PATCH", "#{path}/#{name}", {"metadata" => {"labels" => {"selected" => "true"}}})

    assert_equal 200, updated.status, updated.body.inspect
    assert_equal root, updated.body.dig("spec", "trustBundle")
  end

  private

  def prepare(projection, security_context: {})
    @pod = {"metadata" => {"uid" => "pod", "name" => "pod"}, "spec" => {
      "securityContext" => security_context,
      "volumes" => [{"name" => "trust", "projected" => {"defaultMode" => 0o664, "sources" => [
        {"clusterTrustBundle" => projection.merge("path" => "ca.pem")}
      ]}}],
      "containers" => [{"name" => "reader", "volumeMounts" => [{"name" => "trust", "mountPath" => "/trust"}]}]
    }}
    @handle = @volumes.prepare(@pod)
  end

  def bundle_path
    File.join(@handle.dig("mounts", "trust", "path"), "ca.pem")
  end

  def read_bundle
    File.binread(bundle_path)
  end

  def bundle_anchors
    OpenSSL::X509::Certificate.load(read_bundle).map(&:to_der)
  end

  def create_bundle(name, pem, signer: nil, labels: {})
    version = "#{VERSION}/#{@versions.first}"
    name = "#{signer.tr("/", ":")}:#{name}" if signer
    object = {"apiVersion" => version, "kind" => "ClusterTrustBundle", "metadata" => {"name" => name, "labels" => labels},
              "spec" => {"signerName" => signer, "trustBundle" => pem}.compact}
    response = admin_request("POST", "/apis/#{version}/clustertrustbundles", object)

    assert_equal 201, response.status, response.body.inspect
  end

  def admin_request(method, path, body)
    content_type = method == "PATCH" ? "application/merge-patch+json" : "application/json"
    @api.call(API::Request.new(method: method, path: path, headers: {"content-type" => content_type}, body: JSON.generate(body),
                               identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def certificate(serial, ca: true, extension_bytes: 0)
    key = OpenSSL::PKey::EC.generate("prime256v1")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=projection-root-#{serial}")
    cert.public_key = key
    cert.not_before = Time.utc(2026, 1, 1)
    cert.not_after = Time.utc(2027, 1, 1)
    cert.add_extension(OpenSSL::X509::ExtensionFactory.new.create_extension("basicConstraints", "CA:#{ca ? "TRUE" : "FALSE"}", true))
    if extension_bytes.positive?
      data = OpenSSL::ASN1::OctetString.new("x" * extension_bytes).to_der
      cert.add_extension(OpenSSL::X509::Extension.new("1.3.6.1.4.1.32473.1", data))
    end
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert.to_pem
  end
end
