# frozen_string_literal: true

require "tmpdir"
require "base64"
require "openssl"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/volume"
require "rubernetes/volume/native_mount_adapter"
require "rubernetes/platform/linux/openat2"

# PodCertificateRequest kubelet manager: a projected podCertificate source
# gets a key and a request, the issued chain lands in the volume, refresh
# requests follow beginRefreshAt, and the states are reported.
class PodCertificateManagerTest < Minitest::Test
  Node = Rubernetes::Node
  M = Node::PodCertificateManager

  # The API server: PodCertificateRequests are created, a "signer" issues
  # them when the test says so.
  class FakeAPI
    attr_reader :requests, :created

    def initialize(ca_key:, ca_cert:)
      @ca_key = ca_key
      @ca_cert = ca_cert
      @requests = {}
      @created = []
      @serial = 0
    end

    def get(resource, name, namespace: nil, api_version: "v1")
      case resource
      when "serviceaccounts" then {"metadata" => {"name" => name, "namespace" => namespace, "uid" => "sa-uid"}}
      when "nodes" then {"metadata" => {"name" => name, "uid" => "node-uid"}}
      when "podcertificaterequests"
        @requests.fetch("#{namespace}/#{name}") do
          raise Rubernetes::Client::HTTPError.new("not found", status: 404)
        rescue StandardError
          raise("404 not found")
        end
      end
    end

    def create(manifest, namespace: nil, api_version: nil)
      @serial += 1
      name = "req-#{@serial}"
      stored = Marshal.load(Marshal.dump(manifest))
      stored["metadata"]["name"] = name
      stored["metadata"]["creationTimestamp"] = Time.now.utc.iso8601
      @requests["#{namespace}/#{name}"] = stored
      @created << stored
      stored
    end

    # The signer: issue the newest request with a chain valid for +seconds+.
    def issue!(seconds: 3600, begin_refresh_in: 1800)
      request = @created.last
      csr = OpenSSL::X509::Request.new(Base64.strict_decode64(request["spec"]["stubPKCS10Request"]))
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = @serial
      cert.subject = OpenSSL::X509::Name.parse("/CN=#{request["spec"]["podName"]}")
      cert.issuer = @ca_cert.subject
      cert.public_key = csr.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + seconds
      cert.sign(@ca_key, "SHA256")
      now = Time.now.utc
      request["status"] = {"certificateChain" => cert.to_pem + @ca_cert.to_pem,
                           "notBefore" => (now - 60).iso8601, "beginRefreshAt" => (now + begin_refresh_in).iso8601, "notAfter" => (now + seconds).iso8601,
                           "conditions" => [{"type" => "Issued", "status" => "True", "reason" => "Issued", "message" => "ok"}]}
    end

    def deny!(reason: "Policy", message: "no")
      @created.last["status"] = {"conditions" => [{"type" => "Denied", "status" => "True", "reason" => reason, "message" => message}]}
    end
  end

  def setup
    @ca_key = OpenSSL::PKey::RSA.new(2048)
    @ca_cert = OpenSSL::X509::Certificate.new
    @ca_cert.version = 2
    @ca_cert.serial = 1
    @ca_cert.subject = @ca_cert.issuer = OpenSSL::X509::Name.parse("/CN=pod-ca")
    @ca_cert.public_key = @ca_key.public_key
    @ca_cert.not_before = Time.now - 60
    @ca_cert.not_after = Time.now + 86_400
    @ca_cert.sign(@ca_key, "SHA256")
    @api = FakeAPI.new(ca_key: @ca_key, ca_cert: @ca_cert)
    @now = Time.now.utc
    @events = []
  end

  def pod(name = "web")
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "ns", "uid" => "uid-#{name}"},
     "spec" => {"serviceAccountName" => "app", "containers" => [{"name" => "c"}],
                "volumes" => [{"name" => "certs", "projected" => {"sources" => [{"podCertificate" => {"signerName" => "example.com/pods", "keyType" => "ECDSAP256",
                                                                                                      "credentialBundlePath" => "creds.pem"}}]}}]}}
  end

  def manager
    @manager ||= M.new(client: @api, node_name: "worker-0", node_uid: -> { "node-uid" }, clock: -> { @now }, jitter: -> { 0.0 },
                       events: ->(pod, type, reason, message) { @events << [pod.dig("metadata", "name"), type, reason, message] })
  end

  def source = {"signerName" => "example.com/pods", "keyType" => "ECDSAP256", "credentialBundlePath" => "creds.pem"}

  def test_request_issue_refresh_and_states
    subject = manager
    error = assert_raises(M::NotReady) { subject.credential_bundle(pod, "certs", 0, source) }
    assert_match(/not issued yet/, error.message)
    created = @api.created.last

    assert_equal "req-", created["metadata"]["generateName"]
    spec = created["spec"]

    assert_equal({"signerName" => "example.com/pods", "podName" => "web", "podUID" => "uid-web", "serviceAccountName" => "app", "serviceAccountUID" => "sa-uid",
                  "nodeName" => "worker-0", "nodeUID" => "node-uid"}, spec.slice(*%w[signerName podName podUID serviceAccountName serviceAccountUID nodeName nodeUID]))
    csr = OpenSSL::X509::Request.new(Base64.strict_decode64(spec["stubPKCS10Request"]))

    assert csr.verify(csr.public_key), "the stub CSR proves possession of the key"
    assert_equal "prime256v1", csr.public_key.group.curve_name
    assert_equal({["example.com/pods", "not_yet_issued"] => 1}, subject.metric_report)
    assert_equal [%w[uid-web Pod]],
                 [[created["metadata"]["ownerReferences"].first["uid"], created["metadata"]["ownerReferences"].first["kind"]]]

    @api.issue!(seconds: 3600, begin_refresh_in: 1800)
    subject.step_all
    key_pem, chain_pem = subject.credential_bundle(pod, "certs", 0)

    assert_match(/BEGIN (EC )?PRIVATE KEY/, key_pem)
    assert_equal 2, chain_pem.scan("BEGIN CERTIFICATE").length
    assert_equal({["example.com/pods", "fresh"] => 1}, subject.metric_report)
    assert_equal 1, subject.version(pod, "certs", 0)

    # Past beginRefreshAt a refresh request is filed while the old bundle stays.
    @now += 1801
    subject.step_all

    assert_equal 2, @api.created.length, "a refresh PodCertificateRequest"
    assert_equal key_pem, subject.credential_bundle(pod, "certs", 0).first
    assert_equal({["example.com/pods", "fresh"] => 1}, subject.metric_report)
    @now += 601
    subject.step_all

    assert_equal({["example.com/pods", "overdue_for_refresh"] => 1}, subject.metric_report)
    assert_includes @events, ["web", "Warning", "CertificateOverdueForRefresh", "PodCertificate refresh overdue"]
    @api.issue!(seconds: 7200, begin_refresh_in: 3600)
    subject.step_all
    new_key, = subject.credential_bundle(pod, "certs", 0)

    refute_equal key_pem, new_key, "the refreshed bundle uses the new key"
    assert_equal 2, subject.version(pod, "certs", 0)
    assert_equal({["example.com/pods", "fresh"] => 1}, subject.metric_report)

    subject.forget_pod("uid-web")

    assert_empty subject.metric_report
  end

  def test_denied_requests_are_terminal
    subject = manager
    assert_raises(M::NotReady) { subject.credential_bundle(pod, "certs", 0, source) }
    @api.deny!(reason: "Policy", message: "not for you")
    subject.step_all
    error = assert_raises(M::NotReady) { subject.credential_bundle(pod, "certs", 0) }
    assert_match(/permanently denied/, error.message)
    assert_equal({["example.com/pods", "denied"] => 1}, subject.metric_report)
    assert_equal %w[web Warning Denied], @events.first.first(3)
    subject.step_all

    assert_equal 1, @api.created.length, "a denied projection files no new request"
  end

  def test_key_types
    %w[RSA3072 ECDSAP256 ECDSAP384 ECDSAP521 ED25519].each do |type|
      key, der = M.generate_key_and_proof(type)
      request = OpenSSL::X509::Request.new(der)

      assert request.verify(request.public_key), type
      assert_equal key.public_to_der, request.public_key.public_to_der, type
    end
    assert_raises(M::Error) { M.generate_key_and_proof("DSA") }
    cleaned = M.clean_certificate_chain("garbage\n#{@ca_cert.to_pem}-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n")

    assert_equal 1, cleaned.scan("BEGIN CERTIFICATE").length
    refute_match(/PRIVATE KEY/, cleaned)
  end

  def test_projected_volume_writes_the_bundle_and_refreshes_it
    skip "a projected podCertificate volume lives on tmpfs (needs root)" unless Process.uid.zero?

    Dir.mktmpdir do |dir|
      subject = manager
      security = Rubernetes::Volume::PathSecurity.new(root: "/",
                                                      adapter: Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true), require_openat2: true)
      volume_manager = Rubernetes::Volume::Manager.new(data_dir: dir, fsync: false,
                                                       mount_adapter: Rubernetes::Volume::NativeMountAdapter.new, path_security: security)
      volumes = Node::PodVolumes.new(volume: volume_manager, root: File.join(dir, "pods"), node_name: "worker-0")
      volumes.pod_certificates = subject
      error = assert_raises(Node::PodVolumes::MissingDependency) { volumes.prepare(pod) }
      assert_match(/not issued yet/, error.message)
      @api.issue!
      subject.step_all
      handle = volumes.prepare(pod)
      path = File.join(handle.dig("mounts", "certs", "path"), "creds.pem")

      assert_path_exists path
      content = File.read(path)

      assert_match(/PRIVATE KEY/, content)
      assert_equal 2, content.scan("BEGIN CERTIFICATE").length

      @now += 1801
      subject.step_all
      @api.issue!(seconds: 7200)
      subject.step_all
      rotated = volumes.rotate_tokens(pod, handle, now: @now)

      assert_includes rotated, "certs"
      refute_equal content, File.read(path), "the refreshed bundle is on disk"
      metrics = Node::KubeletMetrics.new(node_name: "worker-0")
      metrics.pod_certificates = subject

      assert_match(%r{kubelet_podcertificate_states\{signer_name="example.com/pods",state="fresh"\} 1}, metrics.registry.render)
      volumes.release(pod, handle)

      assert_empty subject.metric_report
    ensure
      # The pods root is a shared self-bind and the volume a tmpfs: leave the
      # temporary directory removable.
      Dir.glob(File.join(dir, "volumes", "*")).each { |mount| system("umount", mount, err: File::NULL) }
      system("umount", File.join(dir, "pods"), err: File::NULL)
    end
  end
end
