# frozen_string_literal: true

require "fileutils"
require "json"
require_relative "../test_helper"
require "rubernetes/image/resolver"
require "rubernetes/image/pull_records"
require "rubernetes/node/image_credentials"
require "rubernetes/bootstrap"

# KubeletEnsureSecretPulledImages (pkg/kubelet/images/pullmanager, v1.36.2):
# an image already on the node is only handed to a Pod whose credentials
# could pull it.
class EnsureSecretPulledImagesTest < Minitest::Test
  Image = Rubernetes::Image
  Records = Image::PullRecords
  SECRET_A = {uid: "uid-a", namespace: "ns", name: "regcred", hash: "hash-a"}.freeze
  SECRET_B = {uid: "uid-b", namespace: "ns", name: "other", hash: "hash-b"}.freeze

  # Pulls (full) and manifest checks, with the credentials they used; a
  # private registry refuses anonymous access.
  class Registry
    attr_reader :pulls, :checks

    def initialize(private_image: true, allowed: %w[alice])
      @private = private_image
      @allowed = allowed
      @pulls = []
      @checks = []
    end

    def digest = Image::Digest.parse("sha256:#{"c" * 64}")
    def config = {"architecture" => "amd64", "os" => "linux", "config" => {"Cmd" => ["/app"]}}

    def factory
      registry = self
      lambda do |_reference, credentials = nil|
        user = credentials && (credentials[:username] || credentials["username"])
        puller = Object.new
        puller.define_singleton_method(:pull) do |reference, platform:, rootfs:, unpack:|
          registry.authorize!(user)
          registry.pulls << user
          FileUtils.mkdir_p(rootfs)
          Image::Image.new(reference: reference.with_digest(registry.digest), manifest: Struct.new(:digest).new(registry.digest),
                           config: JSON.generate(registry.config), rootfs: rootfs, config_object: registry.config)
        end
        puller.define_singleton_method(:resolve_digest) do |_reference, platform:|
          registry.authorize!(user)
          registry.checks << user
          registry.digest
        end
        puller
      end
    end

    def authorize!(user)
      return unless @private
      raise Image::RegistryError, "unauthorized" unless @allowed.include?(user)
    end
  end

  def resolver(registry, records: Records.new)
    @resolvers ||= []
    Image::Resolver.new(puller_factory: registry.factory, platform: {"os" => "linux", "architecture" => "amd64"},
                        pull_records: records).tap { |resolver| @resolvers << resolver }
  end

  def teardown
    Array(@resolvers).each { |resolver| resolver.cached_images.each { |key, _image, _| resolver.evict_cached_image(key) } }
  end

  IMAGE = "registry.example/team/app:1.0"

  def test_an_anonymous_image_is_shared_without_any_registry_request
    registry = Registry.new(private_image: false)
    images = resolver(registry)
    first = images.resolve(IMAGE)
    second = images.resolve(IMAGE, credentials: {username: "bob"}, pull_secret: SECRET_B)
    assert_same first, second
    assert_equal [nil], registry.pulls
    assert_empty registry.checks
  end

  def test_a_private_image_is_not_lent_to_a_pod_without_credentials
    registry = Registry.new
    images = resolver(registry)
    images.resolve(IMAGE, credentials: {username: "alice"}, pull_secret: SECRET_A)
    error = assert_raises(Image::RegistryError) { images.resolve(IMAGE) }
    assert_equal "unauthorized", error.message
    assert_equal [nil], registry.checks.empty? ? [nil] : registry.checks
    assert_equal ["alice"], registry.pulls
  end

  def test_the_same_secret_matches_without_a_request
    registry = Registry.new
    images = resolver(registry)
    first = images.resolve(IMAGE, credentials: {username: "alice"}, pull_secret: SECRET_A)
    again = images.resolve(IMAGE, credentials: {username: "alice"}, pull_secret: SECRET_A,
                                  pod_credentials: -> { [[SECRET_A], nil] })
    assert_same first, again
    assert_empty registry.checks
  end

  def test_another_secret_is_verified_with_a_manifest_request_and_remembered
    registry = Registry.new(allowed: %w[alice carol])
    images = resolver(registry)
    first = images.resolve(IMAGE, credentials: {username: "alice"}, pull_secret: SECRET_A)
    other = {uid: "uid-c", namespace: "ns2", name: "carol", hash: "hash-c"}
    reused = images.resolve(IMAGE, credentials: {username: "carol"}, pull_secret: other, pod_credentials: -> { [[other], nil] })
    assert_same first, reused, "a matching digest reuses the unpacked image"
    assert_equal ["carol"], registry.checks
    images.resolve(IMAGE, credentials: {username: "carol"}, pull_secret: other, pod_credentials: -> { [[other], nil] })
    assert_equal ["carol"], registry.checks, "the verified Secret is recorded"
  end

  def test_a_copy_of_the_credential_in_another_secret_matches_by_hash
    records = Records.new
    records.record_pulled("r/app", "sha256:x", Records::Credentials.secret(**SECRET_A))
    copy = SECRET_A.merge(uid: "uid-z", name: "copy")
    refute records.must_attempt_pull?("r/app", "sha256:x", -> { [[copy], nil] })
    names = records.record("sha256:x")[:mapping]["r/app"].secrets.map { |secret| secret[:name] }
    assert_equal %w[copy regcred], names
    # A rotated Secret (same coordinates, new hash) still may use it.
    rotated = SECRET_A.merge(hash: "hash-new")
    refute records.must_attempt_pull?("r/app", "sha256:x", -> { [[rotated], nil] })
    assert records.must_attempt_pull?("r/app", "sha256:x", -> { [[SECRET_B], nil] })
    # Another repository of the same image has no record.
    assert records.must_attempt_pull?("r/other", "sha256:x", -> { [[SECRET_A], nil] })
  end

  def test_service_accounts_and_node_access
    records = Records.new
    account = {uid: "sa-1", namespace: "ns", name: "builder"}
    records.record_pulled("r/app", "sha256:x", Records::Credentials.new(node_accessible: false, secrets: [], service_accounts: [account]))
    refute records.must_attempt_pull?("r/app", "sha256:x", -> { [[], account] })
    assert records.must_attempt_pull?("r/app", "sha256:x", -> { [[], nil] })
    records.record_pulled("r/app", "sha256:x", Records::Credentials.node)
    refute records.must_attempt_pull?("r/app", "sha256:x", -> { raise "not consulted" })
  end

  def test_policies_and_allowlist
    never = Records.new(policy: "NeverVerify")
    refute never.must_attempt_pull?("r/app", "sha256:x", -> { [[], nil] })
    always = Records.new(policy: "AlwaysVerify")
    always.record_pulled("r/app", "sha256:x", Records::Credentials.secret(**SECRET_A))
    assert always.must_attempt_pull?("r/app", "sha256:x", -> { [[], nil] })
    listed = Records.new(policy: "NeverVerifyAllowlistedImages", allowlist: ["registry.example/team/*", "docker.io/library/busybox"])
    refute listed.verification_required?("registry.example/team/app")
    refute listed.verification_required?("docker.io/library/busybox")
    assert listed.verification_required?("registry.example/other")
    assert_raises(Records::InvalidPolicy) { Records.new(policy: "Sometimes") }
    ["registry.example/*/x", " a/b", "busybox:1.36", "*", "/*"].each do |pattern|
      assert_raises(Records::InvalidPolicy, pattern) { Records.parse_allowlist([pattern]) }
    end
    Records.parse_allowlist(["localhost:5000/app"])
  end

  def test_pull_policy_never_uses_only_an_image_the_pod_may_use
    registry = Registry.new
    images = resolver(registry)
    error = assert_raises(Image::NeverPullError) { images.resolve(IMAGE, pull_policy: "Never") }
    assert_equal %(Container image "#{IMAGE}" is not present with pull policy of Never), error.message
    first = images.resolve(IMAGE, credentials: {username: "alice"}, pull_secret: SECRET_A)
    assert_same first, images.resolve(IMAGE, pull_policy: "Never", pull_secret: SECRET_A, pod_credentials: -> { [[SECRET_A], nil] })
    assert_raises(Image::NeverPullError) { images.resolve(IMAGE, pull_policy: "Never") }
    assert_empty registry.checks, "Never never asks the registry"
  end

  def test_pull_policy_always_asks_the_registry_and_reuses_an_unchanged_image
    registry = Registry.new(private_image: false)
    images = resolver(registry)
    first = images.resolve(IMAGE, pull_policy: "Always")
    assert_equal [nil], registry.pulls
    assert_same first, images.resolve(IMAGE, pull_policy: "Always")
    assert_same first, images.resolve(IMAGE, pull_policy: "Always")
    assert_equal [nil, nil], registry.checks
    assert_equal [nil], registry.pulls, "an unchanged digest is not downloaded again"
  end

  def test_a_credential_provider_service_account_is_recorded_and_matched
    registry = Registry.new(allowed: %w[alice carol])
    images = resolver(registry)
    account = {uid: "sa-1", namespace: "ns", name: "builder"}
    first = images.resolve(IMAGE, credentials: {username: "alice"}, pull_secret: {service_account: account})
    assert_same first, images.resolve(IMAGE, credentials: {username: "alice"}, pull_secret: {service_account: account},
                                             pod_credentials: -> { [[], account] })
    assert_empty registry.checks
    other = {uid: "sa-2", namespace: "ns", name: "other"}
    images.resolve(IMAGE, credentials: {username: "carol"}, pull_secret: {service_account: other}, pod_credentials: -> { [[], other] })
    assert_equal ["carol"], registry.checks
  end

  def test_evicting_the_image_forgets_its_record
    registry = Registry.new(private_image: false)
    images = resolver(registry)
    image = images.resolve(IMAGE)
    refute_nil images.pull_records.record(image.digest.to_s)
    key, = images.cached_images.first
    images.evict_cached_image(key)
    assert_nil images.pull_records.record(image.digest.to_s)
  end

  def test_the_check_can_be_turned_off
    registry = Registry.new
    images = resolver(registry, records: nil)
    first = images.resolve(IMAGE, credentials: {username: "alice"}, pull_secret: SECRET_A)
    assert_same first, images.resolve(IMAGE)
  end

  def test_keyring_names_every_secret_and_its_hash
    keyring = Rubernetes::Node::ImageCredentials.new
    config = ->(user) { {"auths" => {"registry.example" => {"username" => user, "password" => "pw"}}} }
    %w[a b].each do |name|
      keyring.add_secret({"type" => "kubernetes.io/dockerconfigjson", "metadata" => {"name" => name, "uid" => "uid-#{name}", "namespace" => "ns"},
                          "data" => {".dockerconfigjson" => [JSON.generate(config.call(name))].pack("m0")}})
    end
    all = keyring.lookup_all(IMAGE)
    assert_equal %w[a b], all.map { |credential| credential.source[:name] }
    assert_equal({uid: "uid-b", namespace: "ns", name: "b", hash: all.last.auth_hash}, keyring.lookup(IMAGE).pull_secret)
    refute_equal all.first.auth_hash, all.last.auth_hash
  end

  def test_agent_config_validation
    base = {"version" => 1, "logging" => {"level" => "info"},
            "processes" => {"rubernetes-agent" => {"node_name" => "n1", "api_server" => "https://127.0.0.1:6443"}}}
    build = lambda do |section, gates = nil|
      data = JSON.parse(JSON.generate(base))
      data["processes"]["rubernetes-agent"]["image_pull_credentials"] = section
      data["processes"]["rubernetes-agent"]["feature_gates"] = gates if gates
      Rubernetes::Bootstrap::Config.new(process_name: "rubernetes-agent", data: data)
    end
    error = Rubernetes::Bootstrap::Config::Error
    build.call({"verification_policy" => "AlwaysVerify"})
    build.call({"verification_policy" => "NeverVerifyAllowlistedImages", "preloaded_images_verification_allowlist" => ["registry.example/*"]})
    assert_raises(error) { build.call({"verification_policy" => "Sometimes"}) }
    assert_raises(error) { build.call({"preloaded_images_verification_allowlist" => ["registry.example/*"]}) }
    assert_raises(error) { build.call({"verification_policy" => "NeverVerifyAllowlistedImages", "preloaded_images_verification_allowlist" => ["a:1"]}) }
    assert_raises(error) { build.call({"verification_policy" => "AlwaysVerify"}, {"KubeletEnsureSecretPulledImages" => false}) }
  end
end
