# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "rubernetes/security/encryption"
require "rubernetes/storage/memory_store"
require "rubernetes/observability/metrics"

# --encryption-provider-config: EncryptionConfiguration parsed, the store
# wrapped so listed resources are sealed at rest, keys reloaded, and the
# apiserver_storage_* / apiserver_envelope_encryption_* series.
class EncryptionAtRestTest < Minitest::Test
  Encryption = Rubernetes::Security::Encryption

  def key(name)
    {"name" => name, "secret" => Base64.strict_encode64(SecureRandom.random_bytes(32))}
  end

  def configuration(provider = "aesgcm", key_name = "k1", resources: ["secrets"])
    {"apiVersion" => "apiserver.config.k8s.io/v1", "kind" => "EncryptionConfiguration",
     "resources" => [{"resources" => resources, "providers" => [{provider => {"keys" => [key(key_name)]}}, {"identity" => {}}]}]}
  end

  def setup
    @metrics = Rubernetes::Observability::Metrics.new
    Encryption.metrics = @metrics
    Encryption.apiserver_id = "apiserver-test"
  end

  def teardown
    Encryption.metrics = nil
  end

  def secret(name)
    {"apiVersion" => "v1", "kind" => "Secret", "metadata" => {"name" => name, "namespace" => "default"},
     "data" => {"password" => "cGFzcw=="}}
  end

  def test_listed_resources_are_sealed_at_rest_and_plain_through_the_wrapper
    raw = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    config = Encryption::Configuration.from_h(configuration)
    store = config.wrap(raw)
    store.create("registry/v1/secrets/default/db", secret("db"))
    store.create("registry/v1/configmaps/default/plain",
                 {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "plain", "namespace" => "default"},
                  "data" => {"a" => "b"}})
    stored = raw.get("registry/v1/secrets/default/db")

    assert stored.key?("__encrypted__"), "the secret body is sealed in the raw store"
    refute stored.key?("data")
    assert stored["__encrypted__"].start_with?("k8s:enc:aesgcm:v1:k1:")
    assert_equal({"password" => "cGFzcw=="}, store.get("registry/v1/secrets/default/db")["data"])
    assert_equal({"a" => "b"}, raw.get("registry/v1/configmaps/default/plain")["data"], "unlisted resources stay plain")
    assert_equal(["db"], store.list("registry/v1/secrets/default").items.map { |item| item.dig("metadata", "name") })
    assert_equal({"password" => "cGFzcw=="}, store.list("registry/v1/secrets/default").items.first["data"])
    text = @metrics.render_own

    assert_match(
      /apiserver_storage_transformation_operations_total\{resource="secrets",status="OK",transformation_type="to_storage",transformer_prefix="k8s:enc:aesgcm:v1:"\} 1/, text
    )
    assert_match(
      /apiserver_storage_transformation_operations_total\{resource="secrets",status="OK",transformation_type="from_storage",transformer_prefix="k8s:enc:aesgcm:v1:"\} \d+/, text
    )
    assert_match(
      /apiserver_storage_transformation_duration_seconds_count\{transformation_type="to_storage",transformer_prefix="k8s:enc:aesgcm:v1:"\} 1/, text
    )
  end

  def test_aescbc_identity_and_matcher_rules
    cbc = Encryption::Configuration.from_h(configuration("aescbc", "c1", resources: ["deployments.apps", "*.batch", "configmaps"]))
    matcher = cbc.groups.first.matcher

    assert matcher.call("registry/apps/v1/deployments/default/web")
    assert matcher.call("registry/batch/v1/jobs/default/build")
    assert matcher.call("registry/v1/configmaps/default/x")
    refute matcher.call("registry/v1/secrets/default/x")
    refute matcher.call("registry/apps/v1/statefulsets/default/x")
    everything = Encryption::Configuration.matcher_for(["*.*"])

    assert everything.call("registry/v1/secrets/default/x")
    assert everything.call("registry/apps/v1/deployments/default/x")
    core = Encryption::Configuration.matcher_for(["*."])

    assert core.call("registry/v1/secrets/default/x")
    refute core.call("registry/apps/v1/deployments/default/x")

    provider = cbc.groups.first.transformer.writer

    assert_equal "aescbc", provider.name
    envelope = provider.encrypt("hello", "aad")

    assert envelope.start_with?("k8s:enc:aescbc:v1:c1:")
    assert_equal "hello", provider.decrypt(envelope, "aad")
    assert_equal "plain", Encryption::IdentityProvider.new.encrypt("plain", "aad")
    error = assert_raises(Encryption::Error) { Encryption::Configuration.from_h(configuration("secretbox")) }
    assert_match(/secretbox/, error.message)
  end

  def test_reload_swaps_keys_and_records_the_controller_series
    Dir.mktmpdir do |dir|
      path = File.join(dir, "encryption.yaml")
      File.write(path, configuration("aesgcm", "old").to_yaml)
      raw = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
      config = Encryption::Configuration.load(path)
      store = config.wrap(raw)
      controller = Encryption::ReloadController.new(path: path, wrapped: store, interval: 3600, clock: -> { 1000.0 })
      controller.note_loaded(config)
      store.create("registry/v1/secrets/default/a", secret("a"))

      assert raw.get("registry/v1/secrets/default/a")["__encrypted__"].start_with?("k8s:enc:aesgcm:v1:old:")
      refute controller.check!, "an unchanged file is not a reload"

      # A rotated file: new writes use the new key, old envelopes stay readable
      # only if the old key is kept -- the rotated configuration lists both.
      old_key = configuration("aesgcm", "old")["resources"][0]["providers"][0]["aesgcm"]["keys"][0]
      rotated = {"apiVersion" => "apiserver.config.k8s.io/v1", "kind" => "EncryptionConfiguration",
                 "resources" => [{"resources" => ["secrets"], "providers" => [{"aesgcm" => {"keys" => [key("new"), old_key]}}, {"identity" => {}}]}]}
      original = YAML.safe_load_file(path)
      rotated["resources"][0]["providers"][0]["aesgcm"]["keys"][1] = original["resources"][0]["providers"][0]["aesgcm"]["keys"][0]
      File.write(path, rotated.to_yaml)

      assert controller.check!
      store.create("registry/v1/secrets/default/b", secret("b"))

      assert raw.get("registry/v1/secrets/default/b")["__encrypted__"].start_with?("k8s:enc:aesgcm:v1:new:")
      assert_equal({"password" => "cGFzcw=="}, store.get("registry/v1/secrets/default/a")["data"], "the old key still reads old data")
      text = @metrics.render_own

      assert_match(
        /apiserver_encryption_config_controller_automatic_reloads_total\{apiserver_id_hash="sha256:[0-9a-f]+",status="success"\} 1/, text
      )
      assert_match(/apiserver_encryption_config_controller_automatic_reload_last_timestamp_seconds\{[^}]*status="success"\} 1000/, text)
      assert_equal 1, text.scan("apiserver_encryption_config_controller_last_config_info{").length, "only the active hash is shown"

      File.write(path, "kind: Broken\n")

      refute controller.check!
      assert_match(/automatic_reloads_total\{[^}]*status="failure"\} 1/, @metrics.render_own)
    end
  end

  class FakeKMS
    attr_reader :calls

    def initialize
      @calls = []
      @key = SecureRandom.random_bytes(32)
    end

    def status
      @calls << "Status"
      {"healthz" => "ok", "key_id" => "key-2026", "version" => "v2"}
    end

    def encrypt(dek, uid:)
      @calls << "Encrypt"
      {"ciphertext" => xor(dek), "key_id" => "key-2026", "annotations" => {}}
    end

    def decrypt(ciphertext, uid:, key_id:, annotations:)
      @calls << "Decrypt"
      xor(ciphertext)
    end

    def xor(bytes) = bytes.bytes.each_with_index.map { |byte, index| byte ^ @key.getbyte(index % 32) }.pack("C*")
  end

  def test_kms_v2_envelope_metrics
    kms = FakeKMS.new
    provider = Encryption::KMSv2Provider.new(name: "vault", endpoint: "unix:///tmp/kms.sock", client: kms, cache_size: 10)
    provider.status
    envelope = provider.encrypt("top secret", "aad")

    assert_equal "top secret", provider.decrypt(envelope, "aad")
    assert_equal "top secret", provider.decrypt(envelope, "aad"), "the DEK is cached after the first decrypt"
    assert_equal %w[Status Encrypt Decrypt], kms.calls
    text = @metrics.render_own

    assert_match(
      %r{apiserver_envelope_encryption_kms_operations_latency_seconds_count\{grpc_status_code="OK",method_name="/v2.KeyManagementService/Encrypt",provider_name="vault"\} 1}, text
    )
    assert_match(/apiserver_storage_data_key_generation_duration_seconds_count 1/, text)
    assert_match(/apiserver_storage_envelope_transformation_cache_misses_total 1/, text)
    assert_match(/apiserver_envelope_encryption_dek_source_cache_size\{provider_name="vault"\} 1/, text)
    assert_match(/apiserver_envelope_encryption_dek_cache_fill_percent 10/, text)
    assert_match(
      /apiserver_envelope_encryption_key_id_hash_total\{apiserver_id_hash="sha256:[0-9a-f]+",key_id_hash="sha256:[0-9a-f]+",provider_name="vault",transformation_type="to_storage"\} 1/, text
    )
    assert_match(/apiserver_envelope_encryption_key_id_hash_total\{[^}]*transformation_type="from_storage"\} 2/, text)
    assert_match(/apiserver_envelope_encryption_key_id_hash_status_last_timestamp_seconds\{/, text)
  end
end
