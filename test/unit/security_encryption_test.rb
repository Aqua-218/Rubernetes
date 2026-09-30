# frozen_string_literal: true

require "base64"
require_relative "../test_helper"
require "rubernetes/security/encryption"

class SecurityEncryptionTest < Minitest::Test
  E = Rubernetes::Security::Encryption

  def key(name)
    {"name" => name, "secret" => Base64.strict_encode64(OpenSSL::Random.random_bytes(32))}
  end

  def test_aes_gcm_round_trip_tamper_and_key_binding
    provider = E::AESGCMProvider.new(keys: [key("k1")])
    envelope = provider.encrypt("secret-bytes", "registry/v1/secrets/ns/a")

    assert envelope.start_with?("k8s:enc:aesgcm:v1:k1:")
    assert_equal "secret-bytes", provider.decrypt(envelope, "registry/v1/secrets/ns/a")
    assert_raises(E::Error, "ciphertext is bound to its storage key") { provider.decrypt(envelope, "registry/v1/secrets/ns/b") }
    tampered = envelope[0...-4] + "AAAA"
    assert_raises(E::Error) { provider.decrypt(tampered, "registry/v1/secrets/ns/a") }
    assert_raises(E::Error) { E::AESGCMProvider.new(keys: [{"name" => "short", "secret" => Base64.strict_encode64("x" * 16)}]) }
    other = E::AESGCMProvider.new(keys: [key("k2")])
    assert_raises(E::Error) { other.decrypt(envelope, "registry/v1/secrets/ns/a") }
  end

  def test_encrypted_store_keeps_metadata_clear_and_never_stores_plaintext
    inner = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    transformer = E::Transformer.new(providers: [E::AESGCMProvider.new(keys: [key("k1")])])
    store = E::EncryptedStore.new(inner, transformer: transformer, resources: ["v1/secrets"])
    created = store.create("registry/v1/secrets/ns/db",
                           {"apiVersion" => "v1", "kind" => "Secret", "metadata" => {"name" => "db", "namespace" => "ns", "labels" => {"app" => "db"}},
                            "data" => {"password" => "cGFzcw=="}})

    assert_equal "cGFzcw==", created.dig("data", "password")
    raw = inner.get("registry/v1/secrets/ns/db")

    assert raw.key?("__encrypted__")
    refute raw.key?("data")
    assert_equal "db", raw.dig("metadata", "name")
    refute_includes inner.export_state.to_json, "cGFzcw=="
    assert_equal "cGFzcw==", store.get("registry/v1/secrets/ns/db").dig("data", "password")
    listed = store.list("registry/v1/secrets/ns", label_selector: "app=db")

    assert_equal "cGFzcw==", listed.items.first.dig("data", "password")
    updated = store.guaranteed_update("registry/v1/secrets/ns/db", prec: created.dig("metadata", "resourceVersion")) do |current|
      current["data"]["password"] = "bmV3"
      current
    end

    assert_equal "bmV3", updated.dig("data", "password")
    # A zero resourceVersion replays the CURRENT state, so this asserts the
    # decryption of the state dump; the second watcher asserts it for a
    # historical event replayed from an explicit revision.
    watcher = store.watch("registry/v1/secrets/ns", since: 0)
    event = watcher.next(timeout: 1)

    assert_equal "bmV3", event.object.dig("data", "password")
    watcher.close
    watcher = store.watch("registry/v1/secrets/ns", since: created.dig("metadata", "resourceVersion").to_i)
    replayed = watcher.next(timeout: 1)

    assert_equal "MODIFIED", replayed.type.to_s.upcase
    assert_equal "bmV3", replayed.object.dig("data", "password")
    watcher.close
    plain = store.create("registry/v1/configmaps/ns/cfg", {"metadata" => {"name" => "cfg"}, "data" => {"k" => "v"}})

    assert_equal "v", inner.get("registry/v1/configmaps/ns/cfg").dig("data", "k"), "unconfigured resources stay in the clear"
    assert_equal "v", plain.dig("data", "k")
  end

  def test_key_rotation_reads_old_writes_new_and_rewrites
    old_key = key("old")
    new_key = key("new")
    inner = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    first = E::EncryptedStore.new(inner, transformer: E::Transformer.new(providers: [E::AESGCMProvider.new(keys: [old_key])]),
                                         resources: ["v1/secrets"])
    first.create("registry/v1/secrets/ns/a", {"metadata" => {"name" => "a", "namespace" => "ns"}, "data" => {"x" => "1"}})
    rotated = E::EncryptedStore.new(inner, transformer: E::Transformer.new(providers: [E::AESGCMProvider.new(keys: [new_key, old_key])]),
                                           resources: ["v1/secrets"])

    assert_equal "1", rotated.get("registry/v1/secrets/ns/a").dig("data", "x"), "old key still reads"
    assert inner.get("registry/v1/secrets/ns/a")["__encrypted__"].start_with?("k8s:enc:aesgcm:v1:old:")
    assert_equal 1, rotated.rewrite_stale!("registry/v1/secrets")
    assert inner.get("registry/v1/secrets/ns/a")["__encrypted__"].start_with?("k8s:enc:aesgcm:v1:new:")
    retired = E::EncryptedStore.new(inner, transformer: E::Transformer.new(providers: [E::AESGCMProvider.new(keys: [new_key])]),
                                           resources: ["v1/secrets"])

    assert_equal "1", retired.get("registry/v1/secrets/ns/a").dig("data", "x")
  end

  def test_kms_v2_provider_wraps_per_object_deks
    fake = Object.new
    kek = OpenSSL::Random.random_bytes(32)
    fake.define_singleton_method(:status) { {"version" => "v2", "healthz" => "ok", "key_id" => "kid-1"} }
    fake.define_singleton_method(:encrypt) do |plaintext, uid:|
      cipher = OpenSSL::Cipher.new("aes-256-gcm").encrypt
      cipher.key = kek
      iv = OpenSSL::Random.random_bytes(12)
      cipher.iv = iv
      {"ciphertext" => iv + cipher.update(plaintext) + cipher.final + cipher.auth_tag, "key_id" => "kid-1",
       "annotations" => {"note.example.com" => Base64.strict_encode64("v")}}
    end
    fake.define_singleton_method(:decrypt) do |ciphertext, uid:, key_id:, annotations:|
      raise "unknown key" unless key_id == "kid-1"

      cipher = OpenSSL::Cipher.new("aes-256-gcm").decrypt
      cipher.key = kek
      cipher.iv = ciphertext.byteslice(0, 12)
      cipher.auth_tag = ciphertext.byteslice(-16, 16)
      cipher.update(ciphertext.byteslice(12, ciphertext.bytesize - 28)) + cipher.final
    end
    provider = E::KMSv2Provider.new(name: "kms", endpoint: "unix:///tmp/none.sock", client: fake)
    envelope = provider.encrypt("top-secret", "key-a")

    assert envelope.start_with?("k8s:enc:kms:v2:kms:")
    assert_equal "top-secret", provider.decrypt(envelope, "key-a")
    assert provider.current_key?(envelope)
    assert_raises(E::Error) { provider.decrypt(envelope, "key-b") }
  end
end
