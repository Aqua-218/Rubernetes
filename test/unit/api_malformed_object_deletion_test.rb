# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/security/encryption"
require "rubernetes/storage/memory_store"

class APIMalformedObjectDeletionTest < Minitest::Test
  Encryption = Rubernetes::Security::Encryption
  Authorization = Rubernetes::Security::Authorization
  PATH = "/api/v1/namespaces/default/secrets"
  KEY = "registry/v1/secrets/default/"
  OPTION = "ignoreStoreReadErrorWithClusterBreakingPotential"
  UNSAFE_VERB = "unsafe-delete-ignore-read-errors"

  def setup
    @raw = Rubernetes::Storage::MemoryStore.new
    provider = Encryption::AESGCMProvider.new(keys: [{"name" => "test", "secret" => Base64.strict_encode64("a" * 32)}])
    @transformer = Encryption::Transformer.new(providers: [provider])
    @permissions = %w[get list create delete deletecollection]
    permissions = @permissions
    @authorizer = Object.new
    @authorizer.define_singleton_method(:authorize) do |attributes|
      permissions.include?(attributes.verb) ? Authorization::Decision.allow : Authorization::Decision.deny
    end
  end

  def test_separate_authorization_and_corruption_are_both_required
    server, store = build_server
    create_secret(store, "corrupt")
    corrupt("corrupt")
    create_secret(store, "readable")

    get = call_api(server, "GET", "#{PATH}/corrupt")

    assert_equal 500, get.status
    assert_equal "InternalError", get.body["reason"]
    assert_equal 500, call_api(server, "DELETE", "#{PATH}/corrupt").status
    refused = call_api(server, "DELETE", "#{PATH}/corrupt", {OPTION => true})

    assert_equal 403, refused.status
    assert_includes refused.body["message"], UNSAFE_VERB
    assert @raw.get("#{KEY}corrupt")

    @permissions << UNSAFE_VERB
    @permissions.delete("delete")

    assert_equal 403, call_api(server, "DELETE", "#{PATH}/corrupt", {OPTION => true}).status
    @permissions << "delete"

    assert_equal 422, call_api(server, "DELETE", "#{PATH}/readable", {OPTION => true}).status
    assert_equal 422, call_api(server, "DELETE", "#{PATH}/missing", {OPTION => true}).status
    assert_equal 422, call_api(server, "DELETE", PATH, {OPTION => true}).status
    %w[dryRun propagationPolicy orphanDependents gracePeriodSeconds preconditions].zip([["All"], "Foreground", false, 0, {}]).each do |key, value|
      invalid = call_api(server, "DELETE", "#{PATH}/corrupt", {OPTION => true, key => value})

      assert_equal 422, invalid.status
      assert_includes invalid.body.dig("details", "causes", 0, "message"), key
    end
    assert_equal 400, call_api(server, "DELETE", "#{PATH}/readable", {OPTION => "true"}).status
    assert_equal 200, call_api(server, "GET", "#{PATH}/readable").status
    assert_equal 200, call_api(server, "DELETE", "#{PATH}/corrupt?#{OPTION}=true").status
    assert_equal 404, call_api(server, "GET", "#{PATH}/corrupt").status
    assert_equal 200, call_api(server, "GET", "#{PATH}/readable").status
  end

  def test_pod_eviction_rejects_the_option_even_with_the_gate_disabled
    server, _store = build_server(enabled: false)
    eviction = {"kind" => "Eviction", "metadata" => {"name" => "pod"}, "deleteOptions" => {OPTION => true}}
    result = call_api(server, "POST", "/api/v1/namespaces/default/pods/pod/eviction", eviction)

    assert_equal 422, result.status
    assert_equal "deleteOptions.#{OPTION}", result.body.dig("details", "causes", 0, "field")
  end

  def test_list_aggregates_corrupt_objects_only_while_the_gate_is_enabled
    server, store = build_server
    %w[first second].each do |name|
      create_secret(store, name)
      corrupt(name)
    end
    result = call_api(server, "GET", PATH)

    assert_equal "StoreReadError", result.body["reason"]
    assert_equal(["#{KEY}first", "#{KEY}second"], result.body.dig("details", "causes").map { |cause| cause["field"] })

    disabled, _store = build_server(enabled: false)
    @permissions << UNSAFE_VERB

    assert_equal "InternalError", call_api(disabled, "GET", PATH).body["reason"]
    assert_equal 500, call_api(disabled, "DELETE", "#{PATH}/first", {OPTION => true}).status
    assert @raw.get("#{KEY}first")
  end

  def test_a_concurrent_repair_is_not_deleted
    server, store = build_server
    create_secret(store, "repaired")
    healthy = @raw.get("#{KEY}repaired")
    corrupt("repaired")
    @permissions << UNSAFE_VERB
    original_delete = @raw.method(:delete)
    @raw.define_singleton_method(:delete) do |key, **options|
      guaranteed_update(key) { healthy }
      original_delete.call(key, **options)
    end

    result = call_api(server, "DELETE", "#{PATH}/repaired", {OPTION => true})

    assert_equal 409, result.status
    assert_equal 200, call_api(server, "GET", "#{PATH}/repaired").status
  end

  def test_storage_decode_metrics_count_invalid_plaintext_but_not_failed_decryption
    server, store = build_server
    create_secret(store, "bad-ciphertext")
    corrupt("bad-ciphertext")
    create_secret(store, "bad-document")
    key = "#{KEY}bad-document"
    @raw.guaranteed_update(key) { |stored| stored.merge("__encrypted__" => @transformer.encrypt("{", key)) }

    assert_equal 500, call_api(server, "GET", "#{PATH}/bad-ciphertext").status
    refute_match(/^apiserver_storage_decode_errors_total\{/, server.metrics.render_own)
    assert_equal 500, call_api(server, "GET", "#{PATH}/bad-document").status
    assert_match(/^apiserver_storage_decode_errors_total\{group="",resource="secrets"\} 1$/, server.metrics.render_own)
    assert_equal "StoreReadError", call_api(server, "GET", PATH).body["reason"]
    assert_match(/^apiserver_storage_decode_errors_total\{group="",resource="secrets"\} 2$/, server.metrics.render_own)
  end

  private

  def build_server(enabled: true)
    store = Encryption::EncryptedStore.new(@raw, transformer: @transformer, resources: ["secrets"], corrupt_deletion: enabled)
    security = Rubernetes::Security::Pipeline.new(authorizer: @authorizer)
    registry = Rubernetes::API::Registry.new
    registry.unregister(group: "", version: "v1", resource: "pods")
    registry.register(Rubernetes::API::Resource.new(resource: "pods", kind: "Pod", scope: :namespaced,
                                                    subresources: {"eviction" => {kind: "Eviction", verbs: ["create"]}}))
    server = Rubernetes::API::Server.new(store: store, security: security, registry: registry,
                                         feature_gates: {"AllowUnsafeMalformedObjectDeletion" => enabled})
    [server, store]
  end

  def call_api(server, method, path, body = nil)
    server.call(method: method, path: path, body: body, identity: {"username" => "test", "groups" => ["system:authenticated"]})
  end

  def create_secret(store, name)
    store.create("#{KEY}#{name}", {"apiVersion" => "v1", "kind" => "Secret",
                                   "metadata" => {"name" => name, "namespace" => "default", "finalizers" => ["test/finalizer"]},
                                   "data" => {"secret" => "aGk="}})
  end

  def corrupt(name)
    @raw.guaranteed_update("#{KEY}#{name}") do |stored|
      envelope = stored.fetch("__encrypted__")
      prefix, _, payload = envelope.rpartition(":")
      bytes = Base64.strict_decode64(payload)
      bytes.setbyte(-1, bytes.getbyte(-1) ^ 1)
      stored.merge("__encrypted__" => "#{prefix}:#{Base64.strict_encode64(bytes)}")
    end
  end
end
