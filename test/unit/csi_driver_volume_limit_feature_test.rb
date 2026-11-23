# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/bootstrap/api_server_service"

class CSIDriverVolumeLimitFeatureTest < Minitest::Test
  API = Rubernetes::API
  PATH = "/apis/storage.k8s.io/v1/csidrivers"
  FIELD = "preventPodSchedulingIfMissing"

  def setup
    @store = API::MemoryStore.new
    definition = Rubernetes::Generated::IoK8sApiStorageV1CSIDriver::DEFINITION
    schema = Rubernetes::Bootstrap::APIServerService::SchemaContract.new(definition)
    resource = API::Resource.new(group: "storage.k8s.io", version: "v1", kind: "CSIDriver", resource: "csidrivers", scope: :cluster, schema: schema)
    @registry = API::Registry.new(resources: [resource])
  end

  def test_gate_defaults_enabled_writes_and_reads_of_objects_created_before_upgrade
    off = server(false)
    old = create(off, "old.example")

    refute old.body.fetch("spec").key?(FIELD)

    on = server(true)

    assert_equal false, request(on, "GET", "#{PATH}/old.example").body.dig("spec", FIELD)
    listed = request(on, "GET", PATH)

    assert_equal false, listed.body.dig("items", 0, "spec", FIELD)
    watch = request(on, "GET", "#{PATH}?watch=true&resourceVersion=0").body

    assert_equal false, watch.next(timeout: 0).object.dig("spec", FIELD)

    assert_equal false, create(on, "new.example").body.dig("spec", FIELD)
    assert_equal true, create(on, "opted-in.example", FIELD => true).body.dig("spec", FIELD)
  ensure
    watch&.close
  end

  def test_disabled_strategy_drops_new_uses_but_preserves_existing_explicit_false
    on = server(true)
    existing = create(on, "prior.example", FIELD => false)
    off = server(false)
    dropped = create(off, "new.example", FIELD => true)

    refute dropped.body.fetch("spec").key?(FIELD)

    absent = request(off, "PATCH", "#{PATH}/new.example", body: {"spec" => {FIELD => true}})

    assert_equal 200, absent.status, absent.body.inspect
    refute absent.body.fetch("spec").key?(FIELD)
    changed = request(off, "PUT", "#{PATH}/prior.example", body: existing.body.merge("spec" => existing.body.fetch("spec").merge(FIELD => true)))

    assert_equal 200, changed.status, changed.body.inspect
    assert_equal true, changed.body.dig("spec", FIELD)
    assert_equal 1, changed.body.dig("metadata", "generation")
  end

  private

  def server(enabled)
    API::Server.new(registry: @registry, store: @store, feature_gates: {"VolumeLimitScaling" => enabled})
  end

  def create(api, name, spec = {})
    response = request(api, "POST", PATH, body: {"metadata" => {"name" => name}, "spec" => spec})

    assert_equal 201, response.status, response.body.inspect
    response
  end

  def request(api, method, path, body: nil)
    content_type = method == "PATCH" ? "application/merge-patch+json" : "application/json"
    api.call(API::Request.new(method: method, path: path, body: body, headers: {"content-type" => content_type}))
  end
end
