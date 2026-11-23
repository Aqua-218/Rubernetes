# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class PersistentVolumeClaimReferenceWireTest < Minitest::Test
  API = Rubernetes::API
  CLAIMS = "/api/v1/namespaces/default/persistentvolumeclaims"
  STORAGE = "registry/v1/persistentvolumeclaims/default/"
  SOURCE = {"kind" => "PersistentVolumeClaim", "name" => "parent"}.freeze
  REF_FIELDS = %w[dataSource dataSourceRef].freeze
  PROTOBUF = "application/vnd.kubernetes.protobuf"

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @backing = API::MemoryStore.new
    @server = API::Server.new(registry: registry, store: @backing)
  end

  def test_omitted_group_is_null_in_json_without_entering_storage
    expected = SOURCE.merge("apiGroup" => nil)
    created = request("POST", CLAIMS, claim("clone", SOURCE))

    assert_equal 201, created.status
    assert_references expected, created.body
    assert_references SOURCE, @backing.get("#{STORAGE}clone")

    fetched = request("GET", "#{CLAIMS}/clone")
    listed = request("GET", CLAIMS)
    watched = request("GET", "#{CLAIMS}?watch=true&resourceVersion=0&timeoutSeconds=1").body

    assert_references expected, fetched.body
    assert_references expected, listed.body.fetch("items").first
    assert_references expected, watched.next(timeout: 0.1).object

    changed = fetched.body.merge("metadata" => fetched.body.fetch("metadata").merge("labels" => {"update" => "put"}))
    updated = request("PUT", "#{CLAIMS}/clone", changed)
    patched = request("PATCH", "#{CLAIMS}/clone", {"metadata" => {"labels" => {"update" => "patch"}}},
                      content_type: "application/merge-patch+json")

    assert_equal 200, updated.status, updated.body.inspect
    assert_equal 200, patched.status, patched.body.inspect
    assert_references expected, updated.body
    assert_references expected, patched.body
    assert_references SOURCE, @backing.get("#{STORAGE}clone")
  ensure
    watched&.close
  end

  def test_protobuf_omits_nil_and_encodes_explicit_empty_and_named_groups
    snapshot = {"apiGroup" => "snapshot.storage.k8s.io", "kind" => "VolumeSnapshot", "name" => "parent"}
    [SOURCE.merge("apiGroup" => nil), SOURCE.merge("apiGroup" => ""), snapshot].each_with_index do |source, index|
      name = "clone-#{index}"
      created = request("POST", CLAIMS, claim(name, source))

      assert_equal 201, created.status, created.body.inspect
      assert_references source, created.body

      response = request("GET", "#{CLAIMS}/#{name}", accept: PROTOBUF)
      node = Rubernetes::Schema::Codec::KubernetesProtobuf.new.decode(response.body)
      reference = source["apiGroup"].nil? ? source.except("apiGroup") : source

      assert_equal PROTOBUF, response.content_type
      assert_references reference, node
    end
  end

  def test_watch_reads_both_reference_aliases_from_an_old_record
    old = claim("legacy", SOURCE)
    @backing.create("#{STORAGE}legacy", old.merge("spec" => old.fetch("spec").except("dataSourceRef").merge("dataSource" => SOURCE)))
    stream = request("GET", "#{CLAIMS}?watch=true&resourceVersion=0&timeoutSeconds=1").body

    assert_references SOURCE.merge("apiGroup" => nil), JSON.parse(stream.each_json_line.first).fetch("object")
    refute @backing.get("#{STORAGE}legacy").fetch("spec").key?("dataSourceRef")
  ensure
    stream&.close
  end

  def test_apply_only_owns_api_group_when_the_client_supplies_it
    [SOURCE, SOURCE.merge("apiGroup" => nil)].each_with_index do |source, index|
      name = "apply-#{index}"
      applied = request("PATCH", "#{CLAIMS}/#{name}?fieldManager=writer", claim(name, source), content_type: "application/apply-patch+yaml")

      assert_equal 201, applied.status, applied.body.inspect
      assert_references SOURCE.merge("apiGroup" => nil), applied.body
      managed = applied.body.dig("metadata", "managedFields").find { |entry| entry["manager"] == "writer" }

      assert_equal source.key?("apiGroup"), managed.dig("fieldsV1", "f:spec", "f:dataSourceRef").key?("f:apiGroup")
    end
  end

  private

  def assert_references(expected, object)
    REF_FIELDS.each { |field| assert_equal expected, object.dig("spec", field) }
  end

  def request(method, path, body = nil, content_type: "application/json", accept: "application/json")
    request = API::Request.new(method: method, path: path, body: body && JSON.generate(body),
                               headers: {"Content-Type" => content_type, "Accept" => accept},
                               identity: {"username" => "admin", "groups" => ["system:masters"]})
    @server.call(request)
  end

  def claim(name, source)
    {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim", "metadata" => {"name" => name},
     "spec" => {"accessModes" => ["ReadWriteOnce"], "resources" => {"requests" => {"storage" => "1Gi"}}, "dataSourceRef" => source}}
  end
end
