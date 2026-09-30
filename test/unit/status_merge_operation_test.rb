# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

# The attach/detach controller owns one field of the Node status the kubelet
# writes (volumesAttached).  Its write has to name only that field: the
# production adapter's forced server-side apply of a whole status would take
# the kubelet's fields over, and the in-memory adapter's status update
# replaced the status outright.  status_merge is a JSON merge patch of the
# status subresource in both (upstream PatchNodeStatus).
class StatusMergeOperationTest < Minitest::Test
  Controller = Rubernetes::Controller
  NODE = Controller::ResourceDescriptor.parse("Node")

  def node(status)
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "n1", "uid" => "nu"}, "status" => status}
  end

  def operation(patch) = Controller::Operation.new(action: :status_merge, resource: NODE, object: node({}), patch: patch)

  def test_the_in_memory_adapter_merges_the_named_fields
    adapter = Controller::StoreAdapter.new(Rubernetes::Storage::MemoryStore.new)
    adapter.create(node({"conditions" => [{"type" => "Ready", "status" => "True"}], "volumesInUse" => ["v"]}), descriptor: NODE)

    adapter.apply(operation({"volumesAttached" => [{"name" => "v", "devicePath" => ""}]}))
    status = adapter.find(NODE, name: "n1")["status"]

    assert_equal [{"type" => "Ready", "status" => "True"}], status["conditions"], "the kubelet's fields stay"
    assert_equal [{"name" => "v", "devicePath" => ""}], status["volumesAttached"]

    adapter.apply(operation({"volumesAttached" => nil}))

    refute adapter.find(NODE, name: "n1")["status"].key?("volumesAttached"), "nil removes the field"
  end

  class FakeClient
    attr_reader :patches

    def initialize = @patches = []

    def patch(resource, body, **options)
      @patches << [resource, body, options]
      {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "n1", "uid" => "nu", "resourceVersion" => "9"}}.merge(body)
    end

    def get(*, **) = nil
  end

  class Cache
    def initialize(objects) = @objects = objects
    def list = @objects
    def get(name, namespace: nil) = @objects.find { |object| object.dig("metadata", "name") == name }
    def apply_event(*) = nil
  end

  def test_the_production_adapter_sends_a_merge_patch_to_status_and_skips_a_no_op
    client = FakeClient.new
    adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(client: client, resource_descriptors: [NODE])
    adapter.caches = {NODE.identifier => Cache.new([node({"volumesAttached" => [{"name" => "v", "devicePath" => ""}]})])}

    adapter.apply(operation({"volumesAttached" => [{"name" => "v", "devicePath" => ""}]}))

    assert_empty client.patches, "already so: no request"

    adapter.apply(operation({"volumesAttached" => nil}))
    resource, body, options = client.patches.fetch(0)

    assert_equal "nodes", resource
    assert_equal({"status" => {"volumesAttached" => nil}}, body)
    assert_equal({type: :merge, name: "n1", subresource: "status"}, options.slice(:type, :name, :subresource))
  end
end
