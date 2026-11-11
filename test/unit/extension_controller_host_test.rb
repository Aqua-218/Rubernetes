# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/extension"
require "rubernetes/extension/controller_host"

# A controller block of an Extension object is called with what it watches,
# by the controller manager that is the leader, and can act on the cluster
# through the handle it is given.
class ExtensionControllerHostTest < Minitest::Test
  E = Rubernetes::Extension
  Response = Struct.new(:body)

  # An API with one collection per path, and watches that deliver whatever a
  # test pushes.
  class FakeClient
    attr_reader :requests, :applied

    def initialize
      @collections = Hash.new { |hash, path| hash[path] = [] }
      @watches = Hash.new { |hash, path| hash[path] = Queue.new }
      @requests = []
      @applied = []
    end

    def seed(path, kind, *objects)
      @collections[path] = objects
      @kinds = (@kinds || {}).merge(path => kind)
    end

    def push(path, type, object) = @watches[path] << {"type" => type, "object" => object}

    def raw(method, path, body: nil, headers: {}, query: nil)
      @requests << [method, path, body && JSON.parse(body), query]
      return Response.new(JSON.generate({"preferredVersion" => {"groupVersion" => "apps/v1"}})) if path == "/apis/apps"
      raise not_found(path) if method != "GET" && path.end_with?("/missing")
      return Response.new("{}") unless method == "GET"

      item = @collections.each_value.flat_map(&:itself).find { |object| path.end_with?("/#{object.dig("metadata", "name")}") }
      return Response.new(JSON.generate(item)) if item
      raise not_found(path) unless @collections.key?(path)

      Response.new(JSON.generate({"apiVersion" => "v1", "kind" => "#{@kinds.fetch(path)}List", "metadata" => {"resourceVersion" => "7"},
                                  "items" => @collections.fetch(path)}))
    end

    def watch_each(path, query:, reconnect:)
      loop { yield(@watches[path].pop) }
    end

    def apply(manifest, field_manager:, force:)
      @applied << [manifest, field_manager, force]
      manifest
    end

    def not_found(path)
      Rubernetes::Client::APIError.new("#{path} not found", response: Struct.new(:status).new(404))
    end
  end

  CONFIGMAPS = "/api/v1/configmaps"

  def configmap(name, version = "1")
    {"metadata" => {"name" => name, "namespace" => "shop", "resourceVersion" => version}, "data" => {}}
  end

  def setup
    @client = FakeClient.new
    @client.seed(CONFIGMAPS, "ConfigMap", configmap("site"))
    @seen = Queue.new
    @hook_failures = Queue.new
    @leader = true
    @host = E::ControllerHost.new(client: @client, leader: -> { @leader }, on_failure: ->(*failure) { @hook_failures << failure })
  end

  def teardown
    @host.stop
  end

  # The blocks under test report through this queue.
  def extension(source, generation: 1)
    seen = @seen
    definition = E::Definition.new("demo")
    definition.define_singleton_method(:seen) { seen }
    definition.instance_eval(source)
    definition.compiled(generation)
  end

  def next_delivery = @seen.pop(timeout: 5) || flunk("the controller block was not called")

  def test_a_block_sees_what_exists_and_then_every_change
    @host.replace([extension(<<~RUBY)])
      controller "c", watch: "configmaps" do |object, _api, event|
        seen << [object.dig("metadata", "resourceVersion"), event, object["kind"]]
      end
    RUBY

    assert_equal ["1", :added, "ConfigMap"], next_delivery

    @client.push(CONFIGMAPS, "MODIFIED", configmap("site", "2"))

    assert_equal ["2", :modified, nil], next_delivery

    @client.push(CONFIGMAPS, "DELETED", configmap("site", "3"))

    assert_equal ["3", :deleted, nil], next_delivery
  end

  def test_a_block_with_two_parameters_is_not_called_for_deletions
    @host.replace([extension('controller("c", watch: "configmaps") { |object, _api| seen << object.dig("metadata", "resourceVersion") }')])
    next_delivery
    @client.push(CONFIGMAPS, "DELETED", configmap("site", "3"))
    @client.push(CONFIGMAPS, "MODIFIED", configmap("other", "4"))

    assert_equal "4", next_delivery
  end

  def test_a_block_that_raises_is_reported_and_tried_again
    @host.replace([extension(<<~RUBY)])
      attempts = 0
      controller "c", watch: "configmaps" do |object, _api|
        attempts += 1
        raise "not yet" if attempts == 1

        seen << attempts
      end
    RUBY

    extension, hook, error = @hook_failures.pop(timeout: 5)

    assert_equal ["demo", "controller:c", "not yet"], [extension, hook, error.message]
    assert_equal 2, next_delivery
  end

  def test_nothing_is_delivered_while_another_controller_manager_leads
    @leader = false
    @host.replace([extension('controller("c", watch: "configmaps") { |object, _api| seen << object.dig("metadata", "name") }')])

    assert_nil @seen.pop(timeout: 0.3)

    @leader = true

    assert_equal "site", next_delivery
  end

  def test_a_changed_extension_replaces_its_controllers_and_a_removed_one_stops_them
    @host.replace([extension('controller("c", watch: "configmaps") { |_object, _api| seen << :old }')])

    assert_equal :old, next_delivery

    @host.replace([extension('controller("c", watch: "configmaps") { |_object, _api| seen << :new }', generation: 2)])

    assert_equal :new, next_delivery

    @host.replace([])
    @client.push(CONFIGMAPS, "MODIFIED", configmap("site", "9"))

    assert_nil @seen.pop(timeout: 0.3)
  end

  def test_the_handle_reads_writes_and_tolerates_what_is_not_there
    @client.seed("/apis/apps/v1/namespaces/shop/deployments", "Deployment", {"metadata" => {"name" => "web", "namespace" => "shop"}})
    api = E::API.new(client: @client, resources: E::Resources.new(@client), extension: "demo")

    assert_equal "web", api.get("deployments.apps", "web", namespace: "shop").dig("metadata", "name")
    assert_nil api.get("deployments.apps", "gone", namespace: "shop")
    assert_equal(%w[web], api.list("deployments.apps", namespace: "shop").map { |item| item.dig("metadata", "name") })
    refute api.delete("configmaps", "missing", namespace: "shop")
    assert api.delete("configmaps", "site", namespace: "shop")

    api.patch("deployments.apps", "web", {"spec" => {"replicas" => 3}}, namespace: "shop", subresource: "scale")

    assert_equal ["PATCH", "/apis/apps/v1/namespaces/shop/deployments/web/scale", {"spec" => {"replicas" => 3}}, nil], @client.requests.last

    api.apply({"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "made"}})

    assert_equal ["extension-demo", true], @client.applied.last.last(2)
    assert_equal 1, @client.requests.count { |_method, path| path == "/apis/apps" }, "a group's version is asked for once"
  end
end
