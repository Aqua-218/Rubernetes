# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

class ReplicationControllerDeleteRaceTest < Minitest::Test
  API = Rubernetes::API
  ROOT = "/api/v1/namespaces/default/replicationcontrollers"
  MEMBER = "#{ROOT}/simpletest.rc".freeze

  class ContendedStore < API::MemoryStore
    attr_accessor :before_mark, :finish_between_remove_and_retry
    attr_reader :competing_removal

    def update(key = nil, object = nil, **options)
      if @before_mark && owner?(options) && object&.dig("metadata", "deletionTimestamp")
        callback = @before_mark
        @before_mark = nil
        callback.call(get(key))
      end
      super
    end

    def delete(key = nil, **options)
      return super unless @finish_between_remove_and_retry && owner?(options)

      @finish_between_remove_and_retry = false
      marked = get(key)
      raise "DELETE did not persist the marker" unless marked.dig("metadata", "deletionTimestamp")

      updated = update(key, marked.merge("status" => {"replicas" => 1}), resource_version: marked.dig("metadata", "resourceVersion"))
      begin
        super
      rescue API::MemoryStore::Conflict
        # The RC's status write has advanced the revision and completes the
        # removal before the incoming UID-only DELETE reads a second time.
        competing_options = options.merge(resource_version: updated.dig("metadata", "resourceVersion"))
        @competing_removal = super(key, **competing_options)
        raise
      end
    end

    private

    def owner?(options) = options[:name] == "simpletest.rc"
  end

  def setup
    @store = ContendedStore.new
    registry = API::Registry.new
    registry.register(API::Resource.new(group: "", version: "v1", resource: "replicationcontrollers",
                                        kind: "ReplicationController", scope: :namespace))
    @server = API::Server.new(registry: registry, store: @store)
    @owner = create_controller
  end

  def test_status_removal_after_a_final_cas_conflict_is_a_successful_uid_delete
    @store.finish_between_remove_and_retry = true
    response = delete_controller("uid" => @owner.dig("metadata", "uid"))

    assert_equal @owner.dig("metadata", "uid"), @store.competing_removal.dig("metadata", "uid")
    assert_equal 200, response.status, response.body.inspect
    assert_equal 404, call("GET", MEMBER).status
  end

  def test_explicit_resource_version_cannot_be_rebased_before_the_mark
    @store.before_mark = lambda do |owner|
      @store.update("registry/v1/replicationcontrollers/default/simpletest.rc", owner.merge("status" => {"replicas" => 1}),
                    resource_version: owner.dig("metadata", "resourceVersion"))
    end
    metadata = @owner.fetch("metadata")
    response = delete_controller(metadata.slice("uid", "resourceVersion"))
    current = call("GET", MEMBER)

    assert_equal 409, response.status, response.body.inspect
    assert_equal 200, current.status
    assert_nil current.body.dig("metadata", "deletionTimestamp")
  end

  def test_uid_retry_never_marks_a_replacement_with_the_same_name
    replacement = nil
    @store.before_mark = lambda do |owner|
      @store.delete("registry/v1/replicationcontrollers/default/simpletest.rc", resource_version: owner.dig("metadata", "resourceVersion"))
      replacement = create_controller
    end
    response = delete_controller("uid" => @owner.dig("metadata", "uid"))
    current = call("GET", MEMBER)

    assert_equal 409, response.status, response.body.inspect
    assert_equal 200, current.status
    assert_equal replacement.dig("metadata", "uid"), current.body.dig("metadata", "uid")
    assert_nil current.body.dig("metadata", "deletionTimestamp")
  end

  private

  def call(method, path, body = nil)
    @server.call(method: method, path: path, body: body)
  end

  def create_controller
    response = call("POST", ROOT, {"apiVersion" => "v1", "kind" => "ReplicationController",
                                   "metadata" => {"name" => "simpletest.rc"}, "spec" => {"replicas" => 2}})
    raise response.body.inspect unless response.status == 201

    response.body
  end

  def delete_controller(preconditions)
    call("DELETE", MEMBER, {"apiVersion" => "v1", "kind" => "DeleteOptions",
                            "propagationPolicy" => "Background", "preconditions" => preconditions})
  end
end
