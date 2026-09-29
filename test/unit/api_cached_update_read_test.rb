# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/consensus"
require "rubernetes/api"

# kube-apiserver's GuaranteedUpdate starts from its watch cache's copy
# (cachedExistingObject) and relies on etcd's compare-and-swap.  Our
# conditional PUT paid a linearizable ReadIndex round trip first -- 1.5 ms of
# each of the 499 updates of "[sig-node] Pods Extended ... 500 podspec
# updates".  An update naming the resourceVersion it read now starts from the
# replica's copy; the proposal carries that version, so a stale copy still
# ends in a 409 and never in a lost update.
class APICachedUpdateReadTest < Minitest::Test
  class CountingServer
    attr_reader :read_indexes, :store

    def initialize
      @read_indexes = 0
      @store = Rubernetes::Storage::MemoryStore.new
    end

    def read_index(**_options) = (@read_indexes += 1) && 1
    def local_store = @store
    def state_machine = nil
  end

  def setup
    @server = CountingServer.new
    @machine = Rubernetes::Consensus::KVStateMachine.new(store: @server.store)
    @index = 0
    @raft = Rubernetes::Consensus::RaftStore.new(@server)
    server = @server
    machine = @machine
    counter = -> { @index += 1 }
    @raft.define_singleton_method(:local_store) { server.local_store }
    @raft.define_singleton_method(:submit) do |command, effect:, key:|
      Thread.current[Rubernetes::Consensus::RaftStore::BARRIER_SCOPE_KEY]&.store(:taken, false)
      result = machine.apply(counter.call, command)
      raise Rubernetes::Storage::Conflict.new(key, result.inspect, resource_version: result.dig("error", "resource_version")) unless result["ok"]

      result["object"]
    end
    @api = Rubernetes::API::Server.new(store: @raft)
    call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "dev"}})
    @created = body(call("POST", "/api/v1/namespaces/dev/configmaps",
                         {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "a"}, "data" => {"n" => "0"}}))
  end

  def call(method, path, payload = nil) = @api.call(method: method, path: path, body: payload)
  def body(response) = response.body.is_a?(String) ? JSON.parse(response.body) : JSON.parse(JSON.generate(response.body))

  def put(object) = call("PUT", "/api/v1/namespaces/dev/configmaps/a", object)

  def test_a_conditional_update_takes_no_read_barrier
    before = @server.read_indexes
    response = put(@created.merge("data" => {"n" => "1"}))
    assert_equal 200, response.status
    assert_equal before, @server.read_indexes
  end

  def test_an_unconditional_update_still_reads_through_the_barrier
    unconditional = @created.merge("data" => {"n" => "1"})
    unconditional["metadata"] = unconditional["metadata"].except("resourceVersion")
    before = @server.read_indexes
    assert_equal 200, put(unconditional).status
    assert_equal before + 1, @server.read_indexes
  end

  # The replica's copy is behind the version the client read elsewhere: it is
  # read again through the barrier and the update goes through.
  def test_a_copy_that_does_not_match_is_read_again_through_the_barrier
    newer = body(put(@created.merge("data" => {"n" => "1"})))
    stale = @server.store.get("registry/v1/configmaps/dev/a") rescue nil
    lagging = @raft.local_store
    real_get = lagging.method(:get)
    calls = 0
    lagging.define_singleton_method(:get) do |*arguments, **options|
      calls += 1
      calls == 1 ? @created_copy : real_get.call(*arguments, **options)
    end
    lagging.instance_variable_set(:@created_copy, @created)
    before = @server.read_indexes
    response = put(newer.merge("data" => {"n" => "2"}))

    assert_equal 200, response.status, response.body.inspect
    assert_equal before + 1, @server.read_indexes
    refute_nil stale
  end

  def test_a_stale_client_version_is_a_conflict_not_a_lost_update
    put(@created.merge("data" => {"n" => "1"}))
    response = put(@created.merge("data" => {"n" => "stale"}))

    assert_equal 409, response.status
    assert_equal "1", body(call("GET", "/api/v1/namespaces/dev/configmaps/a"))["data"]["n"]
  end
end
