# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/consensus"
require "rubernetes/api"

# Every store read used to pay its own ReadIndex round trip; a Pod create's
# admission alone reads fourteen times.  Inside a request scope the first
# barrier is shared, and a write re-arms it.
class RaftStoreRequestBarrierTest < Minitest::Test
  class CountingServer
    attr_reader :read_indexes

    def initialize
      @read_indexes = 0
      @store = Rubernetes::Storage::MemoryStore.new
    end

    def read_index(**_options)
      @read_indexes += 1
      1
    end

    def local_store = @store
    def state_machine = nil
  end

  def store(server)
    store = Rubernetes::Consensus::RaftStore.new(server)
    store.define_singleton_method(:local_store) { server.local_store }
    store
  end

  def test_reads_inside_one_scope_share_a_single_barrier
    server = CountingServer.new
    raft = store(server)

    raft.with_read_barrier do
      3.times { raft.get("registry/v1/configmaps/dev/a") rescue nil }
      raft.list("registry/v1/configmaps/dev")
    end

    assert_equal 1, server.read_indexes
  end

  def test_reads_outside_a_scope_still_barrier_each_time
    server = CountingServer.new
    raft = store(server)

    2.times { raft.list("registry/v1/configmaps/dev") }

    assert_equal 2, server.read_indexes
  end

  def test_a_write_inside_the_scope_re_arms_the_barrier
    server = CountingServer.new
    raft = store(server)
    raft.define_singleton_method(:submit) do |command, effect:, key:|
      Thread.current[Rubernetes::Consensus::RaftStore::BARRIER_SCOPE_KEY]&.store(:taken, false)
      {}
    end

    raft.with_read_barrier do
      raft.list("registry/v1/configmaps/dev")
      raft.create("registry/v1/configmaps/dev/a", {"metadata" => {"name" => "a"}})
      raft.list("registry/v1/configmaps/dev")
    end

    assert_equal 2, server.read_indexes
  end

  class ScopedStore < Rubernetes::Storage::MemoryStore
    attr_reader :scopes

    def with_read_barrier
      @scopes = (@scopes || 0) + 1
      yield
    end
  end

  def test_the_api_server_runs_each_request_in_one_barrier_scope
    store = ScopedStore.new
    server = Rubernetes::API::Server.new(store: store)

    server.call(method: "POST", path: "/api/v1/namespaces/dev/configmaps", body: {"metadata" => {"name" => "a"}})
    server.call(method: "GET", path: "/api/v1/namespaces/dev/configmaps/a")

    assert_equal 2, store.scopes
  end
end
