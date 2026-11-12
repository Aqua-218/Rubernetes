# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/consensus"
require "rubernetes/storage/memory_store"
require "rubernetes/cluster/cli"
require "stringio"

# Moving a cluster from the in-memory datastore to raft: what the memory
# store held is what the first raft node serves, at the same versions, and
# the node goes on from there.
class ConsensusSeedTest < Minitest::Test
  C = Rubernetes::Consensus

  def setup
    @root = Dir.mktmpdir("raft-seed-test")
    @memory = Rubernetes::Storage::MemoryStore.new
    @memory.create("registry/v1/configmaps/shop/a", object("a", "1"))
    @memory.create("registry/v1/configmaps/shop/b", object("b", "1"))
    @memory.update("registry/v1/configmaps/shop/a", object("a", "2"))
    @memory.delete("registry/v1/configmaps/shop/b")
  end

  def teardown
    @server&.stop
    FileUtils.rm_rf(@root)
  end

  def object(name, value)
    {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => name, "namespace" => "shop"}, "data" => {"k" => value}}
  end

  def start_seeded
    directory = File.join(@root, "control-0")
    C::Seed.write(data_directory: directory, state: @memory.export_state, voters: %w[control-0])
    ca, key = C::Identity.generate_ca("t")
    bundle = C::Identity.issue_node(ca, key, cluster_id: "t", node_id: "control-0")
    @server = C::Server.new(id: "control-0", cluster_id: "t", data_directory: directory, bundle: bundle, initial_voters: %w[control-0])
    @server.start
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
    sleep 0.02 until @server.leader? || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
    C::RaftStore.new(@server)
  end

  def test_the_first_raft_node_serves_what_the_memory_store_held
    before = @memory.get("registry/v1/configmaps/shop/a")
    store = start_seeded
    after = store.get("registry/v1/configmaps/shop/a")

    assert_equal before, after, "the same object at the same resourceVersion"
    assert_equal "2", after.dig("data", "k")
    assert_raises(Rubernetes::Storage::MemoryStore::NotFound) { store.get("registry/v1/configmaps/shop/b") }
    assert_equal @memory.list("registry/v1/configmaps").resource_version.to_s, store.list("registry/v1/configmaps").resource_version.to_s
  end

  def test_the_cluster_goes_on_from_the_revision_it_had
    last = Integer(@memory.list("registry").resource_version.to_s)
    store = start_seeded
    created = store.create("registry/v1/configmaps/shop/c", object("c", "1"))

    assert_operator Integer(created.dig("metadata", "resourceVersion")), :>, last
    assert_equal %w[a c], store.list("registry/v1/configmaps").items.map { |item| item.dig("metadata", "name") }.sort
  end

  def test_a_datastore_that_already_has_state_is_not_seeded_over
    directory = File.join(@root, "control-0")
    C::Seed.write(data_directory: directory, state: @memory.export_state, voters: %w[control-0])

    assert_raises(ArgumentError) { C::Seed.write(data_directory: directory, state: @memory.export_state, voters: %w[control-0]) }
  end

  # `rubectl cluster seed`: the state file an API server exported becomes the
  # data directory the raft-backed one starts on.
  def test_the_seed_command_turns_an_exported_state_file_into_a_data_directory
    state = File.join(@root, "state.json")
    File.write(state, JSON.generate(@memory.export_state))
    stdout = StringIO.new
    stderr = StringIO.new
    directory = File.join(@root, "seeded")
    status = Rubernetes::Cluster::CLI.run(["seed", "--state", state, "--data-dir", directory, "--voter", "control-0"], stdout: stdout, stderr: stderr)

    assert_equal 0, status, stderr.string
    assert_match(/holds revision #{@memory.export_state.fetch("revision")}/, stdout.string)
    assert_equal 1, Dir[File.join(directory, "snapshots", "*.rbsnap")].length
    assert_equal 1, Rubernetes::Cluster::CLI.run(["seed", "--state", state, "--data-dir", directory, "--voter", "control-0"], stdout: stdout, stderr: stderr)
    assert_match(/is not empty/, stderr.string)
    assert_equal 1, Rubernetes::Cluster::CLI.run(%w[seed --voter control-0], stdout: stdout, stderr: stderr)
    assert_match(/seed needs --state, --data-dir/, stderr.string)
  end
end
