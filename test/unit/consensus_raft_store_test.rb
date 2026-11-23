# frozen_string_literal: true

require "tmpdir"
require "timeout"
require_relative "../test_helper"
require "rubernetes/consensus"

# In-process three-node cluster over the real TLS transport and WAL.
class ConsensusRaftStoreTest < Minitest::Test
  C = Rubernetes::Consensus

  module LegacyTLS
    private

    def build_server_context
      super.tap { |context| context.alpn_select_cb = nil }
    end

    def build_client_context
      super.tap { |context| context.alpn_protocols = [] }
    end
  end

  def setup
    @root = Dir.mktmpdir("raft-store-test")
    @ca, @ca_key = C::Identity.generate_ca("t")
    @ids = %w[a b c]
    @servers = @ids.to_h { |id| [id, build_server(id)] }
    @servers.each_value(&:start)
    connect_all
    wait_for_leader
  end

  def teardown
    @servers.each_value do |server|
      server.stop
    rescue StandardError
      nil
    end
    FileUtils.rm_rf(@root)
  end

  def build_server(id)
    bundle = C::Identity.issue_node(@ca, @ca_key, cluster_id: "t", node_id: id)
    # Real TLS and WAL can stall under CI load. Use the timing an API server
    # uses for those operations, with the shorter timing reserved for simulation.
    C::Server.new(id: id, cluster_id: "t", data_directory: File.join(@root, id), bundle: bundle, initial_voters: @ids,
                  timing: C::Node::Timing.production)
  end

  def connect_all
    @servers.each_value { |server| @servers.each { |peer_id, peer| server.add_peer(peer_id, peer.address) unless peer.equal?(server) } }
  end

  def wait_for_leader(timeout: 10)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until @servers.values.any?(&:leader?)
      raise "no leader" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.02
    end
  end

  def follower
    @servers.values.reject(&:leader?).first
  end

  def test_crud_is_replicated_and_linearizable_through_followers
    store = C::RaftStore.new(follower)
    created = store.create("pods/a", {"metadata" => {"name" => "a"}, "spec" => {"v" => 1}}, request_uid: "c1")

    assert_equal "1", created.dig("metadata", "resourceVersion")
    updated = store.guaranteed_update("pods/a", prec: "1") do |current|
      current["spec"] = {"v" => 2}
      current
    end

    assert_equal "2", updated.dig("metadata", "resourceVersion")
    assert_equal({"v" => 2}, store.get("pods/a")["spec"])
    assert_raises(Rubernetes::Storage::Conflict) { store.update("pods/a", {"metadata" => {"name" => "a"}}, prec: "1") }
    assert_raises(Rubernetes::Storage::AlreadyExists) { store.create("pods/a", {"metadata" => {"name" => "a"}}) }
    assert_raises(Rubernetes::Storage::NotFound) { store.delete("pods/missing") }
    deleted = store.delete("pods/a", prec: "2")

    assert_equal "3", deleted.dig("metadata", "resourceVersion")
    # Every replica applied the same sequence.
    sleep 0.2

    assert_equal([3, 3, 3], @servers.values.map { |server| server.store.revision })
  end

  def test_guarded_writes_wait_for_legacy_peer_upgrade_without_changing_ordinary_traffic
    legacy_id = follower.id
    legacy = replace_server(legacy_id, legacy: true)
    leader = @servers.values.find(&:leader?)
    leader_store = C::RaftStore.new(leader)
    new_follower = @servers.values.find { |server| server != leader && server != legacy }
    follower_store = C::RaftStore.new(new_follower)
    object = {"metadata" => {"name" => "test"}}
    baseline = C::RaftStore.new(legacy).create("test/legacy", object)

    assert_equal baseline, leader_store.get("test/legacy")
    assert_raises(Rubernetes::Storage::Unavailable) { leader_store.create("test/blocked", object, related_versions: {"test/legacy" => nil}) }
    assert_raises(Rubernetes::Storage::Unavailable) { follower_store.create("test/blocked", object, related_versions: {"test/legacy" => nil}) }
    assert_equal 1, leader_store.revision

    upgraded = replace_server(legacy_id)
    Timeout.timeout(10) do
      sleep 0.01 until leader.transport.supports_related_versions?(leader.node.peers) && new_follower.transport.supports_related_versions?([leader.id])
    end

    assert_equal baseline, C::RaftStore.new(upgraded).get("test/legacy")
    assert_raises(Rubernetes::Storage::Conflict) { follower_store.create("test/blocked", object, related_versions: {"test/legacy" => nil}) }
    applied = follower_store.create("test/accepted", object, related_versions: {"test/legacy" => baseline.dig("metadata", "resourceVersion")})
    @servers.each_value do |server|
      assert_equal applied, C::RaftStore.new(server).get("test/accepted")
      assert_raises(Rubernetes::Storage::NotFound) { C::RaftStore.new(server).get("test/blocked") }
    end
  end

  def test_legacy_learner_catches_up_after_upgrading_before_replaying_guarded_entries
    leader = @servers.values.find(&:leader?)
    store = C::RaftStore.new(leader)
    object = {"metadata" => {"name" => "test"}}
    Timeout.timeout(10) { sleep 0.01 until leader.transport.supports_related_versions?(leader.node.peers) }
    applied = store.create("test/guarded", object, related_versions: {"test/dependency" => nil})

    old_learner = build_server("d")
    old_learner.transport.singleton_class.prepend(LegacyTLS)
    @servers["d"] = old_learner.start
    connect_all
    leader.propose_membership(@ids, learners: ["d"])
    ordinary = store.create("test/ordinary", object)

    assert_equal ordinary, store.get("test/ordinary")
    assert_raises(Rubernetes::Storage::Unavailable) { store.create("test/blocked", object, related_versions: {}) }

    upgraded = replace_server("d")
    restored = C::RaftStore.new(upgraded)

    assert_equal applied, restored.get("test/guarded")
    assert_equal ordinary, restored.get("test/ordinary")
  end

  def replace_server(id, legacy: false)
    @servers.fetch(id).stop
    replacement = build_server(id)
    replacement.transport.singleton_class.prepend(LegacyTLS) if legacy
    @servers[id] = replacement.start
    connect_all
    wait_for_leader
    replacement
  end

  def test_request_uid_replay_returns_the_stored_result_without_a_second_effect
    store = C::RaftStore.new(@servers.values.find(&:leader?))
    first = store.create("cm/x", {"metadata" => {"name" => "x"}}, request_uid: "same-uid")
    second = store.create("cm/x", {"metadata" => {"name" => "x"}}, request_uid: "same-uid")

    assert_equal first, second
    assert_equal 1, store.revision
    assert_raises(Rubernetes::Storage::RequestUIDConflict) { store.create("cm/y", {"metadata" => {"name" => "y"}}, request_uid: "same-uid") }
  end

  def test_watch_observes_replicated_mutations_on_a_follower
    leader_store = C::RaftStore.new(@servers.values.find(&:leader?))
    watcher = follower.store.watch("pods/", since: 0)
    leader_store.create("pods/w", {"metadata" => {"name" => "w"}})
    event = watcher.next(timeout: 5)

    assert_equal "ADDED", event.type.to_s.upcase
    assert_equal "w", event.object.dig("metadata", "name")
  ensure
    watcher&.close
  end

  def test_leader_loss_keeps_acknowledged_writes_and_resumes
    leader = @servers.values.find(&:leader?)
    store = C::RaftStore.new(leader)
    10.times { |index| store.create("pods/#{index}", {"metadata" => {"name" => index.to_s}}) }
    first_page = store.list("pods/", limit: 2)
    second_page = C::RaftStore.new(follower).list("pods/", limit: 2, continue: first_page.continue_token)

    assert_equal first_page.resource_version, second_page.resource_version
    assert_equal(%w[2 3], second_page.items.map { |item| item.dig("metadata", "name") })

    leader.stop
    survivor = @servers.values.reject { |server| server.equal?(leader) }.first
    survivor_store = C::RaftStore.new(survivor)
    survivor_store.create("pods/after", {"metadata" => {"name" => "after"}})

    assert_equal 11, survivor_store.list("pods/").items.length
    resumed = survivor_store.list("pods/", limit: 2, continue: second_page.continue_token)

    assert_equal first_page.resource_version, resumed.resource_version
    assert_equal(%w[4 5], resumed.items.map { |item| item.dig("metadata", "name") })

    # Restart the old leader from its WAL; it catches up.
    restarted = build_server(leader.id)
    @servers[leader.id] = restarted
    restarted.start
    connect_all
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
    sleep 0.05 while restarted.store.revision < 11 && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

    assert_equal 11, restarted.store.revision
  end

  def test_backup_and_restore_preserve_the_log_position
    store = C::RaftStore.new(@servers.values.find(&:leader?))
    5.times { |index| store.create("b/#{index}", {"metadata" => {"name" => index.to_s}}) }
    leader = @servers.values.find(&:leader?)
    sleep 0.2
    leader.stop
    backup = File.join(@root, "backup")
    manifest = C::Backup.create(leader.data_directory, backup)

    assert_operator manifest["last_index"], :>=, 5
    restored = File.join(@root, "restored")
    C::Backup.restore(backup, restored)
    storage = C::Storage.new(restored)

    assert_equal manifest["last_index"], storage.log.last_index
    storage.close
  end
end
