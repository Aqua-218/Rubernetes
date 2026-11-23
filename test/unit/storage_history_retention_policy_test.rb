# frozen_string_literal: true

require "stringio"
require "tempfile"
require "timeout"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/bootstrap"

class StorageHistoryRetentionPolicyTest < Minitest::Test
  Store = Rubernetes::Storage::MemoryStore
  Bootstrap = Rubernetes::Bootstrap
  Consensus = Rubernetes::Consensus
  GONE = Rubernetes::Storage::Gone

  def test_s4_uses_the_24_hour_window_and_retains_history_within_either_bound
    now = 100
    store = Store.new(history_revisions: 2, clock: -> { now })
    create(store, "a")
    now = 101
    create(store, "b")
    now = 102
    create(store, "c")
    now = 86_500

    assert_equal 0, store.compact!, "exactly 24 hours old remains in the time window"
    assert_equal 1, store.compact!(now: 86_501)
    assert_equal 1, store.compact!(now: 100_000), "the remaining two revisions stay within the count window"
    assert_equal [2, 3], replay_revisions(store, since: 1, count: 2)
  end

  def test_continuation_age_is_independent_from_exact_list_and_watch_history
    now = 100
    store = Store.new(history_revisions: 2, clock: -> { now })
    %w[a b c d].each { |name| create(store, name) }
    first = store.list("pods/", limit: 1)
    now = 399
    second = store.list("pods/", limit: 1, continue: first.continue_token)

    assert_equal first.resource_version, second.resource_version

    now = 400
    error = assert_raises(GONE) { store.list("pods/", limit: 1, continue: second.continue_token) }
    assert_equal "Expired", error.reason
    refute_includes error.details, "compactedRevision"
    assert_equal 0, store.compacted_revision
    snapshot = store.list("pods/", resource_version: first.resource_version, resource_version_match: "Exact")

    assert_equal %w[a b c d], names(snapshot)

    create(store, "e")

    assert_equal [5], replay_revisions(store, since: first.resource_version, count: 1)
    resumed = store.list("pods/", limit: 1, continue: error.details.fetch("continue"))

    assert_equal "5", resumed.resource_version
    assert_equal ["c"], names(resumed)
    last = store.list("pods/", continue: resumed.continue_token)

    assert_equal %w[d e], names(last)
    assert_equal resumed.resource_version, last.resource_version
  end

  def test_unsigned_deadline_changes_are_rejected_and_legacy_tokens_get_a_fresh_cursor
    support = Rubernetes::Storage::MemoryStoreSupport
    now = 100
    store = Store.new(clock: -> { now }, token_secret: "test-secret")
    %w[a b c].each { |name| create(store, name) }
    first = store.list("pods/", limit: 1)
    cursor = JSON.parse(support.base64_url_decode(first.continue_token))
    tampered = cursor.except("signature").merge("expires_at" => 10_000)
    tampered["signature"] = support.digest(tampered.merge("secret" => "test-secret"))
    assert_raises(Rubernetes::Storage::InvalidContinueToken) do
      store.list("pods/", limit: 1, continue: support.base64_url_encode(JSON.generate(tampered)))
    end

    legacy = cursor.except("expires_at", "signature", "signed_revision", "authenticator")
    legacy["signature"] = support.digest(legacy.merge("secret" => "test-secret"))
    old_token = support.base64_url_encode(JSON.generate(legacy))
    error = assert_raises(GONE) { store.list("pods/", limit: 1, continue: old_token) }
    resumed = store.list("pods/", limit: 1, continue: error.details.fetch("continue"))

    assert_equal ["b"], names(resumed)
  end

  def test_continue_tokens_during_a_raft_rolling_upgrade
    now = 100
    legacy = Store.new(clock: -> { now }, token_secret: nil, legacy_token_secret: "legacy")
    %w[a b c d].each { |name| create(legacy, name) }
    old_page = legacy.list("pods/", limit: 1)
    upgraded = Store.new(clock: -> { now }, token_secret: "cluster-key", legacy_token_secret: "legacy")
    upgraded.import_state(legacy.export_state)

    assert_equal ["b"], names(legacy.list("pods/", limit: 1, continue: old_page.continue_token))
    old_error = assert_raises(GONE) { upgraded.list("pods/", limit: 1, continue: old_page.continue_token) }
    modern_resume = old_error.details.fetch("continue")

    assert_equal ["b"], names(legacy.list("pods/", limit: 1, continue: modern_resume))
    assert_equal ["b"], names(upgraded.list("pods/", limit: 1, continue: modern_resume))

    new_page = upgraded.list("pods/", limit: 1)
    seen_by_legacy = legacy.list("pods/", limit: 1, continue: new_page.continue_token)

    assert_equal ["b"], names(seen_by_legacy)
    assert_equal new_page.resource_version, seen_by_legacy.resource_version

    # An old replica signs the new revision with the legacy digest when
    # recovering a modern token whose original snapshot was compacted.
    create(upgraded, "e")
    support = Rubernetes::Storage::MemoryStoreSupport
    replacement = JSON.parse(support.base64_url_decode(new_page.continue_token)).except("signature")
    replacement["revision"] = upgraded.revision
    replacement["signature"] = support.digest(replacement.merge("secret" => "legacy"))
    token = support.base64_url_encode(JSON.generate(replacement))
    error = assert_raises(GONE) { upgraded.list("pods/", limit: 1, continue: token) }
    assert_equal ["b"], names(upgraded.list("pods/", limit: 1, continue: error.details.fetch("continue")))
  end

  def test_expired_continue_can_resume_without_advancing_a_quiet_store
    now = 100
    store = Store.new(clock: -> { now })
    %w[a b].each { |name| create(store, name) }
    first = store.list("pods/", limit: 1)
    now = 400

    error = assert_raises(GONE) { store.list("pods/", limit: 1, continue: first.continue_token) }
    resumed = store.list("pods/", limit: 1, continue: error.details.fetch("continue"))

    assert_equal ["b"], names(resumed)
    assert_equal first.resource_version, resumed.resource_version
    assert_nil resumed.continue_token
  end

  def test_s4_stops_at_the_first_recent_timestamp_after_a_clock_rollback
    now = nil
    store = Store.new(history_retention_policy: "longer_window", history_revisions: 2, history_seconds: 50, clock: -> { now })
    [100, 80, 85, 110, 145].each_with_index do |time, i|
      now = time
      create(store, i.to_s)
    end

    assert_equal 0, store.compacted_revision
    assert_equal [2, 3, 4, 5], replay_revisions(store, since: 1, count: 4)
    assert_equal 0, store.compact!(now: 150)
    assert_equal 3, store.compact!(now: 151)
    assert_raises(GONE) { store.watch("pods/", since: 2) }
    assert_equal [4, 5], replay_revisions(store, since: 3, count: 2)
    snapshot = store.list("pods/", resource_version: "3", resource_version_match: "Exact")
    names = snapshot.items.map { |item| item.dig("metadata", "name") }

    assert_equal %w[0 1 2], names
  end

  def test_the_compatibility_cap_exposes_expired_revisions_after_a_clock_rollback
    now = nil
    store = Store.new(history_retention_policy: "compatibility", history_revisions: 4, history_seconds: 50, clock: -> { now })
    [100, 80, 85, 110, 145].each_with_index do |time, i|
      now = time
      create(store, i.to_s)
    end

    assert_equal 3, store.compacted_revision
    assert_equal 3, store.compact!
    assert_equal [4, 5], replay_revisions(store, since: 3, count: 2)
  end

  def test_s4_handles_zero_and_disabled_windows
    [
      [nil, nil, 0],
      [0, nil, 4],
      [2, nil, 2],
      [nil, 0, 3],
      [0, 0, 3],
      [nil, 10, 0]
    ].each do |revisions, seconds, boundary|
      now = 0
      store = Store.new(history_retention_policy: "longer_window", history_revisions: revisions,
                        history_seconds: seconds, clock: -> { now })

      assert_equal 0, store.compact!
      4.times do |i|
        now = i
        create(store, i.to_s)
      end

      assert_equal boundary, store.compacted_revision, "revisions=#{revisions.inspect} seconds=#{seconds.inspect}"
    end
  end

  def test_bootstrap_memory_applies_s4_and_still_honors_the_compatibility_settings
    datastore = {"type" => "memory", "compaction_interval_seconds" => "0"}
    compatibility = build_service(datastore.merge("history_retention_policy" => "compatibility"), limit: 2).store
    longer = build_service(datastore, limit: 2).store
    [compatibility, longer].each { |store| 3.times { |i| create(store, i.to_s) } }

    now = Time.now.to_f + 1

    assert_equal compatibility.revision, compatibility.compact!(now: now)
    assert_equal longer.revision - 2, longer.compacted_revision
    assert_equal longer.revision - 2, longer.compact!(now: now)
  end

  def test_bootstrap_null_windows_and_compatibility_defaults
    long = {"type" => "memory", "history_retention_policy" => "longer_window"}
    time_only = build_service(long.merge("compaction_interval_seconds" => "0"), limit: nil).store
    revision_only = build_service(long.merge("compaction_interval_seconds" => nil), limit: 2).store
    compatibility = build_service({"type" => "memory", "history_retention_policy" => "compatibility",
                                   "compaction_interval_seconds" => nil}, limit: 100).store
    [time_only, revision_only, compatibility].each { |store| create(store, "a") }
    now = Time.now.to_f + 1

    assert_equal time_only.revision, time_only.compact!(now: now)
    assert_equal revision_only.revision - 2, revision_only.compact!(now: now + 86_401)
    assert_equal 0, compatibility.compact!(now: now)
    assert_equal compatibility.revision, compatibility.compact!(now: now + 301)
  end

  def test_bootstrap_rejects_invalid_retention_settings
    error = assert_raises(Bootstrap::Config::Error) do
      load_config({"history_retention_policy" => "invalid"}, limit: 2)
    end

    assert_match(/datastore.history_retention_policy/, error.message)

    datastore = {"type" => "memory"}
    [-1, "never", Float::INFINITY, Float::NAN, false].each do |seconds|
      error = assert_raises(Bootstrap::Config::Error) do
        load_config(datastore.merge("compaction_interval_seconds" => seconds), limit: 2)
      end

      assert_match(/datastore.compaction_interval_seconds/, error.message)
    end
    error = assert_raises(Bootstrap::Config::Error) { load_config(datastore, limit: "2") }

    assert_match(/watch_history_limit/, error.message)
  end

  def test_bootstrap_raft_retains_s4_across_a_real_snapshot_restart
    now = 100
    Dir.mktmpdir("raft-retention") do |directory|
      ca, key = Consensus::Identity.generate_ca("retention")
      bundle = Consensus::Identity.issue_node(ca, key, cluster_id: "retention", node_id: "a")
      pki = Consensus::Identity.write_bundle(File.join(directory, "pki"), bundle)
      datastore = {
        "type" => "raft", "node_id" => "a", "cluster_id" => "retention", "voters" => ["a"],
        "data_dir" => File.join(directory, "data"), "pki_dir" => pki,
        "listen_address" => "127.0.0.1", "listen_port" => 0,
        "timing" => {"election_timeout_min" => 0.15, "election_timeout_max" => 0.3, "heartbeat_interval" => 0.05}
      }
      page = nil
      with_raft_server(datastore) do |server|
        store = Consensus::RaftStore.new(server, clock: -> { now })
        store.create("pods/a", object("a"), request_uid: "z-old")
        now = 110
        store.create("pods/b", object("b"), request_uid: "a-new")
        now = 90
        create(store, "c")
        page = store.list("pods/", limit: 1)

        assert_equal 0, store.compacted_revision
        refute_nil server.snapshot!
      end

      with_raft_server(datastore) do |server|
        store = Consensus::RaftStore.new(server, clock: -> { now })
        now = 389
        resumed = store.list("pods/", limit: 1, continue: page.continue_token)

        assert_equal ["b"], names(resumed)
        assert_equal page.resource_version, resumed.resource_version

        now = 390
        error = assert_raises(GONE) { store.list("pods/", limit: 1, continue: resumed.continue_token) }
        quiet = store.list("pods/", limit: 1, continue: error.details.fetch("continue"))

        assert_equal ["c"], names(quiet)
        assert_equal page.resource_version, quiet.resource_version

        now = 86_501
        create(store, "d")

        assert_equal 1, store.compacted_revision
        assert_equal [2, 3, 4], replay_revisions(store, since: 1, count: 3)
        assert_equal ["a-new"], server.store.export_state.fetch("requests").keys
      end
    end
  end

  private

  def create(store, name)
    store.create("pods/#{name}", object(name))
  end

  def names(page)
    page.items.map { |item| item.dig("metadata", "name") }
  end

  def object(name)
    {"metadata" => {"name" => name}}
  end

  def replay_revisions(store, since:, count:)
    watcher = store.watch("pods/", since: since)
    Array.new(count) { watcher.next(timeout: 0)&.revision }
  ensure
    watcher&.close
  end

  def build_service(datastore, limit:)
    config = load_config(datastore, limit: limit)
    logger = Bootstrap::StructuredLogger.new(process_name: "rubernetes-apiserver", io: StringIO.new, level: "fatal")
    Bootstrap::APIServerService.new(config: config.process, logger: logger)
  end

  def load_config(datastore, limit:)
    settings = {"watch_history_limit" => limit, "datastore" => datastore}
    processes = {"rubernetes-apiserver" => settings}
    Tempfile.create(["retention", ".yml"]) do |file|
      file.write(Psych.dump("processes" => processes))
      file.flush
      Bootstrap::Config.load(process_name: "rubernetes-apiserver", path: file.path)
    end
  end

  def with_raft_server(datastore)
    server = build_service(datastore, limit: 2).raft_server
    server.start
    Timeout.timeout(5) { sleep 0.01 until server.leader? }
    yield server
  ensure
    server&.stop
  end
end
