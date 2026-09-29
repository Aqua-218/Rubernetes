# frozen_string_literal: true

# The storage-side apiserver series.  The local replica serves every LIST and
# watch, as kube-apiserver's watch cache does (cacher/metrics), and the raft
# read barrier is the wait for that cache to be fresh:
# apiserver_cache_list_*, apiserver_watch_cache_{events_received,
# events_dispatched,resource_version,consistent_read,read_wait_seconds},
# apiserver_init_events_total, apiserver_terminated_watchers_total,
# etcd_bookmark_total and apiserver_storage_size_bytes.

require_relative "../test_helper"
require "json"
require "tmpdir"
require "rubernetes/api"
require "rubernetes/consensus"

class APIServerWatchCacheMetricsTest < Minitest::Test
  ADMIN = {"username" => "admin", "groups" => ["system:masters"]}.freeze

  def server_with(store)
    server = Rubernetes::API::Server.new(store: store)
    call = lambda do |method, path, body = nil|
      server.call(Rubernetes::API::Request.new(method: method, path: path, headers: body ? {"content-type" => "application/json"} : {},
                                               body: body && JSON.generate(body), identity: ADMIN))
    end
    [server, call]
  end

  def configmap(name, labels = {})
    {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => name, "labels" => labels}}
  end

  def value(text, line)
    text[/^#{Regexp.escape(line)} (\S+)$/, 1]&.to_f
  end

  def test_lists_are_measured_as_watch_cache_lists_and_consistent_reads
    server, call = server_with(Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil))
    call.call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "team"}})
    3.times { |index| call.call("POST", "/api/v1/namespaces/team/configmaps", configmap("c#{index}", "keep" => (index.zero? ? "yes" : "no"))) }
    before = server.metrics.render
    base_lists = value(before, 'apiserver_cache_list_total{group="",index="",resource="configmaps"}').to_i
    base_fetched = value(before, 'apiserver_cache_list_fetched_objects_total{group="",index="",resource="configmaps"}').to_i
    base_returned = value(before, 'apiserver_cache_list_returned_objects_total{group="",resource="configmaps"}').to_i
    base_consistent = value(before, 'apiserver_watch_cache_consistent_read_total{fallback="false",group="",resource="configmaps",success="true"}').to_i

    call.call("GET", "/api/v1/namespaces/team/configmaps?labelSelector=keep%3Dyes")
    call.call("GET", "/api/v1/namespaces/team/configmaps?resourceVersion=0")
    text = server.metrics.render

    assert_equal base_lists + 2, value(text, 'apiserver_cache_list_total{group="",index="",resource="configmaps"}')
    # Both LISTs read every ConfigMap in the namespace; the selector kept one.
    assert_equal base_fetched + 6, value(text, 'apiserver_cache_list_fetched_objects_total{group="",index="",resource="configmaps"}')
    assert_equal base_returned + 4, value(text, 'apiserver_cache_list_returned_objects_total{group="",resource="configmaps"}')
    # Only the LIST without a resourceVersion is a consistent read.
    assert_equal base_consistent + 1,
                 value(text, 'apiserver_watch_cache_consistent_read_total{fallback="false",group="",resource="configmaps",success="true"}')
    assert_match(/^# TYPE apiserver_cache_list_total counter$/, text)
    assert_match(/^# HELP apiserver_cache_list_total \[ALPHA\] Number of LIST requests served from watch cache$/, text)
  end

  def test_group_resource_labels_come_from_the_storage_key
    store = Rubernetes::Storage::MemoryStore
    assert_equal ["", "pods"], store.group_resource("registry/v1/pods/ns/p")
    assert_equal ["apps", "deployments"], store.group_resource("registry/apps/v1/deployments/ns/d")
    assert_equal ["stable.example.com", "crontabs"], store.group_resource("registry/stable.example.com/__stored__/crontabs")
    assert_equal ["", "namespaces"], store.group_resource("registry/v1/namespaces")
  end

  def test_committed_events_and_watch_init_events_are_counted_once_per_event
    metrics = Rubernetes::Observability::Metrics.new
    store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    store.metrics = metrics
    store.create("registry/apps/v1/deployments/ns/a", {"metadata" => {"name" => "a"}})
    store.create("registry/apps/v1/deployments/ns/b", {"metadata" => {"name" => "b"}})
    watchers = Array.new(3) { store.watch("registry/apps/v1/deployments") }
    store.create("registry/apps/v1/deployments/ns/c", {"metadata" => {"name" => "c"}})
    text = metrics.render
    labels = '{group="apps",resource="deployments"}'
    assert_equal 3, value(text, "apiserver_watch_cache_events_received_total#{labels}")
    # Three watchers, one dispatch per event.
    assert_equal 3, value(text, "apiserver_watch_cache_events_dispatched_total#{labels}")
    assert_equal store.revision, value(text, "apiserver_watch_cache_resource_version#{labels}")
    # Each watcher started with the two existing objects.
    assert_equal 6, value(text, "apiserver_init_events_total#{labels}")
    assert_match(/^# TYPE apiserver_watch_cache_resource_version gauge$/, text)
  ensure
    watchers&.each(&:close)
  end

  def test_a_watcher_that_cannot_keep_up_is_terminated_and_counted
    metrics = Rubernetes::Observability::Metrics.new
    store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil, watcher_buffer_size: 2)
    store.metrics = metrics
    slow = store.watch("registry/v1/configmaps", resource_version: store.revision.to_s)
    fast = store.watch("registry/v1/configmaps", resource_version: store.revision.to_s)
    2.times { |index| store.create("registry/v1/configmaps/ns/c#{index}", {"metadata" => {"name" => "c#{index}"}}) }
    2.times { fast.next(timeout: 1) }
    store.create("registry/v1/configmaps/ns/c2", {"metadata" => {"name" => "c2"}})
    store.create("registry/v1/configmaps/ns/c3", {"metadata" => {"name" => "c3"}})

    assert_predicate slow, :overflowed?
    assert_equal 1, value(metrics.render, 'apiserver_terminated_watchers_total{group="",resource="configmaps"}')
  ensure
    [slow, fast].compact.each(&:close)
  end

  class FakeRaftServer
    attr_reader :store, :data_directory, :read_indexes

    def initialize(data_directory)
      @store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
      @data_directory = data_directory
      @read_indexes = 0
    end

    def read_index(**_options)
      @read_indexes += 1
      @store.revision
    end

    def state_machine = nil
  end

  def test_raft_read_barrier_is_the_cache_freshness_wait_and_storage_bookmark
    Dir.mktmpdir do |directory|
      File.binwrite(File.join(directory, "wal-0001"), "x" * 10_000)
      Dir.mkdir(File.join(directory, "snap"))
      File.binwrite(File.join(directory, "snap", "0001.snap"), "y" * 5000)
      server = FakeRaftServer.new(directory)
      metrics = Rubernetes::Observability::Metrics.new
      raft = Rubernetes::Consensus::RaftStore.new(server)
      raft.metrics = metrics
      server.store.create("registry/v1/configmaps/ns/a", {"metadata" => {"name" => "a"}})

      raft.list("registry/v1/configmaps/ns")
      raft.get("registry/v1/configmaps/ns/a")
      raft.with_read_barrier do
        raft.list("registry/v1/configmaps/ns")
        raft.list("registry/v1/configmaps/ns")
      end
      # A historical read needs no barrier.
      raft.list("registry/v1/configmaps/ns", resource_version: "1", resource_version_match: "NotOlderThan")
      text = metrics.render

      labels = '{group="",resource="configmaps"}'
      assert_equal 3, server.read_indexes
      assert_equal 3, value(text, "etcd_bookmark_total#{labels}")
      # ALPHA, deprecated in 1.36.0: hidden.
      refute_match(/^etcd_bookmark_counts/, text)
      assert_equal 3, value(text, "apiserver_watch_cache_read_wait_seconds_count#{labels}")
      assert_match(/^apiserver_watch_cache_read_wait_seconds_bucket\{group="",resource="configmaps",le="3"\} 3$/, text)
      assert_match(/^# HELP etcd_bookmark_total \[ALPHA\] Number of etcd bookmarks \(progress notify events\) split by kind\.$/, text)

      allocated = [File.join(directory, "wal-0001"), File.join(directory, "snap", "0001.snap")].sum { |path| File.stat(path).blocks * 512 }
      assert_equal allocated, value(text, 'apiserver_storage_size_bytes{storage_cluster_id="etcd-0"}')
      assert_match(/^# HELP apiserver_storage_size_bytes \[STABLE\] Size of the storage database file physically allocated in bytes\.$/, text)
      assert_match(/^# TYPE apiserver_storage_size_bytes gauge$/, text)
    end
  end
end
