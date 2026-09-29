# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

class NodeSyncLoopTest < Minitest::Test
  class Source
    attr_accessor :pods
    attr_reader :list_calls, :watch_calls

    def initialize(pods = [])
      @pods = pods
      @list_calls = 0
      @watch_calls = 0
    end

    def list(**_options)
      @list_calls += 1
      {"items" => @pods, "metadata" => {"resourceVersion" => @list_calls.to_s}}
    end

    def watch(**_options)
      @watch_calls += 1
      []
    end
  end

  def pod(uid, node: "node-1")
    {"metadata" => {"uid" => uid, "name" => uid}, "spec" => {"nodeName" => node}}
  end

  def test_watch_filters_other_nodes_and_resync_recovers_missing_pods
    source = Source.new([pod("from-list")])
    seen = []
    loop_ = Rubernetes::Node::SyncLoop.new(
      source: source,
      node_name: "node-1",
      reconcile: ->(object, action: nil, request_id: nil) { seen << [object.dig("metadata", "uid"), action, request_id] },
      resync_period: 60,
      sleeper: ->(_seconds) {}
    )

    loop_.run_once(
      events: [
        {"type" => "ADDED", "object" => pod("watch-local"), "resourceVersion" => "10"},
        {"type" => "ADDED", "object" => pod("watch-remote", node: "other")},
        {"type" => "BOOKMARK", "object" => {}, "resourceVersion" => "11"}
      ],
      resync: false
    )
    loop_.instance_variable_get(:@workers).drain(timeout: 1)

    assert_equal ["watch-local"], loop_.cache.keys.sort
    assert_equal "11", loop_.resource_version
    assert_equal [["watch-local", "ADDED", "10"]], seen

    loop_.run_once(resync: true)
    loop_.instance_variable_get(:@workers).drain(timeout: 1)
    assert_equal ["from-list"], loop_.cache.keys.sort
    assert_equal ["from-list", "watch-local", "watch-local"], seen.map(&:first).sort
    assert_equal "DELETED", seen.last.fetch(1)
  end

  # kubelet's pod worker keeps ONE pending update per Pod and replaces it with
  # the newest one (pkg/kubelet/pod_workers.go pendingUpdate), so a sync that
  # is superseded before it runs is dropped rather than replayed.  A deletion
  # supersedes every pending sync and is still the last thing the worker does.
  def test_a_superseded_sync_is_dropped_and_the_deletion_runs_last
    source = Source.new
    seen = []
    loop_ = Rubernetes::Node::SyncLoop.new(
      source: source,
      node_name: "node-1",
      reconcile: ->(object, action: nil, request_id: nil) { seen << [action, object.dig("metadata", "uid")] },
      sleeper: ->(_seconds) {}
    )
    object = pod("serial")

    loop_.run_once(events: [{"type" => "ADDED", "object" => object}, {"type" => "MODIFIED", "object" => object},
                            {"type" => "DELETED", "object" => object}], resync: false)
    loop_.instance_variable_get(:@workers).drain(timeout: 1)

    assert_equal(["DELETED", "serial"], seen.last)
    assert_equal(1, seen.count { |entry| entry.first == "DELETED" })
    refute(seen.any? { |entry| entry.first == "MODIFIED" && seen.index(entry) > seen.index(["DELETED", "serial"]) })
    assert_empty loop_.cache
  end

  def test_an_unsuperseded_sync_still_runs
    source = Source.new
    seen = []
    loop_ = Rubernetes::Node::SyncLoop.new(
      source: source,
      node_name: "node-1",
      reconcile: ->(object, action: nil, request_id: nil) { seen << [action, object.dig("metadata", "uid")] },
      sleeper: ->(_seconds) {}
    )

    loop_.run_once(events: [{"type" => "ADDED", "object" => pod("solo")}], resync: false)
    loop_.instance_variable_get(:@workers).drain(timeout: 1)

    assert_equal([["ADDED", "solo"]], seen)
  end
end
