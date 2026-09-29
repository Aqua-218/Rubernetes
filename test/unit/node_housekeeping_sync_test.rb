# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# kubelet's syncLoop runs a housekeeping pass on a short timer that re-syncs
# every Pod it already knows about, from its own cache, without asking the API
# server for anything.  That pass is what drives probes, restart backoffs and
# retried starts.  Ours only reconciled a Pod when its API object changed or on
# the 60s resync, so a container in CrashLoopBackOff waited tens of seconds to
# be restarted and a liveness probe ran at the watch's cadence rather than its
# own period -- "[sig-node] Probing container should have monotonically
# increasing restart count" wants five restarts in five minutes.
class NodeHousekeepingSyncTest < Minitest::Test
  Node = Rubernetes::Node

  class Source
    def initialize(pods) = (@pods = pods)

    def list_pods(**_options)
      {"items" => @pods, "metadata" => {"resourceVersion" => "1"}}
    end

    def watch_pods(**_options) = []
    def close = true
  end

  def pod(name)
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "ns", "uid" => "uid-#{name}",
                    "resourceVersion" => "1"},
     "spec" => {"nodeName" => "node-a"}}
  end

  def loop_for(pods, reconciled)
    Node::SyncLoop.new(source: Source.new(pods), node_name: "node-a",
                       reconcile: ->(object, **_options) { reconciled << object.dig("metadata", "name") },
                       sleeper: ->(_seconds) {})
  end

  def test_housekeeping_resyncs_every_cached_pod_without_listing
    reconciled = []
    sync = loop_for([pod("a"), pod("b")], reconciled)
    sync.resync(now: 0)
    sync.instance_variable_get(:@workers).drain if sync.instance_variable_get(:@workers).respond_to?(:drain)
    before = reconciled.length

    assert_equal(2, sync.housekeep(now: 1))
    sync.instance_variable_get(:@workers).drain if sync.instance_variable_get(:@workers).respond_to?(:drain)

    assert_equal(before + 2, reconciled.length)
    assert_equal(%w[a b], reconciled.last(2).sort)
  end

  def test_housekeeping_is_due_on_its_own_short_period
    sync = loop_for([pod("a")], [])

    assert(sync.housekeeping_due?(0), "the first pass is always due")
    sync.housekeep(now: 10)
    refute(sync.housekeeping_due?(10.5))
    assert(sync.housekeeping_due?(10 + Node::SyncLoop::DEFAULT_HOUSEKEEPING_PERIOD_SECONDS))
  end

  # The point of housekeeping is that it costs the API server nothing.
  def test_housekeeping_does_not_call_the_api
    source = Source.new([pod("a")])
    calls = 0
    source.define_singleton_method(:list_pods) do |**_options|
      calls += 1
      {"items" => [], "metadata" => {"resourceVersion" => "1"}}
    end
    sync = Node::SyncLoop.new(source: source, node_name: "node-a",
                              reconcile: ->(_object, **_options) {}, sleeper: ->(_seconds) {})
    sync.resync(now: 0)
    before = calls
    sync.housekeep(now: 1)

    assert_equal(before, calls)
  end
end
