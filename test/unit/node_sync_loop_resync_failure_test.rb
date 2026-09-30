# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# One failed periodic list used to end the sync loop's thread for good: the
# node then never heard of another Pod, and nothing said so.  The loop
# records the failure and carries on.
class NodeSyncLoopResyncFailureTest < Minitest::Test
  class FlakySource
    attr_reader :list_calls, :watch_calls

    def initialize
      @list_calls = 0
      @watch_calls = 0
    end

    def list(**_options)
      @list_calls += 1
      raise IOError, "connection dropped by the server" if @list_calls == 2

      {"items" => [], "metadata" => {"resourceVersion" => @list_calls.to_s}}
    end

    def watch(**_options)
      @watch_calls += 1
      []
    end
  end

  def test_the_loop_survives_a_failed_resync
    source = FlakySource.new
    errors = []
    loop_ = Rubernetes::Node::SyncLoop.new(source: source, node_name: "node-1",
                                           reconcile: ->(*_args, **_kw) {}, resync_period: 0.001,
                                           sleeper: ->(_seconds) { sleep 0.002 },
                                           error_handler: ->(error, *event) { errors << [error.class, event.first] })
    loop_.start
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3
    sleep 0.01 until source.list_calls >= 4 || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

    assert_predicate loop_, :thread_alive?, "the sync thread must outlive a failed list"
    assert_operator source.list_calls, :>=, 4
    assert_includes errors.map(&:first), IOError
  ensure
    loop_&.stop
  end
end
