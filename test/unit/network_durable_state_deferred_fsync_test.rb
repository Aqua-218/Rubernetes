# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"
require "tmpdir"

# Attaching one Pod's network persists its operation about twenty times -- an
# effect cursor, then each claimed resource -- and at two fsyncs apiece that
# serialised every concurrent Pod start on the node behind the disk.  The
# atomic rename still leaves a whole state on disk; only the durability
# barrier is coalesced, as the node's lifecycle state already does.
class NetworkDurableStateDeferredFsyncTest < Minitest::Test
  DurableState = Rubernetes::Network::DurableState

  def test_deferred_mode_writes_atomically_and_defers_the_barrier
    Dir.mktmpdir("durable") do |dir|
      path = File.join(dir, "network.json")
      synced = []
      Rubernetes::Volume::DeferredFsync.stub(:schedule, ->(target) { synced << target }) do
        state = DurableState.new(path, default: {"operations" => {}}, fsync: :deferred)
        state.replace({"operations" => {"a" => {"state" => "committed"}}})
        state.replace({"operations" => {"a" => {"state" => "removed"}}})
        assert_equal [path, path], synced, "each write schedules one coalesced barrier"
      end
      assert_equal({"operations" => {"a" => {"state" => "removed"}}}, JSON.parse(File.read(path)))
      assert_empty Dir.glob(File.join(dir, "*.tmp-*")), "no temporary file is left behind"
    end
  end

  def test_the_state_survives_a_reopen
    Dir.mktmpdir("durable") do |dir|
      path = File.join(dir, "network.json")
      DurableState.new(path, default: {}, fsync: :deferred).replace({"operations" => {"x" => 1}})
      Rubernetes::Volume::DeferredFsync.flush!
      assert_equal({"operations" => {"x" => 1}}, DurableState.new(path, default: {}, fsync: :deferred).read)
    end
  end

  def test_true_still_syncs_inline_and_false_syncs_nothing
    Dir.mktmpdir("durable") do |dir|
      %i[inline none].each do |mode|
        path = File.join(dir, "#{mode}.json")
        calls = 0
        fsync = mode == :inline ? ->(file) { calls += 1; file.fsync } : false
        state = DurableState.new(path, default: {}, fsync: fsync)
        state.replace({"k" => mode.to_s})
        assert_equal({"k" => mode.to_s}, JSON.parse(File.read(path)))
        assert_operator calls, :>, 0 if mode == :inline
      end
    end
  end

  def test_the_assembler_asks_for_the_deferred_barrier
    source = File.read(File.expand_path("../../lib/rubernetes/bootstrap/assembler.rb", __dir__))
    assert_match(/fsync: config\.fetch\("fsync", true\) == false \? false : :deferred/, source)
  end
end
