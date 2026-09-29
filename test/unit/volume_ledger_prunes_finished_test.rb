# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/volume"

# Finished ledger entries were kept for ever: 6,000 of them meant 6 MB of JSON
# rewritten on every volume operation under the volume manager's lock, and a
# Pod with 50 ConfigMap volumes spent 19 minutes in MountVolume.SetUp.  Finished
# entries now expire after a TTL and are capped; pending and unknown ones stay.
class VolumeLedgerPrunesFinishedTest < Minitest::Test
  Ledger = Rubernetes::Volume::OperationLedger

  def ledger(clock)
    Ledger.new(path: File.join(@dir, "operations.json"), fsync: false, clock: clock)
  end

  def run_op(ledger, index, status: "succeeded")
    key = "vol-#{index}"
    ledger.begin!(key: key, operation: "create", token: "t-#{index}", fingerprint: "f-#{index}")
    status == "succeeded" ? ledger.finish!(key: key, operation: "create", token: "t-#{index}") : ledger.fail!(key: key, operation: "create", token: "t-#{index}", error: StandardError.new("boom"))
  end

  def test_finished_entries_are_capped_and_the_oldest_go_first
    Dir.mktmpdir do |dir|
      @dir = dir
      now = Time.utc(2026, 9, 21, 7, 0, 0)
      led = ledger(-> { now })
      (Ledger::MAX_FINISHED_ENTRIES + 50).times { |i| now += 1; run_op(led, i) }

      finished = led.entries.select { |entry| entry.status == "succeeded" }
      assert_equal Ledger::MAX_FINISHED_ENTRIES, finished.length
      assert_nil led.fetch(key: "vol-0", operation: "create"), "the oldest finished entry was pruned"
      refute_nil led.fetch(key: "vol-#{Ledger::MAX_FINISHED_ENTRIES + 49}", operation: "create")
    end
  end

  def test_stale_finished_entries_expire_but_pending_and_unknown_stay
    Dir.mktmpdir do |dir|
      @dir = dir
      now = Time.utc(2026, 9, 21, 7, 0, 0)
      led = ledger(-> { now })
      run_op(led, 1)
      led.begin!(key: "vol-pending", operation: "create", token: "tp", fingerprint: "fp")
      led.begin!(key: "vol-unknown", operation: "create", token: "tu", fingerprint: "fu")
      led.unknown!(key: "vol-unknown", operation: "create", token: "tu", error: StandardError.new("lost"))
      now += Ledger::FINISHED_TTL_SECONDS + 5
      run_op(led, 2)

      assert_nil led.fetch(key: "vol-1", operation: "create"), "a finished entry older than the TTL is gone"
      refute_nil led.fetch(key: "vol-2", operation: "create")
      assert_equal "pending", led.fetch(key: "vol-pending", operation: "create").status
      assert_equal "unknown", led.fetch(key: "vol-unknown", operation: "create").status
    end
  end
end
