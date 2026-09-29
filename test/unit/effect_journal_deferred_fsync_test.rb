# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "tmpdir"

# Records are written and flushed at once; the fsync is coalesced instead of
# paid per record under the controller's write path.
class EffectJournalDeferredFsyncTest < Minitest::Test
  def test_records_are_visible_at_once_and_fsync_is_deferred
    Dir.mktmpdir("effect-journal") do |directory|
      journal = Rubernetes::Controller::EffectJournal.new(path: File.join(directory, "effects.jsonl"), component: "cm", identity: "t")

      journal.record(effect_type: "create", reconcile_key: "ns/a", action: :create, object: {"metadata" => {"name" => "a"}})
      journal.record(effect_type: "create", reconcile_key: "ns/b", action: :create, object: {"metadata" => {"name" => "b"}})

      assert_equal 2, File.readlines(journal.path).length, "written and flushed immediately"
      assert journal.fsync_pending?
      journal.flush!
      refute journal.fsync_pending?
      journal.close
      assert_equal 2, File.readlines(journal.path).length
    end
  end

  def test_the_flusher_syncs_on_its_own
    Dir.mktmpdir("effect-journal") do |directory|
      journal = Rubernetes::Controller::EffectJournal.new(path: File.join(directory, "effects.jsonl"), component: "cm", identity: "t")
      journal.record(effect_type: "update", reconcile_key: "ns/a", action: :update, object: {})

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
      sleep 0.01 while journal.fsync_pending? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

      refute journal.fsync_pending?
      journal.close
    end
  end
end
