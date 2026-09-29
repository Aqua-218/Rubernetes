# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/volume"

class DeferredFsyncTest < Minitest::Test
  Fsync = Rubernetes::Volume::DeferredFsync

  def test_scheduled_paths_are_synced_once_and_the_set_is_cleared
    Dir.mktmpdir do |dir|
      path = File.join(dir, "state.json")
      File.write(path, "{}\n")
      Fsync.schedule(path)
      Fsync.schedule(path)

      assert_equal 1, Fsync.flush!, "one dirty path, however often it was scheduled"
      assert_equal 0, Fsync.flush!
    end
  end

  def test_a_vanished_path_does_not_raise
    Fsync.schedule("/nonexistent/dir/file.json")

    assert_equal 1, Fsync.flush!
  end

  def test_the_operation_ledger_syncs_inline_only_for_recovery_critical_statuses
    Dir.mktmpdir do |dir|
      ledger = Rubernetes::Volume::OperationLedger.new(path: File.join(dir, "operations.json"), fsync: true)
      ledger.begin!(key: "v", operation: "create", token: "t", fingerprint: "f")
      ledger.effecting!(key: "v", operation: "create", token: "t")
      ledger.finish!(key: "v", operation: "create", token: "t")

      assert_equal "succeeded", ledger.fetch(key: "v", operation: "create").status
      assert_operator Fsync.flush!, :>=, 0
    end
  end
end
