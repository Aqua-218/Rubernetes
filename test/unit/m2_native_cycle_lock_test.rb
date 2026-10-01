# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require File.expand_path("../../tools/milestones/m2_probe_support", __dir__)

# Two M2 native-cycle probes on one host serialise on a lock file; a holder
# that outlives the wait is named by pid instead of being waited on for ever.
class M2NativeCycleLockTest < Minitest::Test
  def test_cycles_serialise_and_a_stuck_holder_is_reported
    Dir.mktmpdir do |dir|
      lock_path = File.join(dir, "cycles.lock")
      holder = File.open(lock_path, File::RDWR | File::CREAT)
      holder.flock(File::LOCK_EX)
      holder.write("4242\n")
      holder.flush

      error = assert_raises(RuntimeError) do
        M2ProbeSupport.native_cycle_workspace(lock_path: lock_path, wait: 0.6) { flunk "must not run while locked" }
      end

      assert_includes error.message, "pid 4242"
      holder.flock(File::LOCK_UN)
      ran = nil
      M2ProbeSupport.native_cycle_workspace(lock_path: lock_path, wait: 1) do |directory|
        ran = directory

        assert_equal Process.pid.to_s, File.read(lock_path).strip
        assert File.directory?(directory)
      end

      assert ran
      refute File.directory?(ran), "the workspace is removed afterwards"
      assert holder.flock(File::LOCK_EX | File::LOCK_NB), "the lock is released afterwards"
    ensure
      holder&.close
    end
  end
end
