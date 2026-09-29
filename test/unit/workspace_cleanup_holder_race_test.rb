# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux/native_adapters"

# Workspace cleanup checks that the namespace holder is alive, then reads its
# /proc/<pid>/mountinfo to verify the overlay before unmounting.  The holder
# can exit in between: the read then fails ("overlay mount readback failed:
# Invalid argument @ rb_sysopen - /proc/<pid>/mountinfo") and cleanup reported
# a failure -- even though a dead holder means the mount namespace, and every
# mount in it, is already gone.  That is the state cleanup wants.  Seen on
# roughly one in three 1000-cycle M2 ledger probe runs, which made
# M2ProbesTest fail intermittently with KeyError "l3_available" because the
# probe's report came back INCOMPLETE.
class WorkspaceCleanupHolderRaceTest < Minitest::Test
  Adapters = Rubernetes::Platform::Linux::NativeAdapters
  Subject = Adapters::OverlayFilesystemAdapter

  Handle = Struct.new(:pid, keyword_init: true)

  def adapter_with(destroyed:)
    namespace_adapter = Object.new
    namespace_adapter.define_singleton_method(:destroyed?) { |_handle| destroyed }
    subject = Subject.allocate
    subject.instance_variable_set(:@namespace_adapter, namespace_adapter)
    subject
  end

  def test_a_dead_holder_counts_as_vanished
    subject = adapter_with(destroyed: true)

    assert subject.send(:namespace_holder_vanished?, Handle.new(pid: 999_999_999))
  end

  def test_a_pid_with_no_proc_entry_counts_as_vanished
    subject = adapter_with(destroyed: false)

    # A pid that cannot exist: /proc/<pid>/mountinfo is absent.
    assert subject.send(:namespace_holder_vanished?, Handle.new(pid: 999_999_999))
  end

  def test_a_live_holder_does_not_count_as_vanished
    subject = adapter_with(destroyed: false)

    refute subject.send(:namespace_holder_vanished?, Handle.new(pid: Process.pid)),
           "a live holder must keep the strict readback failure"
  end

  def test_a_missing_pid_counts_as_vanished
    subject = adapter_with(destroyed: false)

    assert subject.send(:namespace_holder_vanished?, Handle.new(pid: nil))
  end
end
