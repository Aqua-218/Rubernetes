# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/volume"
require "tmpdir"

# Readback of one mount target no longer parses the whole mountinfo table;
# it must still return exactly what read_mounts.find returned.
class NativeMountEntryLookupTest < Minitest::Test
  Adapter = Rubernetes::Volume::NativeMountAdapter

  TABLE = <<~INFO
    22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
    40 22 0:45 / /var/lib/pods/a rw,nosuid - tmpfs tmpfs rw,size=1024k
    41 22 8:1 /srv/vol /var/lib/pods/with\\040space rw - ext4 /dev/sda1 rw
    42 22 8:1 /srv/other /var/lib/pods/a rw - ext4 /dev/sda1 rw
  INFO

  def adapter(table = TABLE)
    Adapter.new(mount: Object.new, mountinfo_reader: -> { table })
  end

  def test_matches_the_full_parse_for_every_target
    subject = adapter
    full = subject.send(:read_mounts)
    ["/", "/var/lib/pods/a", "/var/lib/pods/with space", "/nowhere"].each do |target|
      expected = full.find { |entry| entry.fetch("target") == target }
      actual = subject.send(:mount_entry_at, target)
      expected.nil? ? assert_nil(actual) : assert_equal(expected, actual, target)
    end
  end

  def test_first_entry_wins_like_find
    assert_equal "40", adapter.send(:mount_entry_at, "/var/lib/pods/a").fetch("mountId")
  end

  def test_public_find_mount_still_normalizes_and_returns_the_entry
    assert_equal "41", adapter.find_mount("/var/lib/pods/with space").fetch("mountId")
    assert_nil adapter.find_mount("/var/lib/pods/missing")
  end
end

# The pre-mount "already mounted?" check reads mountinfo only when the target
# may be the root of a mount (its fdinfo mnt_id differs from its parent's).
class NativeMountRootPrecheckTest < Minitest::Test
  def adapter
    Rubernetes::Volume::NativeMountAdapter.new(mount: Object.new, mountinfo_reader: -> { "" })
  end

  def test_a_plain_directory_is_not_a_mount_root
    Dir.mktmpdir do |dir|
      target = File.join(dir, "target")
      Dir.mkdir(target)

      refute adapter.send(:possibly_mount_root?, target)
    end
  end

  def test_a_missing_path_is_not_a_mount_root
    refute adapter.send(:possibly_mount_root?, "/nonexistent/#{rand(1 << 30)}")
  end

  def test_a_real_mount_point_is_detected
    assert adapter.send(:possibly_mount_root?, "/proc"), "/proc is its own mount"
  end
end

# Mounts on different targets no longer queue behind one node-wide lock; the
# same target is still serialised.
class NativeMountTargetLockTest < Minitest::Test
  Adapter = Rubernetes::Volume::NativeMountAdapter

  def test_different_targets_use_different_locks_and_the_same_target_the_same
    adapter = Adapter.new(mount: Object.new, mountinfo_reader: -> { "" })
    a = adapter.send(:target_lock, "/var/lib/pods/a/volumes/x")

    assert_same a, adapter.send(:target_lock, "/var/lib/pods/a/volumes/x")
    locks = (1..20).map { |i| adapter.send(:target_lock, "/var/lib/pods/p#{i}/volumes/x") }.uniq

    assert_operator locks.length, :>, 10, "targets spread across the lock stripes"
  end

  def test_a_mount_on_one_target_does_not_wait_for_another_targets_lock
    adapter = Adapter.new(mount: Object.new, mountinfo_reader: -> { "" })
    held = adapter.send(:target_lock, "/busy/target")
    other = (1..200).map { |i| "/free/target#{i}" }.find { |path| !adapter.send(:target_lock, path).equal?(held) }
    entered = Queue.new
    holder = Thread.new do
      held.synchronize do
        entered << :held
        sleep 0.5
      end
    end
    entered.pop
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    adapter.send(:target_lock, other).synchronize { nil }

    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.2
  ensure
    holder&.join
  end
end
