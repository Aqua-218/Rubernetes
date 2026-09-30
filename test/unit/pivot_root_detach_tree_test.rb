# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/platform/linux/mount"
require "rubernetes/platform/linux/pivot_root"

# The old root is detached in one umount2(MNT_DETACH) and then proven
# unreachable: no old mount left in mountinfo, no descriptor on one of them.
class PivotRootDetachTreeTest < Minitest::Test
  Linux = Rubernetes::Platform::Linux

  class RecordingMount
    attr_reader :calls

    def initialize
      @calls = []
    end

    def unmount(target:, flags: 0, resource_id: nil)
      @calls << [target, flags]
      true
    end
  end

  NEW_ROOT = <<~INFO
    100 1 0:50 / / rw - overlay overlay rw
    101 100 0:51 / /proc rw - proc proc rw
  INFO

  def setup
    @dir = Dir.mktmpdir
    @mount = RecordingMount.new
    @pivot = Linux::PivotRoot.new(mount: @mount)
    @fdinfo = File.join(@dir, "fdinfo")
    Dir.mkdir(@fdinfo)
  end

  def teardown
    FileUtils.rm_rf(@dir)
  end

  def mountinfo(contents)
    path = File.join(@dir, "mountinfo")
    File.write(path, contents)
    path
  end

  def descriptor(fd, mnt_id)
    File.write(File.join(@fdinfo, fd.to_s), "pos:\t0\nflags:\t02\nmnt_id:\t#{mnt_id}\n")
  end

  def detach(contents, old_ids: %w[22 40 41])
    @pivot.detach_tree("/.pivot-old", old_mount_ids: old_ids, mountinfo_path: mountinfo(contents), fdinfo_path: @fdinfo)
  end

  def test_one_lazy_detach_replaces_the_per_mount_walk
    descriptor(0, 13)
    descriptor(3, 101)
    detach(NEW_ROOT)

    assert_equal [["/.pivot-old", Linux::Mount::MNT_DETACH]], @mount.calls
  end

  def test_an_old_mount_still_in_the_table_fails_the_proof
    error = assert_raises(Linux::PivotRoot::Busy) { detach(NEW_ROOT + "41 22 8:1 / /.pivot-old/srv rw - ext4 /dev/sda1 rw\n") }
    assert_match "/.pivot-old/srv", error.message
  end

  def test_a_descriptor_on_the_detached_root_fails_the_proof
    descriptor(0, 13)
    descriptor(7, 40)
    error = assert_raises(Linux::PivotRoot::Busy) { detach(NEW_ROOT) }
    assert_match "7", error.message
  end

  # The node keeps unmounting while a container is built, and the kernel
  # hands a freed id to the next mount: a new-root mount carrying an id that
  # was on the old-root list is live, not a remnant of the old root.
  def test_a_recycled_id_in_the_new_root_is_not_an_old_mount
    descriptor(4, 40)
    detach(NEW_ROOT + "40 100 0:5 /null /dev/null rw - devtmpfs devtmpfs rw\n")

    assert_equal [["/.pivot-old", Linux::Mount::MNT_DETACH]], @mount.calls
  end

  def test_a_descriptor_on_a_gone_old_id_still_fails_when_another_id_was_recycled
    descriptor(4, 40)
    descriptor(5, 41)
    assert_raises(Linux::PivotRoot::Busy) { detach(NEW_ROOT + "40 100 0:5 /null /dev/null rw - devtmpfs devtmpfs rw\n") }
  end
end
