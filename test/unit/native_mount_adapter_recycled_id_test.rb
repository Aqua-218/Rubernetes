# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/volume"
require "tmpdir"

# The kernel hands out mount ids from the lowest free number, so the id a
# mount gives up on umount2 is the next one any mount on the host receives.
# The post-unmount readback must not mistake that newcomer for the old mount.
class NativeMountAdapterRecycledIdTest < Minitest::Test
  Adapter = Rubernetes::Volume::NativeMountAdapter

  class Mount
    attr_reader :unmounted

    def mount(**) = true

    def unmount(**)
      @unmounted = true
    end
  end

  def test_the_freed_id_reappearing_at_another_target_is_not_the_old_mount
    Dir.mktmpdir("recycled-id") do |directory|
      target = File.join(directory, "target")
      other = File.join(directory, "other-pod")
      before = "4800 45 0:628 / #{target} rw - tmpfs tmpfs rw\n"
      after = "4800 45 0:700 / #{other} rw - tmpfs tmpfs rw\n"
      mount = Mount.new
      adapter = Adapter.new(mount: mount, mountinfo_reader: -> { mount.unmounted ? after : before })

      assert_equal true, adapter.unmount(target: target, mount_id: "4800")
    end
  end

  def test_the_same_id_still_at_the_same_target_is_the_old_mount
    Dir.mktmpdir("recycled-id") do |directory|
      target = File.join(directory, "target")
      still = "4800 45 0:628 / #{target} rw - tmpfs tmpfs rw\n"
      adapter = Adapter.new(mount: Mount.new, mountinfo_reader: -> { still })

      error = assert_raises(Rubernetes::Volume::CleanupError) { adapter.unmount(target: target, mount_id: "4800") }
      assert_match(/remains mounted/, error.message)
    end
  end
end
