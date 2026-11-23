# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/volume"
require "rubernetes/platform/linux/openat2"

# An atomic-writer volume -- configMap, secret, downwardAPI, projected --
# publishes every entry as a symlink into "..data/", so a subPath into one IS a
# symlink.  A descriptor walk that refuses symlinks outright fails it with
# ELOOP, which meant no Pod could use a subPath into any of those volumes at
# all: "[sig-storage] Subpath Atomic writer volumes should support subpaths
# with projected pod" never started its Pod.
#
# Resolve the target relative to the opened volume (subpath_linux.go
# doBindSubPath) and require a strict descriptor walk of the resolved path.
class SubPathSymlinkResolutionTest < Minitest::Test
  Openat2 = Rubernetes::Platform::Linux::Openat2

  def validate(resolve, **)
    Openat2.allocate.send(:validate_resolve!, resolve, **)
  end

  def test_the_strict_walk_is_still_accepted
    assert(validate(Openat2::DEFAULT_RESOLVE))
  end

  # Symlinks followed, but clamped to the volume.
  def test_in_root_resolution_is_accepted
    assert(validate(Openat2::RESOLVE_IN_ROOT | Openat2::RESOLVE_NO_MAGICLINKS | Openat2::RESOLVE_NO_XDEV))
  end

  # Following symlinks WITHOUT the clamp is what lets a subPath escape.
  def test_following_symlinks_without_containment_is_refused
    assert_raises(Openat2::UnsafePath) do
      validate(Openat2::RESOLVE_NO_MAGICLINKS | Openat2::RESOLVE_NO_XDEV)
    end
  end

  def test_magic_links_stay_forbidden
    assert_raises(Openat2::UnsafePath) do
      validate(Openat2::RESOLVE_IN_ROOT | Openat2::RESOLVE_NO_XDEV)
    end
  end

  def test_mount_crossing_stays_forbidden
    assert_raises(Openat2::UnsafePath) do
      validate(Openat2::RESOLVE_IN_ROOT | Openat2::RESOLVE_NO_MAGICLINKS)
    end
  end

  def test_resolution_is_relative_to_the_open_volume
    Dir.mktmpdir("subpath-symlinks") do |root|
      volume = File.join(root, "volume")
      FileUtils.mkdir_p(File.join(volume, "..generation"))
      File.write(File.join(volume, "..generation", "key"), "projected")
      File.symlink("..generation", File.join(volume, "..data"))
      File.symlink("..data/key", File.join(volume, "key"))
      File.symlink("../", File.join(volume, "outside"))
      security = Rubernetes::Volume::PathSecurity.new(root: root, adapter: Openat2.new(root: root))
      parent = security.open(volume)
      begin
        key = security.validate_sub_path!(parent, "key")

        assert_equal "projected", File.read("/proc/self/fd/#{key.fd}")
        assert_raises(Rubernetes::Volume::PathSecurityError) { security.validate_sub_path!(parent, "outside") }
      ensure
        key&.close
        parent.close
      end
    end
  end
end
