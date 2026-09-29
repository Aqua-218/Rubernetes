# frozen_string_literal: true

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
# The property a subPath actually has to hold is that it stays INSIDE the
# volume.  RESOLVE_IN_ROOT is the kernel's way of saying exactly that: the
# directory descriptor becomes "/", so an absolute symlink target, a "..", and
# a symlink chain are all clamped to the volume -- the same containment kubelet
# gets by evaluating the symlink and then requiring the result to be within the
# volume (subpath_linux.go doBindSubPath).
class SubPathSymlinkResolutionTest < Minitest::Test
  Openat2 = Rubernetes::Platform::Linux::Openat2

  def validate(resolve, **options)
    Openat2.allocate.send(:validate_resolve!, resolve, **options)
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

  # An ELOOP from the strict walk is what triggers the second attempt.
  def test_an_eloop_is_recognised_however_it_is_wrapped
    security = Rubernetes::Volume::PathSecurity.allocate
    direct = Errno::ELOOP.new("openat2")
    wrapped = RuntimeError.new("descriptor-relative subPath resolution failed: " \
                               "Too many levels of symbolic links - openat2")

    assert(security.send(:symlink_resolution_error?, direct))
    assert(security.send(:symlink_resolution_error?, wrapped))
    refute(security.send(:symlink_resolution_error?, RuntimeError.new("permission denied")))
  end
end
