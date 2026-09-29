# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/volume"
require "tmpdir"

class NativeVolumeMountAdapterTest < Minitest::Test
  Adapter = Rubernetes::Volume::NativeMountAdapter

  class RecordingMount
    attr_reader :mount_calls, :unmount_calls
    attr_accessor :unmount_result, :unmount_error

    def initialize
      @mount_calls = []
      @unmount_calls = []
    end

    def mount(**kwargs)
      @mount_calls << kwargs
      true
    end

    def unmount(**kwargs)
      @unmount_calls << kwargs
      raise unmount_error if unmount_error

      unmount_result.nil? ? true : unmount_result
    end
  end

  def test_mountinfo_parser_decodes_escaped_fields_and_exposes_stable_identity
    entry = Adapter.parse_mountinfo(
      "123 45 8:1 /root\\040path /mnt\\040target rw,nosuid - ext4 /dev/disk\\040one rw\\n"
    ).fetch(0)

    assert_equal "123", entry.fetch("mountId")
    assert_equal "8:1", entry.fetch("deviceId")
    assert_equal "/root path", entry.fetch("root")
    assert_equal "/mnt target", entry.fetch("target")
    assert_equal "ext4", entry.fetch("filesystem")
    assert_equal "/dev/disk one", entry.fetch("source")
    assert_equal %w[mountId deviceId root target filesystem source options], entry.fetch("stableIdentity").keys
    assert_nil entry.fetch("filesystemUuid")
    refute entry.fetch("filesystemUuidAvailable")
  end

  def test_mount_fails_closed_when_syscall_success_has_no_mountinfo_readback
    mount = RecordingMount.new
    adapter = Adapter.new(mount: mount, mountinfo_reader: -> { "" })

    Dir.mktmpdir("native-mount-no-readback") do |directory|
      error = assert_raises(Rubernetes::Volume::MountIdentityError) do
        adapter.mount(source: "tmpfs", target: File.join(directory, "target"), filesystem: "tmpfs")
      end

      assert_match(/absent from mountinfo/, error.message)
      assert_equal 1, mount.mount_calls.length
      assert_equal 1, mount.unmount_calls.length
    end
  end

  def test_mount_cleanup_false_is_ambiguous_and_verified
    mount = RecordingMount.new
    mount.unmount_result = false
    adapter = Adapter.new(mount: mount, mountinfo_reader: -> { "" })

    Dir.mktmpdir("native-mount-cleanup-false") do |directory|
      error = assert_raises(Rubernetes::Volume::CleanupError) do
        adapter.mount(source: "tmpfs", target: File.join(directory, "target"), filesystem: "tmpfs")
      end

      assert error.ambiguous?
      assert_match(/cleanup failed/, error.message)
      assert_equal 1, mount.unmount_calls.length
    end
  end

  def test_mount_cleanup_error_is_not_suppressed
    mount = RecordingMount.new
    mount.unmount_error = Errno::EIO.new("simulated cleanup I/O error")
    adapter = Adapter.new(mount: mount, mountinfo_reader: -> { "" })

    Dir.mktmpdir("native-mount-cleanup-error") do |directory|
      error = assert_raises(Rubernetes::Volume::CleanupError) do
        adapter.mount(source: "tmpfs", target: File.join(directory, "target"), filesystem: "tmpfs")
      end

      assert error.ambiguous?
      assert_match(/simulated cleanup I\/O error/, error.message)
      assert_equal 1, mount.unmount_calls.length
    end
  end

  def test_unmount_refuses_a_replaced_mount_identity_before_umount2
    mount = RecordingMount.new
    Dir.mktmpdir("native-mount-identity") do |directory|
      target = File.join(directory, "target")
      mountinfo = "321 45 8:1 / #{target} rw - ext4 /dev/sda1 rw\n"
      adapter = Adapter.new(mount: mount, mountinfo_reader: -> { mountinfo })

      error = assert_raises(Rubernetes::Volume::MountIdentityError) do
        adapter.unmount(target: target, mount_id: "999")
      end

      assert_match(/mount id changed/, error.message)
      assert_empty mount.unmount_calls
    end
  end

  def test_mount_readback_contains_kernel_identity_and_explicit_uuid_absence
    mount = RecordingMount.new
    Dir.mktmpdir("native-mount-identity") do |directory|
      target = File.join(directory, "target")
      mountinfo = "321 45 8:1 / #{target} rw - ext4 /dev/sda1 rw\n"
      # The target appears in mountinfo once mount(2) has been issued.
      adapter = Adapter.new(mount: mount, mountinfo_reader: -> { mount.mount_calls.empty? ? "" : mountinfo })

      result = adapter.mount(source: "/source", target: target, filesystem: nil, options: {"bind" => true})

      assert_equal "321", result.fetch("mountId")
      assert_equal "8:1", result.fetch("deviceId")
      assert_equal "/", result.fetch("root")
      assert_equal target, result.fetch("target")
      assert_equal "ext4", result.fetch("filesystem")
      assert_equal "rw", result.fetch("options")
      assert_nil result.fetch("filesystemUuid")
      refute result.fetch("filesystemUuidAvailable")
    end
  end

  def test_mountinfo_parser_rejects_malformed_device_identity
    assert_raises(Rubernetes::Volume::MountIdentityError) do
      Adapter.parse_mountinfo("321 45 invalid / /target rw - ext4 /dev/sda1 rw\n")
    end
  end
end
