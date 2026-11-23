# frozen_string_literal: true

require_relative "../test_helper"
require "minitest/mock"
require "rubernetes/platform/linux/native_adapters"

class WorkspaceCleanupReadbackTest < Minitest::Test
  NativeAdapters = Rubernetes::Platform::Linux::NativeAdapters
  Workspace = Data.define(:root, :identity)
  Namespace = Data.define(:pid)

  class LostReply
    def with_mount_namespace(_namespace)
      yield
      raise NativeAdapters::EffectError, "namespace helper timed out"
    end

    def destroyed?(_namespace) = false
  end

  def test_an_unmount_that_loses_its_reply_is_confirmed_from_mountinfo
    workspace = Workspace.new("/workspace/merged", "workspace")
    lines = [mount_entry(workspace.root)]
    mount = Object.new
    mount.define_singleton_method(:unmount) { |**| lines.clear }
    adapter = NativeAdapters::OverlayFilesystemAdapter.new(root: "/workspace", namespace_adapter: LostReply.new, mount: mount)
    metadata = {"mount_identity" => {"mount_id" => 42, "mountpoint" => workspace.root, "filesystem" => "overlay"}}

    File.stub(:readlines, lines) do
      assert(adapter.send(:cleanup_mounted_workspace, workspace, metadata, Namespace.new(Process.pid)))
      assert(adapter.send(:cleanup_mounted_workspace, workspace, metadata, Namespace.new(Process.pid)))
    end
  end

  def test_a_missing_overlay_does_not_prove_the_workspace_is_empty
    workspace = Workspace.new("/workspace/merged", "workspace")
    adapter = NativeAdapters::OverlayFilesystemAdapter.new(root: "/workspace", namespace_adapter: LostReply.new)

    File.stub(:readlines, [mount_entry("#{workspace.root}/child")]) do
      error = assert_raises(NativeAdapters::EffectError) do
        adapter.send(:cleanup_mounted_workspace, workspace, {}, Namespace.new(Process.pid))
      end
      assert_match(/still contains mounts/, error.message)
    end
  end

  def test_mount_readback_uses_the_kernel_escaped_target
    target = "/workspace/with spaces and \\ slash\ttab\nnewline"
    escaped = '/workspace/with\040spaces\040and\040\134\040slash\011tab\012newline'
    adapter = NativeAdapters::OverlayFilesystemAdapter.new(root: "/workspace", namespace_adapter: LostReply.new)

    File.stub(:readlines, [mount_entry(escaped)]) do
      identity = adapter.send(:mount_readback, Namespace.new(Process.pid), target, allow_absent: true)

      assert_equal target, identity.fetch("mountpoint")
    end
  end

  def mount_entry(path)
    "42 5 0:15 / #{path} rw - overlay overlay rw"
  end
end
