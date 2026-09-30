# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/volume"
require "rubernetes/volume/native_mount_adapter"
require "rubernetes/platform/linux/mount"
require "rubernetes/platform/linux/openat2"

# The Pod root has to be a shared mount for a bind made after a sandbox
# exists (a subPath resolved when its container starts) to reach the
# sandbox's slave mount namespace.  With the in-memory adapter nothing is
# mounted; with real mounts the root becomes a shared self-bind once.
class PodVolumesPropagatingRootTest < Minitest::Test
  Node = Rubernetes::Node
  Mount = Rubernetes::Platform::Linux::Mount

  def test_the_in_memory_adapter_never_mounts
    Dir.mktmpdir do |dir|
      manager = Rubernetes::Volume::Manager.new(data_dir: dir, fsync: false)
      volumes = Node::PodVolumes.new(volume: manager, root: File.join(dir, "pods"), node_name: "worker-0")

      refute volumes.ensure_propagating_root!
      refute_predicate volumes, :propagating_root?
      assert_nil Mount.new.mountinfo_entry(File.join(dir, "pods"))
    end
  end

  def test_real_mounts_make_the_root_a_shared_self_bind_once
    skip "bind mounts need root" unless Process.uid.zero?

    Dir.mktmpdir do |dir|
      root = File.join(dir, "pods")
      security = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true),
                                                      require_openat2: true)
      manager = Rubernetes::Volume::Manager.new(data_dir: dir, fsync: false, mount_adapter: Rubernetes::Volume::NativeMountAdapter.new,
                                                path_security: security)
      volumes = Node::PodVolumes.new(volume: manager, root: root, node_name: "worker-0")
      begin
        assert volumes.ensure_propagating_root!
        assert_predicate volumes, :propagating_root?
        fields = Mount.new.mountinfo_entry(root)

        refute_nil fields, "the Pod root is a mount point"
        assert fields.any? { |field| field.start_with?("shared:") }, "the Pod root is shared: #{fields.inspect}"

        # Idempotent, and a second PodVolumes over the same root reuses it.
        assert volumes.ensure_propagating_root!
        again = Node::PodVolumes.new(volume: manager, root: root, node_name: "worker-0")

        assert again.ensure_propagating_root!
        refute Mount.new.ensure_shared_self_bind(target: root), "nothing left to change"

        # Lost propagation (something made the tree private) is repaired on
        # the next Pod start instead of being trusted from the first check.
        Mount.new.make_private(target: root, recursive: false)

        refute(Mount.new.mountinfo_entry(root).any? { |field| field.start_with?("shared:") })
        assert volumes.ensure_propagating_root!
        assert Mount.new.mountinfo_entry(root).any? { |field| field.start_with?("shared:") }, "re-shared"

        # Lookups from "/" cross the Pod-root mount only because it is a
        # registered boundary (kubelet MakeRShared + RESOLVE_NO_XDEV).
        assert_includes manager.path_security.resolver.mount_boundaries, root.delete_prefix("/")
        FileUtils.mkdir_p(File.join(root, "u1", "stages"))
        handle = manager.path_security.open(File.join(root, "u1", "stages"))

        assert handle.fd, "resolved through the boundary"
        handle.close
        strict = Rubernetes::Volume::PathSecurity.new(root: "/", adapter: Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true),
                                                      require_openat2: true)
        error = assert_raises(Rubernetes::Volume::PathSecurityError) { strict.open(File.join(root, "u1", "stages")) }
        assert_match(/cross-device|EXDEV/i, error.message)
      ensure
        system("umount", root, err: File::NULL)
      end
    end
  end
end
