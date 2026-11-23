# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/platform/linux/kubelet_cgroup_layout"

class KubeletCgroupLayoutTest < Minitest::Test
  Linux = Rubernetes::Platform::Linux
  UID = "f82b6839-0627-499e-9bf5-5bb55c467380"
  SANDBOX = "pod#{UID}-aaa000000001".freeze

  def test_uid_parent_follows_cgroupfs_qos_and_leaves_keep_generation_identity
    layout = Linux::KubeletCgroupLayout.new("/delegated")

    {"guaranteed" => "", "burstable" => "burstable", "besteffort" => "besteffort"}.each do |qos, tier|
      base = File.join("/delegated/kubepods", tier, "pod#{UID}")
      path = layout.path(qos: qos, pod_id: SANDBOX, container_id: "sandbox", pod_uid: UID, sandbox: nil)

      assert_equal File.join(base, "rbn-aaa000000001-sandbox"), path
      original = layout.handle(path)

      assert_equal "cgroup:#{SANDBOX}", original.identity
      assert_equal qos, original.qos

      container = layout.path(qos: "besteffort", pod_id: SANDBOX, container_id: "container-1", pod_uid: nil, sandbox: original)

      assert_equal File.join(base, "rbn-aaa000000001-container-1"), container
      assert_equal "cgroup:#{SANDBOX}:container-1", layout.handle(container).identity
      refute layout.handle(File.join(base, "another-runtime-scope"))
    end
  end

  def test_upgrade_reads_legacy_and_canonical_paths_with_original_identities
    Dir.mktmpdir("cgroup-layout-") do |root|
      layout = Linux::KubeletCgroupLayout.new(root)
      adapter = Linux::CgroupV2.new(root: root, kubelet_layout: layout)
      legacy = File.join(root, "rubernetes", "burstable", SANDBOX, "sandbox")
      canonical = layout.path(qos: "guaranteed", pod_id: SANDBOX, container_id: "sandbox", pod_uid: UID, sandbox: nil)
      FileUtils.mkdir_p([legacy, canonical])

      assert_equal "cgroup:#{SANDBOX}", adapter.lookup(legacy).identity
      assert_equal "cgroup:#{SANDBOX}", adapter.lookup(canonical).identity
      assert_equal [canonical, legacy].sort, adapter.resources.map(&:path).sort
      assert_nil layout.path(qos: "burstable", pod_id: SANDBOX, container_id: "container-1", pod_uid: UID, sandbox: adapter.lookup(legacy))
    end
  end

  def test_disabling_new_qos_layout_still_reads_an_existing_canonical_sandbox
    layout = Linux::KubeletCgroupLayout.new("/delegated", enabled: false)

    assert_nil layout.path(qos: "burstable", pod_id: SANDBOX, container_id: "sandbox", pod_uid: UID, sandbox: nil)
    parent = "/delegated/kubepods/burstable/pod#{UID}"
    recovered = layout.handle(File.join(parent, "rbn-aaa000000001-sandbox"))

    assert_equal File.join(parent, "rbn-aaa000000001-container-1"),
                 layout.path(qos: "burstable", pod_id: SANDBOX, container_id: "container-1", pod_uid: nil, sandbox: recovered)
    assert_raises(Linux::CgroupV2::InvalidPath) do
      layout.path(qos: "burstable", pod_id: "pod#{UID}-aaa000000002", container_id: "container-1", pod_uid: UID, sandbox: recovered)
    end
  end

  def test_tier_lock_is_released_while_a_concurrent_fork_still_inherits_the_descriptor
    Dir.mktmpdir("cgroup-layout-lock-") do |root|
      layout = Linux::KubeletCgroupLayout.new(root)
      adapter = Linux::CgroupV2.new(root: root, kubelet_layout: layout)
      target = layout.path(qos: "besteffort", pod_id: SANDBOX, container_id: "sandbox", pod_uid: UID, sandbox: nil)
      reader, writer = IO.pipe

      adapter.send(:with_kubelet_tier_lock, target, create: true) do
        @lock_witness = fork do
          writer.close
          reader.read
        end
        reader.close
      end

      File.open(File.dirname(target, 2), File::RDONLY) do |candidate|
        assert_equal 0, candidate.flock(File::LOCK_EX | File::LOCK_NB)
      end
    ensure
      writer&.close
      Process.wait(@lock_witness) if @lock_witness
    end
  end

  def test_reservation_creates_the_pod_parent_before_start_and_releases_it_on_error
    Dir.mktmpdir("cgroup-layout-pending-") do |root|
      layout = Linux::KubeletCgroupLayout.new(root)
      FileUtils.mkdir_p(layout.tier_paths)
      owner = Linux::KubeletCgroupLayout.reservation_owner("worker-0")
      parent = File.join(root, "kubepods", "burstable", "pod#{UID}")

      assert_raises(RuntimeError) do
        layout.with_reservation(UID, "burstable", owner) do
          assert_path_exists parent
          assert_empty layout.handles
          raise "image pull failed"
        end
      end
      refute_path_exists parent
    end
  end

  def test_reservation_cleanup_does_not_rmdir_a_parent_with_a_sandbox
    Dir.mktmpdir("cgroup-layout-held-") do |root|
      layout = Linux::KubeletCgroupLayout.new(root)
      owner = Linux::KubeletCgroupLayout.reservation_owner("worker-0")
      leaf = layout.path(qos: "burstable", pod_id: SANDBOX, container_id: "sandbox", pod_uid: UID, sandbox: nil)
      FileUtils.mkdir_p(leaf)
      parent = File.dirname(leaf)
      original = Dir.method(:rmdir)
      rmdir = lambda do |path|
        # cgroupfs reports EBUSY when a Pod still has an attached child.
        raise Errno::EBUSY if path == parent

        original.call(path)
      end

      Dir.stub(:rmdir, rmdir) do
        layout.with_reservation(UID, "burstable", owner) { assert_path_exists leaf }
      end

      assert_equal [File.basename(leaf)], Dir.children(parent)
    end
  end
end
