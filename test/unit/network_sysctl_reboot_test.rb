# frozen_string_literal: true

require_relative "../test_helper"
require "fileutils"
require "tmpdir"
require "rubernetes/network"

# A host reboot resets every sysctl to its boot default and ends every
# sandbox that referenced the node's forwarding sysctls.  The journal written
# under the previous boot must not be verified against the new kernel.
class NetworkSysctlRebootTest < Minitest::Test
  VALUES = Rubernetes::Network::SysctlManager::STATIC_TARGETS.merge(
    "net/ipv4/conf/rbr0/rp_filter" => "0", "net/ipv6/conf/rbr0/forwarding" => "1"
  ).freeze

  def test_a_journal_from_a_previous_boot_owns_nothing
    Dir.mktmpdir("network-sysctl-reboot-") do |directory|
      write_all(directory, "9")
      manager(directory, boot_id: "boot-1").acquire(owner: "pod-a", bridge: "rbr0")

      # The reboot: kernel defaults again, and they differ from both the
      # journaled original and the target.
      write_all(directory, "2")
      restarted = manager(directory, boot_id: "boot-2")

      assert_equal "inactive", restarted.snapshot.fetch("state")
      assert_equal 0, restarted.snapshot.fetch("refcount")
      restarted.recover
      restarted.acquire(owner: "pod-b", bridge: "rbr0")
      assert(VALUES.all? { |relative, target| File.binread(File.join(directory, relative)).strip == target })
      restarted.release(owner: "pod-b")
      assert(VALUES.all? { |relative, _target| File.binread(File.join(directory, relative)).strip == "2" })
    end
  end

  def test_a_journal_from_this_boot_is_still_verified
    Dir.mktmpdir("network-sysctl-reboot-") do |directory|
      write_all(directory, "9")
      manager(directory, boot_id: "boot-1").acquire(owner: "pod-a", bridge: "rbr0")
      write_all(directory, "2")
      restarted = manager(directory, boot_id: "boot-1")

      assert_equal "active", restarted.snapshot.fetch("state")
      assert_raises(Rubernetes::Network::OwnershipError) { restarted.acquire(owner: "pod-b", bridge: "rbr0") }
    end
  end

  private

  def manager(directory, boot_id:)
    Rubernetes::Network::SysctlManager.new(state_path: File.join(directory, "state.json"), root: directory, fsync: false,
                                           boot_id: boot_id)
  end

  def write_all(directory, value)
    VALUES.each_key do |relative|
      path = File.join(directory, relative)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, "#{value}\n")
    end
  end
end
