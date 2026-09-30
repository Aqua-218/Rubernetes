# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/volume"

# A ledger entry whose cleanup never finished keeps a kernel mount id the
# kernel has since handed to a different mount.  With a liveness check the
# stale entry is dropped instead of refusing every later mount that draws the
# same id; without one the ledger stays strict.
class MountLedgerStaleConflictTest < Minitest::Test
  Ledger = Rubernetes::Volume::MountIdentityLedger

  def register(ledger, volume_id:, target:, mount_id:)
    ledger.register(volume_id: volume_id, source: "tmpfs", target: target, mount_id: mount_id, filesystem_uuid: nil,
                    device_id: "0:#{mount_id}", owner: "volume:#{volume_id}", root: "/", source_identity: "tmpfs",
                    filesystem_uuid_available: false, filesystem: "tmpfs")
  end

  def test_a_dead_entry_with_a_recycled_id_is_dropped_and_the_new_mount_registers
    ledger = Ledger.new(live_check: ->(_mount) { false })
    register(ledger, volume_id: "vol-old", target: "/mnt/old", mount_id: "4800")

    register(ledger, volume_id: "vol-new", target: "/mnt/new", mount_id: "4800")

    assert_equal(%w[vol-new], ledger.entries.map { |entry| entry.fetch("volumeId") })
    assert_equal 1, ledger.stale_dropped
  end

  def test_a_live_entry_with_the_same_id_still_conflicts
    ledger = Ledger.new(live_check: ->(_mount) { true })
    register(ledger, volume_id: "vol-old", target: "/mnt/old", mount_id: "4800")

    error = assert_raises(Rubernetes::Volume::MountIdentityError) do
      register(ledger, volume_id: "vol-new", target: "/mnt/new", mount_id: "4800")
    end
    assert_match(/vol-old/, error.message)
  end

  def test_without_a_liveness_check_the_ledger_stays_strict
    ledger = Ledger.new
    register(ledger, volume_id: "vol-old", target: "/mnt/old", mount_id: "4800")

    assert_raises(Rubernetes::Volume::MountIdentityError) do
      register(ledger, volume_id: "vol-new", target: "/mnt/new", mount_id: "4800")
    end
  end

  def test_the_manager_wires_the_check_to_the_mount_adapter
    Dir.mktmpdir("ledger-live") do |directory|
      adapter = Rubernetes::Volume::NativeMountAdapter.new(mount: Object.new, mountinfo_reader: -> { "" })
      manager = Rubernetes::Volume::Manager.new(data_dir: directory, mount_adapter: adapter, fsync: false)
      mount = Ledger::Mount.new(volume_id: "v", target: "/mnt/gone", mount_id: "4800")

      assert_equal false, manager.mount_ledger.live_check.call(mount)
    end
  end
end
