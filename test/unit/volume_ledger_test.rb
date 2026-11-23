# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "rubernetes/volume"
require "tmpdir"

class VolumeLedgerTest < Minitest::Test
  Ledger = Rubernetes::Volume::MountIdentityLedger

  def test_partial_batch_removal_retains_the_mount_whose_record_could_not_be_deleted
    Dir.mktmpdir do |dir|
      path = File.join(dir, "mounts")
      ledger = Ledger.new(path: path, fsync: false)
      register_mount(ledger, target: "/one", mount_id: "101")
      second = register_mount(ledger, target: "/two", mount_id: "102")
      target = Rubernetes::Volume::RecordFiles.new(path: path).file_for(ledger.identity_for(second))
      backup = File.join(dir, "second.saved")
      File.rename(target, backup)
      Dir.mkdir(target)

      assert_raises(Rubernetes::Volume::JournalError) { ledger.remove_volume("volume") }
      assert_equal [second], ledger.entries
      Dir.rmdir(target)
      File.rename(backup, target)

      assert_equal [second], Ledger.new(path: path).entries
      assert_equal 1, ledger.remove_volume("volume")
      assert_empty Ledger.new(path: path).entries
    end
  end

  def test_bind_mount_without_uuid_persists_kernel_identity_and_canonical_paths
    ledger = Ledger.new
    record = register_mount(ledger, volume_id: "bind", source: "/var/lib/../source",
                                    source_identity: "/var/lib/../source", root: "/mnt/../",
                                    filesystem: "bind", mount_id: "101", device_id: "0:42")

    assert_nil record.fetch("filesystemUuid")
    refute record.fetch("filesystemUuidAvailable")
    assert_equal "/", record.fetch("root")
    assert_equal "/var/source", record.fetch("sourceIdentity")
    assert_equal 2, record.fetch("identityVersion")
  end

  def test_tmpfs_mount_without_uuid_is_owned_by_mountinfo_identity
    ledger = Ledger.new
    register_mount(ledger, volume_id: "tmpfs", source: "tmpfs", source_identity: "tmpfs",
                           target: "/tmpfs", filesystem: "tmpfs", mount_id: "102", device_id: "0:43")

    report = ledger.reconcile([
                                {"mountId" => "102", "filesystemUuid" => nil, "filesystemUuidAvailable" => false,
                                 "deviceId" => "0:43", "root" => "/", "source" => "tmpfs", "target" => "/tmpfs",
                                 "filesystem" => "tmpfs"}
                              ])

    assert_equal 1, report.fetch("owned").length
    assert_empty report.fetch("identityMismatches")
    assert_empty report.fetch("orphans")
  end

  def test_persistent_block_ext4_and_xfs_mounts_require_a_real_uuid
    %w[ext4 xfs].each do |filesystem|
      ledger = Ledger.new
      error = assert_raises(Rubernetes::Volume::MountIdentityError) do
        register_mount(ledger, volume_id: filesystem, source: "/dev/sda1",
                               source_identity: "/dev/sda1", filesystem: filesystem,
                               mount_id: filesystem == "ext4" ? "103" : "104",
                               device_id: filesystem == "ext4" ? "8:1" : "8:2")
      end
      assert_match(/filesystem UUID/, error.message)
      assert_empty ledger.entries
    end
  end

  def test_unavailable_uuid_requires_explicit_source_identity
    ledger = Ledger.new
    assert_raises(Rubernetes::Volume::MountIdentityError) do
      register_mount(ledger, source_identity: nil, filesystem: "bind")
    end
  end

  def test_a_storage_device_can_stage_for_multiple_pods_and_survive_reload
    Dir.mktmpdir("volume-ledger-shared") do |directory|
      path = File.join(directory, "mounts.json")
      fields = {source: "/dev/sdb", source_identity: "/dev/sdb",
                filesystem: "ext4", filesystem_uuid: "disk-uuid", filesystem_uuid_available: true,
                device_id: "8:16", shared_source: "san-volume"}
      ledger = Ledger.new(path: path, fsync: false)
      register_mount(ledger, **fields, volume_id: "a", target: "/a", mount_id: "100")
      register_mount(ledger, **fields, volume_id: "b", target: "/b", mount_id: "101")

      assert_equal %w[a b], Ledger.new(path: path, fsync: false).entries.map { |entry| entry.fetch("volumeId") }.sort
      assert_raises(Rubernetes::Volume::MountIdentityError) do
        register_mount(ledger, **fields, device_id: "8:32", volume_id: "clone", target: "/clone", mount_id: "102")
      end
      assert_raises(Rubernetes::Volume::MountIdentityError) do
        register_mount(ledger, **fields, shared_source: "other", volume_id: "other", target: "/other", mount_id: "103")
      end
    end
  end

  def test_mount_id_conflict_cannot_be_hidden_by_changed_source_identity
    ledger = Ledger.new
    register_mount(ledger, volume_id: "first", source: "/source", source_identity: "/source",
                           target: "/first", mount_id: "105", device_id: "0:44", filesystem: "bind")

    assert_raises(Rubernetes::Volume::MountIdentityError) do
      register_mount(ledger, volume_id: "second", source: "/other", source_identity: "/other",
                             target: "/second", mount_id: "105", device_id: "0:45", filesystem: "bind")
    end
    assert_equal 1, ledger.entries.length
  end

  def test_strict_identity_survives_reload_and_reconcile
    Dir.mktmpdir("volume-ledger") do |directory|
      path = File.join(directory, "mounts.json")
      ledger = Ledger.new(path: path, fsync: false)
      record = register_mount(ledger, volume_id: "reload", source: "/source",
                                      source_identity: "/source", target: "/reload", root: "/",
                                      filesystem: "bind", mount_id: "106", device_id: "0:46")

      persisted = Rubernetes::Volume::RecordFiles.read(path).fetch(0)

      assert_equal "/", persisted.fetch("root")
      assert_equal "/source", persisted.fetch("sourceIdentity")
      refute persisted.fetch("filesystemUuidAvailable")

      reloaded = Ledger.new(path: path, fsync: false)

      assert_equal record, reloaded.entries.fetch(0)
      report = reloaded.reconcile([persisted])

      assert_equal 1, report.fetch("owned").length
      assert_empty report.fetch("missing")
      assert_empty report.fetch("identityMismatches")
    end
  end

  def test_legacy_record_reloads_and_reconciles_by_legacy_identity
    Dir.mktmpdir("volume-ledger-legacy") do |directory|
      path = File.join(directory, "mounts.json")
      File.write(path, JSON.generate([
                                       {"volumeId" => "legacy", "source" => "/dev/sda1", "target" => "/legacy",
                                        "mountId" => "m1", "filesystemUuid" => "fs1", "deviceId" => "8:1", "owner" => "legacy"}
                                     ]))

      ledger = Ledger.new(path: path, fsync: false)
      record = ledger.entries.fetch(0)

      assert_equal 1, record.fetch("identityVersion")
      assert_equal "/dev/sda1", record.fetch("sourceIdentity")
      assert record.fetch("filesystemUuidAvailable")

      report = ledger.reconcile([
                                  {"mountId" => "m1", "filesystemUuid" => "fs1", "deviceId" => "8:1",
                                   "root" => "/", "source" => "/dev/sda1", "target" => "/legacy",
                                   "filesystem" => "ext4", "filesystemUuidAvailable" => true}
                                ])

      assert_equal 1, report.fetch("owned").length
      assert_empty report.fetch("orphans")
    end
  end

  private

  def register_mount(ledger, **overrides)
    ledger.register(volume_id: "volume", source: "/source", target: "/tmp/target", mount_id: "100",
                    filesystem_uuid: nil, device_id: "0:41", owner: "volume", root: "/",
                    source_identity: "/source", filesystem_uuid_available: false, filesystem: "bind", **overrides)
  end
end
