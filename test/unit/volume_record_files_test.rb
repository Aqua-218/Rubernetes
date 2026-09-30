# frozen_string_literal: true

require "json"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/volume"

# The node's volume state is kept one file per record: a change rewrites its
# own record only.  Rewriting every record on every change made a Pod with 50
# ConfigMap volumes spend most of a minute in MountVolume.SetUp.
class VolumeRecordFilesTest < Minitest::Test
  Volume = Rubernetes::Volume

  def record(id, state: "Declared")
    now = Time.utc(2026, 9, 23)
    Volume::VolumeRecord.new(id: id, spec: {"size" => 1}, backend: "configMap", state: state, generation: 0,
                             attachments: {}, stages: {}, publishes: {}, operation: nil, capacity_bytes: nil,
                             created_at: now, updated_at: now)
  end

  def snapshot(directory)
    Dir.children(directory).sort.to_h do |name|
      stat = File.stat(File.join(directory, name))
      [name, [stat.ino, stat.mtime.to_r]]
    end
  end

  def test_a_change_writes_only_its_own_record
    Dir.mktmpdir do |dir|
      path = File.join(dir, "volumes.json")
      store = Volume::VolumeStore.new(path: path)
      300.times { |i| store["vol-#{i}"] = record("vol-#{i}") }
      before = snapshot("#{path}.d")

      assert_equal 300, before.length

      store["vol-7"] = record("vol-7", state: "Staged")
      after = snapshot("#{path}.d")
      changed = after.keys.select { |name| after[name] != before[name] }

      assert_equal 1, changed.length, "only vol-7's record file is replaced"
      refute_path_exists path, "no single all-records file is written"

      store.delete("vol-8")

      assert_equal 299, Dir.children("#{path}.d").length
      reloaded = Volume::VolumeStore.new(path: path)

      assert_equal "Staged", reloaded["vol-7"].state
      assert_nil reloaded["vol-8"]
      assert_equal 299, reloaded.values.length
    end
  end

  def test_volume_store_migrates_a_legacy_single_file
    Dir.mktmpdir do |dir|
      path = File.join(dir, "volumes.json")
      File.write(path, JSON.generate({"vol-a" => record("vol-a", state: "Published").to_h}))

      store = Volume::VolumeStore.new(path: path)

      assert_equal "Published", store["vol-a"].state
      refute_path_exists path, "the legacy file is removed once migrated"
      assert_equal "Published", Volume::VolumeStore.new(path: path)["vol-a"].state
    end
  end

  def test_operation_ledger_persists_entries_and_drops_retracted_ones
    Dir.mktmpdir do |dir|
      path = File.join(dir, "operations.json")
      ledger = Volume::OperationLedger.new(path: path, fsync: false)
      ledger.begin!(key: "vol-1", operation: "stage:/a", token: "t1", fingerprint: "f1")
      ledger.effecting!(key: "vol-1", operation: "stage:/a", token: "t1")
      ledger.begin!(key: "vol-2", operation: "create", token: "t2", fingerprint: "f2")
      ledger.finish!(key: "vol-2", operation: "create", token: "t2", result: {"ok" => true})

      reloaded = Volume::OperationLedger.new(path: path, fsync: false)

      assert_equal "effecting", reloaded.fetch(key: "vol-1", operation: "stage:/a").status
      assert_equal({"ok" => true}, reloaded.fetch(key: "vol-2", operation: "create").result)

      reloaded.retract!(key: "vol-2", operation: "create")

      assert_nil Volume::OperationLedger.new(path: path, fsync: false).fetch(key: "vol-2", operation: "create")
    end
  end

  def test_operation_ledger_migrates_a_legacy_single_file
    Dir.mktmpdir do |dir|
      path = File.join(dir, "operations.json")
      File.write(path, JSON.generate([{"key" => "vol-1", "operation" => "create", "token" => "t1", "fingerprint" => "f1",
                                       "payload" => nil, "status" => "unknown", "result" => nil, "error" => nil,
                                       "timestamp" => "2026-09-23T00:00:00.000000Z"}]))
      ledger = Volume::OperationLedger.new(path: path, fsync: false)

      assert_equal "unknown", ledger.fetch(key: "vol-1", operation: "create").status
      refute_path_exists path
      assert_equal "unknown", Volume::OperationLedger.new(path: path, fsync: false).fetch(key: "vol-1", operation: "create").status
    end
  end

  def test_mount_ledger_removals_reach_disk
    Dir.mktmpdir do |dir|
      path = File.join(dir, "mounts.json")
      File.write(path, JSON.generate([
                                       {"volumeId" => "v1", "source" => "/dev/sda1", "target" => "/t1", "mountId" => "m1", "filesystemUuid" => "u", "deviceId" => "8:1",
                                        "owner" => "o"},
                                       {"volumeId" => "v2", "source" => "/dev/sdb1", "target" => "/t2", "mountId" => "m2", "filesystemUuid" => "u2", "deviceId" => "8:17",
                                        "owner" => "o"}
                                     ]))
      ledger = Volume::MountIdentityLedger.new(path: path, fsync: false)

      assert_equal 2, ledger.entries.length
      refute_path_exists path

      assert_equal 1, ledger.remove_volume("v1")
      assert_equal 1, ledger.remove_target("/t2")
      assert_empty Volume::MountIdentityLedger.new(path: path, fsync: false).entries
      assert_empty Volume::RecordFiles.read(path)
    end
  end
end
