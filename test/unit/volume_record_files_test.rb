# frozen_string_literal: true

require "json"
require "open3"
require "rbconfig"
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
      changed = after.keys.reject { |name| after[name] == before[name] }

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

  def test_unencodable_record_leaves_only_the_last_committed_file
    Dir.mktmpdir do |dir|
      store = Volume::RecordFiles.new(path: File.join(dir, "records"), fsync: false)
      store.write("one", {"key" => "before"})
      assert_raises(JSON::GeneratorError) { store.write("one", {"key" => "\xff".b}) }

      assert_equal [File.basename(store.file_for("one"))], Dir.children(store.directory)
      assert_equal [{"key" => "before"}], store.load
    end
  end

  def test_recovery_reads_utf8_records_in_the_c_locale
    Dir.mktmpdir do |dir|
      path = File.join(dir, "records")
      legacy = {"payload" => "日本語"}
      current = {"payload" => "é"}
      File.binwrite(path, JSON.generate([legacy]))
      Volume::RecordFiles.new(path: path, fsync: false).write("current", current)

      output, error, status = Open3.capture3(
        {"LC_ALL" => "C"}, RbConfig.ruby, "-Ilib", "-rrubernetes/volume/record_files", "-e",
        "puts JSON.generate(Rubernetes::Volume::RecordFiles.read(ARGV.fetch(0)))", path
      )

      assert_predicate status, :success?, error
      assert_equal [legacy, current], JSON.parse(output)
    end
  end

  def test_failed_ledger_writes_do_not_advance_in_memory_state
    Dir.mktmpdir do |dir|
      path = File.join(dir, "operations")
      records = "#{path}.d"
      ledger = Volume::OperationLedger.new(path: path, fsync: false)
      ledger.begin!(key: "v", operation: "create", token: "first", fingerprint: "f")
      File.rename(records, "#{records}.saved")
      File.write(records, "unavailable")

      assert_raises(Volume::JournalError) { ledger.finish!(key: "v", operation: "create", token: "first", result: "done") }
      assert_raises(Volume::JournalError) { ledger.begin!(key: "other", operation: "create", token: "second", fingerprint: "f") }
      assert_raises(Volume::JournalError) { ledger.retract!(key: "v", operation: "create") }
      File.unlink(records)
      File.rename("#{records}.saved", records)
      [ledger, Volume::OperationLedger.new(path: path, fsync: false)].each do |view|
        assert_equal "pending", view.fetch_token(key: "v", token: "first").status
        assert_nil view.fetch_token(key: "other", token: "second")
      end
      ledger.finish!(key: "v", operation: "create", token: "first", result: "done")

      assert_equal "done", Volume::OperationLedger.new(path: path).fetch_token(key: "v", token: "first").result
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
                                       {"volumeId" => "v1", "source" => "/dev/sda1", "target" => "/t1", "mountId" => "m1", "filesystemUuid" => "u",
                                        "deviceId" => "8:1",
                                        "owner" => "o"},
                                       {"volumeId" => "v2", "source" => "/dev/sdb1", "target" => "/t2", "mountId" => "m2", "filesystemUuid" => "u2",
                                        "deviceId" => "8:17",
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
