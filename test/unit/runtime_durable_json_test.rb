# frozen_string_literal: true

require_relative "../test_helper"
require "digest"
require "json"
require "tmpdir"

class RuntimeDurableJSONTest < Minitest::Test
  Runtime = Rubernetes::Runtime

  def test_common_wal_rejects_top_level_duplicate_keys
    with_directory do |directory|
      line = valid_wal_line.gsub('"event":"state_transition"', '"event":"state_transition","event":"forged"')
      path = File.join(directory, "runtime.wal")
      File.write(path, line << "\n")

      assert_raises(Runtime::JournalCorruption) { Runtime::DurableWAL.new(path, fsync: false) }
    end
  end

  def test_common_wal_rejects_nested_duplicate_keys
    with_directory do |directory|
      line = valid_wal_line.gsub('"payload":{}', '"payload":{"nested":{"value":1,"value":2}}')
      path = File.join(directory, "runtime.wal")
      File.write(path, line << "\n")

      assert_raises(Runtime::JournalCorruption) { Runtime::DurableWAL.new(path, fsync: false) }
    end
  end

  def test_native_rollback_journal_rejects_duplicate_keys
    with_directory do |directory|
      line = valid_wal_line.gsub('"operation_id":"op"', '"operation_id":"op","operation_id":"forged"')
      path = File.join(directory, "ledger.jsonl")
      File.write(path, line << "\n")

      assert_raises(Runtime::Native::Support::JournalCorruption) do
        Runtime::Native::RollbackJournal.new(path, fsync: false)
      end
    end
  end

  def test_snapshot_rejects_nested_duplicate_keys
    with_directory do |directory|
      snapshot = valid_snapshot
      json = JSON.generate(snapshot).gsub('"payload":{}', '"payload":{"nested":{"value":1,"value":2}}')
      File.write(File.join(directory, "base.snapshot.json"), json << "\n")

      assert_raises(Runtime::SnapshotCorruption) do
        Runtime::AtomicSnapshotStore.new(directory, fsync: false).read("base")
      end
    end
  end

  def test_wal_rejects_torn_last_line
    with_directory do |directory|
      path = File.join(directory, "runtime.wal")
      File.write(path, valid_wal_line)

      assert_raises(Runtime::JournalCorruption) { Runtime::DurableWAL.new(path, fsync: false) }
    end
  end

  def test_native_rollback_journal_rejects_torn_last_line
    with_directory do |directory|
      path = File.join(directory, "ledger.jsonl")
      File.write(path, valid_wal_line)

      assert_raises(Runtime::Native::Support::JournalCorruption) do
        Runtime::Native::RollbackJournal.new(path, fsync: false)
      end
    end
  end

  def test_snapshot_rejects_torn_document
    with_directory do |directory|
      File.write(File.join(directory, "base.snapshot.json"), JSON.generate(valid_snapshot))

      assert_raises(Runtime::SnapshotCorruption) do
        Runtime::AtomicSnapshotStore.new(directory, fsync: false).read("base")
      end
    end
  end

  def test_durable_loaders_reject_oversized_records_and_documents
    with_directory do |directory|
      oversized_payload = "x" * Runtime::DurableWAL::MAX_RECORD_BYTES
      wal_path = File.join(directory, "runtime.wal")
      File.write(wal_path, JSON.generate("payload" => oversized_payload) << "\n")
      assert_raises(Runtime::JournalCorruption) { Runtime::DurableWAL.new(wal_path, fsync: false) }

      snapshot_path = File.join(directory, "base.snapshot.json")
      File.write(snapshot_path, ("{" + ("x" * Runtime::AtomicSnapshotStore::MAX_DOCUMENT_BYTES) + "}\n"))
      assert_raises(Runtime::SnapshotCorruption) do
        Runtime::AtomicSnapshotStore.new(directory, fsync: false).read("base")
      end
    end
  end

  def test_durable_loaders_reject_excessive_nesting
    with_directory do |directory|
      nested = {}
      (Runtime::DurableWAL::MAX_RECORD_DEPTH + 2).times { nested = {"nested" => nested} }
      path = File.join(directory, "runtime.wal")
      File.write(path, JSON.generate({"payload" => nested}, max_nesting: false) << "\n")
      assert_raises(Runtime::JournalCorruption) { Runtime::DurableWAL.new(path, fsync: false) }

      snapshot = valid_snapshot.merge("payload" => nested)
      File.write(File.join(directory, "base.snapshot.json"), JSON.generate(snapshot, max_nesting: false) << "\n")
      assert_raises(Runtime::SnapshotCorruption) do
        Runtime::AtomicSnapshotStore.new(directory, fsync: false).read("base")
      end
    end
  end

  def test_wal_rejects_invalid_hash_chain
    with_directory do |directory|
      path = File.join(directory, "runtime.wal")
      wal = Runtime::DurableWAL.new(path, fsync: false)
      wal.append(operation_id: "op", event: "state_transition", payload: {"to" => "Validated"})
      record = JSON.parse(File.binread(path)).merge("previous_digest" => "f" * 64)
      File.write(path, JSON.generate(record) << "\n")

      assert_raises(Runtime::JournalCorruption) { Runtime::DurableWAL.new(path, fsync: false) }
    end
  end

  def test_snapshot_rejects_invalid_checksum
    with_directory do |directory|
      store = Runtime::AtomicSnapshotStore.new(directory, fsync: false)
      store.write(snapshot_id: "base", state: "WorkloadStopped", identity: "base-id", payload: {})
      path = File.join(directory, "base.snapshot.json")
      snapshot = JSON.parse(File.binread(path), create_additions: false)
      snapshot["checksum"] = "0" * 64
      File.write(path, JSON.generate(snapshot) << "\n")

      assert_raises(Runtime::SnapshotCorruption) { store.read("base") }
    end
  end

  private

  def with_directory
    Dir.mktmpdir("runtime-durable-json-") { |directory| yield directory }
  end

  def valid_wal_line
    body = {
      "sequence" => 1,
      "operation_id" => "op",
      "event" => "state_transition",
      "payload" => {},
      "timestamp" => "2026-01-01T00:00:00.000000Z",
      "previous_digest" => Runtime::DurableWAL::EMPTY_DIGEST
    }
    body.merge("digest" => Digest::SHA256.hexdigest(JSON.generate(body))).then { |record| JSON.generate(record) }
  end

  def valid_snapshot
    body = {
      "schema" => Runtime::AtomicSnapshotStore::SCHEMA,
      "snapshot_id" => "base",
      "state" => "WorkloadStopped",
      "identity" => "base-id",
      "payload" => {}
    }
    body.merge("checksum" => Runtime::Canonical.digest(body))
  end
end
