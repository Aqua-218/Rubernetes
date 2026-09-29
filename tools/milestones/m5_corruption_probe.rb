#!/usr/bin/env ruby
# frozen_string_literal: true

# WAL/snapshot corruption corpus (M5 exit criterion 3).  Each case damages
# real files written by the production WAL/SnapshotStore and records how the
# production reader reacts.  Disk-full is produced on a real tmpfs mounted
# with a tiny size limit (L2); short writes and fsync errors are injected
# through the L1 device contract because the kernel cannot be asked to fail
# fsync on demand.  Every case must fail closed: no partial application, no
# acknowledgement after the failure, and an explicit error class.

require "fileutils"
require "tmpdir"
require "open3"

require_relative "m5_probe_support"
$LOAD_PATH.unshift File.join(M5ProbeSupport::ROOT, "lib")
require "rubernetes/consensus"

module M5CorruptionProbe
  C = Rubernetes::Consensus

  class FaultDevice
    attr_accessor :fail_fsync, :short_write

    def initialize(path)
      @inner = C::WAL::FileDevice.new(path)
    end

    def size = @inner.size

    def write(bytes)
      @short_write ? @inner.write(bytes.byteslice(0, [bytes.bytesize - 3, 1].max)) : @inner.write(bytes)
    end

    def fsync
      raise Errno::EIO, "injected fsync failure" if @fail_fsync

      @inner.fsync
    end

    def truncate(length) = @inner.truncate(length)
    def close = @inner.close
  end

  module_function

  def populate(dir, entries: 20)
    storage = C::Storage.new(dir)
    storage.log.save_hard_state(term: 2, voted_for: "n1")
    storage.log.append((1..entries).map { |index| C::Log::Entry.new(index: index, term: 2, command: {"type" => "create", "key" => "k/#{index}", "object" => {"metadata" => {"name" => "o#{index}"}}, "request_uid" => "r#{index}"}) })
    storage.close
  end

  def outcome(name)
    yield
    {"id" => name, "error" => nil, "fail_closed" => false}
  rescue C::Error => error
    {"id" => name, "error" => error.class.name, "message" => error.message, "fail_closed" => true}
  end

  def wal_cases
    cases = []
    Dir.mktmpdir("m5-wal") do |dir|
      populate(dir)
      storage = C::Storage.new(dir)
      path = storage.wal_path
      storage.close
      original = File.binread(path)
      record_offset = C::WAL::HEADER_BYTES + C::WAL::RECORD_HEADER_BYTES + 5
      variants = {
        "wal_bit_flip_middle" => original.dup.tap { |b| b.setbyte(record_offset, b.getbyte(record_offset) ^ 0x01) },
        "wal_torn_tail" => original.byteslice(0, original.bytesize - 7),
        "wal_zero_filled_tail" => original + ("\0" * 64),
        "wal_length_overflow" => original + [C::WAL::MAX_RECORD_BYTES + 1, 0, 2].pack("NNC"),
        "wal_magic_mismatch" => "BADMAGIC" + original.byteslice(8..),
        "wal_truncated_header" => original.byteslice(0, 6),
        "wal_swapped_records" => original.byteslice(0, C::WAL::HEADER_BYTES) + original.byteslice(C::WAL::HEADER_BYTES..).reverse
      }
      variants.each do |name, bytes|
        File.binwrite(path, bytes)
        strict = outcome(name) { C::Storage.new(dir, recover_torn_tail: false).close }
        recovered = outcome("#{name}_with_tail_recovery") { C::Storage.new(dir, recover_torn_tail: true).close }
        expected_recoverable = %w[wal_torn_tail wal_zero_filled_tail].include?(name)
        cases << strict.merge(
          "expected" => "fail_closed",
          "tail_recovery_outcome" => recovered["error"] || "recovered",
          "recoverable_with_explicit_tail_recovery" => expected_recoverable,
          "passed" => strict["fail_closed"] && (expected_recoverable ? recovered["error"].nil? : recovered["fail_closed"]),
          "measurement_level" => "L2"
        )
        File.binwrite(path, original)
      end
      # After explicit tail recovery no acknowledged record is lost: entries
      # 1..19 remain, entry 20 (the torn record) was never acknowledged in
      # this scenario because a torn record is by construction one whose
      # fsync did not complete.
      File.binwrite(path, variants["wal_torn_tail"])
      storage = C::Storage.new(dir, recover_torn_tail: true)
      cases << {"id" => "wal_torn_tail_preserves_durable_prefix", "last_index" => storage.log.last_index,
                "recovery" => storage.recovery, "passed" => storage.log.last_index == 19 && storage.recovery.length == 1,
                "measurement_level" => "L2"}
      storage.close
    end
    cases
  end

  def snapshot_cases
    cases = []
    Dir.mktmpdir("m5-snap") do |dir|
      store = C::SnapshotStore.new(dir)
      machine = C::KVStateMachine.new
      10.times { |index| machine.apply(index + 1, {"type" => "create", "key" => "k/#{index}", "object" => {"metadata" => {"name" => "o#{index}"}}, "leader_time" => 1.0}) }
      metadata = store.write(state: machine.snapshot, index: 10, term: 1, membership: {"voters" => %w[a b c], "learners" => []})
      original = File.binread(metadata.path)
      variants = {
        "snapshot_truncated" => original.byteslice(0, original.bytesize / 2),
        "snapshot_state_bit_flip" => original.dup.tap { |b| b.setbyte(original.bytesize - 40, b.getbyte(original.bytesize - 40) ^ 0x10) },
        "snapshot_header_bit_flip" => original.dup.tap { |b| b.setbyte(16, b.getbyte(16) ^ 0x10) },
        "snapshot_trailer_bit_flip" => original.dup.tap { |b| b.setbyte(original.bytesize - 1, b.getbyte(original.bytesize - 1) ^ 0x01) },
        "snapshot_magic_mismatch" => "XXXXXXXX" + original.byteslice(8..),
        "snapshot_zeroed" => "\0" * original.bytesize,
        "snapshot_empty" => ""
      }
      variants.each do |name, bytes|
        File.binwrite(metadata.path, bytes)
        result = outcome(name) { store.latest(strict: true) }
        # A restore into the state machine must not happen either.
        applied = outcome("#{name}_restore") do
          snapshot, _ = store.latest(strict: true)
          C::KVStateMachine.new.restore(snapshot.state) if snapshot
        end
        cases << result.merge("expected" => "fail_closed", "restore_blocked" => applied["fail_closed"],
                              "passed" => result["fail_closed"] && applied["fail_closed"], "measurement_level" => "L2")
        File.binwrite(metadata.path, original)
      end
      # Corrupted compressed state inside a structurally valid file.
      bad_state = store.write(state: "not-zlib".b, index: 11, term: 1, membership: {"voters" => %w[a], "learners" => []})
      result = outcome("snapshot_state_not_decodable") do
        snapshot, _ = store.latest(strict: true)
        C::KVStateMachine.new.restore(snapshot.state)
      end
      cases << result.merge("expected" => "fail_closed", "passed" => result["fail_closed"], "measurement_level" => "L2")
      File.delete(bad_state.path)
    end
    cases
  end

  def injected_cases
    cases = []
    {short_write: C::ShortWrite, fail_fsync: C::FsyncFailed}.each do |fault, klass|
      Dir.mktmpdir("m5-inject") do |dir|
        device = nil
        storage = C::Storage.new(dir, device_factory: ->(path) { device = FaultDevice.new(path) })
        storage.log.append([C::Log::Entry.new(index: 1, term: 1, command: {"type" => "noop"})])
        device.public_send("#{fault}=", true)
        result = outcome(fault.to_s) { storage.log.append([C::Log::Entry.new(index: 2, term: 1, command: {"type" => "noop"})]) }
        after = outcome("#{fault}_subsequent_append") { storage.log.append([C::Log::Entry.new(index: 2, term: 1, command: {"type" => "noop"})]) }
        storage.close
        device.public_send("#{fault}=", false)
        reopened = C::Storage.new(dir, recover_torn_tail: true)
        cases << result.merge(
          "expected_error" => klass.name,
          "subsequent_append_refused" => after["fail_closed"],
          "durable_entries_after_reopen" => reopened.log.last_index,
          # A short write leaves a torn (never acknowledged) record that
          # recovery removes.  A failed fsync leaves bytes whose durability
          # is unknown; the WAL refuses further appends and the entry was
          # never acknowledged, so both 1 and 2 are legitimate on reopen.
          "passed" => result["error"] == klass.name && after["fail_closed"] &&
                      (fault == :short_write ? reopened.log.last_index == 1 : [1, 2].include?(reopened.log.last_index)),
          "measurement_level" => "L1"
        )
        reopened.close
      end
    end
    cases
  end

  # Real ENOSPC on a size-limited tmpfs (requires root, which the evidence
  # capture already needs for the kernel probes).
  def disk_full_case
    mount_point = Dir.mktmpdir("m5-enospc")
    mounted = system("mount", "-t", "tmpfs", "-o", "size=256k", "m5-enospc", mount_point, err: File::NULL)
    return {"id" => "wal_disk_full_tmpfs", "passed" => false, "error" => "tmpfs mount unavailable", "measurement_level" => "L2"} unless mounted

    begin
      storage = C::Storage.new(File.join(mount_point, "node"))
      big = "x" * 4096
      appended = 0
      error = nil
      begin
        200.times do |index|
          storage.log.append([C::Log::Entry.new(index: index + 1, term: 1, command: {"type" => "create", "key" => "k/#{index}", "object" => {"data" => big}})])
          appended += 1
        end
      rescue C::DurabilityError => raised
        error = raised
      end
      refused = outcome("disk_full_subsequent_append") { storage.log.append([C::Log::Entry.new(index: appended + 1, term: 1, command: {"type" => "noop"})]) }
      storage.close
      # Free space and reopen: every acknowledged entry (appended) is intact.
      reopened = C::Storage.new(File.join(mount_point, "node"), recover_torn_tail: true)
      durable = reopened.log.last_index
      reopened.close
      {
        "id" => "wal_disk_full_tmpfs",
        "acknowledged_entries" => appended,
        "error" => error&.class&.name,
        "message" => error&.message,
        "subsequent_append_refused" => refused["fail_closed"],
        "durable_entries_after_reopen" => durable,
        "tmpfs_size" => "256k",
        # tmpfs reports exhaustion either as ENOSPC or as a partial write;
        # both are durability failures that close the WAL.
        "passed" => (error.is_a?(C::DiskFull) || error.is_a?(C::ShortWrite)) && refused["fail_closed"] && durable == appended,
        "measurement_level" => "L2"
      }
    ensure
      system("umount", mount_point, err: File::NULL)
      FileUtils.rm_rf(mount_point)
    end
  end

  def backup_case
    Dir.mktmpdir("m5-backup") do |dir|
      data = File.join(dir, "data")
      populate(data, entries: 5)
      backup = File.join(dir, "backup")
      manifest = C::Backup.create(data, backup)
      restored = File.join(dir, "restored")
      C::Backup.restore(backup, restored)
      storage = C::Storage.new(restored)
      ok = storage.log.last_index == 5 && storage.log.current_term == 2
      storage.close
      wal_copy = Dir.glob(File.join(backup, "*.rbwal")).first
      bytes = File.binread(wal_copy)
      bytes.setbyte(30, bytes.getbyte(30) ^ 1)
      File.binwrite(wal_copy, bytes)
      tampered = outcome("backup_tampered") { C::Backup.restore(backup, File.join(dir, "restored2")) }
      {"id" => "backup_restore_round_trip", "manifest_files" => manifest["files"].length, "restored_last_index" => 5,
       "tampered_backup_rejected" => tampered["fail_closed"], "passed" => ok && tampered["fail_closed"], "measurement_level" => "L2"}
    end
  end

  def run
    started_at = M5ProbeSupport.now
    cases = wal_cases + snapshot_cases + injected_cases + [disk_full_case, backup_case]
    M5ProbeSupport.emit(M5ProbeSupport.report(
      kind: "m5_corruption_corpus", measurement_level: "integration_tested", started_at: started_at, cases: cases,
      extra: {"sources" => M5ProbeSupport.source_files(%w[lib/rubernetes/consensus/wal.rb lib/rubernetes/consensus/snapshot.rb
                                                          lib/rubernetes/consensus/storage.rb lib/rubernetes/consensus/backup.rb]),
              "required_case_ids" => %w[wal_bit_flip_middle wal_torn_tail wal_length_overflow snapshot_truncated snapshot_state_bit_flip
                                        short_write fail_fsync wal_disk_full_tmpfs backup_restore_round_trip]}
    ))
  end
end

M5CorruptionProbe.run if $PROGRAM_NAME == __FILE__
