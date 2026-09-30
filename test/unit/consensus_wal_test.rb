# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/consensus"

class ConsensusWALTest < Minitest::Test
  C = Rubernetes::Consensus

  # Level L1 device with injectable faults.
  class FaultyDevice
    attr_accessor :fail_fsync, :short_write, :disk_full

    def initialize(path)
      @inner = C::WAL::FileDevice.new(path)
    end

    def size = @inner.size

    def write(bytes)
      raise Errno::ENOSPC, "no space" if @disk_full

      if @short_write
        @inner.write(bytes.byteslice(0, bytes.bytesize / 2))
      else
        @inner.write(bytes)
      end
    end

    def fsync
      raise Errno::EIO, "fsync failed" if @fail_fsync

      @inner.fsync
    end

    def truncate(length) = @inner.truncate(length)
    def close = @inner.close
  end

  def with_dir(&)
    Dir.mktmpdir("wal-test", &)
  end

  def test_records_survive_reopen_and_are_checksummed
    with_dir do |dir|
      path = File.join(dir, "wal")
      wal = C::WAL.new(path)
      wal.append([C::WAL::TYPE_HARD_STATE, {"term" => 3, "voted_for" => "n2"}])
      wal.append([[C::WAL::TYPE_ENTRY, {"index" => 1, "term" => 3, "command" => {"type" => "noop"}}],
                  [C::WAL::TYPE_ENTRY, {"index" => 2, "term" => 3, "command" => {"type" => "noop"}}]])
      wal.close

      reopened = C::WAL.new(path)

      assert_equal 3, reopened.records.length
      assert_equal({"term" => 3, "voted_for" => "n2"}, reopened.records.first.payload)
      assert_equal 2, reopened.records.last.payload["index"]
      refute reopened.recovery_report.truncated
    end
  end

  # A CRD description with "—" made the canonical JSON UTF-8; the record header is
  # BINARY and String#+ across them raised inside the flusher, failing every flush.
  def test_non_ascii_payloads_are_written_and_read_back
    with_dir do |dir|
      path = File.join(dir, "wal")
      command = {"type" => "put", "object" => {"description" => "brackets — e.g [2001:db8::1] — 日本語"}}
      wal = C::WAL.new(path)
      wal.append([C::WAL::TYPE_ENTRY, {"index" => 1, "term" => 1, "command" => command}])
      wal.close

      reopened = C::WAL.new(path)

      assert_equal command, reopened.records.last.payload["command"]
      refute reopened.recovery_report.truncated
    end
  end

  def test_middle_corruption_is_fail_closed
    with_dir do |dir|
      path = File.join(dir, "wal")
      wal = C::WAL.new(path)
      wal.append([[C::WAL::TYPE_ENTRY, {"index" => 1, "term" => 1, "command" => {"a" => 1}}],
                  [C::WAL::TYPE_ENTRY, {"index" => 2, "term" => 1, "command" => {"a" => 2}}]])
      wal.close
      bytes = File.binread(path)
      offset = C::WAL::HEADER_BYTES + C::WAL::RECORD_HEADER_BYTES + 3
      bytes.setbyte(offset, bytes.getbyte(offset) ^ 0xFF)
      File.binwrite(path, bytes)

      error = assert_raises(C::WALCorruption) { C::WAL.new(path, recover_torn_tail: true) }
      assert_match(/checksum mismatch/, error.message)
      refute_kind_of C::TornWAL, error
    end
  end

  def test_torn_tail_requires_explicit_recovery_and_is_reported
    with_dir do |dir|
      path = File.join(dir, "wal")
      wal = C::WAL.new(path)
      wal.append([[C::WAL::TYPE_ENTRY, {"index" => 1, "term" => 1, "command" => {"a" => 1}}],
                  [C::WAL::TYPE_ENTRY, {"index" => 2, "term" => 1, "command" => {"a" => 2}}]])
      wal.close
      bytes = File.binread(path)
      File.binwrite(path, bytes.byteslice(0, bytes.bytesize - 4))

      assert_raises(C::TornWAL) { C::WAL.new(path) }
      recovered = C::WAL.new(path, recover_torn_tail: true)

      assert_equal 1, recovered.records.length
      assert recovered.recovery_report.truncated
      assert_equal 4 - 4 + (C::WAL::RECORD_HEADER_BYTES + C::WAL.encode_record(C::WAL::TYPE_ENTRY, {"index" => 2, "term" => 1, "command" => {"a" => 2}}).bytesize - C::WAL::RECORD_HEADER_BYTES) - 4,
                   recovered.recovery_report.torn_tail_bytes
      # The file is now clean and appendable.
      recovered.append([C::WAL::TYPE_ENTRY, {"index" => 2, "term" => 1, "command" => {"a" => 3}}])
      recovered.close

      assert_equal 2, C::WAL.new(path).records.length
    end
  end

  def test_oversized_length_is_corruption_not_torn_tail
    with_dir do |dir|
      path = File.join(dir, "wal")
      C::WAL.new(path).close
      File.open(path, "ab") { |file| file.write([C::WAL::MAX_RECORD_BYTES + 1, 0, 2].pack("NNC")) }
      assert_raises(C::WALCorruption) { C::WAL.new(path, recover_torn_tail: true) }
    end
  end

  def test_disk_full_short_write_and_fsync_failure_close_the_wal
    {disk_full: C::DiskFull, short_write: C::ShortWrite, fail_fsync: C::FsyncFailed}.each do |fault, klass|
      with_dir do |dir|
        path = File.join(dir, "wal")
        device = nil
        wal = C::WAL.new(path, device_factory: ->(p) { device = FaultyDevice.new(p) })
        wal.append([C::WAL::TYPE_HARD_STATE, {"term" => 1, "voted_for" => nil}])
        device.public_send("#{fault}=", true)
        assert_raises(klass) { wal.append([C::WAL::TYPE_ENTRY, {"index" => 1, "term" => 1, "command" => {}}]) }
        assert_predicate wal, :failed?
        device.public_send("#{fault}=", false)
        assert_raises(C::StorageFailed) { wal.append([C::WAL::TYPE_ENTRY, {"index" => 1, "term" => 1, "command" => {}}]) }
        # A short write leaves a torn tail that recovery removes; a failed
        # fsync leaves bytes of unknown durability (the record was never
        # acknowledged), so either 1 or 2 records may be visible.
        reopened = C::WAL.new(path, recover_torn_tail: true)
        if fault == :fail_fsync
          assert_includes [1, 2], reopened.records.length
        else
          assert_equal 1, reopened.records.length
        end

        assert_equal fault == :short_write, reopened.recovery_report.truncated
      end
    end
  end

  def test_append_is_all_or_nothing_for_a_batch
    with_dir do |dir|
      path = File.join(dir, "wal")
      device = nil
      wal = C::WAL.new(path, device_factory: ->(p) { device = FaultyDevice.new(p) })
      device.short_write = true
      assert_raises(C::ShortWrite) do
        wal.append([[C::WAL::TYPE_ENTRY, {"index" => 1, "term" => 1, "command" => {}}],
                    [C::WAL::TYPE_ENTRY, {"index" => 2, "term" => 1, "command" => {}}]])
      end
      assert_empty wal.records
    end
  end
end
