# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/consensus"
require "tmpdir"
require "zlib"

# WAL format 1 checksummed every record with a CRC-32C computed in Ruby a
# byte at a time -- a third of a millisecond per Pod-sized entry, on the
# leader and again on every follower.  Format 2 uses zlib's CRC-32.  A file
# is read and appended in the format its header names, so a WAL written
# before the change stays valid and internally consistent.
class ConsensusWALFormatVersionTest < Minitest::Test
  WAL = Rubernetes::Consensus::WAL

  def entry(index)
    {"index" => index, "term" => 1, "command" => {"type" => "noop", "n" => index}}
  end

  def test_a_new_file_is_format_2_with_zlib_checksums
    Dir.mktmpdir("wal") do |dir|
      path = File.join(dir, "wal.log")
      wal = WAL.new(path)
      wal.append([[WAL::TYPE_ENTRY, entry(1)]])

      assert_equal 2, wal.version
      bytes = File.binread(path)

      assert_equal 2, bytes.byteslice(WAL::MAGIC.bytesize, 4).unpack1("N")
      length, crc, type = bytes.byteslice(WAL::HEADER_BYTES, WAL::RECORD_HEADER_BYTES).unpack("NNC")
      payload = bytes.byteslice(WAL::HEADER_BYTES + WAL::RECORD_HEADER_BYTES, length)

      assert_equal Zlib.crc32([type].pack("C") + payload), crc
      records, = WAL.read(path)

      assert_equal [entry(1)], records.map(&:payload)
    end
  end

  def test_a_format_1_file_is_read_and_appended_in_format_1
    Dir.mktmpdir("wal") do |dir|
      path = File.join(dir, "wal.log")
      File.binwrite(path, WAL.header_bytes(1) + WAL.encode_record(WAL::TYPE_ENTRY, entry(1), version: 1))
      wal = WAL.new(path)

      assert_equal 1, wal.version
      wal.append([[WAL::TYPE_ENTRY, entry(2)]])
      records, report = WAL.read(path)

      assert_equal [entry(1), entry(2)], records.map(&:payload)
      assert_equal 0, report.torn_tail_bytes
      bytes = File.binread(path)
      offset = WAL::HEADER_BYTES + WAL::RECORD_HEADER_BYTES + WAL.encode_record(WAL::TYPE_ENTRY, entry(1), version: 1).bytesize - WAL::RECORD_HEADER_BYTES
      length, crc, type = bytes.byteslice(offset, WAL::RECORD_HEADER_BYTES).unpack("NNC")
      payload = bytes.byteslice(offset + WAL::RECORD_HEADER_BYTES, length)

      assert_equal Rubernetes::Consensus::CRC32C.checksum([type].pack("C") + payload), crc,
                   "the appended record keeps the file's checksum kind"
    end
  end

  def test_a_record_with_the_wrong_checksum_kind_is_corruption
    Dir.mktmpdir("wal") do |dir|
      path = File.join(dir, "wal.log")
      File.binwrite(path,
                    WAL.header_bytes(2) + WAL.encode_record(WAL::TYPE_ENTRY, entry(1),
                                                            version: 1) + WAL.encode_record(WAL::TYPE_ENTRY, entry(2), version: 2))
      assert_raises(Rubernetes::Consensus::WALCorruption) { WAL.read(path) }
    end
  end

  def test_an_unknown_version_is_rejected
    Dir.mktmpdir("wal") do |dir|
      path = File.join(dir, "wal.log")
      File.binwrite(path, WAL.header_bytes(3))
      error = assert_raises(Rubernetes::Consensus::WALCorruption) { WAL.new(path) }
      assert_match(/unsupported WAL format version 3/, error.message)
    end
  end
end
