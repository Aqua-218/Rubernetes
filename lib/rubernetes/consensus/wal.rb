# frozen_string_literal: true

require "zlib"
require "fileutils"

require_relative "errors"
require_relative "crc32c"
require_relative "canonical"

module Rubernetes
  module Consensus
    # Write-ahead log with per-record CRC-32C, bounded record length and
    # explicit crash-recovery semantics.
    #
    # File layout:
    #   header: MAGIC (8 bytes) || u32 format version
    #   record: u32 payload length || u32 crc32c(type || payload) || u8 type || payload
    #
    # A record is durable only after #append returns: the bytes were written
    # completely and fsync succeeded.  Any durability failure (ENOSPC, a short
    # write, a failed fsync) closes the WAL for further writes; the caller must
    # stop acknowledging and recover.  On open, a checksum failure in the
    # middle of the file is unrecoverable corruption.  An incomplete record at
    # the very end (a torn write from a crash) can only be removed when the
    # caller explicitly asks for tail recovery; the truncation is then
    # reported so it appears in the audit trail.
    class WAL
      MAGIC = "RBWAL\x00\x01\x00".b.freeze
      # Format 1 checksums records with CRC-32C, computed in Ruby a byte at a
      # time: a third of a millisecond per Pod-sized entry, paid on the leader
      # and again on every follower.  Format 2 uses CRC-32 (IEEE) from zlib,
      # which the interpreter ships in C.  New files are written as format 2;
      # a file that exists is read and appended in the format its header
      # names, so a WAL from before the change stays valid and consistent.
      FORMAT_VERSION = 2
      SUPPORTED_FORMAT_VERSIONS = [1, 2].freeze
      HEADER_BYTES = MAGIC.bytesize + 4
      RECORD_HEADER_BYTES = 9
      MAX_RECORD_BYTES = 16 * 1024 * 1024

      TYPE_HARD_STATE = 1
      TYPE_ENTRY = 2
      TYPE_TRUNCATE = 3
      TYPE_COMPACT = 4
      TYPES = {
        TYPE_HARD_STATE => "hard_state",
        TYPE_ENTRY => "entry",
        TYPE_TRUNCATE => "truncate",
        TYPE_COMPACT => "compact"
      }.freeze
      TYPE_CODES = TYPES.invert.freeze

      Record = Data.define(:type, :payload, :offset, :bytes)
      PendingRecord = Data.define(:type, :frame, :offset)

      RecoveryReport = Data.define(:path, :records, :torn_tail_bytes, :torn_tail_offset, :truncated) do
        def to_h
          {
            "path" => path,
            "records" => records,
            "torn_tail_bytes" => torn_tail_bytes,
            "torn_tail_offset" => torn_tail_offset,
            "truncated" => truncated
          }
        end
      end

      # Default I/O device: a regular file opened for append with fsync.
      # The device contract is deliberately small so failure injection can
      # wrap it at level L1 without touching the WAL logic.
      class FileDevice
        def initialize(path)
          @path = path
          @file = File.open(path, File::WRONLY | File::CREAT | File::APPEND, 0o600)
          @file.sync = true
        end

        def size
          File.size(@path)
        end

        def write(bytes)
          @file.syswrite(bytes)
        end

        def fsync
          @file.fsync
        end

        def truncate(length)
          @file.truncate(length)
        end

        def close
          @file.close unless @file.closed?
        end
      end

      class << self
        # Read every record of a WAL without keeping the file open for writes.
        # Returns [records, recovery_report].  Raises WALCorruption for damage
        # that cannot be attributed to a torn tail and TornWAL when an
        # incomplete tail exists and recover_torn_tail is false.
        def read(path, recover_torn_tail: false, max_record_bytes: MAX_RECORD_BYTES)
          bytes = File.binread(path)
          parse(bytes, path: path, recover_torn_tail: recover_torn_tail, max_record_bytes: max_record_bytes)
        end

        def parse(bytes, path: nil, recover_torn_tail: false, max_record_bytes: MAX_RECORD_BYTES)
          raise WALCorruption.new("WAL header is incomplete", path: path, offset: 0) if bytes.bytesize < HEADER_BYTES
          raise WALCorruption.new("WAL magic mismatch", path: path, offset: 0) unless bytes.byteslice(0, MAGIC.bytesize) == MAGIC

          version = bytes.byteslice(MAGIC.bytesize, 4).unpack1("N")
          unless SUPPORTED_FORMAT_VERSIONS.include?(version)
            raise WALCorruption.new("unsupported WAL format version #{version}", path: path, offset: MAGIC.bytesize)
          end

          records = []
          offset = HEADER_BYTES
          total = bytes.bytesize
          torn_offset = nil
          while offset < total
            remaining = total - offset
            if remaining < RECORD_HEADER_BYTES
              torn_offset = offset
              break
            end
            length, crc, type = bytes.byteslice(offset, RECORD_HEADER_BYTES).unpack("NNC")
            if length.zero? && crc.zero? && type.zero?
              # An all-zero header is never a valid record (type 0 does not
              # exist).  A run of zero bytes to end of file is the footprint
              # of a pre-allocated or partially flushed tail and is treated as
              # a torn tail; zeros followed by other bytes are corruption.
              if bytes.byteslice(offset, remaining).each_byte.all?(&:zero?)
                torn_offset = offset
                break
              end
              raise WALCorruption.new("WAL record header is zero-filled inside the file", path: path, offset: offset)
            end
            if length > max_record_bytes
              raise WALCorruption.new("WAL record length #{length} exceeds #{max_record_bytes}", path: path, offset: offset)
            end
            if remaining < RECORD_HEADER_BYTES + length
              torn_offset = offset
              break
            end
            payload = bytes.byteslice(offset + RECORD_HEADER_BYTES, length)
            expected = record_checksum(version, [type].pack("C") << payload.b)
            if expected != crc
              # Only the last record may be a torn write.  A checksum
              # failure followed by further bytes is corruption.
              if offset + RECORD_HEADER_BYTES + length == total
                torn_offset = offset
                break
              end
              raise WALCorruption.new("WAL record checksum mismatch", path: path, offset: offset)
            end
            raise WALCorruption.new("unknown WAL record type #{type}", path: path, offset: offset) unless TYPES.key?(type)

            records << Record.new(type: type, payload: decode_payload(payload, path, offset), offset: offset,
                                  bytes: RECORD_HEADER_BYTES + length)
            offset += RECORD_HEADER_BYTES + length
          end
          torn_bytes = torn_offset.nil? ? 0 : total - torn_offset
          if torn_offset && !recover_torn_tail
            raise TornWAL.new("WAL has #{torn_bytes} incomplete trailing bytes at offset #{torn_offset}; explicit tail recovery is required",
                              path: path, offset: torn_offset)
          end
          [records, RecoveryReport.new(path: path, records: records.length, torn_tail_bytes: torn_bytes,
                                       torn_tail_offset: torn_offset, truncated: false)]
        end

        def encode_record(type, payload, version: FORMAT_VERSION)
          type_code = type.is_a?(Integer) ? type : TYPE_CODES.fetch(type.to_s) { raise ArgumentError, "unknown WAL record type #{type.inspect}" }
          encoded = Canonical.encode(payload)
          raise ArgumentError, "WAL record exceeds #{MAX_RECORD_BYTES} bytes" if encoded.bytesize > MAX_RECORD_BYTES

          # Canonical.encode is UTF-8 JSON; the header is BINARY.  String#+ across the
          # two raised Encoding::CompatibilityError for the first non-ASCII object
          # (a CRD description) and every flush failed from then on.
          bytes = encoded.b
          crc = record_checksum(version, [type_code].pack("C") << bytes)
          [encoded.bytesize, crc, type_code].pack("NNC") << bytes
        end

        def record_checksum(version, bytes)
          case version
          when 1 then CRC32C.checksum(bytes)
          when 2 then Zlib.crc32(bytes)
          else raise ArgumentError, "unsupported WAL format version #{version}"
          end
        end

        def header_bytes(version = FORMAT_VERSION)
          MAGIC + [version].pack("N")
        end

        # The format version named in an existing file's header.
        def header_version(path)
          header = File.binread(path, HEADER_BYTES)
          raise WALCorruption.new("WAL header is incomplete", path: path, offset: 0) if header.nil? || header.bytesize < HEADER_BYTES
          raise WALCorruption.new("WAL magic mismatch", path: path, offset: 0) unless header.byteslice(0, MAGIC.bytesize) == MAGIC

          header.byteslice(MAGIC.bytesize, 4).unpack1("N")
        end

        private

        def decode_payload(payload, path, offset)
          Canonical.decode(payload, max_bytes: MAX_RECORD_BYTES)
        rescue ProtocolError => error
          raise WALCorruption.new("WAL record payload is invalid: #{error.message}", path: path, offset: offset)
        end
      end

      attr_reader :path, :recovery_report, :version

      # Open (or create) a WAL for appending.  Existing content is verified
      # completely before the first append.
      def initialize(path, recover_torn_tail: false, device_factory: nil, fsync_directory: true)
        @path = File.expand_path(path)
        @device_factory = device_factory || ->(file_path) { FileDevice.new(file_path) }
        @fsync_directory = fsync_directory
        @failed = nil
        # @mutex guards writes and the record bookkeeping; @sync_mutex
        # serialises fsyncs.  An fsync runs under @sync_mutex alone, so a
        # write of the next batch never waits for the previous batch's
        # fsync (the leader's flusher thread syncs outside the node lock).
        @mutex = Mutex.new
        @sync_mutex = Mutex.new
        FileUtils.mkdir_p(File.dirname(@path))
        if File.exist?(@path)
          @version = self.class.header_version(@path)
          @records, report = self.class.read(@path, recover_torn_tail: recover_torn_tail)
          if report.torn_tail_offset
            File.open(@path, File::RDWR) do |file|
              file.truncate(report.torn_tail_offset)
              file.fsync
            end
            sync_directory
            report = RecoveryReport.new(**report.to_h.transform_keys(&:to_sym), truncated: true)
          end
          @recovery_report = report
          @device = @device_factory.call(@path)
        else
          @version = FORMAT_VERSION
          @records = []
          @device = @device_factory.call(@path)
          write_all(self.class.header_bytes(@version))
          @device.fsync
          sync_directory
          @recovery_report = RecoveryReport.new(path: @path, records: 0, torn_tail_bytes: 0, torn_tail_offset: nil, truncated: false)
        end
        @size = File.size(@path)
        @synced_size = @size
      end

      # Records appended by this process are kept as their encoded frames and
      # decoded here, exactly as a reopen would read them: #records is read
      # once, when the log replays at start, while normalising every payload
      # again on append was a tenth of an apiserver's CPU under writes.
      def records
        @mutex.synchronize do
          @records.map! do |record|
            next record unless record.is_a?(PendingRecord)

            payload = record.frame.byteslice(RECORD_HEADER_BYTES, record.frame.bytesize - RECORD_HEADER_BYTES)
            Record.new(type: record.type, payload: self.class.send(:decode_payload, payload, @path, record.offset),
                       offset: record.offset, bytes: record.frame.bytesize)
          end
          @records.dup
        end
      end

      def size
        @mutex.synchronize { @size }
      end

      def failed?
        !@failed.nil?
      end

      def failure
        @failed
      end

      # Append one or more records durably.  Either every record is durable
      # when this returns, or an exception is raised and the WAL refuses all
      # further appends until it is reopened after recovery.
      # +sync: false+ writes the records without the fsync; the caller owes a
      # #sync before anything may rely on them being durable.
      def append(entries, sync: true)
        entries = [entries] if entries.is_a?(Array) && entries.length == 2 && !entries[0].is_a?(Array)
        raise ArgumentError, "append requires at least one [type, payload] pair" if !entries.is_a?(Array) || entries.empty?
        raise ArgumentError, "each WAL record must be a [type, payload] pair" unless entries.all? { |pair| pair.is_a?(Array) && pair.length == 2 }

        frames = entries.map { |(type, payload)| self.class.encode_record(type, payload, version: @version) }
        bytes = frames.join
        @mutex.synchronize do
          raise StorageFailed, "WAL is closed after a durability failure: #{@failed.message}" if @failed
          raise StorageFailed, "WAL is closed" if @closed

          begin
            write_all(bytes)
            if sync
              @device.fsync
              @unsynced = false
              @synced_size = @size + bytes.bytesize
            else
              @unsynced = true
            end
          rescue Errno::ENOSPC, Errno::EDQUOT => error
            fail!(DiskFull.new("WAL append failed: #{error.message}"))
          rescue Errno::EIO, Errno::EROFS, Errno::EBADF, IOError => error
            fail!(FsyncFailed.new("WAL append failed: #{error.class}: #{error.message}"))
          rescue DurabilityError => error
            fail!(error)
          rescue SystemCallError => error
            fail!(StorageFailed.new("WAL append failed: #{error.class}: #{error.message}"))
          end
          offset = @size
          frames.each_with_index do |frame, index|
            type_code = self.class::TYPE_CODES.fetch(entries[index][0].to_s) { entries[index][0] }
            @records << PendingRecord.new(type: type_code, frame: frame, offset: offset)
            offset += frame.bytesize
          end
          @size = offset
        end
        true
      end

      # Makes every record written by an append(sync: false) durable.  The
      # fsync itself runs without the write lock: appends of later records
      # proceed meanwhile and are covered by the next sync.
      def sync
        written = @mutex.synchronize do
          raise StorageFailed, "WAL is closed after a durability failure: #{@failed.message}" if @failed
          return true if @closed
          return true unless @unsynced

          @size
        end
        @sync_mutex.synchronize do
          begin
            @device.fsync
          rescue Errno::EIO, Errno::EROFS, Errno::EBADF, IOError => error
            @mutex.synchronize { fail!(FsyncFailed.new("WAL fsync failed: #{error.class}: #{error.message}")) }
          rescue DurabilityError => error
            @mutex.synchronize { fail!(error) }
          rescue SystemCallError => error
            @mutex.synchronize { fail!(StorageFailed.new("WAL fsync failed: #{error.class}: #{error.message}")) }
          end
          @mutex.synchronize do
            @synced_size = written if written > @synced_size
            @unsynced = @size > @synced_size
          end
        end
        true
      end

      # Bytes made durable so far (for tests and diagnostics).
      def synced_size
        @mutex.synchronize { @synced_size }
      end

      def close
        # An fsync in flight finishes first: closing under it would turn a
        # clean shutdown into a durability failure.
        @sync_mutex.synchronize do
          @mutex.synchronize do
            @closed = true
            @device.close if @device.respond_to?(:close)
          end
        end
      end

      private

      def write_all(bytes)
        written = @device.write(bytes)
        unless written == bytes.bytesize
          # The device wrote fewer bytes than requested.  A partial record is
          # now on disk; refuse to continue instead of appending after it.
          raise ShortWrite, "WAL short write: #{written} of #{bytes.bytesize} bytes"
        end
        written
      end

      def fail!(error)
        @failed = error
        begin
          @device.close if @device.respond_to?(:close)
        rescue StandardError
          nil
        end
        raise error
      end

      def sync_directory
        return unless @fsync_directory

        directory = File.open(File.dirname(@path), File::RDONLY)
        directory.fsync
      rescue SystemCallError
        nil
      ensure
        directory&.close
      end
    end
  end
end
