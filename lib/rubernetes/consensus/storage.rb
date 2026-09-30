# frozen_string_literal: true

require "fileutils"
require "securerandom"

require_relative "errors"
require_relative "wal"
require_relative "log"
require_relative "snapshot"

module Rubernetes
  module Consensus
    # Node data directory layout:
    #   <dir>/wal/wal-<seq>.rbwal      active write-ahead log (highest complete seq)
    #   <dir>/snapshots/snapshot-*.rbsnap
    #   <dir>/node.json                node identity (cluster_id, node_id)
    #
    # Rotation writes a fresh WAL containing the hard state, the compaction
    # marker and the retained entries to a temporary file, fsyncs, renames it
    # to the next sequence number and only then deletes older files.  A crash
    # at any point leaves either the old or the new WAL complete.
    class Storage
      WAL_PATTERN = /\Awal-(\d{20})\.rbwal\z/

      attr_reader :directory, :wal, :log, :snapshots, :recovery

      def initialize(directory, recover_torn_tail: false, device_factory: nil, fsync: true)
        @directory = File.expand_path(directory)
        @device_factory = device_factory
        @fsync = fsync
        @wal_directory = File.join(@directory, "wal")
        FileUtils.mkdir_p(@wal_directory)
        @snapshots = SnapshotStore.new(File.join(@directory, "snapshots"), fsync: fsync)
        @recovery = []
        open_wal(recover_torn_tail)
        @log = Log.new(@wal)
        @log.define_singleton_method(:rotate!) { storage_rotate_hook.call }
        storage = self
        @log.define_singleton_method(:storage_rotate_hook) { -> { storage.rotate! } }
      end

      def wal_size
        @wal.size
      end

      def wal_path
        @wal.path
      end

      # Rewrite the WAL from the in-memory log.  Older WAL files are deleted
      # only after the new one is complete and the directory is synced.
      def rotate!
        sequence = current_sequence + 1
        final = wal_file(sequence)
        temporary = File.join(@wal_directory, ".wal-#{sequence}.tmp-#{Process.pid}-#{SecureRandom.hex(6)}")
        records = [[WAL::TYPE_HARD_STATE, {"term" => @log.current_term, "voted_for" => @log.voted_for}]]
        records << [WAL::TYPE_COMPACT, {"index" => @log.snapshot_index, "term" => @log.snapshot_term}] if @log.snapshot_index.positive?
        @log.entries.each { |entry| records << [WAL::TYPE_ENTRY, entry.to_h] }
        bytes = WAL.header_bytes + records.map { |(type, payload)| WAL.encode_record(type, payload) }.join
        begin
          File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
            written = file.syswrite(bytes)
            raise ShortWrite, "WAL rotation short write" unless written == bytes.bytesize

            file.fsync if @fsync
          end
          File.rename(temporary, final)
          sync_directory
        rescue Errno::ENOSPC => error
          File.delete(temporary) if File.exist?(temporary)
          raise DiskFull, "WAL rotation failed: #{error.message}"
        rescue StandardError
          File.delete(temporary) if File.exist?(temporary)
          raise
        end
        old = @wal
        @wal = WAL.new(final, device_factory: @device_factory, fsync_directory: @fsync)
        @log.replace_wal(@wal)
        old.close
        wal_files.each { |path| File.delete(path) unless path == final }
        sync_directory
        final
      end

      def close
        @wal.close
      end

      def wal_files
        Dir.children(@wal_directory).select { |name| name.match?(WAL_PATTERN) }.sort.map { |name| File.join(@wal_directory, name) }
      end

      private

      def open_wal(recover_torn_tail)
        files = wal_files
        if files.empty?
          @wal = WAL.new(wal_file(1), device_factory: @device_factory, fsync_directory: @fsync)
          return
        end
        # The newest file is authoritative when it is readable.  A newest
        # file that is itself torn is only a rotation crash if an older
        # complete file still exists; otherwise recovery semantics apply.
        newest = files.last
        begin
          @wal = WAL.new(newest, recover_torn_tail: recover_torn_tail, device_factory: @device_factory, fsync_directory: @fsync)
        rescue TornWAL, WALCorruption => error
          previous = files[0...-1].last
          raise if previous.nil? || !File.basename(newest).match?(WAL_PATTERN)

          # Rotation crashed before the new file was fully renamed: it would
          # have been a temporary file.  A named but damaged newest file is
          # corruption, never silently replaced by an older generation.
          raise error
        end
        @recovery << @wal.recovery_report.to_h if @wal.recovery_report.truncated
        files[0...-1].each { |path| File.delete(path) }
      end

      def current_sequence
        files = wal_files
        return 0 if files.empty?

        Integer(File.basename(files.last).match(WAL_PATTERN)[1], 10)
      end

      def wal_file(sequence)
        File.join(@wal_directory, format("wal-%020d.rbwal", sequence))
      end

      def sync_directory
        return unless @fsync

        handle = File.open(@wal_directory, File::RDONLY)
        handle.fsync
      rescue SystemCallError
        nil
      ensure
        handle&.close
      end
    end
  end
end
