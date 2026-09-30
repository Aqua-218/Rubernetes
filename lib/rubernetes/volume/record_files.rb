# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "securerandom"
require_relative "deferred_fsync"

module Rubernetes
  module Volume
    # One file per record for the node's volume state (volume records, the
    # operation ledger, the mount identity ledger).  Each store used to
    # rewrite ONE JSON file holding every record on every change: a Pod with
    # 50 ConfigMap volumes made about a dozen changes per volume, each
    # regenerating and writing ~1.5 MB across the three files under the
    # manager's lock, so five such Pods spent 37 s in MountVolume.SetUp where
    # kubelet takes well under one.  A change now writes only its own record.
    #
    # Records live in "<path>.d/<digest of key>.json", each renamed into place
    # whole (a crash never leaves a torn record).  A store written by an
    # earlier version as the single file at <path> is read once and migrated.
    class RecordFiles
      attr_reader :path, :directory

      def initialize(path:, fsync: true)
        @path = File.expand_path(path.to_s)
        @directory = "#{@path}.d"
        @fsync = fsync
      end

      # Every stored record as parsed JSON: the legacy single file's records
      # (an Array, or a Hash's values) first, then the per-record files.
      def load
        records = []
        legacy = legacy_records
        records.concat(legacy) if legacy
        if File.directory?(@directory)
          Dir.children(@directory).sort.each do |name|
            next unless name.end_with?(".json")

            records << JSON.parse(File.read(File.join(@directory, name)))
          end
        end
        records
      end

      def legacy?
        File.file?(@path)
      end

      # Writes every record into the directory, then removes the legacy file.
      def migrate!(records_by_key)
        records_by_key.each { |key, record| write(key, record) }
        File.delete(@path) if File.file?(@path)
        DeferredFsync.schedule(@directory) if @fsync == true
        true
      end

      def write(key, record, durable: false)
        FileUtils.mkdir_p(@directory)
        target = file_for(key)
        temporary = "#{target}.tmp-#{Process.pid}-#{SecureRandom.hex(6)}"
        File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
          file.write(JSON.generate(record))
          file.flush
          file.fsync if durable && @fsync == true
        end
        File.rename(temporary, target)
        if @fsync == true
          if durable
            File.open(@directory, File::RDONLY, &:fsync)
          else
            DeferredFsync.schedule(target)
          end
        end
        true
      rescue SystemCallError, IOError
        File.delete(temporary) if temporary && File.exist?(temporary)
        raise
      end

      def delete(key)
        File.delete(file_for(key))
        DeferredFsync.schedule(@directory) if @fsync == true
        true
      rescue Errno::ENOENT
        false
      end

      def file_for(key)
        File.join(@directory, "#{Digest::SHA256.hexdigest(key.to_s)[0, 40]}.json")
      end

      # For readers outside the owning store (diagnostics, observation
      # harnesses): every record of the store at +path+, whichever layout.
      def self.read(path)
        new(path: path, fsync: false).load
      end

      private

      def legacy_records
        return nil unless File.file?(@path)

        data = JSON.parse(File.read(@path))
        data.is_a?(Hash) ? data.values : data
      end
    end
  end
end
