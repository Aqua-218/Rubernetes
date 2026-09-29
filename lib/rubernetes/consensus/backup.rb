# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "time"

require_relative "errors"
require_relative "canonical"
require_relative "snapshot"
require_relative "wal"
require_relative "storage"

module Rubernetes
  module Consensus
    # Backup and restore of a node's durable state.  A backup is a directory
    # holding the latest verified snapshot, the complete WAL and a manifest
    # with the SHA-256 of every file plus the log position; restore verifies
    # every digest and refuses a partial or tampered backup.
    module Backup
      MANIFEST = "backup-manifest.json"

      module_function

      def create(data_directory, destination, created_at: Time.now.utc)
        storage = Storage.new(data_directory, recover_torn_tail: false)
        begin
          FileUtils.mkdir_p(destination)
          files = []
          snapshot, _rejected = storage.snapshots.latest(strict: true)
          if snapshot
            target = File.join(destination, File.basename(snapshot.path))
            FileUtils.cp(snapshot.path, target)
            files << entry(target, destination)
          end
          wal_target = File.join(destination, File.basename(storage.wal_path))
          FileUtils.cp(storage.wal_path, wal_target)
          files << entry(wal_target, destination)
          manifest = {
            "schema_version" => 1,
            "kind" => "rubernetes_raft_backup",
            "created_at" => created_at.iso8601(6),
            "last_index" => storage.log.last_index,
            "last_term" => storage.log.last_term,
            "snapshot_index" => storage.log.snapshot_index,
            "current_term" => storage.log.current_term,
            "files" => files.sort_by { |file| file["path"] }
          }
          path = File.join(destination, MANIFEST)
          File.write(path, JSON.pretty_generate(manifest) << "\n")
          File.open(path) { |file| file.fsync }
          manifest
        ensure
          storage.close
        end
      end

      def verify(backup_directory)
        manifest = JSON.parse(File.read(File.join(backup_directory, MANIFEST)))
        raise CorruptionError.new("backup manifest kind is invalid", path: backup_directory) unless manifest["kind"] == "rubernetes_raft_backup"

        manifest.fetch("files").each do |file|
          path = File.join(backup_directory, file.fetch("path"))
          raise CorruptionError.new("backup file missing: #{file["path"]}", path: path) unless File.file?(path)
          raise CorruptionError.new("backup file digest mismatch: #{file["path"]}", path: path) unless Digest::SHA256.file(path).hexdigest == file.fetch("sha256")
          raise CorruptionError.new("backup file size mismatch: #{file["path"]}", path: path) unless File.size(path) == file.fetch("bytes")
        end
        manifest
      end

      # Restore into an empty data directory.  The WAL and snapshot are
      # re-verified structurally (checksums, framing) after the copy.
      def restore(backup_directory, data_directory)
        manifest = verify(backup_directory)
        raise Error, "restore target #{data_directory} is not empty" if Dir.exist?(data_directory) && !Dir.empty?(data_directory)

        FileUtils.mkdir_p(File.join(data_directory, "wal"))
        FileUtils.mkdir_p(File.join(data_directory, "snapshots"))
        manifest.fetch("files").each do |file|
          name = file.fetch("path")
          source = File.join(backup_directory, name)
          target = if name.end_with?(".rbsnap")
                     File.join(data_directory, "snapshots", name)
                   else
                     File.join(data_directory, "wal", name)
                   end
          FileUtils.cp(source, target)
          File.open(target) { |handle| handle.fsync }
        end
        storage = Storage.new(data_directory, recover_torn_tail: false)
        begin
          unless storage.log.last_index == manifest.fetch("last_index") && storage.log.snapshot_index == manifest.fetch("snapshot_index")
            raise CorruptionError.new("restored log position differs from the backup manifest", path: data_directory)
          end
        ensure
          storage.close
        end
        manifest
      end

      def entry(path, root)
        {"path" => path.delete_prefix("#{root}/"), "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
      end
    end
  end
end
