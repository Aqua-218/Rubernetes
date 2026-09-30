# frozen_string_literal: true

require "fileutils"
require "json"
require "securerandom"

require_relative "canonical"
require_relative "errors"
require_relative "strict_json"

module Rubernetes
  module Runtime
    # Content-checked snapshots written through a sibling file and atomic
    # rename.  A snapshot never contains a workload identity or live secret.
    class AtomicSnapshotStore
      SCHEMA = "rubernetes.runtime.snapshot.v1"
      MAX_DOCUMENT_BYTES = StrictJSON::DEFAULT_MAX_BYTES
      MAX_DOCUMENT_DEPTH = StrictJSON::DEFAULT_MAX_DEPTH

      def initialize(directory, fsync: true)
        @directory = File.expand_path(directory.to_s)
        @fsync = fsync
        FileUtils.mkdir_p(@directory)
      end

      attr_reader :directory

      def write(snapshot_id:, state:, payload: {}, identity: nil)
        snapshot_id = identifier(snapshot_id, "snapshot_id")
        raise ValidationError, "snapshot state must be WorkloadStopped" unless state.to_s == "WorkloadStopped"
        raise ValidationError, "snapshot identity is required" if identity.to_s.empty?

        body = {
          "schema" => SCHEMA,
          "snapshot_id" => snapshot_id,
          "state" => state.to_s,
          "identity" => String(identity),
          "payload" => Canonical.normalize(Canonical.copy(payload))
        }
        envelope = body.merge("checksum" => Canonical.digest(body))
        path = path_for(snapshot_id)
        temporary = "#{path}.tmp-#{Process.pid}-#{SecureRandom.hex(8)}"
        File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
          write_all(file, JSON.generate(envelope) << "\n")
          file.flush
          fsync(file)
        end
        File.rename(temporary, path)
        fsync_directory
        envelope.freeze
      rescue SystemCallError, IOError => error
        raise Error, "snapshot write failed for #{snapshot_id}: #{error.message}"
      ensure
        File.delete(temporary) if temporary && File.exist?(temporary)
      end

      def read(snapshot_id)
        path = path_for(snapshot_id)
        envelope = StrictJSON.parse(File.binread(path), max_bytes: MAX_DOCUMENT_BYTES, max_depth: MAX_DOCUMENT_DEPTH,
                                                        require_newline: true)
        validate_envelope!(envelope, snapshot_id)
        Canonical.immutable(envelope)
      rescue Errno::ENOENT
        nil
      rescue StrictJSON::Error, JSON::ParserError, KeyError, TypeError, ArgumentError => error
        raise SnapshotCorruption, "snapshot #{snapshot_id} is invalid: #{error.message}"
      end

      alias load read

      def ids
        Dir.glob(File.join(@directory, "*.snapshot.json")).filter_map do |path|
          File.basename(path, ".snapshot.json")
        end.sort.freeze
      end

      private

      def path_for(snapshot_id)
        snapshot_id = identifier(snapshot_id, "snapshot_id")
        raise ArgumentError, "snapshot_id contains path separator" if snapshot_id.include?(File::SEPARATOR)

        File.join(@directory, "#{snapshot_id}.snapshot.json")
      end

      def validate_envelope!(envelope, requested_id)
        raise SnapshotCorruption, "snapshot schema is unsupported" unless envelope.fetch("schema") == SCHEMA
        raise SnapshotCorruption, "snapshot id does not match its path" unless envelope.fetch("snapshot_id") == String(requested_id)
        raise SnapshotCorruption, "snapshot state is not WorkloadStopped" unless envelope.fetch("state") == "WorkloadStopped"

        expected = envelope.slice("schema", "snapshot_id", "state", "identity", "payload")
        return if envelope.fetch("checksum") == Canonical.digest(expected)

        raise SnapshotCorruption, "snapshot checksum mismatch"
      end

      def write_all(file, content)
        offset = 0
        while offset < content.bytesize
          written = file.write(content.byteslice(offset, content.bytesize - offset))
          raise IOError, "snapshot short write" unless written && written.positive?

          offset += written
        end
      end

      def fsync(file)
        case @fsync
        when false, nil
          nil
        when true
          file.fsync
        else
          @fsync.arity.zero? ? @fsync.call : @fsync.call(file)
        end
      end

      def fsync_directory
        directory = File.open(@directory, File::RDONLY)
        fsync(directory)
      ensure
        directory&.close
      end

      def identifier(value, name)
        string = String(value)
        raise ArgumentError, "#{name} must not be empty" if string.empty? || string.include?("\0")

        string
      end
    end

    SnapshotStore = AtomicSnapshotStore
    AtomicSnapshot = AtomicSnapshotStore
    Snapshot = AtomicSnapshotStore
  end
end
