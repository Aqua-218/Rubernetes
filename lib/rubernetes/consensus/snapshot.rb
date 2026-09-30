# frozen_string_literal: true

require "digest"
require "fileutils"
require "securerandom"

require_relative "errors"
require_relative "canonical"

module Rubernetes
  module Consensus
    # Durable snapshot store.  A snapshot records the complete state-machine
    # state plus the last included index/term and the membership at that
    # index.  Files are written to a sibling temporary name, fsynced, renamed
    # and the directory fsynced.  Readers verify the header length, the state
    # length, the state SHA-256 and the trailing file digest before returning
    # anything, so a corrupted or truncated snapshot is never installed.
    #
    # Layout:
    #   MAGIC (8) || u32 header length || header JSON || state bytes || SHA-256(header JSON || state bytes)
    class SnapshotStore
      MAGIC = "RBSNAP\x00\x01".b.freeze
      MAX_HEADER_BYTES = 1024 * 1024
      MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024 * 1024
      DIGEST_BYTES = 32

      Snapshot = Data.define(:index, :term, :membership, :state, :state_sha256, :created_at, :path, :bytes) do
        def to_h
          {"index" => index, "term" => term, "membership" => membership, "state_sha256" => state_sha256,
           "created_at" => created_at, "path" => path, "bytes" => bytes}
        end
      end

      Metadata = Data.define(:index, :term, :membership, :state_sha256, :created_at, :path, :bytes)

      attr_reader :directory

      def initialize(directory, fsync: true)
        @directory = File.expand_path(directory)
        @fsync = fsync
        FileUtils.mkdir_p(@directory)
      end

      def self.encode(state:, index:, term:, membership:, created_at:)
        raise ArgumentError, "state must be a binary String" unless state.is_a?(String)

        header = Canonical.encode(
          "index" => index,
          "term" => term,
          "membership" => membership,
          "state_bytes" => state.bytesize,
          "state_sha256" => Digest::SHA256.hexdigest(state),
          "created_at" => created_at
        )
        raise ArgumentError, "snapshot header exceeds #{MAX_HEADER_BYTES} bytes" if header.bytesize > MAX_HEADER_BYTES

        # header is UTF-8 JSON (may hold non-ASCII membership metadata); everything
        # after this line is bytes.
        body = header.b << state.b
        MAGIC.b + [header.bytesize].pack("N") + body + Digest::SHA256.digest(body)
      end

      def self.decode(bytes, path: nil)
        if bytes.bytesize < MAGIC.bytesize + 4 + DIGEST_BYTES
          raise SnapshotCorruption.new("snapshot is shorter than its header", path: path,
                                                                              offset: 0)
        end
        raise SnapshotCorruption.new("snapshot magic mismatch", path: path, offset: 0) unless bytes.byteslice(0, MAGIC.bytesize) == MAGIC

        header_length = bytes.byteslice(MAGIC.bytesize, 4).unpack1("N")
        if header_length > MAX_HEADER_BYTES
          raise SnapshotCorruption.new("snapshot header length #{header_length} exceeds bound", path: path,
                                                                                                offset: MAGIC.bytesize)
        end

        body_offset = MAGIC.bytesize + 4
        body_length = bytes.bytesize - body_offset - DIGEST_BYTES
        if body_length < header_length
          raise SnapshotCorruption.new("snapshot body is shorter than its header", path: path,
                                                                                   offset: body_offset)
        end

        body = bytes.byteslice(body_offset, body_length)
        trailer = bytes.byteslice(body_offset + body_length, DIGEST_BYTES)
        unless Digest::SHA256.digest(body) == trailer
          raise SnapshotCorruption.new("snapshot file digest mismatch", path: path,
                                                                        offset: body_offset + body_length)
        end

        header = begin
          Canonical.decode(body.byteslice(0, header_length), max_bytes: MAX_HEADER_BYTES)
        rescue ProtocolError => error
          raise SnapshotCorruption.new("snapshot header is invalid: #{error.message}", path: path, offset: body_offset)
        end
        raise SnapshotCorruption.new("snapshot header must be an object", path: path, offset: body_offset) unless header.is_a?(Hash)

        state = body.byteslice(header_length, body_length - header_length)
        declared = header["state_bytes"]
        unless declared == state.bytesize
          raise SnapshotCorruption.new("snapshot state length mismatch", path: path,
                                                                         offset: body_offset + header_length)
        end
        unless header["state_sha256"] == Digest::SHA256.hexdigest(state)
          raise SnapshotCorruption.new("snapshot state digest mismatch", path: path,
                                                                         offset: body_offset + header_length)
        end

        index = header["index"]
        term = header["term"]
        unless index.is_a?(Integer) && index >= 0 && term.is_a?(Integer) && term >= 0
          raise SnapshotCorruption.new("snapshot index/term are invalid", path: path,
                                                                          offset: body_offset)
        end

        Snapshot.new(index: index, term: term, membership: header["membership"], state: state,
                     state_sha256: header["state_sha256"], created_at: header["created_at"], path: path, bytes: bytes.bytesize)
      end

      # Write a snapshot atomically and return its metadata.
      def write(state:, index:, term:, membership:, created_at: Time.now.utc.iso8601(6))
        bytes = self.class.encode(state: state, index: index, term: term, membership: membership, created_at: created_at)
        final = path_for(index, term)
        temporary = File.join(@directory, ".#{File.basename(final)}.tmp-#{Process.pid}-#{SecureRandom.hex(6)}")
        begin
          File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
            written = file.syswrite(bytes)
            raise ShortWrite, "snapshot short write: #{written} of #{bytes.bytesize} bytes" unless written == bytes.bytesize

            file.fsync if @fsync
          end
          File.rename(temporary, final)
          sync_directory
        rescue Errno::ENOSPC, Errno::EDQUOT => error
          FileUtils.rm_f(temporary)
          raise DiskFull, "snapshot write failed: #{error.message}"
        rescue Errno::EIO => error
          FileUtils.rm_f(temporary)
          raise FsyncFailed, "snapshot write failed: #{error.message}"
        rescue StandardError
          FileUtils.rm_f(temporary)
          raise
        end
        Metadata.new(index: index, term: term, membership: Canonical.normalize(membership),
                     state_sha256: Digest::SHA256.hexdigest(state), created_at: created_at, path: final, bytes: bytes.bytesize)
      end

      # Install snapshot bytes received from a leader; verified before rename.
      def install(bytes)
        snapshot = self.class.decode(bytes)
        write(state: snapshot.state, index: snapshot.index, term: snapshot.term, membership: snapshot.membership,
              created_at: snapshot.created_at || Time.now.utc.iso8601(6))
      end

      def read(path)
        raise SnapshotCorruption.new("snapshot exceeds #{MAX_SNAPSHOT_BYTES} bytes", path: path) if File.size(path) > MAX_SNAPSHOT_BYTES

        self.class.decode(File.binread(path), path: path)
      end

      def read_bytes(path)
        bytes = File.binread(path)
        self.class.decode(bytes, path: path)
        bytes
      end

      # Latest valid snapshot.  Corrupted candidates are reported, never
      # silently skipped: a caller that asks for strict behavior gets the
      # error, otherwise the newest verifiable snapshot is returned along with
      # the list of rejected files.
      def latest(strict: true)
        rejected = []
        candidates.reverse_each do |path|
          return [read(path), rejected]
        rescue SnapshotCorruption => error
          raise if strict

          rejected << {"path" => path, "error" => error.message}
        end
        [nil, rejected]
      end

      def candidates
        Dir.glob(File.join(@directory, "snapshot-*.rbsnap")).select { |path| File.file?(path) }.sort_by do |path|
          match = File.basename(path).match(/\Asnapshot-(\d+)-(\d+)\.rbsnap\z/)
          match ? [Integer(match[1], 10), Integer(match[2], 10)] : [-1, -1]
        end
      end

      def prune(keep: 2)
        candidates[0...-keep].each { |path| File.delete(path) } if candidates.length > keep
        sync_directory
        candidates
      end

      def path_for(index, term)
        File.join(@directory, format("snapshot-%020d-%020d.rbsnap", index, term))
      end

      private

      def sync_directory
        return unless @fsync

        handle = File.open(@directory, File::RDONLY)
        handle.fsync
      rescue SystemCallError
        nil
      ensure
        handle&.close
      end
    end
  end
end
