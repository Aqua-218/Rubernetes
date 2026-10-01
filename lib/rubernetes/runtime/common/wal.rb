# frozen_string_literal: true

require "fileutils"
require "json"
require "securerandom"
require "time"

require_relative "canonical"
require_relative "errors"
require_relative "strict_json"

module Rubernetes
  module Runtime
    # Hash-chained JSON-lines WAL.  A record is visible to recovery only after
    # the complete line and its fsync have succeeded.
    class DurableWAL
      Record = Struct.new(:sequence, :operation_id, :event, :payload, :timestamp,
                          :previous_digest, :digest, keyword_init: true) do
        def to_h
          {
            "sequence" => sequence,
            "operation_id" => operation_id,
            "event" => event,
            "payload" => payload,
            "timestamp" => timestamp,
            "previous_digest" => previous_digest,
            "digest" => digest
          }
        end
      end

      EMPTY_DIGEST = "0" * 64
      DIGEST_PATTERN = /\A[0-9a-f]{64}\z/
      MAX_RECORD_BYTES = StrictJSON::DEFAULT_MAX_BYTES
      MAX_RECORD_DEPTH = StrictJSON::DEFAULT_MAX_DEPTH

      def initialize(path, clock: -> { Time.now.utc }, fsync: true)
        @path = File.expand_path(path.to_s)
        @clock = clock
        @fsync = fsync
        @mutex = Mutex.new
        FileUtils.mkdir_p(File.dirname(@path))
        @records = load_records
      end

      attr_reader :path

      def append(operation_id:, event:, payload: {}, timestamp: nil)
        operation_id = identifier(operation_id, "operation_id")
        event = identifier(event, "event")
        payload = Canonical.copy(payload)
        @mutex.synchronize do
          sequence = @records.length + 1
          previous_digest = @records.empty? ? EMPTY_DIGEST : @records.last.digest
          timestamp_value = timestamp || @clock.call
          timestamp_value = Time.iso8601(timestamp_value.to_s) unless timestamp_value.is_a?(Time)
          timestamp_value = timestamp_value.utc.iso8601(6)
          body = {
            "sequence" => sequence,
            "operation_id" => operation_id,
            "event" => event,
            "payload" => Canonical.normalize(payload),
            "timestamp" => timestamp_value,
            "previous_digest" => previous_digest
          }
          digest = Digest::SHA256.hexdigest(JSON.generate(body))
          record = Record.new(**body, digest: digest)
          line = JSON.generate(record.to_h) << "\n"
          append_line(line)
          @records << record
          immutable_record(record)
        end
      rescue SystemCallError, IOError => error
        raise Error, "WAL append failed for #{operation_id}: #{error.message}"
      end

      def records
        @mutex.synchronize { @records.map { |record| immutable_record(record) }.freeze }
      end

      alias entries records

      def each
        return enum_for(__method__) unless block_given?

        @mutex.synchronize { @records.each { |record| yield immutable_record(record) } }
        self
      end

      def last
        @mutex.synchronize { @records.last && immutable_record(@records.last) }
      end

      def empty?
        @mutex.synchronize { @records.empty? }
      end

      # Replace the WAL only after a complete, validated snapshot has been
      # prepared.  The directory fsync closes the rename durability window.
      def compact!(records)
        normalized = Array(records).map { |record| normalize_record(record) }
        validate_records!(normalized)
        temporary = "#{@path}.tmp-#{Process.pid}-#{SecureRandom.hex(8)}"
        File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
          normalized.each { |record| write_all(file, JSON.generate(record.to_h) << "\n") }
          file.flush
          fsync(file)
        end
        File.rename(temporary, @path)
        fsync_directory
        @mutex.synchronize { @records = normalized }
        true
      rescue StandardError
        File.delete(temporary) if temporary && File.exist?(temporary)
        raise
      end

      private

      def append_line(line)
        File.open(@path, File::WRONLY | File::CREAT | File::APPEND, 0o600) do |file|
          file.flock(File::LOCK_EX)
          write_all(file, line)
          file.flush
          fsync(file)
          file.flock(File::LOCK_UN)
        end
      end

      def write_all(file, content)
        offset = 0
        while offset < content.bytesize
          written = file.write(content.byteslice(offset, content.bytesize - offset))
          raise IOError, "WAL short write" unless written && written.positive?

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
        directory = File.open(File.dirname(@path), File::RDONLY)
        fsync(directory)
      ensure
        directory&.close
      end

      def load_records
        return [] unless File.exist?(@path)

        records = []
        File.open(@path, "rb") do |file|
          file.each_line.with_index(1) do |line, line_number|
            raise JournalCorruption, "WAL line #{line_number} is not newline terminated" unless line.end_with?("\n")

            begin
              records << normalize_record(StrictJSON.parse(line, max_bytes: MAX_RECORD_BYTES, max_depth: MAX_RECORD_DEPTH,
                                                                 require_newline: true))
            rescue StrictJSON::Error, JSON::ParserError, KeyError, TypeError, ArgumentError => error
              raise JournalCorruption, "WAL line #{line_number} is invalid: #{error.message}"
            end
          end
        end
        validate_records!(records)
        # A reopened durable WAL must remain appendable.  The public `records`
        # accessor returns an immutable snapshot, so freezing this internal
        # array would make the first post-crash transition fail with
        # FrozenError.
        records
      rescue Errno::ENOENT
        []
      end

      def normalize_record(value)
        hash = value.respond_to?(:to_h) ? value.to_h : value
        Record.new(
          sequence: Integer(hash.fetch("sequence") { hash.fetch(:sequence) }),
          operation_id: identifier(hash.fetch("operation_id") { hash.fetch(:operation_id) }, "operation_id"),
          event: identifier(hash.fetch("event") { hash.fetch(:event) }, "event"),
          payload: Canonical.normalize(hash.fetch("payload") { hash.fetch(:payload) }),
          timestamp: Time.iso8601(String(hash.fetch("timestamp") { hash.fetch(:timestamp) })).utc.iso8601(6),
          previous_digest: String(hash.fetch("previous_digest") { hash.fetch(:previous_digest) }),
          digest: String(hash.fetch("digest") { hash.fetch(:digest) })
        )
      end

      def validate_records!(records)
        previous = EMPTY_DIGEST
        records.each_with_index do |record, index|
          expected_sequence = index + 1
          raise JournalCorruption, "WAL sequence #{record.sequence} expected #{expected_sequence}" unless record.sequence == expected_sequence
          raise JournalCorruption, "WAL previous digest mismatch at #{record.sequence}" unless record.previous_digest == previous
          raise JournalCorruption, "WAL digest is invalid at #{record.sequence}" unless record.digest.match?(DIGEST_PATTERN)

          body = {
            "sequence" => record.sequence,
            "operation_id" => record.operation_id,
            "event" => record.event,
            "payload" => Canonical.normalize(record.payload),
            "timestamp" => record.timestamp,
            "previous_digest" => record.previous_digest
          }
          expected_digest = Digest::SHA256.hexdigest(JSON.generate(body))
          raise JournalCorruption, "WAL hash mismatch at #{record.sequence}" unless expected_digest == record.digest

          previous = record.digest
        end
        records
      end

      def immutable_record(record)
        Record.new(sequence: record.sequence, operation_id: record.operation_id,
                   event: record.event, payload: Canonical.immutable(record.payload),
                   timestamp: record.timestamp, previous_digest: record.previous_digest,
                   digest: record.digest).freeze
      end

      def identifier(value, name)
        string = String(value)
        raise ArgumentError, "#{name} must not be empty" if string.empty? || string.include?("\0")

        string
      end
    end

    DurableWal = DurableWAL
    WAL = DurableWAL
    Journal = DurableWAL
    RollbackJournal = DurableWAL
  end
end
