# frozen_string_literal: true

require "fileutils"
require "json"
require "securerandom"
require "time"

require_relative "canonical"
require_relative "errors"
require_relative "journal_records"

module Rubernetes
  module Runtime
    # Hash-chained JSON-lines WAL.  A record is visible to recovery only after
    # the complete line and its fsync have succeeded.
    class DurableWAL
      Record = Struct.new(:sequence, :operation_id, :event, :payload, :timestamp,
                          :previous_digest, :digest, keyword_init: true) do
        include JournalRecords::WireFields
      end

      include JournalRecords

      JOURNAL_LABEL = "WAL"
      CORRUPTION_ERROR = JournalCorruption

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
          timestamp_value = timestamp || @clock.call
          timestamp_value = Time.iso8601(timestamp_value.to_s) unless timestamp_value.is_a?(Time)
          timestamp_value = timestamp_value.utc.iso8601(6)
          record = append_record(operation_id, event, Canonical.normalize(payload), timestamp_value)
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
        @mutex.synchronize do
          replace_records_file(normalized)
          @records = normalized
        end
        true
      end

      private

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

      def immutable_record(record)
        Record.new(sequence: record.sequence, operation_id: record.operation_id,
                   event: record.event, payload: Canonical.immutable(record.payload),
                   timestamp: record.timestamp, previous_digest: record.previous_digest,
                   digest: record.digest).freeze
      end
    end

    DurableWal = DurableWAL
    WAL = DurableWAL
    Journal = DurableWAL
    RollbackJournal = DurableWAL
  end
end
