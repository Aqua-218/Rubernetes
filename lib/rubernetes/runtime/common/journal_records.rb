# frozen_string_literal: true

require_relative "canonical"
require_relative "strict_json"

module Rubernetes
  module Runtime
    # Both journals hash the same ordered JSON fields. normalize_record turns
    # the wire payload into canonical order before the digest is checked.
    module JournalRecords
      EMPTY_DIGEST = "0" * 64
      DIGEST_PATTERN = /\A[0-9a-f]{64}\z/
      MAX_RECORD_BYTES = StrictJSON::DEFAULT_MAX_BYTES
      MAX_RECORD_DEPTH = StrictJSON::DEFAULT_MAX_DEPTH

      module WireFields
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

      private

      def signed_record(sequence, previous_digest, operation_id, event, payload, timestamp)
        body = {
          "sequence" => sequence,
          "operation_id" => operation_id,
          "event" => event,
          "payload" => payload,
          "timestamp" => timestamp,
          "previous_digest" => previous_digest
        }
        digest = Digest::SHA256.hexdigest(JSON.generate(body))
        self.class::Record.new(**body, digest: digest)
      end

      def append_record(operation_id, event, payload, timestamp)
        previous = @records.last&.digest || EMPTY_DIGEST
        record = signed_record(@records.length + 1, previous, operation_id, event, payload, timestamp)
        append_line(JSON.generate(record.to_h) << "\n")
        @records << record
        record
      end

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

      def replace_records_file(records)
        temporary = "#{@path}.tmp-#{Process.pid}-#{SecureRandom.hex(8)}"
        File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
          records.each { |record| write_all(file, JSON.generate(record.to_h) << "\n") }
          file.flush
          fsync(file)
        end
        File.rename(temporary, @path)
        fsync_directory
      rescue StandardError
        File.delete(temporary) if temporary && File.exist?(temporary)
        raise
      end

      def load_records
        records = []
        label = self.class::JOURNAL_LABEL
        File.open(@path, "rb") do |file|
          file.each_line.with_index(1) do |line, number|
            raise self.class::CORRUPTION_ERROR, "#{label} line #{number} is not newline terminated" unless line.end_with?("\n")

            begin
              records << normalize_record(StrictJSON.parse(line, max_bytes: MAX_RECORD_BYTES, max_depth: MAX_RECORD_DEPTH))
            rescue StrictJSON::Error, JSON::ParserError, KeyError, TypeError, ArgumentError => error
              raise self.class::CORRUPTION_ERROR, "#{label} line #{number} is invalid: #{error.message}"
            end
          end
        end
        validate_records!(records)
      rescue Errno::ENOENT
        []
      end

      def validate_records!(records)
        previous = EMPTY_DIGEST
        error = self.class::CORRUPTION_ERROR
        label = self.class::JOURNAL_LABEL
        records.each_with_index do |record, index|
          sequence = record.sequence
          raise error, "#{label} sequence #{sequence} expected #{index + 1}" unless sequence == index + 1
          raise error, "#{label} previous digest mismatch at #{sequence}" unless record.previous_digest == previous
          raise error, "#{label} digest is invalid at #{sequence}" unless record.digest.match?(DIGEST_PATTERN)

          previous = Digest::SHA256.hexdigest(JSON.generate(record.to_h.except("digest")))
          raise error, "#{label} hash mismatch at #{sequence}" unless previous == record.digest
        end
        records
      end

      def identifier(value, name)
        string = String(value)
        raise ArgumentError, "#{name} must not be empty" if string.empty? || string.include?("\0")

        string
      end
    end
  end
end
