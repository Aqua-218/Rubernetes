# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "monitor"
require "time"

require_relative "errors"
require_relative "canonical"

module Rubernetes
  module Consensus
    # Durable client-side operation journal for effect points (stage 13).
    #
    # Every effect a component performs against the store passes through
    # three durable records: `request` (the intent, fsynced before the effect
    # is attempted), `outcome` (applied / rejected / unknown) and `resolved`
    # (what a retry discovered).  On restart the journal distinguishes:
    #
    #   * request loss   — a `request` record with no `outcome`: the effect
    #     may never have reached the store; re-execution with the same
    #     request UID is safe because the store deduplicates by UID (S6).
    #   * response loss  — an `outcome` with state `unknown`: the request may
    #     have been applied; the retry replays the stored result or
    #     converges to the same result without a second effect.
    #
    # Records are hash-chained so a torn write or an edited record is
    # detected on replay.
    class OperationJournal
      EMPTY_DIGEST = "0" * 64
      STATES = %w[applied rejected unknown].freeze

      Record = Data.define(:sequence, :kind, :request_id, :payload, :timestamp, :previous_digest, :digest) do
        def to_h
          {"sequence" => sequence, "kind" => kind, "request_id" => request_id, "payload" => payload,
           "timestamp" => timestamp, "previous_digest" => previous_digest, "digest" => digest}
        end
      end

      attr_reader :path, :component

      def initialize(path, component:, clock: -> { Time.now.utc }, fsync: true)
        @path = File.expand_path(path)
        @component = component.to_s
        @clock = clock
        @fsync = fsync
        @monitor = Monitor.new
        FileUtils.mkdir_p(File.dirname(@path))
        @records = load
      end

      def record_request(request_id:, effect:, key:, command:)
        append("request", request_id, "effect" => effect, "key" => key, "command_sha256" => Canonical.digest(command),
                                      "component" => @component)
      end

      def record_outcome(request_id:, state:, result: nil, error: nil)
        raise ArgumentError, "unknown outcome state #{state}" unless STATES.include?(state.to_s)

        append("outcome", request_id, "state" => state.to_s,
                                      "result_sha256" => result.nil? ? nil : Canonical.digest(result),
                                      "error" => error.nil? ? nil : {"class" => error.class.name, "message" => error.message})
      end

      def record_resolution(request_id:, discovered:, result: nil)
        append("resolved", request_id, "discovered" => discovered.to_s,
                                       "result_sha256" => result.nil? ? nil : Canonical.digest(result))
      end

      def records
        @monitor.synchronize { @records.map(&:to_h) }
      end

      # Classification of every request after a crash.
      def pending
        @monitor.synchronize do
          by_request = {}
          @records.each do |record|
            entry = by_request[record.request_id] ||= {"request_id" => record.request_id, "request" => nil, "outcome" => nil, "resolved" => nil}
            entry[record.kind] = record.payload
          end
          by_request.values.filter_map do |entry|
            next nil if entry["resolved"]
            next entry.merge("classification" => "request_loss") if entry["request"] && entry["outcome"].nil?
            next entry.merge("classification" => "response_loss") if entry["outcome"] && entry["outcome"]["state"] == "unknown"

            nil
          end
        end
      end

      def classification(request_id)
        pending.find { |entry| entry["request_id"] == request_id }&.fetch("classification")
      end

      private

      def append(kind, request_id, payload)
        request_id = String(request_id)
        raise ArgumentError, "request_id must not be empty" if request_id.empty?

        @monitor.synchronize do
          sequence = @records.length + 1
          previous = @records.empty? ? EMPTY_DIGEST : @records.last.digest
          body = {"sequence" => sequence, "kind" => kind, "request_id" => request_id, "payload" => Canonical.normalize(payload),
                  "timestamp" => @clock.call.utc.iso8601(6), "previous_digest" => previous}
          digest = Digest::SHA256.hexdigest(JSON.generate(body))
          record = Record.new(**body.transform_keys(&:to_sym), digest: digest)
          File.open(@path, File::WRONLY | File::CREAT | File::APPEND, 0o600) do |file|
            file.write(JSON.generate(record.to_h) << "\n")
            file.flush
            file.fsync if @fsync
          end
          @records << record
          record
        end
      rescue Errno::ENOSPC => error
        raise DiskFull, "operation journal append failed: #{error.message}"
      end

      def load
        return [] unless File.exist?(@path)

        records = []
        previous = EMPTY_DIGEST
        File.foreach(@path).with_index(1) do |line, number|
          stripped = line.chomp
          next if stripped.empty?

          if !line.end_with?("\n")
            # Torn final line: the record was never durable (fsync happens
            # after the newline); it is dropped and reported through pending.
            break
          end
          value = JSON.parse(stripped)
          body = value.reject { |key, _| key == "digest" }
          expected = Digest::SHA256.hexdigest(JSON.generate(body))
          raise CorruptionError.new("operation journal record #{number} digest mismatch", path: @path) unless expected == value["digest"]
          raise CorruptionError.new("operation journal chain broken at record #{number}", path: @path) unless value["previous_digest"] == previous

          previous = value["digest"]
          records << Record.new(sequence: value["sequence"], kind: value["kind"], request_id: value["request_id"], payload: value["payload"],
                                timestamp: value["timestamp"], previous_digest: value["previous_digest"], digest: value["digest"])
        end
        records
      rescue JSON::ParserError => error
        raise CorruptionError.new("operation journal is not valid JSON lines: #{error.message}", path: @path)
      end
    end
  end
end
