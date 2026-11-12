# frozen_string_literal: true

require "digest"
require "json"

module Rubernetes
  module Runtime
    class Native
      # The ownership journal of the pure profile: the same append/each/last
      # contract as the durable RollbackJournal, kept in memory because a pure
      # runtime has no kernel state to recover after a restart.
      class MemoryJournal
        Record = Data.define(:sequence, :operation_id, :event, :payload, :timestamp, :previous_digest, :digest)

        def initialize(clock: -> { Time.now.utc })
          @clock = clock
          @records = []
          @mutex = Mutex.new
        end

        def append(operation_id:, event:, payload: {}, timestamp: nil)
          @mutex.synchronize do
            sequence = @records.length + 1
            record = Record.new(
              sequence: sequence,
              operation_id: String(operation_id),
              event: String(event),
              payload: deep_copy(payload),
              timestamp: (timestamp || @clock.call).utc,
              previous_digest: @records.last&.digest || ("0" * 64),
              digest: Digest::SHA256.hexdigest([sequence, operation_id, event, JSON.generate(payload)].join("\0"))
            )
            @records << record
            record
          end
        end

        def each(&block)
          return enum_for(__method__) unless block

          @mutex.synchronize { @records.each(&block) }
          self
        end

        def records
          @mutex.synchronize { @records.map { |record| record }.freeze }
        end

        alias entries records

        def last
          @mutex.synchronize { @records.last }
        end

        private

        def deep_copy(value)
          case value
          when Hash then value.to_h { |key, child| [String(key), deep_copy(child)] }
          when Array then value.map { |child| deep_copy(child) }
          else value
          end
        end
      end
    end
  end
end
