# frozen_string_literal: true

require "json"
require "time"

module Rubernetes
  module Bootstrap
    class StructuredLogger
      LEVELS = {"debug" => 0, "info" => 1, "warn" => 2, "error" => 3, "fatal" => 4}.freeze
      RESERVED_FIELDS = %i[timestamp level event process].freeze

      def initialize(io:, process_name:, level: "info", clock: -> { Time.now.utc })
        raise ArgumentError, "unknown log level #{level.inspect}" unless LEVELS.key?(level)

        @io = io
        @process_name = process_name.dup.freeze
        @threshold = LEVELS.fetch(level)
        @clock = clock
        @lock = Mutex.new
      end

      # The threshold changed at runtime (kubelet's /debug/flags/v).
      def level=(level)
        level = level.to_s
        raise ArgumentError, "unknown log level #{level.inspect}" unless LEVELS.key?(level)

        @lock.synchronize { @threshold = LEVELS.fetch(level) }
      end

      LEVELS.each_key do |level|
        define_method(level) do |event, **fields|
          log(level, event, **fields)
        end
      end

      def log(level, event, **fields)
        severity = LEVELS.fetch(level) { raise ArgumentError, "unknown log level #{level.inspect}" }
        return false if severity < @threshold

        collision = fields.keys & RESERVED_FIELDS
        raise ArgumentError, "reserved log fields: #{collision.join(", ")}" unless collision.empty?

        payload = {
          timestamp: @clock.call.utc.iso8601(6),
          level: level,
          event: String(event),
          process: @process_name
        }.merge(normalize(fields))
        line = JSON.generate(payload)
        @lock.synchronize do
          @io.write(line)
          @io.write("\n")
          @io.flush
        end
        true
      end

      private

      def normalize(value)
        case value
        when Hash
          value.to_h { |key, child| [key, normalize(child)] }
        when Array
          value.map { |child| normalize(child) }
        when Exception
          {class: value.class.name, message: value.message}
        when String, Numeric, TrueClass, FalseClass, NilClass
          value
        else
          String(value)
        end
      end
    end
  end
end
