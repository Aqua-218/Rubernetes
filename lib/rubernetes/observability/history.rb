# frozen_string_literal: true

require "json"
require "monitor"

module Rubernetes
  module Observability
    # Concurrent operation history recorder (spec/verification/testing.md 8.3).
    # Each client operation is recorded as invoke/ok/fail/info with a
    # monotonic timestamp so a linearizability checker can reconstruct the
    # real-time partial order.  `info` marks an operation whose outcome is
    # unknown (timeout, response loss): it may or may not have taken effect.
    class History
      Event = Data.define(:sequence, :type, :process, :operation, :input, :output, :time) do
        def to_h
          {"sequence" => sequence, "type" => type, "process" => process, "operation" => operation,
           "input" => input, "output" => output, "time" => time}
        end
      end

      TYPES = %w[invoke ok fail info].freeze

      def initialize(clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @clock = clock
        @events = []
        @monitor = Monitor.new
        @sequence = 0
      end

      def invoke(process, operation, input)
        record("invoke", process, operation, input, nil)
      end

      def ok(process, operation, input, output)
        record("ok", process, operation, input, output)
      end

      def fail(process, operation, input, output = nil)
        record("fail", process, operation, input, output)
      end

      def info(process, operation, input, output = nil)
        record("info", process, operation, input, output)
      end

      # Run a block as one recorded operation.  A nil return from the block
      # with an unknown outcome should be reported by raising
      # History::UnknownOutcome.
      def measure(process, operation, input)
        invoke(process, operation, input)
        output = yield
        ok(process, operation, input, output)
        output
      rescue UnknownOutcome => error
        info(process, operation, input, error.message)
        raise
      rescue StandardError => error
        fail(process, operation, input, {"error" => error.class.name, "message" => error.message})
        raise
      end

      class UnknownOutcome < StandardError; end

      def events
        @monitor.synchronize { @events.dup }
      end

      def to_a
        events.map(&:to_h)
      end

      def to_json(*args)
        JSON.generate(to_a, *args)
      end

      def self.from_a(list)
        history = new
        list.each do |event|
          history.instance_variable_get(:@events) << Event.new(sequence: event.fetch("sequence"), type: event.fetch("type"),
                                                                process: event.fetch("process"), operation: event.fetch("operation"),
                                                                input: event["input"], output: event["output"], time: event.fetch("time"))
        end
        history
      end

      private

      def record(type, process, operation, input, output)
        raise ArgumentError, "unknown event type #{type}" unless TYPES.include?(type)

        @monitor.synchronize do
          @sequence += 1
          event = Event.new(sequence: @sequence, type: type, process: process.to_s, operation: operation.to_s,
                            input: input, output: output, time: @clock.call)
          @events << event
          event
        end
      end
    end
  end
end
