# frozen_string_literal: true

require "json"

module Rubernetes
  module Watch
    # Both storage engines expose a blocking next and a bounded drain. The
    # legacy API store also drains by default when callers use each directly.
    module EventStream
      def each(timeout: nil)
        return enum_for(__method__, timeout: timeout) unless block_given?

        while (event = self.next(timeout: timeout))
          yield event
        end
        self
      end

      def to_a(timeout: :default)
        each(timeout: drain_timeout(timeout)).to_a
      end
      alias events to_a

      def each_json_line(timeout: :default)
        return enum_for(__method__, timeout: timeout) unless block_given?

        each(timeout: drain_timeout(timeout)) { |event| yield JSON.generate(event.to_h) << "\n" }
      end

      private

      def drain_timeout(timeout)
        timeout == :default ? (@timeout_seconds || 0) : timeout
      end
    end
  end
end
