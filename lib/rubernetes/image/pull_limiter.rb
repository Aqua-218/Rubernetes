# frozen_string_literal: true

module Rubernetes
  module Image
    # One limit for the node's registry pulls, shared by native and CRI
    # runtimes. Cache lookups and joining an existing pull need no slot.
    class PullLimiter
      def self.serialized?(config)
        serialize = config["serialize_image_pulls"]
        return serialize unless serialize.nil?

        config["max_parallel_image_pulls"].to_i < 2
      end

      def self.from_config(config)
        new(serialized?(config) ? 1 : config["max_parallel_image_pulls"])
      end

      def initialize(limit)
        @slots = SizedQueue.new(limit) if limit
      end

      def synchronize
        return yield unless @slots

        @slots.push(true)
        begin
          yield
        ensure
          @slots.pop
        end
      end
    end
  end
end
