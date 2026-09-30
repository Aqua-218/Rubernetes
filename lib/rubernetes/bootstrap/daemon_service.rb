# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    class DaemonService
      def initialize(process_name:, config:, logger:)
        @process_name = process_name
        @config = config
        @logger = logger
        @started = false
      end

      def start
        raise "#{@process_name} is already started" if @started

        @started = true
        @logger.info("process.ready", configuration: @config)
      end

      def stop(reason:)
        return unless @started

        @logger.info("process.stopped", reason: reason)
        @started = false
      end
    end
  end
end
