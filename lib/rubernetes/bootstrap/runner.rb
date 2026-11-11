# frozen_string_literal: true

require_relative "../console/server"

module Rubernetes
  module Bootstrap
    class Runner
      SUCCESS = 0
      FAILURE = 1

      def initialize(assembly:)
        @assembly = assembly
      end

      def run
        started = false
        status = SUCCESS
        request = nil
        console = nil
        begin
          @assembly.shutdown.install!
          @assembly.service.start
          started = true
          console = start_console
          request = @assembly.shutdown.wait
        rescue StandardError => error
          status = FAILURE
          @assembly.logger.error("process.failed", error: error)
        ensure
          console&.stop
          if started
            reason = request&.signal || "failure"
            begin
              @assembly.service.stop(reason: reason)
            rescue StandardError => error
              status = FAILURE
              @assembly.logger.error("process.stop_failed", error: error)
            end
          end
          @assembly.shutdown.close
        end
        status
      end

      private

      # The console is a way to look at the component, not a part of it: one
      # that cannot be opened is logged and the component runs without.
      def start_console
        path = @assembly.config.console_socket
        return nil if path.nil?

        Console::Server.new(path: path, process_name: @assembly.config.process_name, service: @assembly.service,
                            logger: @assembly.logger).start
      rescue StandardError => error
        @assembly.logger.warn("console.unavailable", error: error.class.name, message: error.message)
        nil
      end
    end
  end
end
