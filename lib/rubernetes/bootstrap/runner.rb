# frozen_string_literal: true

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
        begin
          @assembly.shutdown.install!
          @assembly.service.start
          started = true
          request = @assembly.shutdown.wait
        rescue StandardError => error
          status = FAILURE
          @assembly.logger.error("process.failed", error: error)
        ensure
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
    end
  end
end
