# frozen_string_literal: true

require_relative "container_stream_service"

module Rubernetes
  module Node
    # Connects an exec request to the runtime's process stream.  The returned
    # DuplexStream keeps stdin half-close and stdout/stderr binary, so callers
    # can bridge HTTP/WebSocket/SPDY transports without transcode surprises.
    class ExecService < ContainerStreamService
      def exec(container_id = nil, command = nil, tty: false, stdin: false, stdout: true, stderr: false,
               request_id: nil, identity: nil, **options)
        command ||= options.delete(:cmd) || options.delete(:command)
        open_container_stream(
          :exec, container_id,
          request_id: request_id, identity: identity, options: options,
          tty: tty, stdin: stdin, stdout: stdout, stderr: stderr
        ) { normalize_command(command) }
      end

      alias call exec
      alias open exec

      private

      def normalize_command(value)
        command = Array(value)
        raise InvalidRequest, "command must contain at least one argument" if command.empty?

        command.map { |argument| normalize_string(argument, "command argument") }.freeze
      rescue TypeError
        raise InvalidRequest, "command must be an Array of strings"
      end
    end

    Exec = ExecService
  end
end
