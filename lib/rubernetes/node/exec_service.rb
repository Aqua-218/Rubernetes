# frozen_string_literal: true

require_relative "service"

module Rubernetes
  module Node
    # Connects an exec request to the runtime's process stream.  The returned
    # DuplexStream keeps stdin half-close and stdout/stderr binary, so callers
    # can bridge HTTP/WebSocket/SPDY transports without transcode surprises.
    class ExecService < Service
      def exec(container_id = nil, command = nil, tty: false, stdin: false, stdout: true, stderr: false,
               request_id: nil, identity: nil, **options)
        container_id ||= options.delete(:container_id) || options.delete(:id) || options.delete(:container)
        command ||= options.delete(:cmd) || options.delete(:command)
        request = context(
          operation: "exec",
          container_id: container_id,
          request_id: request_id,
          identity: identity,
          metadata: options
        )
        tty = normalize_bool(tty, "tty")
        stream_flags = normalize_stream_flags(stdin: stdin, stdout: stdout, stderr: stderr)
        command = normalize_command(command)
        authorize!(request)

        result = invoke_runtime(
          :exec,
          [request.container_id, command],
          {
            tty: tty,
            stdin: stream_flags.fetch(:stdin_value),
            stdout: stream_flags.fetch(:stdout_value),
            stderr: tty ? false : stream_flags.fetch(:stderr_value),
            request_id: request.request_id,
            identity: request.identity
          },
          request_id: request.request_id
        )
        normalize_duplex(
          result,
          request,
          tty: tty,
          metadata: {
            operation: "exec",
            command: command,
            stdin: stream_flags.fetch(:stdin),
            stdout: stream_flags.fetch(:stdout),
            stderr: tty ? false : stream_flags.fetch(:stderr)
          }
        )
      end

      alias call exec
      alias open exec

      private

      def normalize_command(value)
        command = Array(value)
        raise InvalidRequest, "command must contain at least one argument" if command.empty?

        command.map do |argument|
          normalized = normalize_string(argument, "command argument")
          normalized
        end.freeze
      rescue TypeError
        raise InvalidRequest, "command must be an Array of strings"
      end

      def normalize_stream_flags(stdin:, stdout:, stderr:)
        stdin_flag, stdin_value = normalize_stream_option(stdin, "stdin", default: false)
        stdout_flag, stdout_value = normalize_stream_option(stdout, "stdout", default: true)
        stderr_flag, stderr_value = normalize_stream_option(stderr, "stderr", default: false)
        {
          stdin: stdin_flag,
          stdin_value: stdin_value,
          stdout: stdout_flag,
          stdout_value: stdout_value,
          stderr: stderr_flag,
          stderr_value: stderr_value
        }.freeze
      end

      def normalize_stream_option(value, name, default:)
        value = default if value.nil?
        return [value, value] if [true, false].include?(value)
        return [true, value] if value.is_a?(Stream) || value.respond_to?(:read) || value.respond_to?(:write)

        raise InvalidRequest, "#{name} must be boolean or an IO-like stream"
      end
    end

    Exec = ExecService
  end
end
