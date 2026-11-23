# frozen_string_literal: true

require_relative "service"

module Rubernetes
  module Node
    # Exec and attach share the runtime's duplex stream and authorization contract.
    class ContainerStreamService < Service
      private

      def open_container_stream(operation, container_id, request_id:, identity:, options:, tty:, stdin:, stdout:, stderr:)
        container_id ||= options.delete(:container_id) || options.delete(:id) || options.delete(:container)
        request = context(
          operation: operation.to_s, container_id: container_id,
          request_id: request_id, identity: identity, metadata: options
        )
        tty = normalize_bool(tty, "tty")
        streams = {
          stdin: stream_option(stdin, "stdin", default: false),
          stdout: stream_option(stdout, "stdout", default: true),
          stderr: stream_option(stderr, "stderr", default: false)
        }
        streams[:stderr] = false if tty

        args = [request.container_id]
        metadata = {operation: request.operation}
        if block_given?
          command = yield
          args << command
          metadata[:command] = command
        end
        metadata.merge!(streams.transform_values { |stream| !false.equal?(stream) })
        authorize!(request)
        keywords = streams.merge(tty: tty, request_id: request.request_id, identity: request.identity)
        result = invoke_runtime(operation, args, keywords, request_id: request.request_id)
        normalize_duplex(result, request, tty: tty, metadata: metadata)
      end

      def stream_option(value, name, default:)
        return default if value.nil?
        return value if [true, false].include?(value) || value.is_a?(Stream) || Stream.readable?(value) || Stream.writable?(value)

        raise InvalidRequest, "#{name} must be boolean or an IO-like stream"
      end
    end
  end
end
