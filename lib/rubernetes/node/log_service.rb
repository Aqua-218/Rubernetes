# frozen_string_literal: true

require_relative "service"

module Rubernetes
  module Node
    # Serves container logs as a binary stream.  The runtime remains the
    # source of follow/since semantics; this class validates the request and
    # applies a local tail only to bounded data returned by simple adapters.
    class LogService < Service
      def logs(container_id = nil, follow: false, since: nil, tail: nil, request_id: nil, identity: nil,
               timestamps: false, limit_bytes: nil, **options)
        container_id ||= options.delete(:container_id) || options.delete(:id) || options.delete(:container)
        since ||= options.delete(:since_time) || options.delete(:since_seconds)
        tail ||= options.delete(:tail_lines)
        stream_name = normalize_log_stream(options.delete(:stream))
        request = context(
          operation: "logs",
          container_id: container_id,
          request_id: request_id,
          identity: identity,
          metadata: options
        )
        follow = normalize_bool(follow, "follow")
        since = normalize_since(since)
        tail = normalize_tail(tail)
        timestamps = normalize_bool(timestamps, "timestamps")
        limit_bytes = normalize_limit_bytes(limit_bytes)
        authorize!(request)

        result = invoke_runtime(
          :logs,
          [request.container_id],
          {follow: follow, since: since, tail: tail, stream: stream_name, timestamps: timestamps,
           request_id: request.request_id, identity: request.identity},
          request_id: request.request_id
        )
        result = result[:body] || result["body"] if result.is_a?(Hash) && (result.key?(:body) || result.key?("body"))
        stream = normalize_stream(result, request,
                                  metadata: {operation: "logs", follow: follow, since: since, tail: tail, stream: stream_name})
        if bounded_source?(result, follow: follow) && !tail.nil?
          stream = Stream.new(
            source: tail_bytes(result, tail),
            request_id: request.request_id,
            metadata: stream.metadata,
            clock: clock
          )
        end
        return stream if limit_bytes.nil?

        Stream.new(source: LimitedSource.new(stream, limit_bytes), request_id: request.request_id,
                   metadata: stream.metadata, clock: clock)
      end

      # PodLogOptions.limitBytes: the log ends after that many bytes, even
      # mid-line, and a followed log stops there too.
      class LimitedSource
        include Enumerable

        def initialize(source, limit)
          @source = source
          @remaining = limit
        end

        def each
          return to_enum(:each) unless block_given?

          @source.each do |chunk|
            break if @remaining <= 0

            piece = chunk.to_s.b.byteslice(0, @remaining)
            @remaining -= piece.bytesize
            yield piece unless piece.empty?
            break if @remaining <= 0
          end
          close
          self
        end

        def close
          @source.close if @source.respond_to?(:close)
          nil
        end
      end

      alias call logs
      alias open logs

      private

      def normalize_since(value)
        return nil if value.nil?

        case value
        when Integer
          raise InvalidRequest, "since must be non-negative" if value.negative?

          value
        when Time
          value.utc.iso8601(6).freeze
        when String
          raise InvalidRequest, "since must not be empty" if value.empty?
          raise InvalidRequest, "since must not contain NUL" if value.include?("\0")

          value.dup.freeze
        else
          raise InvalidRequest, "since must be an integer, Time, or String"
        end
      end

      def normalize_limit_bytes(value)
        return nil if value.nil? || value.to_s.empty?

        limit = Integer(value)
        raise InvalidRequest, "limitBytes must be a positive integer" unless limit.positive?

        limit
      rescue TypeError, ArgumentError => error
        raise InvalidRequest, "limitBytes must be a positive integer: #{error.message}"
      end

      def normalize_tail(value)
        return nil if value.nil?

        tail = Integer(value)
        raise InvalidRequest, "tail must be -1 or a non-negative integer" if tail < -1

        tail
      rescue TypeError, ArgumentError => error
        raise InvalidRequest, "tail must be -1 or a non-negative integer: #{error.message}"
      end

      # The Pod log API's `stream` parameter: "All" by default, so a
      # container's log is both of its streams.  kubelet returns whatever the
      # container wrote to either -- the CRI tags each line with the stream it
      # came from and ReadLogs returns them all -- and serving stdout alone
      # hid every diagnostic a workload writes to stderr.
      def normalize_log_stream(value)
        stream = value.to_s.downcase
        return :all if stream.empty? || stream == "all"
        return stream.to_sym if %w[stdout stderr].include?(stream)

        raise InvalidRequest, "stream must be All, Stdout, or Stderr"
      end

      def bounded_source?(value, follow:)
        return false if value.is_a?(Stream)
        return true if value.is_a?(String) || value.is_a?(Array)

        !follow && value.is_a?(Enumerator)
      end

      def tail_bytes(value, tail)
        return "".b if tail == 0

        bytes = if value.is_a?(Array)
                  value.join
                elsif value.is_a?(String)
                  value
                else
                  value.each_with_object("".b) { |chunk, output| output << Stream.binary(chunk) }
                end
        return Stream.binary(bytes) if tail == -1

        bytes = Stream.binary(bytes)
        return bytes if bytes.empty?

        trailing_newline = bytes.end_with?("\n".b)
        lines = bytes.split("\n".b, -1)
        lines.pop if trailing_newline
        selected = lines.last(tail)
        result = selected.join("\n".b)
        result << "\n".b if trailing_newline && !selected.empty?
        result.force_encoding(Encoding::BINARY)
      end
    end

    LogsService = LogService
  end
end
