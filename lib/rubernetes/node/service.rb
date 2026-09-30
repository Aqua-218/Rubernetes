# frozen_string_literal: true

# Shared contracts for node subresources.  The node layer owns request
# validation, authorization, request correlation, and byte-oriented streams;
# runtime adapters own process and socket effects behind this boundary.

require "securerandom"
require "socket"
require "timeout"

module Rubernetes
  module Node
    class Error < StandardError
      attr_reader :request_id, :details

      def initialize(message, request_id: nil, details: {})
        @request_id = request_id
        @details = details.dup.freeze
        super(message)
      end
    end

    class InvalidRequest < Error; end
    class AuthorizationError < Error; end
    class RuntimeUnavailable < Error; end
    class StreamClosed < Error; end
    class StreamTimeout < Error; end
    class BackpressureError < StreamTimeout; end

    # Immutable context shared by authorization hooks and runtime calls.
    RequestContext = Data.define(:operation, :container_id, :request_id, :identity, :metadata) do
      def to_h
        {
          operation: operation,
          container_id: container_id,
          request_id: request_id,
          identity: identity,
          metadata: metadata
        }
      end
    end

    # A bounded byte pipe used by tests and adapters that need explicit
    # backpressure.  It has independent read and write closure, matching the
    # half-close semantics of a TCP stream without assuming a socket backend.
    class StreamBuffer
      attr_reader :capacity

      def initialize(capacity: 1_048_576, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @capacity = Integer(capacity)
        raise ArgumentError, "stream buffer capacity must be positive" unless @capacity.positive?

        @clock = clock
        @mutex = Mutex.new
        @read_condition = ConditionVariable.new
        @write_condition = ConditionVariable.new
        @bytes = "".b
        @write_closed = false
        @read_closed = false
      end

      def write(value, timeout: nil)
        bytes = Stream.binary(value)
        raise StreamClosed, "stream write side is closed" if bytes.empty? && closed_for_write?

        deadline = timeout_deadline(timeout)
        @mutex.synchronize do
          raise StreamClosed, "stream write side is closed" if @write_closed || @read_closed

          offset = 0
          while offset < bytes.bytesize
            available = @capacity - @bytes.bytesize
            if available.zero?
              wait_for(@write_condition, deadline, BackpressureError, "stream write timed out while waiting for capacity")
              next
            end

            chunk_size = [available, bytes.bytesize - offset].min
            @bytes << bytes.byteslice(offset, chunk_size)
            offset += chunk_size
            @read_condition.broadcast
            if offset < bytes.bytesize
              wait_for(@write_condition, deadline, BackpressureError, "stream write timed out while waiting for capacity")
            end
          end
        end
        bytes.bytesize
      end

      def read(length = nil, timeout: nil)
        requested = length.nil? ? nil : Integer(length)
        raise ArgumentError, "stream read length must be positive" if requested && requested <= 0

        deadline = timeout_deadline(timeout)
        @mutex.synchronize do
          while @bytes.empty? && !@write_closed
            return nil if @read_closed

            wait_for(@read_condition, deadline, StreamTimeout, "stream read timed out waiting for data")
          end
          return nil if @bytes.empty? && @write_closed

          size = requested ? [requested, @bytes.bytesize].min : @bytes.bytesize
          value = @bytes.byteslice(0, size)
          @bytes = @bytes.byteslice(size, @bytes.bytesize - size) || "".b
          @write_condition.broadcast
          value
        end
      end

      def close_write
        @mutex.synchronize do
          return self if @write_closed

          @write_closed = true
          @read_condition.broadcast
          self
        end
      end

      def close
        @mutex.synchronize do
          return self if @read_closed && @write_closed

          @read_closed = true
          @write_closed = true
          @bytes = "".b
          @read_condition.broadcast
          @write_condition.broadcast
          self
        end
      end

      def closed?
        @mutex.synchronize { @read_closed && @write_closed }
      end

      def write_closed?
        @mutex.synchronize { @write_closed }
      end

      def read_closed?
        @mutex.synchronize { @read_closed }
      end

      private

      def closed_for_write?
        @mutex.synchronize { @write_closed || @read_closed }
      end

      def timeout_deadline(timeout)
        return nil if timeout.nil?

        seconds = Float(timeout)
        raise ArgumentError, "stream timeout must be non-negative" if seconds.negative?

        @clock.call + seconds
      rescue TypeError, ArgumentError => error
        raise ArgumentError, "stream timeout must be a non-negative number: #{error.message}"
      end

      def wait_for(condition, deadline, error_class, message)
        return condition.wait(@mutex) if deadline.nil?

        remaining = deadline - @clock.call
        raise error_class, message if remaining <= 0

        condition.wait(@mutex, remaining)
        raise error_class, message if deadline - @clock.call <= 0
      end
    end

    # Transport-neutral binary stream.  A stream can be backed by a String,
    # an IO, an Enumerable of chunks, or an object implementing read/write.
    # No operation ever transcodes data, which is required for arbitrary
    # container logs and exec output.
    class Stream
      include Enumerable

      attr_reader :request_id, :metadata

      def self.binary(value)
        raise TypeError, "stream chunks must be String values" unless value.is_a?(String)

        value.dup.force_encoding(Encoding::BINARY)
      end

      def self.memory(capacity: 1_048_576, request_id: nil, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        buffer = StreamBuffer.new(capacity: capacity, clock: clock)
        stream = new(source: buffer, sink: buffer, request_id: request_id, clock: clock)
        [stream, buffer]
      end

      def initialize(source: nil, sink: nil, request_id: nil, metadata: {}, read_timeout: nil, write_timeout: nil,
                     close_source: true, close_sink: true, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @source = source
        @sink = sink
        @request_id = request_id&.to_s&.dup&.freeze
        @metadata = deep_freeze(metadata)
        @read_timeout = read_timeout
        @write_timeout = write_timeout
        @close_source = close_source
        @close_sink = close_sink
        @clock = clock
        @mutex = Mutex.new
        @source_buffer = "".b
        @source_offset = 0
        @source_enumerator = source.is_a?(String) || source.nil? || source.respond_to?(:read) ? nil : source.to_enum
        @read_closed = false
        @write_closed = false
        @eof = source.nil?
      end

      def read(length = nil, timeout: @read_timeout)
        requested = length.nil? ? nil : Integer(length)
        raise ArgumentError, "stream read length must be positive" if requested && requested <= 0
        raise StreamClosed.new("stream read side is closed", request_id: request_id) if read_closed?
        return nil if eof?

        value = read_from_source(requested, timeout: timeout)
        if value.nil? || value.empty?
          @mutex.synchronize { @eof = true }
          return nil
        end
        self.class.binary(value)
      rescue EOFError
        @mutex.synchronize { @eof = true }
        nil
      rescue StreamTimeout => error
        raise error if error.request_id == request_id

        raise StreamTimeout.new(error.message, request_id: request_id), cause: error
      rescue IO::WaitReadable, IO::WaitWritable => error
        raise StreamTimeout.new("stream read timed out: #{error.message}", request_id: request_id), cause: error
      end

      def read_nonblock(length = 16_384, exception: true)
        value = read(length, timeout: 0)
        return value unless value.nil? && exception

        raise IO::WaitReadable
      rescue StreamTimeout
        raise IO::WaitReadable if exception

        :wait_readable
      end

      def write_nonblock(value, exception: true)
        write(value, timeout: 0)
      rescue BackpressureError
        raise IO::WaitWritable if exception

        :wait_writable
      end

      def each
        return enum_for(__method__) unless block_given?

        loop do
          # Enumerable consumers (HTTP chunking, WebSocket relays) must see
          # bytes while a live process is still running. An unbounded IO#read
          # waits for EOF and turns attach/follow streams into a deadlock.
          value = read(16 * 1024)
          break if value.nil?

          yield value
        end
        self
      end

      def write(value, timeout: @write_timeout)
        raise StreamClosed.new("stream write side is closed", request_id: request_id) if write_closed?

        bytes = self.class.binary(value)
        return 0 if bytes.empty?

        raise IOError, "stream has no writable sink" unless @sink.respond_to?(:write)

        offset = 0
        while offset < bytes.bytesize
          chunk = bytes.byteslice(offset, bytes.bytesize - offset)
          timeout_options = timeout_keyword(@sink, timeout)
          result = if timeout_options.empty?
                     invoke_with_timeout(timeout, BackpressureError, "stream write timed out") { @sink.write(chunk) }
                   else
                     @sink.write(chunk, **timeout_options)
                   end
          written = result.nil? ? chunk.bytesize : Integer(result)
          raise IOError, "stream sink wrote an invalid byte count" if written <= 0 || written > chunk.bytesize

          offset += written
        end
        offset
      rescue IO::WaitWritable, Errno::EAGAIN => error
        raise BackpressureError.new("stream write would block", request_id: request_id), cause: error
      rescue BackpressureError => error
        raise error if error.request_id == request_id

        raise BackpressureError.new(error.message, request_id: request_id), cause: error
      end

      def flush
        return self unless @sink.respond_to?(:flush)

        @sink.flush
        self
      end

      def close_write
        @mutex.synchronize do
          return self if @write_closed

          @write_closed = true
        end
        if @sink.respond_to?(:close_write)
          @sink.close_write
        elsif @sink.respond_to?(:shutdown)
          @sink.shutdown(Socket::SHUT_WR)
        elsif @sink.respond_to?(:close) && @close_sink
          @sink.close
        end
        self
      rescue IOError, SystemCallError => error
        raise StreamClosed.new("failed to half-close stream: #{error.message}", request_id: request_id), cause: error
      end

      def close
        should_close_source = false
        should_close_sink = false
        @mutex.synchronize do
          should_close_source = @close_source && !@read_closed
          should_close_sink = @close_sink && !@write_closed
          @read_closed = true
          @write_closed = true
          @eof = true
        end
        close_endpoint(@source) if should_close_source
        close_endpoint(@sink) if should_close_sink && !@sink.equal?(@source)
        close_endpoint(@sink) if should_close_sink && @sink.equal?(@source)
        self
      end

      def closed?
        @mutex.synchronize { @read_closed && @write_closed }
      end

      def read_closed?
        @mutex.synchronize { @read_closed }
      end

      def write_closed?
        @mutex.synchronize { @write_closed }
      end

      def eof?
        @mutex.synchronize { @eof }
      end

      def half_closed?
        write_closed? && !read_closed?
      end

      def with_request_id(value)
        self.class.new(
          source: @source,
          sink: @sink,
          request_id: value,
          metadata: metadata,
          read_timeout: @read_timeout,
          write_timeout: @write_timeout,
          close_source: @close_source,
          close_sink: @close_sink,
          clock: @clock
        )
      end

      private

      def read_from_source(length, timeout:)
        return read_from_string(length) if @source.is_a?(String)
        return nil if @source.nil?

        if @source.respond_to?(:read)
          if endpoint_accepts_timeout?(@source,
                                       :read) || (@source.respond_to?(:readpartial) && endpoint_accepts_timeout?(@source, :readpartial))
            read_io(@source, length, timeout: timeout)
          else
            invoke_with_timeout(timeout, StreamTimeout, "stream read timed out") do
              read_io(@source, length, timeout: nil)
            end
          end
        else
          read_from_enumerator(length)
        end
      end

      def read_from_string(length)
        remaining = @source.bytesize - @source_offset
        return nil if remaining <= 0

        size = length.nil? ? remaining : [length, remaining].min
        value = @source.byteslice(@source_offset, size)
        @source_offset += size
        value
      end

      def read_from_enumerator(length)
        while @source_buffer.empty?
          begin
            @source_buffer = self.class.binary(@source_enumerator.next)
          rescue StopIteration
            return nil
          end
        end
        # A followed log never reaches EOF.  Like IO#readpartial (and the Go
        # io.Reader contract every streaming client copies with), hand back what
        # is available as soon as anything is, at most `length` bytes; filling
        # the whole request first blocks an attach until the container exits.
        consume_buffer(length.nil? ? @source_buffer.bytesize : [length, @source_buffer.bytesize].min)
      end

      def consume_buffer(length)
        size = [length, @source_buffer.bytesize].min
        value = @source_buffer.byteslice(0, size)
        @source_buffer = @source_buffer.byteslice(size, @source_buffer.bytesize - size) || "".b
        value
      end

      def read_io(io, length, timeout: nil)
        if length.nil?
          invoke_io_read(io, nil, timeout: timeout)
        elsif io.respond_to?(:readpartial)
          invoke_io_read(io, length, method_name: :readpartial, timeout: timeout)
        else
          invoke_io_read(io, length, timeout: timeout)
        end
      end

      def invoke_io_read(io, length, method_name: :read, timeout: nil)
        callable = io.method(method_name)
        parameters = callable.parameters
        if parameters.any? { |kind, _| kind == :keyrest } || parameters.any? do |kind, name|
          %i[key keyreq].include?(kind) && name == :timeout
        end
          return length.nil? ? callable.call(timeout: timeout) : callable.call(length, timeout: timeout)
        end

        length.nil? ? callable.call : callable.call(length)
      end

      def invoke_with_timeout(timeout, error_class, message, &)
        return yield if timeout.nil?

        seconds = Float(timeout)
        raise ArgumentError, "stream timeout must be non-negative" if seconds.negative?

        Timeout.timeout(seconds, &)
      rescue Timeout::Error => error
        raise error_class.new(message, request_id: request_id), cause: error
      end

      def timeout_keyword(callable, timeout)
        return {} if timeout.nil?

        parameters = begin
          callable.method(:write).parameters
        rescue StandardError
          []
        end
        supports_timeout = parameters.any? { |kind, _| kind == :keyrest } ||
                           parameters.any? { |kind, name| %i[key keyreq].include?(kind) && name == :timeout }
        supports_timeout ? {timeout: timeout} : {}
      end

      def endpoint_accepts_timeout?(endpoint, method_name)
        parameters = endpoint.method(method_name).parameters
        parameters.any? { |kind, _| kind == :keyrest } ||
          parameters.any? { |kind, name| %i[key keyreq].include?(kind) && name == :timeout }
      rescue NameError
        false
      end

      def close_endpoint(endpoint)
        return unless endpoint.respond_to?(:close)
        return if endpoint.respond_to?(:closed?) && endpoint.closed?

        endpoint.close
      rescue IOError, SystemCallError
        # Closing an already-disconnected peer is an idempotent stream cleanup.
        nil
      end

      def deep_freeze(value)
        case value
        when Hash
          value.each do |key, child|
            key.freeze
            deep_freeze(child)
          end
        when Array
          value.each { |child| deep_freeze(child) }
        end
        value.freeze
      end
    end

    # A stream with a readable output side and a writable input side.  Runtime
    # adapters may expose stdout/stderr separately; stderr is retained as a
    # second byte stream unless tty mode intentionally merges it.
    class DuplexStream < Stream
      attr_reader :stdin, :stdout, :stderr, :status, :resizer, :terminator

      def self.pair(capacity: 1_048_576, request_id: nil,
                    clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        left_to_right = StreamBuffer.new(capacity: capacity, clock: clock)
        right_to_left = StreamBuffer.new(capacity: capacity, clock: clock)
        left = new(input: left_to_right, output: right_to_left, tty: true, request_id: request_id, clock: clock)
        right = new(input: right_to_left, output: left_to_right, tty: true, request_id: request_id, clock: clock)
        [left, right]
      end

      def initialize(input: nil, output: nil, error: nil, status: nil, tty: false, request_id: nil, metadata: {},
                     read_timeout: nil, write_timeout: nil, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                     resizer: nil, terminator: nil)
        @resizer = resizer
        @terminator = terminator
        @stdin = input.is_a?(Stream) ? input : Stream.new(sink: input, request_id: request_id, write_timeout: write_timeout, clock: clock)
        @stdout = if output.is_a?(Stream)
                    output
                  else
                    Stream.new(source: output, request_id: request_id, read_timeout: read_timeout,
                               clock: clock)
                  end
        @stderr = if tty
                    nil
                  elsif error.is_a?(Stream)
                    error
                  else
                    Stream.new(source: error, request_id: request_id, read_timeout: read_timeout, clock: clock)
                  end
        @status = status
        @tty = !!tty
        super(source: @stdout, sink: @stdin, request_id: request_id, metadata: metadata.merge(tty: @tty),
              read_timeout: read_timeout, write_timeout: write_timeout, close_source: false, close_sink: false, clock: clock)
      end

      def tty?
        @tty
      end

      # Terminal resize for a tty session (kubelet's TerminalSize); a no-op
      # for streams without a pty.
      def resize(width:, height:)
        return false unless @resizer

        @resizer.call(Integer(width), Integer(height))
        true
      end

      def resizable?
        !@resizer.nil?
      end

      # Ends the remote process when the client goes away.
      def terminate(signal = nil)
        return false unless @terminator

        signal.nil? ? @terminator.call : @terminator.call(signal)
        true
      end

      def close_write
        @stdin.close_write
        self
      end

      def write_closed?
        @stdin.write_closed?
      end

      def read_closed?
        @stdout.read_closed?
      end

      def eof?
        @stdout.eof?
      end

      def half_closed?
        write_closed? && !read_closed?
      end

      def with_request_id(value)
        self.class.new(
          input: @stdin,
          output: @stdout,
          error: @stderr,
          status: @status,
          tty: @tty,
          request_id: value,
          metadata: metadata,
          read_timeout: instance_variable_get(:@read_timeout),
          write_timeout: instance_variable_get(:@write_timeout),
          clock: instance_variable_get(:@clock),
          resizer: @resizer,
          terminator: @terminator
        )
      end

      def close
        @stdin.close
        @stdout.close
        @stderr&.close
        self
      end

      def closed?
        @stdin.closed? && @stdout.closed? && (@stderr.nil? || @stderr.closed?)
      end
    end

    BidirectionalStream = DuplexStream
    IOStream = Stream

    # Base class used by all node subresource services.  It deliberately does
    # not know the runtime implementation; adapter invocation filters optional
    # keywords so a minimal spec-compliant adapter remains valid.
    class Service
      attr_reader :runtime, :authorizer, :trusted

      def initialize(runtime: nil, runtime_adapter: nil, authorizer: nil,
                     trusted: false,
                     request_id_generator: -> { SecureRandom.uuid },
                     clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        runtime ||= runtime_adapter
        raise ArgumentError, "runtime must respond to the requested operation" if runtime.nil?

        @runtime = runtime
        @authorizer = authorizer
        @trusted = trusted == true
        @request_id_generator = request_id_generator
        @clock = clock
      end

      private

      attr_reader :request_id_generator, :clock

      def context(operation:, container_id:, request_id:, identity:, metadata: {})
        id = request_id.nil? ? request_id_generator.call : request_id
        id = normalize_string(id, "request_id")
        RequestContext.new(
          operation: normalize_string(operation, "operation"),
          container_id: normalize_string(container_id, "container_id"),
          request_id: id,
          identity: identity,
          metadata: deep_freeze(metadata)
        )
      end

      def authorize!(request_context)
        return request_context if trusted
        unless authorizer
          raise AuthorizationError.new(
            "authorization is not configured for #{request_context.operation}",
            request_id: request_context.request_id,
            details: {operation: request_context.operation, container_id: request_context.container_id}
          )
        end

        verdict = if authorizer.respond_to?(:authorize)
                    invoke_authorizer(authorizer.method(:authorize), request_context)
                  elsif authorizer.respond_to?(:call)
                    callable = authorizer.respond_to?(:parameters) ? authorizer : authorizer.method(:call)
                    invoke_authorizer(callable, request_context)
                  else
                    raise ArgumentError, "authorizer must respond to authorize or call"
                  end
        return request_context if authorization_allowed?(verdict)

        raise AuthorizationError.new(
          "request is not authorized for #{request_context.operation}",
          request_id: request_context.request_id,
          details: {operation: request_context.operation, container_id: request_context.container_id}
        )
      end

      def invoke_authorizer(callable, request_context)
        parameters = callable.parameters
        accepts_keywords = parameters.any? { |kind, _| %i[key keyreq keyrest].include?(kind) }
        return callable.call(**request_context.to_h) if accepts_keywords
        return callable.call if parameters.empty?

        callable.call(request_context)
      end

      def authorization_allowed?(verdict)
        return true if verdict == true
        return verdict.allowed? if verdict.respond_to?(:allowed?)
        return verdict.fetch(:allowed) if verdict.is_a?(Hash) && verdict.key?(:allowed)
        return verdict.fetch("allowed") if verdict.is_a?(Hash) && verdict.key?("allowed")

        false
      end

      def invoke_runtime(operation, positional, keywords, request_id:)
        unless runtime.respond_to?(operation)
          raise RuntimeUnavailable.new(
            "runtime adapter does not implement #{operation}",
            request_id: request_id,
            details: {operation: operation}
          )
        end

        callable = runtime.method(operation)
        filtered = filter_keywords(callable, keywords)
        callable.call(*positional, **filtered)
      rescue NoMethodError => error
        raise RuntimeUnavailable.new(
          "runtime adapter failed to resolve #{operation}: #{error.message}",
          request_id: request_id,
          details: {operation: operation}
        ), cause: error
      end

      def filter_keywords(callable, keywords)
        parameters = callable.parameters
        return keywords if parameters.any? { |kind, _| kind == :keyrest }
        return {} if parameters.none? { |kind, _| %i[key keyreq].include?(kind) }

        accepted = parameters.filter_map { |kind, name| name if %i[key keyreq].include?(kind) }
        keywords.select { |key, _| accepted.include?(key) }
      end

      def normalize_stream(value, request_context, metadata: {})
        return value.with_request_id(request_context.request_id) if value.is_a?(Stream) && value.request_id.nil?
        return value if value.is_a?(Stream)

        Stream.new(source: value, request_id: request_context.request_id, metadata: metadata, clock: clock)
      end

      def normalize_duplex(value, request_context, tty:, metadata: {})
        if value.is_a?(DuplexStream)
          return value.with_request_id(request_context.request_id) if value.request_id.nil?

          return value
        end
        if value.is_a?(Stream)
          return DuplexStream.new(input: value, output: value, tty: tty, request_id: request_context.request_id,
                                  metadata: metadata, clock: clock)
        end

        if value.is_a?(Hash)
          input = value[:stdin] || value["stdin"] || value[:input] || value["input"]
          output = value[:stdout] || value["stdout"] || value[:output] || value["output"]
          error = value[:stderr] || value["stderr"] || value[:error] || value["error"]
          status = value[:status] || value["status"]
          return DuplexStream.new(input: input, output: output, error: error, status: status, tty: tty,
                                  request_id: request_context.request_id, metadata: metadata, clock: clock,
                                  resizer: value[:resize] || value["resize"], terminator: value[:terminate] || value["terminate"])
        end

        DuplexStream.new(output: value, tty: tty, request_id: request_context.request_id, metadata: metadata, clock: clock)
      end

      def normalize_string(value, name)
        string = String(value)
        raise InvalidRequest, "#{name} must not be empty" if string.empty?
        raise InvalidRequest, "#{name} must not contain NUL" if string.include?("\0")

        string.freeze
      rescue TypeError => error
        raise InvalidRequest, "#{name} must be a string: #{error.message}"
      end

      def normalize_bool(value, name)
        return value if [true, false].include?(value)

        raise InvalidRequest, "#{name} must be boolean"
      end

      def normalize_timeout(value, name: "timeout")
        return nil if value.nil?

        timeout = Float(value)
        raise InvalidRequest, "#{name} must be non-negative" if timeout.negative?

        timeout
      rescue TypeError, ArgumentError => error
        raise InvalidRequest, "#{name} must be a non-negative number: #{error.message}"
      end

      def deep_freeze(value)
        case value
        when Hash
          value.each do |key, child|
            key.freeze
            deep_freeze(child)
          end
        when Array
          value.each { |child| deep_freeze(child) }
        end
        value.freeze
      end
    end
  end
end
