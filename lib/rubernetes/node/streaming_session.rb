# frozen_string_literal: true

require "base64"
require "json"

require_relative "../transport/websocket"
require_relative "../transport/spdy"

module Rubernetes
  module Node
    # The kubelet's streaming protocols on the node side: exec/attach over
    # the Kubernetes channel protocols (WebSocket) and the httpstream
    # protocols (SPDY/3.1), and port-forward over SPDY, over the wsstream
    # channel protocol, and over the SPDY-in-WebSocket tunnel kubectl uses.
    #
    # Every session bridges one of the node's DuplexStreams (exec, attach,
    # port-forward) to the client's framing; the runtime never sees the wire.
    module Streaming
      CHANNEL_STDIN = 0
      CHANNEL_STDOUT = 1
      CHANNEL_STDERR = 2
      CHANNEL_ERROR = 3
      CHANNEL_RESIZE = 4
      CHANNEL_CLOSE = 255

      # Channel protocol names, kubelet's remotecommand/websocket.go.
      WS_PRE_V4_BINARY = "channel.k8s.io"
      WS_PRE_V4_BASE64 = "base64.channel.k8s.io"
      WS_V4_BINARY = "v4.channel.k8s.io"
      WS_V4_BASE64 = "v4.base64.channel.k8s.io"
      WS_V5_BINARY = "v5.channel.k8s.io"
      EXEC_WEBSOCKET_PROTOCOLS = [WS_V5_BINARY, WS_V4_BINARY, WS_V4_BASE64, WS_PRE_V4_BINARY, WS_PRE_V4_BASE64, ""].freeze
      PORT_FORWARD_WEBSOCKET_PROTOCOLS = [WS_V4_BINARY, WS_V4_BASE64, ""].freeze

      # httpstream (SPDY) protocol names, kubelet's remotecommand/constants.go.
      SPDY_V4 = "v4.channel.k8s.io"
      SPDY_V3 = "v3.channel.k8s.io"
      SPDY_V2 = "v2.channel.k8s.io"
      SPDY_V1 = "channel.k8s.io"
      EXEC_SPDY_PROTOCOLS = [SPDY_V4, SPDY_V3, SPDY_V2, SPDY_V1].freeze
      PORT_FORWARD_SPDY_PROTOCOL = "portforward.k8s.io"
      PORT_FORWARD_SPDY_PROTOCOLS = [PORT_FORWARD_SPDY_PROTOCOL].freeze
      TUNNEL_PREFIX = "SPDY/3.1+"
      TUNNEL_SUFFIX = ".k8s.io"

      HEADER_PROTOCOL_VERSION = "x-stream-protocol-version"
      HEADER_ACCEPTED_PROTOCOL_VERSIONS = "x-accepted-stream-protocol-versions"

      STREAM_TYPE = "streamtype"
      STREAM_TYPE_STDIN = "stdin"
      STREAM_TYPE_STDOUT = "stdout"
      STREAM_TYPE_STDERR = "stderr"
      STREAM_TYPE_ERROR = "error"
      STREAM_TYPE_RESIZE = "resize"
      STREAM_TYPE_DATA = "data"
      PORT_HEADER = "port"
      REQUEST_ID_HEADER = "requestid"

      STREAM_CREATION_TIMEOUT = 30.0
      IDLE_TIMEOUT = 4 * 60 * 60
      READ_CHUNK = 32 * 1024
      NON_ZERO_EXIT_REASON = "NonZeroExitCode"
      EXIT_CODE_CAUSE = "ExitCode"

      class Error < StandardError; end

      # metav1.Status documents the way kubelet writes them on the error
      # channel (v4+), or the bare message older protocols expect.
      module Status
        module_function

        def success
          {"metadata" => {}, "status" => "Success"}
        end

        def exit_code(code)
          {"metadata" => {}, "status" => "Failure",
           "message" => "command terminated with non-zero exit code: command terminated with exit code #{code}",
           "reason" => NON_ZERO_EXIT_REASON,
           "details" => {"causes" => [{"reason" => EXIT_CODE_CAUSE, "message" => code.to_s}]}}
        end

        def internal_error(message)
          {"metadata" => {}, "status" => "Failure", "message" => "Internal error occurred: #{message}",
           "reason" => "InternalError", "code" => 500}
        end

        # v4+ protocols carry JSON; v1-v3 carry only a failure message.
        def encode(status, json:)
          return JSON.generate(status).b if json
          return "".b if status["status"] == "Success"

          status["message"].to_s.b
        end
      end

      # Runs one exec/attach session: pumps the duplex's stdout/stderr to the
      # client, the client's stdin/resize to the duplex, then reports the
      # process status on the error channel and closes the transport.
      class RemoteCommand
        def initialize(duplex:, channels:, tty:, stdin:, stdout:, stderr:, json_status:, logger: nil,
                       status_timeout: 5.0)
          @duplex = duplex
          @channels = channels
          @tty = tty
          @stdin = stdin
          @stdout = stdout
          @stderr = stderr && !tty
          @json_status = json_status
          @logger = logger
          @status_timeout = status_timeout
          @mutex = Mutex.new
          @finished = false
          @client_gone = false
        end

        def run
          pumps = []
          pumps << pump_thread(@duplex.stdout) { |bytes| @channels.write_stdout(bytes) } if @stdout && @duplex.stdout
          pumps << pump_thread(@duplex.stderr) { |bytes| @channels.write_stderr(bytes) } if @stderr && @duplex.stderr
          stdin_thread = Thread.new { pump_stdin } if @stdin
          resize_thread = Thread.new { pump_resize } if @tty && @duplex.respond_to?(:resizable?) && @duplex.resizable?
          @channels.on_close { client_gone! }
          pumps.each(&:join)
          status = wait_status(pumps.empty? ? nil : @status_timeout)
          stdin_thread&.kill
          resize_thread&.kill
          write_status(status)
        rescue StandardError => error
          @logger&.call(:warn, "streaming.remote_command_failed", error: error.class.name, message: error.message)
          begin
            @channels.write_error(Status.encode(Status.internal_error("#{error.class}: #{error.message}"), json: @json_status))
          rescue StandardError
            nil
          end
        ensure
          [stdin_thread, resize_thread].compact.each { |thread| thread.kill if thread.alive? }
          finish!
        end

        private

        def client_gone!
          @mutex.synchronize do
            return if @client_gone

            @client_gone = true
          end
          terminate_process
        end

        def finish!
          @mutex.synchronize do
            return if @finished

            @finished = true
          end
          terminate_process if @client_gone
          begin
            @channels.finish
          rescue StandardError
            nil
          end
          begin
            @duplex.close if @duplex.respond_to?(:close)
          rescue StandardError
            nil
          end
        end

        def terminate_process
          @duplex.terminate if @duplex.respond_to?(:terminate)
        rescue StandardError
          nil
        end

        def pump_thread(stream)
          Thread.new do
            loop do
              chunk = read_chunk(stream)
              break if chunk.nil?
              next if chunk.empty?

              yield chunk
            end
          rescue Transport::WebSocket::Closed, Transport::SPDY::StreamClosed, IOError, SystemCallError
            client_gone!
          rescue StandardError => error
            @logger&.call(:debug, "streaming.pump_ended", error: error.class.name, message: error.message)
          end
        end

        # nil at EOF.  A pty master raises EIO once the slave side is gone,
        # which is its way of saying EOF.
        def read_chunk(stream)
          stream.read(READ_CHUNK, timeout: nil)
        rescue Errno::EIO, EOFError
          nil
        rescue StreamClosed
          nil
        rescue StreamTimeout, IO::WaitReadable
          retry
        rescue ArgumentError
          stream.read(READ_CHUNK)
        end

        def pump_stdin
          loop do
            data = @channels.read_stdin
            break if data.nil?
            next if data.empty?

            @duplex.stdin.write(data)
          end
          @duplex.close_write if @duplex.respond_to?(:close_write)
        rescue StandardError => error
          @logger&.call(:debug, "streaming.stdin_ended", error: error.class.name, message: error.message)
          begin
            @duplex.close_write if @duplex.respond_to?(:close_write)
          rescue StandardError
            nil
          end
        end

        def pump_resize
          while (size = @channels.read_resize)
            width = size["Width"] || size["width"]
            height = size["Height"] || size["height"]
            next unless width && height

            begin
              @duplex.resize(width: Integer(width), height: Integer(height))
            rescue StandardError => error
              @logger&.call(:debug, "streaming.resize_failed", error: error.class.name, message: error.message)
            end
          end
        end

        # The exit status arrives on the duplex's status queue once the
        # wrapper reaps the workload.  Output EOF precedes it by a hair; a
        # session with no output streams waits for it outright.
        def wait_status(timeout)
          source = @duplex.respond_to?(:status) ? @duplex.status : nil
          return nil if source.nil?

          value = if source.respond_to?(:pop)
                    timeout ? source.pop(timeout: timeout) : source.pop
                  elsif source.respond_to?(:call)
                    source.call
                  else
                    source
                  end
          source << value if source.respond_to?(:<<) && !value.nil?
          value
        rescue StandardError
          nil
        end

        def exit_code_of(status)
          return nil if status.nil?

          if status.is_a?(Process::Status) || status.respond_to?(:exitstatus)
            code = status.exitstatus
            return code unless code.nil?
            return 128 + status.termsig if status.respond_to?(:termsig) && status.termsig

            return nil
          end
          return Integer(status) if status.is_a?(Integer)

          if status.respond_to?(:exit_status)
            code = status.exit_status
            return code unless code.nil?
            return 128 + status.term_signal.to_i if status.respond_to?(:term_signal) && status.term_signal
          end
          if status.is_a?(Hash)
            code = status[:exit_status] || status["exit_status"] || status[:exitCode] || status["exitCode"]
            return Integer(code) if code
          end
          nil
        end

        def write_status(status)
          document = if status.is_a?(Exception)
                       Status.internal_error("#{status.class}: #{status.message}")
                     else
                       code = exit_code_of(status)
                       code.nil? || code.zero? ? Status.success : Status.exit_code(code)
                     end
          @channels.write_error(Status.encode(document, json: @json_status))
        rescue Transport::WebSocket::Closed, Transport::SPDY::StreamClosed, IOError, SystemCallError
          nil
        end
      end

      # The channel protocol over one WebSocket connection: each message is a
      # channel byte followed by payload (base64 variants use a digit and
      # base64 text), and v5 adds a close signal for half-closing a channel.
      class WebSocketChannels
        def initialize(connection, protocol:, channel_count: 5, stdin: true, stdout: true, stderr: true, logger: nil)
          @connection = connection
          @protocol = protocol
          @base64 = protocol.to_s.include?("base64")
          @stream_close = protocol == WS_V5_BINARY
          @stdin_queue = Queue.new
          @resize_queue = Queue.new
          @channel_queues = Hash.new { |hash, key| hash[key] = Queue.new }
          @channel_count = channel_count
          @stdin_enabled = stdin
          @stdout_enabled = stdout
          @stderr_enabled = stderr
          @logger = logger
          @close_callbacks = []
          @closed = false
          @reader = Thread.new { read_loop }
          @reader.name = "websocket-channels"
        end

        def on_close(&block)
          @close_callbacks << block
        end

        # kubelet writes an empty frame on the first output channel so the
        # client learns the negotiated channel layout before any data.
        def announce
          channel = if @stdout_enabled then CHANNEL_STDOUT
                    elsif @stderr_enabled then CHANNEL_STDERR
                    else CHANNEL_ERROR
                    end
          write_channel(channel, "".b)
        end

        def read_stdin
          value = @stdin_queue.pop
          value == :eof ? nil : value
        end

        def read_resize
          value = @resize_queue.pop
          value == :eof ? nil : value
        end

        # Generic channel read (port-forward data channels).
        def read_channel(index)
          value = @channel_queues[index].pop
          value == :eof ? nil : value
        end

        def write_stdout(bytes)
          write_channel(CHANNEL_STDOUT, bytes) if @stdout_enabled
        end

        def write_stderr(bytes)
          write_channel(CHANNEL_STDERR, bytes) if @stderr_enabled
        end

        def write_error(bytes)
          write_channel(CHANNEL_ERROR, bytes)
        end

        def write_channel(index, bytes)
          if @base64
            @connection.write_message(("0".ord + index).chr + Base64.strict_encode64(bytes.to_s.b), binary: false)
          else
            @connection.write_message(index.chr.b + bytes.to_s.b, binary: true)
          end
        end

        def finish
          return if @closed

          @closed = true
          @connection.close(Transport::WebSocket::CLOSE_NORMAL)
          # Give the peer a moment to answer the close before the socket goes.
          @reader.join(2) if @reader.alive? && @reader != Thread.current
          @connection.close(Transport::WebSocket::CLOSE_NORMAL, shutdown: true)
        end

        private

        def read_loop
          @connection.each_message do |message|
            payload = message.payload
            next if payload.empty?

            channel = payload.getbyte(0)
            data = payload.byteslice(1..) || "".b
            if @stream_close && channel == CHANNEL_CLOSE
              target = data.getbyte(0)
              close_channel(target) if target
              next
            end
            channel -= "0".ord if @base64
            if @base64
              data = begin
                Base64.decode64(data)
              rescue ArgumentError
                "".b
              end
            end
            next if channel >= @channel_count

            deliver(channel, data)
          end
        rescue StandardError => error
          @logger&.call(:debug, "streaming.websocket_read_ended", error: error.class.name, message: error.message)
        ensure
          @stdin_queue << :eof
          @resize_queue << :eof
          @channel_queues.each_value { |queue| queue << :eof }
          @close_callbacks.each do |callback|
            callback.call
          rescue StandardError
            nil
          end
        end

        def deliver(channel, data)
          case channel
          when CHANNEL_STDIN then @stdin_queue << data if @stdin_enabled
          when CHANNEL_RESIZE
            begin
              @resize_queue << JSON.parse(data) unless data.strip.empty?
            rescue JSON::ParserError
              nil
            end
          end
          @channel_queues[channel] << data
        end

        def close_channel(channel)
          case channel
          when CHANNEL_STDIN then @stdin_queue << :eof
          when CHANNEL_RESIZE then @resize_queue << :eof
          end
          @channel_queues[channel] << :eof
        end
      end

      # The httpstream protocols over SPDY: one stream per channel, each
      # announced by the client with a `streamType` header.
      class SPDYChannels
        attr_reader :streams

        def initialize(session, streams, logger: nil)
          @session = session
          @streams = streams
          @logger = logger
          @close_callbacks = []
          @closed = false
        end

        def on_close(&block)
          @close_callbacks << block
          Thread.new do
            @session.join
            yield unless @closed
          rescue StandardError
            nil
          end
        end

        def read_stdin
          stream = @streams[STREAM_TYPE_STDIN]
          return nil unless stream

          stream.read
        end

        def read_resize
          stream = @streams[STREAM_TYPE_RESIZE]
          return nil unless stream

          @resize_buffer ||= "".b
          loop do
            document, rest = next_json(@resize_buffer)
            if document
              @resize_buffer = rest
              return document
            end
            chunk = stream.read
            return nil if chunk.nil?

            @resize_buffer << chunk
          end
        end

        def write_stdout(bytes)
          @streams[STREAM_TYPE_STDOUT]&.write(bytes)
        end

        def write_stderr(bytes)
          @streams[STREAM_TYPE_STDERR]&.write(bytes)
        end

        def write_error(bytes)
          @streams[STREAM_TYPE_ERROR]&.write(bytes) unless bytes.to_s.empty?
        end

        def finish
          return if @closed

          @closed = true
          %w[stdout stderr error].each do |type|
            @streams[type]&.close
          rescue StandardError
            nil
          end
          # Let the FINs reach the peer before the GOAWAY tears everything down.
          sleep(0.05)
          @session.close
        end

        private

        # The resize stream is a sequence of JSON objects without separators.
        def next_json(buffer)
          return [nil, buffer] if buffer.empty?

          depth = 0
          in_string = false
          escaped = false
          buffer.each_char.with_index do |char, index|
            if in_string
              if escaped then escaped = false
              elsif char == "\\" then escaped = true
              elsif char == '"' then in_string = false
              end
              next
            end
            case char
            when '"' then in_string = true
            when "{" then depth += 1
            when "}"
              depth -= 1
              if depth.zero?
                document = JSON.parse(buffer[0..index])
                return [document, buffer[(index + 1)..] || "".b]
              end
            end
          end
          [nil, buffer]
        rescue JSON::ParserError
          [nil, "".b]
        end
      end

      # Collects the exec/attach streams the SPDY client opens, in any order,
      # and starts the command once every expected stream has arrived.
      class SPDYRemoteCommandSession
        def initialize(io, protocol:, stdin:, stdout:, stderr:, tty:, logger: nil, &runner)
          @protocol = protocol
          @expected = 1 + (stdin ? 1 : 0) + (stdout ? 1 : 0) + (stderr && !tty ? 1 : 0)
          @expected += 1 if tty && [SPDY_V4, SPDY_V3].include?(protocol)
          @streams = {}
          @mutex = Mutex.new
          @ready = ConditionVariable.new
          @logger = logger
          @runner = runner
          @session = Transport::SPDY::Session.new(io, server: true, on_stream: method(:accept_stream), logger: logger)
        end

        def run(timeout: STREAM_CREATION_TIMEOUT)
          @session.start
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          @mutex.synchronize do
            while @streams.length < @expected
              remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
              break if remaining <= 0 || @session.closed?

              @ready.wait(@mutex, remaining)
            end
          end
          if @streams.length < @expected
            @logger&.call(:warn, "streaming.spdy_streams_timeout", expected: @expected, received: @streams.keys)
            @session.close
            return false
          end
          channels = SPDYChannels.new(@session, @streams.dup, logger: @logger)
          @runner.call(channels, json_status: @protocol == SPDY_V4)
          @session.join(5)
          true
        end

        private

        def accept_stream(stream)
          type = stream.header(STREAM_TYPE).to_s
          return false unless [STREAM_TYPE_STDIN, STREAM_TYPE_STDOUT, STREAM_TYPE_STDERR, STREAM_TYPE_ERROR,
                               STREAM_TYPE_RESIZE].include?(type)

          @mutex.synchronize do
            return false if @streams.key?(type)

            @streams[type] = stream
            @ready.broadcast
          end
          true
        end
      end

      # Bridges one forwarded connection (a DuplexStream over the runtime's
      # per-port connector, whose frames carry a leading channel byte) to a
      # data stream and an error stream on the client's side.
      class PortForwardBridge
        def initialize(duplex:, data:, error:, port:, pod:, uid:, logger: nil)
          @duplex = duplex
          @data = data
          @error = error
          @port = port
          @pod = pod
          @uid = uid
          @logger = logger
        end

        # `data` and `error` are objects with read(length=nil) -> bytes|nil,
        # write(bytes), close.
        def run
          to_container = Thread.new do
            loop do
              chunk = @data.read
              break if chunk.nil?
              next if chunk.empty?

              @duplex.stdin.write("\x00".b + chunk)
            end
            @duplex.close_write if @duplex.respond_to?(:close_write)
          rescue StandardError => error
            @logger&.call(:debug, "streaming.port_forward_upstream_ended", error: error.class.name, message: error.message)
          end
          from_container = Thread.new do
            loop do
              chunk = begin
                @duplex.stdout.read(READ_CHUNK, timeout: nil)
              rescue StreamTimeout, IO::WaitReadable
                retry
              rescue StreamClosed, IOError
                nil
              end
              break if chunk.nil?
              next if chunk.empty?

              channel = chunk.getbyte(0)
              payload = chunk.byteslice(1..) || "".b
              next if payload.empty?

              if channel.zero?
                @data.write(payload)
              else
                @error.write(payload)
              end
            end
          rescue StandardError => error
            @logger&.call(:debug, "streaming.port_forward_downstream_ended", error: error.class.name, message: error.message)
          end
          from_container.join
          to_container.kill if to_container.alive?
          report_connect_failure
        ensure
          [to_container, from_container].compact.each { |thread| thread.kill if thread.alive? }
          begin
            @duplex.close if @duplex.respond_to?(:close)
          rescue StandardError
            nil
          end
          begin
            @data.close
          rescue StandardError
            nil
          end
          begin
            @error.close
          rescue StandardError
            nil
          end
        end

        private

        # The runtime's connector exits 111 when nothing listens on the port;
        # kubelet reports that on the error stream.
        def report_connect_failure
          statuses = @duplex.respond_to?(:status) ? Array(@duplex.status) : []
          statuses.each do |source|
            value = source.respond_to?(:pop) ? source.pop(timeout: 1.0) : source
            next if value.nil?

            source << value if source.respond_to?(:<<)
            code = value.respond_to?(:exitstatus) ? value.exitstatus : nil
            next unless code && code != 0

            message = if code == 111
                        "error forwarding port #{@port} to pod #{@pod}, uid #{@uid}: failed to connect to localhost:#{@port} inside namespace: connection " \
                          "refused"
                      else
                        "error forwarding port #{@port} to pod #{@pod}, uid #{@uid}: connector exited with #{code}"
                      end
            begin
              @error.write(message.b)
            rescue StandardError
              nil
            end
          end
        end
      end

      # A SPDY stream viewed through the read/write/close contract the bridge
      # expects.
      class StreamEndpoint
        def initialize(stream)
          @stream = stream
        end

        def read(length = nil)
          @stream.read(length)
        end

        def write(bytes)
          @stream.write(bytes)
        end

        def close
          @stream.close
        end
      end

      # Port-forward over SPDY (portforward.k8s.io): the client opens an
      # error stream and a data stream per connection, both carrying the port
      # and a request id; the pair is forwarded once complete.
      class SPDYPortForwardSession
        Pair = Struct.new(:request_id, :data, :error, :created_at)

        def initialize(io, pod:, uid:, logger: nil, &connector)
          @pod = pod
          @uid = uid
          @logger = logger
          @connector = connector
          @pairs = {}
          @mutex = Mutex.new
          @workers = []
          @session = Transport::SPDY::Session.new(io, server: true, on_stream: method(:accept_stream), logger: logger)
        end

        def run
          @session.start
          @session.join
          @workers.each { |worker| worker.join(2) }
          true
        ensure
          @workers.each { |worker| worker.kill if worker.alive? }
        end

        private

        def accept_stream(stream)
          port = stream.header(PORT_HEADER).to_s
          type = stream.header(STREAM_TYPE).to_s
          raise Error, "\"port\" header is required" if port.empty?
          raise Error, "unable to parse #{port.inspect} as a port" unless port.match?(/\A\d+\z/) && port.to_i.between?(1, 65_535)
          raise Error, "\"streamType\" header is required" if type.empty?
          raise Error, "invalid stream type #{type.inspect}" unless [STREAM_TYPE_DATA, STREAM_TYPE_ERROR].include?(type)

          request_id = stream.header(REQUEST_ID_HEADER).to_s
          request_id = (type == STREAM_TYPE_ERROR ? stream.id : stream.id - 2).to_s if request_id.empty?
          pair = nil
          complete = false
          @mutex.synchronize do
            pair = @pairs[request_id] ||= Pair.new(request_id, nil, nil, Process.clock_gettime(Process::CLOCK_MONOTONIC))
            if type == STREAM_TYPE_ERROR
              raise Error, "error stream already assigned" if pair.error

              pair.error = stream
            else
              raise Error, "data stream already assigned" if pair.data

              pair.data = stream
            end
            complete = pair.data && pair.error
            @pairs.delete(request_id) if complete
          end
          @workers << if complete
                        Thread.new { forward(pair, port.to_i) }
                      else
                        Thread.new { monitor(pair, request_id) }
                      end
          true
        end

        def monitor(pair, request_id)
          sleep(STREAM_CREATION_TIMEOUT)
          stale = @mutex.synchronize { @pairs.delete(request_id) if @pairs[request_id].equal?(pair) }
          return unless stale

          message = "timed out waiting for streams for request #{request_id}"
          @logger&.call(:warn, "streaming.port_forward_pair_timeout", request: request_id)
          begin
            pair.error&.write(message.b)
          rescue StandardError
            nil
          end
          [pair.data, pair.error].compact.each do |stream|
            stream.reset
          rescue StandardError
            nil
          end
        end

        def forward(pair, port)
          duplex = @connector.call(port)
          PortForwardBridge.new(duplex: duplex, data: StreamEndpoint.new(pair.data), error: StreamEndpoint.new(pair.error),
                                port: port, pod: @pod, uid: @uid, logger: @logger).run
        rescue StandardError => error
          @logger&.call(:warn, "streaming.port_forward_failed", port: port, error: error.class.name, message: error.message)
          begin
            pair.error.write("error forwarding port #{port} to pod #{@pod}, uid #{@uid}: #{error.message}".b)
          rescue StandardError
            nil
          end
          [pair.data, pair.error].each do |stream|
            stream.reset
          rescue StandardError
            nil
          end
        end
      end

      # A websocket channel viewed through the bridge's contract.
      class ChannelEndpoint
        def initialize(channels, index, readable:)
          @channels = channels
          @index = index
          @readable = readable
        end

        def read(_length = nil)
          return nil unless @readable

          @channels.read_channel(@index)
        end

        def write(bytes)
          @channels.write_channel(@index, bytes)
        end

        def close
          nil
        end
      end

      # Port-forward over the wsstream channel protocol (kubelet's
      # portforward/websocket.go): two channels per requested port, data
      # (read/write) and error (write), each announced with the port number.
      class WebSocketPortForwardSession
        def initialize(connection, protocol:, ports:, pod:, uid:, logger: nil, &connector)
          @connection = connection
          @protocol = protocol
          @ports = ports
          @pod = pod
          @uid = uid
          @logger = logger
          @connector = connector
        end

        def run
          channels = WebSocketChannels.new(@connection, protocol: @protocol, channel_count: @ports.length * 2, logger: @logger)
          @ports.each_with_index do |port, index|
            announcement = [port].pack("v")
            channels.write_channel(index * 2, announcement)
            channels.write_channel((index * 2) + 1, announcement)
          end
          workers = @ports.each_with_index.map do |port, index|
            Thread.new do
              duplex = @connector.call(port)
              PortForwardBridge.new(duplex: duplex,
                                    data: ChannelEndpoint.new(channels, index * 2, readable: true),
                                    error: ChannelEndpoint.new(channels, (index * 2) + 1, readable: false),
                                    port: port, pod: @pod, uid: @uid, logger: @logger).run
            rescue StandardError => error
              @logger&.call(:warn, "streaming.port_forward_failed", port: port, error: error.class.name, message: error.message)
              begin
                channels.write_channel((index * 2) + 1, "error forwarding port #{port} to pod #{@pod}, uid #{@uid}: #{error.message}".b)
              rescue StandardError
                nil
              end
            end
          end
          workers.each(&:join)
          channels.finish
          true
        end
      end
    end
  end
end
