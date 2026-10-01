# frozen_string_literal: true

require_relative "hpack"
require_relative "headers"
require_relative "request"
require_relative "response"
require_relative "errors"

module Rubernetes
  module Transport
    # Server side of HTTP/2 (RFC 9113) for TLS connections that negotiate
    # "h2" through ALPN.  kube-apiserver serves h2, and client-go multiplexes
    # every request of a client -- its watches and its writes -- over one
    # connection to one apiserver.  Over HTTP/1.1 a client opened several
    # connections, the kubernetes Service spread them over the apiservers, and
    # a client could see its own write before its own watch did (the DRA
    # ResourceClaim CRUD specs lost ~12 s to that).
    #
    # One connection: the thread that accepted it reads and dispatches frames;
    # a writer thread drains the outbound queue, so reading never waits on a
    # slow peer; each request runs the handler on a thread of its own.  Ruby's
    # OpenSSL calls hold the GVL, so the reader's and the writer's SSL calls
    # never overlap.  Upgrades (exec/attach/port-forward) stay on HTTP/1.1:
    # clients never negotiate h2 for them.
    module HTTP2
      PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b.freeze

      DATA = 0x0
      HEADERS = 0x1
      PRIORITY = 0x2
      RST_STREAM = 0x3
      SETTINGS = 0x4
      PUSH_PROMISE = 0x5
      PING = 0x6
      GOAWAY = 0x7
      WINDOW_UPDATE = 0x8
      CONTINUATION = 0x9

      FLAG_END_STREAM = 0x1
      FLAG_ACK = 0x1
      FLAG_END_HEADERS = 0x4
      FLAG_PADDED = 0x8
      FLAG_PRIORITY = 0x20

      SETTINGS_HEADER_TABLE_SIZE = 0x1
      SETTINGS_ENABLE_PUSH = 0x2
      SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
      SETTINGS_INITIAL_WINDOW_SIZE = 0x4
      SETTINGS_MAX_FRAME_SIZE = 0x5
      SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

      NO_ERROR = 0x0
      PROTOCOL_ERROR = 0x1
      INTERNAL_ERROR = 0x2
      FLOW_CONTROL_ERROR = 0x3
      STREAM_CLOSED = 0x5
      FRAME_SIZE_ERROR = 0x6
      REFUSED_STREAM = 0x7
      CANCEL = 0x8
      COMPRESSION_ERROR = 0x9
      ENHANCE_YOUR_CALM = 0xb

      DEFAULT_WINDOW = 65_535
      MAX_WINDOW = (2**31) - 1
      DEFAULT_MAX_FRAME_SIZE = 16_384
      MAX_FRAME_SIZE_LIMIT = (2**24) - 1

      # Headers that only mean something on an HTTP/1.1 connection.
      CONNECTION_HEADERS = %w[connection keep-alive proxy-connection transfer-encoding upgrade].freeze

      class ConnectionError < StandardError
        attr_reader :code

        def initialize(code, message)
          super(message)
          @code = code
        end
      end

      class StreamError < StandardError
        attr_reader :stream_id, :code

        def initialize(stream_id, code, message)
          super(message)
          @stream_id = stream_id
          @code = code
        end
      end

      # The stream ended under a response being written: reset by the peer,
      # or the connection went away.
      class StreamClosed < StandardError; end

      module_function

      def frame(type, flags, stream_id, payload = "".b)
        length = payload.bytesize
        [length >> 16, length & 0xffff, type, flags, stream_id & MAX_WINDOW].pack("CnCCN") << payload.b
      end

      class Stream
        attr_reader :id
        attr_accessor :fields, :body, :send_window, :recv_window, :remote_closed, :reset, :response_body,
                      :dispatched, :rejected

        def initialize(id, send_window:, recv_window:)
          @id = id
          @fields = nil
          @body = +"".b
          @send_window = send_window
          @recv_window = recv_window
          @remote_closed = false
          @reset = false
          @response_body = nil
          @dispatched = false
          @rejected = false
        end
      end

      class Connection
        MAX_CONCURRENT_STREAMS = 1000
        # Per-stream and connection receive windows advertised to the peer.
        # Received data is credited back as it arrives: request bodies are
        # bounded by max_body_bytes, not by flow control.
        LOCAL_STREAM_WINDOW = 1 << 20
        LOCAL_CONNECTION_WINDOW = 1 << 24
        READ_CHUNK = 64 * 1024
        # Response data waiting for the writer; a stream writing past it waits.
        OUTBOUND_LIMIT = 1 << 20
        TICK_SECONDS = 1.0
        # A write whose event a watch on this same connection sent while the
        # write ran is answered this long after that event.  The server sends
        # the event first (API::Server#await_watch_delivery), but client-go
        # then needs ~1 ms to decode it into the informer cache, and the
        # writer reading its informer right after the response saw the old
        # object 2 times in 3 (the e2e CRUD helper then waits 2 s).  Clients
        # that do not watch their own writes are not delayed.
        WATCH_EVENT_LEAD_SECONDS = 0.003
        MUTATING_METHODS = %w[POST PUT PATCH DELETE].freeze
        GOAWAY_LINGER_SECONDS = 1.0

        attr_reader :streams

        def initialize(io, server:, remote_address: nil, client_certificate: nil, client_chain: [],
                       idle_timeout: 30.0, write_timeout: 30.0, max_header_bytes: 64 * 1024,
                       max_header_count: 256, max_body_bytes: 3 * 1024 * 1024, max_response_bytes: nil,
                       server_name: nil)
          @io = io
          @server = server
          @remote_address = remote_address
          @client_certificate = client_certificate
          @client_chain = Array(client_chain)
          @idle_timeout = idle_timeout
          @write_timeout = write_timeout
          @max_header_bytes = max_header_bytes
          @max_header_count = max_header_count
          @max_body_bytes = max_body_bytes
          @max_response_bytes = max_response_bytes
          @server_name = server_name
          @decoder = HPACK::Decoder.new(max_header_list_bytes: [max_header_bytes * 4, 1 << 20].max)
          @mutex = Mutex.new
          @window_changed = ConditionVariable.new
          @outbound_changed = ConditionVariable.new
          @outbound = []
          @outbound_bytes = 0
          @streams = {}
          @last_stream_id = 0
          @conn_send_window = DEFAULT_WINDOW
          @conn_recv_window = LOCAL_CONNECTION_WINDOW
          @peer_initial_window = DEFAULT_WINDOW
          @peer_max_frame_size = DEFAULT_MAX_FRAME_SIZE
          @continuation = nil
          @closed = false
          @goaway_sent = false
          @peer_goaway = false
          @writer_done = false
          @rbuf = +"".b
          @last_activity = monotonic_time
          @settings_received = false
          @last_watch_data_at = nil
        end

        # Serves the connection until it ends.  The caller closes the socket.
        def serve
          read_preface
          @writer = Thread.new { writer_loop }
          @writer.name = "http2-writer" if @writer.respond_to?(:name=)
          enqueue(HTTP2.frame(SETTINGS, 0, 0, settings_payload(
            SETTINGS_MAX_CONCURRENT_STREAMS => MAX_CONCURRENT_STREAMS,
            SETTINGS_INITIAL_WINDOW_SIZE => LOCAL_STREAM_WINDOW,
            SETTINGS_MAX_HEADER_LIST_SIZE => @max_header_bytes
          )))
          enqueue(HTTP2.frame(WINDOW_UPDATE, 0, 0, [LOCAL_CONNECTION_WINDOW - DEFAULT_WINDOW].pack("N")))
          loop do
            frame = read_frame
            break if frame.nil?

            handle_frame(*frame)
          end
        rescue ConnectionError => error
          log(:warn, "HTTP/2 connection error", error: error.message, code: error.code)
          send_goaway(error.code, error.message)
        rescue HPACK::DecodingError => error
          log(:warn, "HTTP/2 header compression error", error: error.message)
          send_goaway(COMPRESSION_ERROR, error.message)
        rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
          nil
        ensure
          finish
        end

        private

        # -- reading -----------------------------------------------------------

        def read_preface
          raise EOFError, "no HTTP/2 preface" unless fill(PREFACE.bytesize, handshake: true)

          preface = @rbuf.slice!(0, PREFACE.bytesize)
          raise ConnectionError.new(PROTOCOL_ERROR, "invalid connection preface") unless preface == PREFACE
        end

        # [type, flags, stream_id, payload], or nil once the connection should end.
        def read_frame
          return nil unless fill(9)

          length = (@rbuf.getbyte(0) << 16) | (@rbuf.getbyte(1) << 8) | @rbuf.getbyte(2)
          type = @rbuf.getbyte(3)
          flags = @rbuf.getbyte(4)
          stream_id = @rbuf.byteslice(5, 4).unpack1("N") & MAX_WINDOW
          raise ConnectionError.new(FRAME_SIZE_ERROR, "frame of #{length} bytes exceeds the maximum") if length > DEFAULT_MAX_FRAME_SIZE

          return nil unless fill(9 + length)

          @rbuf.slice!(0, 9)
          payload = @rbuf.slice!(0, length)
          [type, flags, stream_id, payload]
        end

        # Waits until the buffer holds count bytes.  false: end the connection
        # (the peer closed it, or it idled out / the server is stopping).
        def fill(count, handshake: false)
          while @rbuf.bytesize < count
            chunk = @io.read_nonblock(READ_CHUNK, exception: false)
            case chunk
            when :wait_readable
              return false unless wait_io(readable: true, handshake: handshake)
            when :wait_writable
              return false unless wait_io(readable: false, handshake: handshake)
            when nil
              return false if @rbuf.empty? && !handshake

              raise EOFError, "peer closed the HTTP/2 connection"
            else
              @rbuf << chunk
              @last_activity = monotonic_time
            end
          end
          true
        end

        def wait_io(readable:, handshake:)
          loop do
            io = @io.respond_to?(:to_io) ? @io.to_io : @io
            ready = readable ? io.wait_readable(TICK_SECONDS) : io.wait_writable(TICK_SECONDS)
            return true if ready
            raise EOFError, "HTTP/2 writer stopped" if @mutex.synchronize { @closed }

            idle = monotonic_time - @last_activity
            raise EOFError, "no HTTP/2 preface" if handshake && idle > @idle_timeout

            return false unless keep_reading?(idle)
          end
        end

        def keep_reading?(idle)
          active = @mutex.synchronize { @streams.length }
          stopping = @server.respond_to?(:stopping?) && @server.stopping?
          if stopping || @peer_goaway || (active.zero? && idle > @idle_timeout)
            send_goaway(NO_ERROR, "") unless @goaway_sent
            return false if active.zero?
          end
          true
        end

        # -- frames ------------------------------------------------------------

        def handle_frame(type, flags, stream_id, payload)
          raise ConnectionError.new(PROTOCOL_ERROR, "expected CONTINUATION") if @continuation && type != CONTINUATION
          raise ConnectionError.new(PROTOCOL_ERROR, "the first frame must be SETTINGS") unless @settings_received || type == SETTINGS

          case type
          when DATA then on_data(flags, stream_id, payload)
          when HEADERS then on_headers(flags, stream_id, payload)
          when PRIORITY then on_priority(stream_id, payload)
          when RST_STREAM then on_rst_stream(stream_id, payload)
          when SETTINGS then on_settings(flags, stream_id, payload)
          when PUSH_PROMISE then raise ConnectionError.new(PROTOCOL_ERROR, "clients cannot push")
          when PING then on_ping(flags, stream_id, payload)
          when GOAWAY then on_goaway(stream_id, payload)
          when WINDOW_UPDATE then on_window_update(stream_id, payload)
          when CONTINUATION then on_continuation(flags, stream_id, payload)
          end
        rescue StreamError => error
          reset_stream(error.stream_id, error.code)
        end

        def on_settings(flags, stream_id, payload)
          raise ConnectionError.new(PROTOCOL_ERROR, "SETTINGS on a stream") unless stream_id.zero?

          if flags & FLAG_ACK != 0
            raise ConnectionError.new(FRAME_SIZE_ERROR, "SETTINGS ack with a payload") unless payload.empty?

            return
          end
          raise ConnectionError.new(FRAME_SIZE_ERROR, "SETTINGS payload length") unless (payload.bytesize % 6).zero?

          @settings_received = true
          payload.unpack("nN" * (payload.bytesize / 6)).each_slice(2) do |identifier, value|
            case identifier
            when SETTINGS_ENABLE_PUSH
              raise ConnectionError.new(PROTOCOL_ERROR, "ENABLE_PUSH must be 0 or 1") if value > 1
            when SETTINGS_INITIAL_WINDOW_SIZE
              raise ConnectionError.new(FLOW_CONTROL_ERROR, "INITIAL_WINDOW_SIZE too large") if value > MAX_WINDOW

              @mutex.synchronize do
                delta = value - @peer_initial_window
                @peer_initial_window = value
                @streams.each_value do |stream|
                  stream.send_window += delta
                  raise ConnectionError.new(FLOW_CONTROL_ERROR, "stream window overflow") if stream.send_window > MAX_WINDOW
                end
                @window_changed.broadcast
              end
            when SETTINGS_MAX_FRAME_SIZE
              raise ConnectionError.new(PROTOCOL_ERROR, "MAX_FRAME_SIZE out of range") unless value.between?(DEFAULT_MAX_FRAME_SIZE, MAX_FRAME_SIZE_LIMIT)

              @mutex.synchronize { @peer_max_frame_size = value }
            end
          end
          enqueue(HTTP2.frame(SETTINGS, FLAG_ACK, 0))
        end

        def on_ping(flags, stream_id, payload)
          raise ConnectionError.new(PROTOCOL_ERROR, "PING on a stream") unless stream_id.zero?
          raise ConnectionError.new(FRAME_SIZE_ERROR, "PING payload length") unless payload.bytesize == 8

          enqueue(HTTP2.frame(PING, FLAG_ACK, 0, payload)) if flags & FLAG_ACK == 0
        end

        def on_goaway(stream_id, payload)
          raise ConnectionError.new(PROTOCOL_ERROR, "GOAWAY on a stream") unless stream_id.zero?
          raise ConnectionError.new(FRAME_SIZE_ERROR, "GOAWAY payload length") if payload.bytesize < 8

          @peer_goaway = true
        end

        def on_window_update(stream_id, payload)
          raise ConnectionError.new(FRAME_SIZE_ERROR, "WINDOW_UPDATE payload length") unless payload.bytesize == 4

          increment = payload.unpack1("N") & MAX_WINDOW
          if stream_id.zero?
            raise ConnectionError.new(PROTOCOL_ERROR, "zero connection window increment") if increment.zero?

            @mutex.synchronize do
              @conn_send_window += increment
              raise ConnectionError.new(FLOW_CONTROL_ERROR, "connection window overflow") if @conn_send_window > MAX_WINDOW

              @window_changed.broadcast
            end
            return
          end

          idle_stream!(stream_id, "WINDOW_UPDATE")
          raise StreamError.new(stream_id, PROTOCOL_ERROR, "zero stream window increment") if increment.zero?

          @mutex.synchronize do
            stream = @streams[stream_id]
            return unless stream

            stream.send_window += increment
            raise StreamError.new(stream_id, FLOW_CONTROL_ERROR, "stream window overflow") if stream.send_window > MAX_WINDOW

            @window_changed.broadcast
          end
        end

        def on_priority(stream_id, payload)
          raise ConnectionError.new(PROTOCOL_ERROR, "PRIORITY on stream 0") if stream_id.zero?
          raise StreamError.new(stream_id, FRAME_SIZE_ERROR, "PRIORITY payload length") unless payload.bytesize == 5
        end

        def on_rst_stream(stream_id, payload)
          raise ConnectionError.new(PROTOCOL_ERROR, "RST_STREAM on stream 0") if stream_id.zero?
          raise ConnectionError.new(FRAME_SIZE_ERROR, "RST_STREAM payload length") unless payload.bytesize == 4

          idle_stream!(stream_id, "RST_STREAM")
          stream = @mutex.synchronize do
            stream = @streams.delete(stream_id)
            stream&.reset = true
            @window_changed.broadcast
            @outbound_changed.broadcast
            stream
          end
          close_response_body(stream) if stream
        end

        def on_data(flags, stream_id, payload)
          raise ConnectionError.new(PROTOCOL_ERROR, "DATA on stream 0") if stream_id.zero?

          length = payload.bytesize
          data = strip_padding(flags, payload)
          @conn_recv_window -= length
          raise ConnectionError.new(FLOW_CONTROL_ERROR, "connection receive window exceeded") if @conn_recv_window.negative?

          # Credit the connection window back right away: it is shared by
          # every stream and request bodies are bounded elsewhere.
          if length.positive?
            @conn_recv_window += length
            enqueue(HTTP2.frame(WINDOW_UPDATE, 0, 0, [length].pack("N")))
          end

          idle_stream!(stream_id, "DATA")
          stream = @mutex.synchronize { @streams[stream_id] }
          # A stream already answered and forgotten (reset, or refused).
          return if stream.nil? || stream.rejected
          raise StreamError.new(stream_id, STREAM_CLOSED, "DATA after END_STREAM") if stream.remote_closed

          stream.recv_window -= length
          raise StreamError.new(stream_id, FLOW_CONTROL_ERROR, "stream receive window exceeded") if stream.recv_window.negative?

          if stream.body.bytesize + data.bytesize > @max_body_bytes
            reject_stream(stream, 413, "PayloadTooLarge", "request body exceeds the configured limit")
            return
          end

          stream.body << data
          if flags & FLAG_END_STREAM != 0
            stream.remote_closed = true
            dispatch(stream)
          elsif length.positive?
            stream.recv_window += length
            enqueue(HTTP2.frame(WINDOW_UPDATE, 0, stream_id, [length].pack("N")))
          end
        end

        def on_headers(flags, stream_id, payload)
          raise ConnectionError.new(PROTOCOL_ERROR, "HEADERS on stream 0") if stream_id.zero?

          fragment = strip_padding(flags, payload)
          if flags & FLAG_PRIORITY != 0
            raise ConnectionError.new(PROTOCOL_ERROR, "HEADERS priority block truncated") if fragment.bytesize < 5

            fragment = fragment.byteslice(5, fragment.bytesize - 5)
          end
          @continuation = {stream_id: stream_id, flags: flags, block: fragment.b}
          header_block_complete if flags & FLAG_END_HEADERS != 0
        end

        def on_continuation(flags, stream_id, payload)
          raise ConnectionError.new(PROTOCOL_ERROR, "unexpected CONTINUATION") if @continuation.nil? || @continuation[:stream_id] != stream_id

          @continuation[:block] << payload
          raise ConnectionError.new(ENHANCE_YOUR_CALM, "header block too large") if @continuation[:block].bytesize > [@max_header_bytes * 4, 1 << 20].max

          header_block_complete if flags & FLAG_END_HEADERS != 0
        end

        def header_block_complete
          pending = @continuation
          @continuation = nil
          stream_id = pending[:stream_id]
          # Always decode: the HPACK table is connection state.
          fields = @decoder.decode(pending[:block])
          end_stream = pending[:flags] & FLAG_END_STREAM != 0

          existing = @mutex.synchronize { @streams[stream_id] }
          if existing
            # Trailers: only valid to end the request.
            raise StreamError.new(stream_id, PROTOCOL_ERROR, "HEADERS without END_STREAM after the request head") unless end_stream
            return if existing.rejected

            existing.remote_closed = true
            dispatch(existing)
            return
          end

          if stream_id <= @last_stream_id
            # A closed stream: the reset or response already ended it.
            raise ConnectionError.new(STREAM_CLOSED, "HEADERS on closed stream #{stream_id}") unless stream_id.odd?

            return
          end
          raise ConnectionError.new(PROTOCOL_ERROR, "client stream ids must be odd") unless stream_id.odd?

          @last_stream_id = stream_id
          # After a GOAWAY the client retries these streams elsewhere.
          return if @goaway_sent

          stream = Stream.new(stream_id, send_window: @mutex.synchronize { @peer_initial_window }, recv_window: LOCAL_STREAM_WINDOW)
          admitted = @mutex.synchronize do
            next false if @streams.length >= MAX_CONCURRENT_STREAMS

            @streams[stream_id] = stream
            true
          end
          raise StreamError.new(stream_id, REFUSED_STREAM, "too many concurrent streams") unless admitted

          stream.fields = fields
          return unless end_stream

          stream.remote_closed = true
          dispatch(stream)
        end

        def strip_padding(flags, payload)
          return payload if flags & FLAG_PADDED == 0
          raise ConnectionError.new(PROTOCOL_ERROR, "padded frame without a pad length") if payload.empty?

          pad = payload.getbyte(0)
          raise ConnectionError.new(PROTOCOL_ERROR, "padding exceeds the frame") if pad >= payload.bytesize

          payload.byteslice(1, payload.bytesize - 1 - pad)
        end

        def idle_stream!(stream_id, what)
          return if stream_id <= @last_stream_id

          raise ConnectionError.new(PROTOCOL_ERROR, "#{what} on idle stream #{stream_id}")
        end

        # -- requests ----------------------------------------------------------

        def dispatch(stream)
          return if stream.dispatched

          stream.dispatched = true
          thread = Thread.new { serve_stream(stream) }
          thread.name = "http2-stream" if thread.respond_to?(:name=)
        end

        def serve_stream(stream)
          request = begin
            build_request(stream)
          rescue StreamError => error
            reset_stream(stream.id, error.code)
            return
          rescue RequestError => error
            write_response(stream, @server.__send__(:error_response, error), nil)
            return
          end
          started = monotonic_time
          response = @server.__send__(:respond_to_request, request)
          let_watch_event_lead(started) if MUTATING_METHODS.include?(request.method)
          write_response(stream, response, request)
        rescue StreamClosed
          nil
        rescue ResponseTimeout, ResponseTooLarge => error
          log(:warn, "HTTP/2 response failed", error: error.message)
          reset_stream(stream.id, INTERNAL_ERROR)
        rescue StandardError => error
          log(:error, "HTTP/2 stream failed", error: error.class.name, message: error.message,
                                              backtrace: Array(error.backtrace).first(8))
          reset_stream(stream.id, INTERNAL_ERROR)
        ensure
          forget(stream)
        end

        def build_request(stream)
          pseudo = {}
          headers = Headers.new
          cookies = []
          regular = false
          bytes = 0
          count = 0
          stream.fields.each do |name, value|
            bytes += name.bytesize + value.bytesize + HPACK::ENTRY_OVERHEAD
            if name.start_with?(":")
              raise StreamError.new(stream.id, PROTOCOL_ERROR, "pseudo-header after a regular header") if regular
              unless %w[:method :scheme :path :authority].include?(name) && !pseudo.key?(name)
                raise StreamError.new(stream.id, PROTOCOL_ERROR, "invalid pseudo-header #{name}")
              end

              pseudo[name] = value
              next
            end

            regular = true
            count += 1
            if name.match?(/[A-Z]/) || CONNECTION_HEADERS.include?(name) || (name == "te" && value != "trailers")
              raise StreamError.new(stream.id, PROTOCOL_ERROR, "invalid header #{name}")
            end
            next cookies << value if name == "cookie"

            begin
              headers.add(name, value)
            rescue ArgumentError
              raise StreamError.new(stream.id, PROTOCOL_ERROR, "invalid header #{name}")
            end
          end
          raise HeaderTooLarge if bytes > @max_header_bytes || count > @max_header_count

          method = pseudo[":method"]
          target = pseudo[":path"]
          if method.nil? || method == "CONNECT" || target.nil? || target.empty? || pseudo[":scheme"].nil?
            raise StreamError.new(stream.id, PROTOCOL_ERROR, "missing or unsupported request pseudo-headers")
          end
          raise BadRequest, "request method is invalid" unless Headers::TOKEN_PATTERN.match?(method)

          headers.add("cookie", cookies.join("; ")) unless cookies.empty?
          authority = pseudo[":authority"]
          headers.add("host", authority) if authority && !headers.include?("host")
          if (length = headers["content-length"]) && length.to_s.strip != stream.body.bytesize.to_s
            raise StreamError.new(stream.id, PROTOCOL_ERROR, "content-length does not match the body")
          end

          Request.new(method: method, target: target, headers: headers, body: stream.body, http_version: "HTTP/2.0",
                      remote_address: @remote_address, client_certificate: @client_certificate,
                      client_chain: @client_chain)
        end

        def let_watch_event_lead(started)
          sent = @mutex.synchronize { @last_watch_data_at }
          return unless sent && sent >= started

          delay = sent + WATCH_EVENT_LEAD_SECONDS - monotonic_time
          sleep(delay) if delay.positive?
        end

        # A request the server will not read to its end: answer it and reset
        # the rest of its upload (RFC 9113 8.1).
        def reject_stream(stream, status, reason, message)
          stream.rejected = true
          Thread.new do
            response = Response.json({"kind" => "Status", "apiVersion" => "v1", "metadata" => {}, "status" => "Failure",
                                      "message" => message, "reason" => reason, "code" => status}, status: status)
            write_response(stream, response, nil)
            reset_stream(stream.id, NO_ERROR)
          rescue StreamClosed, ResponseTimeout
            nil
          ensure
            forget(stream)
          end
        end

        # -- responses ---------------------------------------------------------

        def write_response(stream, response, request)
          if response.respond_to?(:upgrade?) && response.upgrade?
            response = @server.__send__(:error_response, BadRequest.new("HTTP upgrades are not supported over HTTP/2"))
          end

          headers = response.headers.dup
          CONNECTION_HEADERS.each { |name| headers.delete(name) }
          headers.delete("content-length")
          headers.set("Date", Time.now.utc.httpdate) unless headers.include?("date")
          headers.set("Server", @server_name) if @server_name && !headers.include?("server")
          no_body = response.no_body? || request&.method == "HEAD"
          streaming = response.stream? && !no_body
          body_bytes = nil
          if no_body
            unless response.no_body? || response.stream?
              headers.set("Content-Length", @server.__send__(:body_to_bytes, response.body).bytesize.to_s)
            end
          elsif !streaming
            body_bytes = @server.__send__(:body_to_bytes, response.body)
            if @max_response_bytes && body_bytes.bytesize > @max_response_bytes
              raise ResponseTooLarge, "response body exceeds #{@max_response_bytes} bytes"
            end

            if request && @server.__send__(:gzip_requested?, request) &&
               body_bytes.bytesize >= HTTPServer::GZIP_MIN_BYTES && !headers.include?("content-encoding")
              body_bytes = @server.__send__(:gzip_bytes, body_bytes)
              headers.set("Content-Encoding", "gzip")
              headers.add("Vary", "Accept-Encoding") unless headers.include?("vary")
            end
            headers.set("Content-Length", body_bytes.bytesize.to_s)
          end

          fields = [[":status", response.status.to_s]]
          headers.each do |name, _value|
            downcased = name.downcase
            headers.raw_values(name).each { |value| fields << [downcased, value] }
          end
          ends = no_body || (!streaming && body_bytes.empty?)
          send_headers(stream, fields, end_stream: ends)
          return if ends

          if streaming
            write_stream_body(stream, response)
          else
            send_data(stream, body_bytes, end_stream: true)
          end
        end

        def write_stream_body(stream, response)
          body = response.body
          registered = @mutex.synchronize do
            stream.response_body = body unless stream.reset || @closed
          end
          # Reset before the body was registered: nobody else will close it.
          unless registered
            body.close if body.respond_to?(:close)
            raise StreamClosed
          end

          unbounded = response.respond_to?(:unbounded?) && response.unbounded?
          sizes = body.respond_to?(:piece_written)
          written = 0
          @server.__send__(:each_stream_piece, body) do |piece|
            encoded = @server.__send__(:encode_stream_piece, piece)
            next if encoded.empty?

            body.piece_written(encoded.bytesize) if sizes
            written += encoded.bytesize
            if !unbounded && @max_response_bytes && written > @max_response_bytes
              raise ResponseTooLarge.new("response stream exceeds #{@max_response_bytes} bytes", partial: true)
            end

            send_data(stream, encoded, end_stream: false)
            @mutex.synchronize { @last_watch_data_at = monotonic_time } if unbounded
          end
          raise StreamClosed if @mutex.synchronize { stream.reset || @closed }

          send_data(stream, "".b, end_stream: true)
        ensure
          taken = @mutex.synchronize do
            owned = stream.response_body
            stream.response_body = nil
            owned
          end
          taken.close if taken.respond_to?(:close)
        end

        def send_headers(stream, fields, end_stream:)
          block = HPACK::Encoder.encode(fields)
          max = @mutex.synchronize { @peer_max_frame_size }
          flags = end_stream ? FLAG_END_STREAM : 0
          frames = +"".b
          first = block.byteslice(0, max)
          rest = block.byteslice(first.bytesize, block.bytesize - first.bytesize)
          frames << HTTP2.frame(HEADERS, flags | (rest.empty? ? FLAG_END_HEADERS : 0), stream.id, first)
          until rest.empty?
            piece = rest.byteslice(0, max)
            rest = rest.byteslice(piece.bytesize, rest.bytesize - piece.bytesize)
            frames << HTTP2.frame(CONTINUATION, rest.empty? ? FLAG_END_HEADERS : 0, stream.id, piece)
          end
          enqueue(frames, stream: stream)
        end

        def send_data(stream, bytes, end_stream:)
          if bytes.empty?
            enqueue(HTTP2.frame(DATA, end_stream ? FLAG_END_STREAM : 0, stream.id), stream: stream) if end_stream
            return
          end

          offset = 0
          while offset < bytes.bytesize
            size = reserve_window(stream, bytes.bytesize - offset)
            last = offset + size == bytes.bytesize
            flags = end_stream && last ? FLAG_END_STREAM : 0
            enqueue(HTTP2.frame(DATA, flags, stream.id, bytes.byteslice(offset, size)), stream: stream, data: true)
            offset += size
          end
        end

        # Takes up to wanted bytes of send window, waiting for the peer to
        # grant some.
        def reserve_window(stream, wanted)
          deadline = monotonic_time + @write_timeout
          @mutex.synchronize do
            loop do
              raise StreamClosed if stream.reset || @closed

              available = [stream.send_window, @conn_send_window, @peer_max_frame_size, wanted].min
              if available.positive?
                stream.send_window -= available
                @conn_send_window -= available
                return available
              end
              remaining = deadline - monotonic_time
              raise ResponseTimeout, "peer granted no HTTP/2 flow-control window" if remaining <= 0

              @window_changed.wait(@mutex, remaining)
            end
          end
        end

        def reset_stream(stream_id, code)
          stream = @mutex.synchronize do
            stream = @streams.delete(stream_id)
            stream&.reset = true
            @window_changed.broadcast
            stream
          end
          close_response_body(stream) if stream
          enqueue(HTTP2.frame(RST_STREAM, 0, stream_id, [code].pack("N")))
        rescue StreamClosed
          nil
        end

        def forget(stream)
          @mutex.synchronize do
            @streams.delete(stream.id) if @streams[stream.id].equal?(stream)
          end
        end

        def close_response_body(stream)
          body = @mutex.synchronize do
            owned = stream.response_body
            stream.response_body = nil
            owned
          end
          body.close if body.respond_to?(:close)
        rescue StandardError => error
          log(:warn, "HTTP/2 stream close hook failed", error: error.class.name)
        end

        def send_goaway(code, message)
          return if @goaway_sent

          @goaway_sent = true
          enqueue(HTTP2.frame(GOAWAY, 0, 0, [@last_stream_id, code].pack("NN") + message.to_s.b))
        rescue StreamClosed
          nil
        end

        # -- writing -----------------------------------------------------------

        def enqueue(bytes, stream: nil, data: false)
          deadline = monotonic_time + @write_timeout
          @mutex.synchronize do
            loop do
              raise StreamClosed if @closed || stream&.reset
              break unless data && @outbound_bytes > OUTBOUND_LIMIT

              remaining = deadline - monotonic_time
              raise ResponseTimeout, "HTTP/2 peer is not reading" if remaining <= 0

              @outbound_changed.wait(@mutex, remaining)
            end
            @outbound << bytes
            @outbound_bytes += bytes.bytesize
            @outbound_changed.broadcast
          end
        end

        def writer_loop
          loop do
            batch = @mutex.synchronize do
              @outbound_changed.wait(@mutex) while @outbound.empty? && !@writer_done
              next nil if @outbound.empty?

              chunk = @outbound.join
              @outbound.clear
              @outbound_bytes = 0
              @outbound_changed.broadcast
              chunk
            end
            break if batch.nil?

            @server.__send__(:write_all, @io, batch, deadline: monotonic_time + @write_timeout, timeout_error: ResponseTimeout)
          end
        rescue ResponseTimeout, IOError, SystemCallError, OpenSSL::SSL::SSLError
          abort_connection
        rescue StandardError => error
          log(:error, "HTTP/2 writer failed", error: error.class.name, message: error.message)
          abort_connection
        end

        def abort_connection
          @mutex.synchronize do
            @closed = true
            @window_changed.broadcast
            @outbound_changed.broadcast
          end
          # Wakes the reader out of its wait.
          io = @io.respond_to?(:to_io) ? @io.to_io : @io
          io.close_read if io.respond_to?(:close_read) && !io.closed?
        rescue IOError, SystemCallError
          nil
        end

        def finish
          streams = @mutex.synchronize do
            @writer_done = true
            @outbound_changed.broadcast
            @streams.values
          end
          # Flush what is queued (a GOAWAY, final responses) before closing.
          @writer&.join(GOAWAY_LINGER_SECONDS)
          @mutex.synchronize do
            @closed = true
            @window_changed.broadcast
            @outbound_changed.broadcast
          end
          streams.each do |stream|
            stream.reset = true
            close_response_body(stream)
          end
          @writer&.kill if @writer&.alive?
        end

        def settings_payload(settings)
          settings.map { |identifier, value| [identifier, value].pack("nN") }.join.b
        end

        def monotonic_time
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end

        def log(level, message, **fields)
          @server.__send__(:log, level, message, **fields)
        rescue StandardError
          nil
        end
      end
    end
  end
end
