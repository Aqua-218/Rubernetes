# frozen_string_literal: true

require "base64"
require "thread"
require "zlib"

module Rubernetes
  module Transport
    # SPDY/3.1 framing as spoken by Kubernetes' httpstream (moby/spdystream):
    # the wire format behind `kubectl exec/attach/port-forward` whenever the
    # client uses the SPDY transport or tunnels SPDY frames over WebSocket.
    #
    # Only the subset spdystream uses is implemented -- SYN_STREAM, SYN_REPLY,
    # RST_STREAM, DATA, PING, GOAWAY, HEADERS, SETTINGS/WINDOW_UPDATE (parsed
    # and ignored: spdystream implements no flow control) -- with the SPDY/3
    # zlib header dictionary so headers interoperate with Go peers.
    module SPDY
      VERSION = 3
      HEADER_SPDY31 = "SPDY/3.1"

      TYPE_SYN_STREAM = 1
      TYPE_SYN_REPLY = 2
      TYPE_RST_STREAM = 3
      TYPE_SETTINGS = 4
      TYPE_PING = 6
      TYPE_GOAWAY = 7
      TYPE_HEADERS = 8
      TYPE_WINDOW_UPDATE = 9

      FLAG_FIN = 0x01
      FLAG_UNIDIRECTIONAL = 0x02

      RST_PROTOCOL_ERROR = 1
      RST_INVALID_STREAM = 2
      RST_REFUSED_STREAM = 3
      RST_CANCEL = 5
      RST_INTERNAL_ERROR = 6
      RST_STREAM_ALREADY_CLOSED = 9

      GOAWAY_OK = 0
      GOAWAY_PROTOCOL_ERROR = 1
      GOAWAY_INTERNAL_ERROR = 2

      MAX_DATA_LENGTH = (1 << 24) - 1
      MAX_HEADER_COUNT = 1000
      MAX_HEADER_FIELD_SIZE = 1 << 20
      HEADER_VALUE_SEPARATOR = "\x00"

      # The SPDY/3 zlib dictionary (draft-mbelshe-httpbis-spdy-00 §2.6.10.1),
      # byte-identical to moby/spdystream's headerDictionary.
      DICTIONARY = Base64.decode64(<<~B64.delete("\n")).b.freeze
        AAAAB29wdGlvbnMAAAAEaGVhZAAAAARwb3N0AAAAA3B1dAAAAAZkZWxldGUAAAAFdHJhY2UAAAAGYWNjZXB0AAAADmFjY2VwdC1jaGFyc2V0AAAAD2FjY2Vw
        dC1lbmNvZGluZwAAAA9hY2NlcHQtbGFuZ3VhZ2UAAAANYWNjZXB0LXJhbmdlcwAAAANhZ2UAAAAFYWxsb3cAAAANYXV0aG9yaXphdGlvbgAAAA1jYWNo
        ZS1jb250cm9sAAAACmNvbm5lY3Rpb24AAAAMY29udGVudC1iYXNlAAAAEGNvbnRlbnQtZW5jb2RpbmcAAAAQY29udGVudC1sYW5ndWFnZQAAAA5jb250
        ZW50LWxlbmd0aAAAABBjb250ZW50LWxvY2F0aW9uAAAAC2NvbnRlbnQtbWQ1AAAADWNvbnRlbnQtcmFuZ2UAAAAMY29udGVudC10eXBlAAAABGRhdGUA
        AAAEZXRhZwAAAAZleHBlY3QAAAAHZXhwaXJlcwAAAARmcm9tAAAABGhvc3QAAAAIaWYtbWF0Y2gAAAARaWYtbW9kaWZpZWQtc2luY2UAAAANaWYtbm9u
        ZS1tYXRjaAAAAAhpZi1yYW5nZQAAABNpZi11bm1vZGlmaWVkLXNpbmNlAAAADWxhc3QtbW9kaWZpZWQAAAAIbG9jYXRpb24AAAAMbWF4LWZvcndhcmRz
        AAAABnByYWdtYQAAABJwcm94eS1hdXRoZW50aWNhdGUAAAATcHJveHktYXV0aG9yaXphdGlvbgAAAAVyYW5nZQAAAAdyZWZlcmVyAAAAC3JldHJ5LWFm
        dGVyAAAABnNlcnZlcgAAAAJ0ZQAAAAd0cmFpbGVyAAAAEXRyYW5zZmVyLWVuY29kaW5nAAAAB3VwZ3JhZGUAAAAKdXNlci1hZ2VudAAAAAR2YXJ5AAAA
        A3ZpYQAAAAd3YXJuaW5nAAAAEHd3dy1hdXRoZW50aWNhdGUAAAAGbWV0aG9kAAAAA2dldAAAAAZzdGF0dXMAAAAGMjAwIE9LAAAAB3ZlcnNpb24AAAAI
        SFRUUC8xLjEAAAADdXJsAAAABnB1YmxpYwAAAApzZXQtY29va2llAAAACmtlZXAtYWxpdmUAAAAGb3JpZ2luMTAwMTAxMjAxMjAyMjA1MjA2MzAwMzAy
        MzAzMzA0MzA1MzA2MzA3NDAyNDA1NDA2NDA3NDA4NDA5NDEwNDExNDEyNDEzNDE0NDE1NDE2NDE3NTAyNTA0NTA1MjAzIE5vbi1BdXRob3JpdGF0aXZl
        IEluZm9ybWF0aW9uMjA0IE5vIENvbnRlbnQzMDEgTW92ZWQgUGVybWFuZW50bHk0MDAgQmFkIFJlcXVlc3Q0MDEgVW5hdXRob3JpemVkNDAzIEZvcmJp
        ZGRlbjQwNCBOb3QgRm91bmQ1MDAgSW50ZXJuYWwgU2VydmVyIEVycm9yNTAxIE5vdCBJbXBsZW1lbnRlZDUwMyBTZXJ2aWNlIFVuYXZhaWxhYmxlSmFu
        IEZlYiBNYXIgQXByIE1heSBKdW4gSnVsIEF1ZyBTZXB0IE9jdCBOb3YgRGVjIDAwOjAwOjAwIE1vbiwgVHVlLCBXZWQsIFRodSwgRnJpLCBTYXQsIFN1
        biwgR01UY2h1bmtlZCx0ZXh0L2h0bWwsaW1hZ2UvcG5nLGltYWdlL2pwZyxpbWFnZS9naWYsYXBwbGljYXRpb24veG1sLGFwcGxpY2F0aW9uL3hodG1s
        K3htbCx0ZXh0L3BsYWluLHRleHQvamF2YXNjcmlwdCxwdWJsaWNwcml2YXRlbWF4LWFnZT1nemlwLGRlZmxhdGUsc2RjaGNoYXJzZXQ9dXRmLThjaGFy
        c2V0PWlzby04ODU5LTEsdXRmLSwqLGVucT0wLg==
      B64

      class Error < StandardError; end
      class ProtocolError < Error; end
      class StreamClosed < Error; end
      class StreamReset < Error; end

      SynStream = Struct.new(:stream_id, :associated_stream_id, :priority, :headers, :fin, :unidirectional, keyword_init: true)
      SynReply = Struct.new(:stream_id, :headers, :fin, keyword_init: true)
      RstStream = Struct.new(:stream_id, :status, keyword_init: true)
      Settings = Struct.new(:entries, keyword_init: true)
      Ping = Struct.new(:id, keyword_init: true)
      GoAway = Struct.new(:last_good_stream_id, :status, keyword_init: true)
      HeadersFrame = Struct.new(:stream_id, :headers, :fin, keyword_init: true)
      WindowUpdate = Struct.new(:stream_id, :delta, keyword_init: true)
      Data = Struct.new(:stream_id, :data, :fin, keyword_init: true)

      # Reads and writes frames on an IO; owns the two zlib contexts that
      # SPDY keeps per direction for the whole connection.
      class Framer
        def initialize(io)
          @io = io
          @write_mutex = Mutex.new
          @deflate = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION)
          @deflate.set_dictionary(DICTIONARY)
          @inflate = Zlib::Inflate.new
          @dictionary_set = false
        end

        # nil at a clean EOF between frames.
        def read_frame
          first = read_exact(4, allow_eof: true)
          return nil if first.nil?

          word = first.unpack1("N")
          if (word & 0x80000000).zero?
            read_data_frame(word & 0x7fffffff)
          else
            version = (word >> 16) & 0x7fff
            type = word & 0xffff
            raise ProtocolError, "unsupported SPDY version #{version}" unless version == VERSION

            read_control_frame(type)
          end
        end

        def write_frame(frame)
          bytes = encode(frame)
          @write_mutex.synchronize do
            @io.write(bytes)
            @io.flush if @io.respond_to?(:flush)
          end
          bytes.bytesize
        end

        # Encoding is public so a tunnel can forward frames it did not build.
        def encode(frame)
          case frame
          when Data then encode_data(frame)
          when SynStream then encode_syn_stream(frame)
          when SynReply then encode_syn_reply(frame)
          when RstStream then control(TYPE_RST_STREAM, 0, [frame.stream_id & 0x7fffffff, frame.status].pack("NN"))
          when Ping then control(TYPE_PING, 0, [frame.id].pack("N"))
          when GoAway then control(TYPE_GOAWAY, 0, [frame.last_good_stream_id & 0x7fffffff, frame.status].pack("NN"))
          when HeadersFrame then control(TYPE_HEADERS, frame.fin ? FLAG_FIN : 0, [frame.stream_id & 0x7fffffff].pack("N") + compress_headers(frame.headers))
          when WindowUpdate then control(TYPE_WINDOW_UPDATE, 0, [frame.stream_id & 0x7fffffff, frame.delta].pack("NN"))
          when Settings then control(TYPE_SETTINGS, 0, [frame.entries.length].pack("N") + frame.entries.map { |(flag, id, value)| [((flag & 0xff) << 24) | (id & 0xffffff), value].pack("NN") }.join)
          else raise ArgumentError, "unknown SPDY frame #{frame.class}"
          end
        end

        private

        def control(type, flags, payload)
          raise ProtocolError, "control frame payload exceeds #{MAX_DATA_LENGTH} bytes" if payload.bytesize > MAX_DATA_LENGTH

          [0x80000000 | (VERSION << 16) | type, ((flags & 0xff) << 24) | payload.bytesize].pack("NN") + payload
        end

        def encode_data(frame)
          data = frame.data.to_s.b
          raise ProtocolError, "data frame exceeds #{MAX_DATA_LENGTH} bytes" if data.bytesize > MAX_DATA_LENGTH

          flags = frame.fin ? FLAG_FIN : 0
          [frame.stream_id & 0x7fffffff, ((flags & 0xff) << 24) | data.bytesize].pack("NN") + data
        end

        def encode_syn_stream(frame)
          flags = 0
          flags |= FLAG_FIN if frame.fin
          flags |= FLAG_UNIDIRECTIONAL if frame.unidirectional
          payload = [frame.stream_id & 0x7fffffff, (frame.associated_stream_id || 0) & 0x7fffffff].pack("NN")
          payload << [((frame.priority || 0) & 0x7) << 5, 0].pack("CC")
          payload << compress_headers(frame.headers)
          control(TYPE_SYN_STREAM, flags, payload)
        end

        def encode_syn_reply(frame)
          control(TYPE_SYN_REPLY, frame.fin ? FLAG_FIN : 0, [frame.stream_id & 0x7fffffff].pack("N") + compress_headers(frame.headers))
        end

        # Header block: count, then (len name)(len value) pairs, names lower
        # case, multiple values NUL-joined; zlib with SYNC flush per block so
        # the peer can inflate each frame without waiting for the next.
        def compress_headers(headers)
          normalized = normalize_headers(headers)
          block = [normalized.length].pack("N")
          normalized.each do |name, values|
            value = values.join(HEADER_VALUE_SEPARATOR)
            block << [name.bytesize].pack("N") << name << [value.bytesize].pack("N") << value
          end
          @write_mutex.synchronize { @deflate.deflate(block, Zlib::SYNC_FLUSH) }
        end

        def normalize_headers(headers)
          (headers || {}).each_with_object({}) do |(name, value), result|
            key = name.to_s.downcase.b
            list = Array(value).map { |item| item.to_s.b }
            result[key] = (result[key] || []) + list
          end
        end

        def read_data_frame(stream_id)
          flags, length = read_flags_and_length
          data = length.zero? ? "".b : read_exact(length)
          Data.new(stream_id: stream_id, data: data, fin: (flags & FLAG_FIN) != 0)
        end

        def read_flags_and_length
          word = read_exact(4).unpack1("N")
          [(word >> 24) & 0xff, word & 0xffffff]
        end

        def read_control_frame(type)
          flags, length = read_flags_and_length
          payload = length.zero? ? "".b : read_exact(length)
          case type
          when TYPE_SYN_STREAM
            raise ProtocolError, "short SYN_STREAM" if payload.bytesize < 10

            stream_id, associated = payload.unpack("NN")
            priority = payload.getbyte(8) >> 5
            SynStream.new(stream_id: stream_id & 0x7fffffff, associated_stream_id: associated & 0x7fffffff, priority: priority,
                          headers: decompress_headers(payload.byteslice(10..)), fin: (flags & FLAG_FIN) != 0,
                          unidirectional: (flags & FLAG_UNIDIRECTIONAL) != 0)
          when TYPE_SYN_REPLY
            raise ProtocolError, "short SYN_REPLY" if payload.bytesize < 4

            SynReply.new(stream_id: payload.unpack1("N") & 0x7fffffff, headers: decompress_headers(payload.byteslice(4..)), fin: (flags & FLAG_FIN) != 0)
          when TYPE_RST_STREAM
            raise ProtocolError, "short RST_STREAM" if payload.bytesize < 8

            stream_id, status = payload.unpack("NN")
            RstStream.new(stream_id: stream_id & 0x7fffffff, status: status)
          when TYPE_SETTINGS
            count = payload.bytesize >= 4 ? payload.unpack1("N") : 0
            entries = (0...count).filter_map do |index|
              entry = payload.byteslice(4 + index * 8, 8)
              next unless entry && entry.bytesize == 8

              id_word, value = entry.unpack("NN")
              [(id_word >> 24) & 0xff, id_word & 0xffffff, value]
            end
            Settings.new(entries: entries)
          when TYPE_PING
            raise ProtocolError, "short PING" if payload.bytesize < 4

            Ping.new(id: payload.unpack1("N"))
          when TYPE_GOAWAY
            raise ProtocolError, "short GOAWAY" if payload.bytesize < 8

            last, status = payload.unpack("NN")
            GoAway.new(last_good_stream_id: last & 0x7fffffff, status: status)
          when TYPE_HEADERS
            raise ProtocolError, "short HEADERS" if payload.bytesize < 4

            HeadersFrame.new(stream_id: payload.unpack1("N") & 0x7fffffff, headers: decompress_headers(payload.byteslice(4..)), fin: (flags & FLAG_FIN) != 0)
          when TYPE_WINDOW_UPDATE
            raise ProtocolError, "short WINDOW_UPDATE" if payload.bytesize < 8

            stream_id, delta = payload.unpack("NN")
            WindowUpdate.new(stream_id: stream_id & 0x7fffffff, delta: delta & 0x7fffffff)
          else
            raise ProtocolError, "unknown SPDY control frame type #{type}"
          end
        end

        def decompress_headers(compressed)
          block = inflate(compressed.to_s)
          offset = 0
          count = block.byteslice(0, 4)&.unpack1("N") || 0
          raise ProtocolError, "too many SPDY headers (#{count})" if count > MAX_HEADER_COUNT

          offset += 4
          headers = {}
          count.times do
            name, offset = read_field(block, offset)
            value, offset = read_field(block, offset)
            key = name.downcase
            headers[key] = (headers[key] || []) + value.split(HEADER_VALUE_SEPARATOR, -1)
          end
          headers
        end

        def read_field(block, offset)
          length = block.byteslice(offset, 4)&.unpack1("N")
          raise ProtocolError, "truncated SPDY header block" if length.nil?
          raise ProtocolError, "SPDY header field exceeds #{MAX_HEADER_FIELD_SIZE} bytes" if length > MAX_HEADER_FIELD_SIZE

          value = block.byteslice(offset + 4, length)
          raise ProtocolError, "truncated SPDY header block" if value.nil? || value.bytesize != length

          [value, offset + 4 + length]
        end

        def inflate(compressed)
          return "".b if compressed.empty?

          @inflate.inflate(compressed)
        rescue Zlib::NeedDict
          raise ProtocolError, "SPDY header block needs an unknown dictionary" if @dictionary_set

          @inflate.set_dictionary(DICTIONARY)
          @dictionary_set = true
          @inflate.inflate("")
        rescue Zlib::Error => error
          raise ProtocolError, "SPDY header block is corrupt: #{error.message}"
        end

        def read_exact(length, allow_eof: false)
          data = "".b
          while data.bytesize < length
            chunk = @io.read(length - data.bytesize)
            if chunk.nil? || chunk.empty?
              return nil if allow_eof && data.empty?

              raise EOFError, "SPDY peer closed the connection"
            end
            data << chunk
          end
          data
        end
      end

      # One multiplexed stream.  Reads deliver the peer's DATA frames in
      # order; writes produce DATA frames; `close` sends the FIN, `reset`
      # sends RST_STREAM(CANCEL).
      class Stream
        attr_reader :id, :headers, :session

        def initialize(session, id, headers, remote_fin: false)
          @session = session
          @id = id
          @headers = headers.freeze
          @queue = Queue.new
          @pending = "".b
          @remote_closed = remote_fin
          @local_closed = false
          @reset = false
          @replied = false
          @mutex = Mutex.new
          @queue << :eof if remote_fin
        end

        def header(name)
          Array(@headers[name.to_s.downcase]).first
        end

        def replied?
          @replied
        end

        # Server side: acknowledge the peer's SYN_STREAM.
        def reply(headers = {}, fin: false)
          @mutex.synchronize do
            return self if @replied

            @replied = true
          end
          @session.send_frame(SynReply.new(stream_id: @id, headers: headers, fin: fin))
          self
        end

        # Client side: the peer's SYN_REPLY arrived.
        def mark_replied!
          @mutex.synchronize { @replied = true }
        end

        # Reads up to `length` bytes (a whole frame when nil).  nil at EOF.
        # A timeout of nil blocks; 0 polls.
        def read(length = nil, timeout: nil)
          if @pending.empty?
            chunk = dequeue(timeout)
            return nil if chunk.nil?

            @pending = chunk
          end
          return @pending.tap { @pending = "".b } if length.nil? || @pending.bytesize <= length

          value = @pending.byteslice(0, length)
          @pending = @pending.byteslice(length..) || "".b
          value
        end

        def readpartial(length)
          value = read(length)
          raise EOFError, "SPDY stream #{@id} closed" if value.nil?

          value
        end

        def read_all
          result = "".b
          while (chunk = read)
            result << chunk
          end
          result
        end

        def write(data)
          bytes = data.to_s.b
          raise StreamClosed, "SPDY stream #{@id} is closed for writing" if @local_closed || @reset

          offset = 0
          while offset < bytes.bytesize
            piece = bytes.byteslice(offset, 65_536)
            @session.send_frame(Data.new(stream_id: @id, data: piece, fin: false))
            offset += piece.bytesize
          end
          @session.send_frame(Data.new(stream_id: @id, data: "".b, fin: false)) if bytes.empty?
          bytes.bytesize
        end

        # Half-close: our side is done writing.
        def close
          @mutex.synchronize do
            return self if @local_closed || @reset

            @local_closed = true
          end
          begin
            @session.send_frame(Data.new(stream_id: @id, data: "".b, fin: true))
          rescue IOError, SystemCallError, StreamClosed
            nil
          end
          @session.stream_finished(self) if @remote_closed
          self
        end

        alias close_write close

        def reset(status = RST_CANCEL)
          @mutex.synchronize do
            return self if @reset

            @reset = true
            @local_closed = true
          end
          @queue << :eof
          begin
            @session.send_frame(RstStream.new(stream_id: @id, status: status))
          rescue IOError, SystemCallError
            nil
          end
          @session.stream_finished(self)
          self
        end

        def eof?
          @remote_closed && @pending.empty? && @queue.empty?
        end

        def closed?
          @reset || (@local_closed && @remote_closed)
        end

        def write_closed?
          @local_closed || @reset
        end

        # Called by the session for inbound frames.
        def deliver(data, fin:)
          @queue << data unless data.nil? || data.empty?
          if fin
            @remote_closed = true
            @queue << :eof
            @session.stream_finished(self) if @local_closed
          end
        end

        def deliver_reset
          @reset = true
          @remote_closed = true
          @local_closed = true
          @queue << :eof
        end

        private

        def dequeue(timeout)
          value = if timeout.nil?
                    @queue.pop
                  elsif timeout.zero?
                    @queue.empty? ? raise(IO::WaitReadable, "no SPDY data available") : @queue.pop(true)
                  else
                    @queue.pop(timeout: timeout)
                  end
          raise IO::WaitReadable, "SPDY stream #{@id} read timed out" if value.nil? && !timeout.nil?
          if value == :eof
            @queue << :eof
            return nil
          end
          value
        end
      end

      # A SPDY connection.  `server: true` accepts the peer's streams and
      # hands each to `on_stream` (which must return truthy to accept; a raise
      # or falsy answer resets the stream).  Either side may `create_stream`.
      class Session
        attr_reader :framer

        def initialize(io, server: true, on_stream: nil, logger: nil, ping_interval: nil)
          @io = io
          @server = server
          @on_stream = on_stream
          @logger = logger
          @framer = Framer.new(io)
          @streams = {}
          @mutex = Mutex.new
          @next_stream_id = server ? 2 : 1
          @next_ping_id = server ? 2 : 1
          @pings = {}
          @closed = false
          @goaway_received = false
          @close_waiters = ConditionVariable.new
          @ping_interval = ping_interval
          @reader = nil
        end

        def closed?
          @closed
        end

        def streams
          @mutex.synchronize { @streams.values }
        end

        # Reads frames until the peer closes.  Run it on its own thread with
        # `start`, or inline when the caller has nothing else to do.
        def serve
          loop do
            frame = @framer.read_frame
            break if frame.nil?

            handle(frame)
          end
        rescue EOFError, IOError, SystemCallError, ProtocolError => error
          @logger&.call(:debug, "spdy.session_ended", error: error.class.name, message: error.message)
        ensure
          shutdown
        end

        def start
          @reader = Thread.new { serve }
          @reader.name = "spdy-session"
          @pinger = Thread.new { ping_loop } if @ping_interval
          self
        end

        def join(timeout = nil)
          @reader&.join(timeout)
        end

        # Opens a stream to the peer (client-side SYN_STREAM, or a
        # server-pushed one).  Blocks until the peer replies or resets.
        def create_stream(headers, fin: false, timeout: 30)
          stream = nil
          @mutex.synchronize do
            raise Error, "SPDY session is closed" if @closed

            id = @next_stream_id
            @next_stream_id += 2
            stream = Stream.new(self, id, headers)
            @streams[id] = stream
          end
          @reply_waiters ||= {}
          queue = Queue.new
          @mutex.synchronize { @reply_waiters[stream.id] = queue }
          send_frame(SynStream.new(stream_id: stream.id, associated_stream_id: 0, priority: 0, headers: headers, fin: fin, unidirectional: false))
          stream.close if fin
          outcome = queue.pop(timeout: timeout)
          @mutex.synchronize { @reply_waiters.delete(stream.id) }
          raise StreamReset, "SPDY stream #{stream.id} was reset by the peer" if outcome == :reset
          raise Error, "timed out waiting for SPDY stream #{stream.id} reply" if outcome.nil?

          stream
        end

        def send_frame(frame)
          raise IOError, "SPDY session is closed" if @closed

          @framer.write_frame(frame)
        end

        def ping(timeout: 10)
          id = nil
          queue = Queue.new
          @mutex.synchronize do
            id = @next_ping_id
            @next_ping_id += 2
            @pings[id] = queue
          end
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          send_frame(Ping.new(id: id))
          result = queue.pop(timeout: timeout)
          @mutex.synchronize { @pings.delete(id) }
          raise Error, "SPDY ping #{id} timed out" if result.nil?

          Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
        end

        # Sends GOAWAY and closes the transport.
        def close(status = GOAWAY_OK)
          return self if @closed

          begin
            last = @mutex.synchronize { @streams.keys.max || 0 }
            @framer.write_frame(GoAway.new(last_good_stream_id: last, status: status))
          rescue IOError, SystemCallError
            nil
          end
          shutdown
          self
        end

        def stream_finished(stream)
          @mutex.synchronize { @streams.delete(stream.id) }
        end

        private

        def shutdown
          @mutex.synchronize do
            return if @closed

            @closed = true
          end
          @pinger&.kill
          @mutex.synchronize { @streams.values }.each(&:deliver_reset)
          @mutex.synchronize { (@reply_waiters || {}).each_value { |queue| queue << :reset } }
          @mutex.synchronize { @pings.each_value { |queue| queue << :closed } }
          begin
            @io.close if @io.respond_to?(:close) && !(@io.respond_to?(:closed?) && @io.closed?)
          rescue IOError, SystemCallError
            nil
          end
        end

        def ping_loop
          loop do
            sleep(@ping_interval)
            break if @closed

            begin
              ping
            rescue StandardError
              break
            end
          end
        end

        def handle(frame)
          case frame
          when SynStream then handle_syn_stream(frame)
          when SynReply
            stream = lookup(frame.stream_id)
            return unless stream

            stream.mark_replied!
            @mutex.synchronize { @reply_waiters&.fetch(frame.stream_id, nil) }&.push(:replied)
            stream.deliver(nil, fin: true) if frame.fin
          when Data
            stream = lookup(frame.stream_id)
            if stream
              stream.deliver(frame.data, fin: frame.fin)
            elsif !frame.data.empty?
              # spdystream ignores data for unknown streams rather than resetting.
              nil
            end
          when RstStream
            stream = lookup(frame.stream_id)
            @mutex.synchronize { @reply_waiters&.fetch(frame.stream_id, nil) }&.push(:reset)
            return unless stream

            stream.deliver_reset
            stream_finished(stream)
          when Ping
            # Even ids are the server's; a ping we did not send is echoed.
            ours = (frame.id.odd? && !@server) || (frame.id.even? && @server)
            if ours
              @mutex.synchronize { @pings[frame.id] }&.push(:pong)
            else
              send_frame(frame)
            end
          when GoAway
            @goaway_received = true
          when HeadersFrame
            stream = lookup(frame.stream_id)
            stream&.deliver(nil, fin: true) if frame.fin
          when Settings, WindowUpdate
            nil
          end
        end

        def handle_syn_stream(frame)
          if @goaway_received || @closed
            send_frame(RstStream.new(stream_id: frame.stream_id, status: RST_REFUSED_STREAM))
            return
          end
          expected_parity = @server ? 1 : 0
          if frame.stream_id % 2 != expected_parity || @mutex.synchronize { @streams.key?(frame.stream_id) }
            send_frame(RstStream.new(stream_id: frame.stream_id, status: RST_PROTOCOL_ERROR))
            return
          end
          stream = Stream.new(self, frame.stream_id, frame.headers, remote_fin: frame.fin)
          @mutex.synchronize { @streams[frame.stream_id] = stream }
          accepted = begin
            @on_stream ? @on_stream.call(stream) : true
          rescue StandardError => error
            @logger&.call(:warn, "spdy.stream_rejected", stream: frame.stream_id, error: error.class.name, message: error.message)
            false
          end
          if accepted
            # httpstream replies immediately with empty headers; the handler
            # only observes the stream after this reply is on the wire.
            stream.reply({}) unless stream.replied?
          else
            stream.reset(RST_REFUSED_STREAM)
          end
        end

        def lookup(stream_id)
          @mutex.synchronize { @streams[stream_id] }
        end
      end
    end
  end
end
