# frozen_string_literal: true

require "base64"
require "digest/sha1"
require "securerandom"

module Rubernetes
  module Transport
    # RFC 6455 framing over an already-upgraded socket.  This is the transport
    # under Kubernetes' channel protocols (`v5.channel.k8s.io` and friends)
    # and the SPDY-over-WebSocket port-forward tunnel; it deliberately covers
    # only what those clients use: binary/text messages with fragmentation,
    # ping/pong, and a clean close handshake.
    module WebSocket
      GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
      VERSION = "13"

      OPCODE_CONTINUATION = 0x0
      OPCODE_TEXT = 0x1
      OPCODE_BINARY = 0x2
      OPCODE_CLOSE = 0x8
      OPCODE_PING = 0x9
      OPCODE_PONG = 0xa

      CLOSE_NORMAL = 1000
      CLOSE_GOING_AWAY = 1001
      CLOSE_PROTOCOL_ERROR = 1002
      CLOSE_MESSAGE_TOO_BIG = 1009
      CLOSE_INTERNAL_ERROR = 1011

      DEFAULT_MAX_MESSAGE_BYTES = 32 * 1024 * 1024

      class Error < StandardError; end
      class ProtocolError < Error; end

      class Closed < Error
        attr_reader :code, :reason

        def initialize(code, reason = "")
          @code = code
          @reason = reason
          super("websocket closed (#{code}) #{reason}".strip)
        end
      end

      Message = Struct.new(:opcode, :payload) do
        def binary? = opcode == OPCODE_BINARY
        def text? = opcode == OPCODE_TEXT
      end

      module_function

      # Is this HTTP request a WebSocket upgrade (RFC 6455 §4.2.1)?
      def upgrade_request?(request)
        connection = request.header("connection").to_s.downcase.split(",").map(&:strip)
        connection.include?("upgrade") && request.header("upgrade").to_s.casecmp("websocket").zero?
      end

      def valid_key?(value)
        Base64.strict_decode64(value.to_s).bytesize == 16
      rescue ArgumentError
        false
      end

      def accept_key(key)
        Base64.strict_encode64(Digest::SHA1.digest(key.to_s + GUID))
      end

      # The client's subprotocol offers, in its preference order.
      def offered_protocols(request)
        header_values(request, "sec-websocket-protocol")
      end

      # Every value of a possibly repeated header, comma lists split.
      def header_values(request, name)
        values = if request.respond_to?(:headers) && request.headers.respond_to?(:raw_values)
                   request.headers.raw_values(name)
                 else
                   Array(request.header(name))
                 end
        values.flat_map { |value| value.to_s.split(",") }.map(&:strip).reject(&:empty?)
      end

      # Kubernetes negotiates in the *server's* order for httpstream and in
      # the client's order for wsstream; callers pass the list they want to
      # honour first.
      def select_protocol(offered, supported)
        offered.find { |candidate| supported.include?(candidate) }
      end

      # Response headers completing the handshake.
      def handshake_headers(request, protocol: nil)
        key = request.header("sec-websocket-key").to_s
        version = request.header("sec-websocket-version").to_s
        raise ProtocolError, "websocket upgrade requires version 13" unless version == VERSION
        raise ProtocolError, "websocket upgrade requires a valid Sec-WebSocket-Key" unless valid_key?(key)

        headers = {"connection" => "Upgrade", "upgrade" => "websocket", "sec-websocket-accept" => accept_key(key)}
        headers["sec-websocket-protocol"] = protocol if protocol && !protocol.empty?
        headers
      end

      # One WebSocket endpoint over a socket-like object (read(n)/write).
      # Server side by default: incoming frames must be masked, outgoing are
      # not.  `client: true` flips that for the dialing side.
      class Connection
        attr_reader :protocol

        def initialize(socket, client: false, protocol: nil, max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
                       ping_interval: nil)
          @socket = socket
          @client = client
          @protocol = protocol
          @max_message_bytes = max_message_bytes
          @write_mutex = Mutex.new
          @closed = false
          @close_sent = false
          @close_received = nil
          @ping_interval = ping_interval
          @pinger = start_pinger if ping_interval && ping_interval.positive?
        end

        def closed?
          @closed
        end

        # Blocks until one complete data message (binary or text) arrives.
        # Control frames are handled inline: ping answered with pong, close
        # answered with close and reported as `nil`.
        def read_message
          opcode = nil
          buffer = "".b
          loop do
            frame = read_frame
            case frame[:opcode]
            when OPCODE_PING
              write_frame(OPCODE_PONG, frame[:payload])
            when OPCODE_PONG
              next
            when OPCODE_CLOSE
              code = frame[:payload].bytesize >= 2 ? frame[:payload].unpack1("n") : CLOSE_NORMAL
              reason = frame[:payload].byteslice(2..) || "".b
              @close_received = [code, reason]
              close(code) unless @close_sent
              return nil
            when OPCODE_TEXT, OPCODE_BINARY
              raise ProtocolError, "unexpected new data frame inside a fragmented message" if opcode

              opcode = frame[:opcode]
              buffer << frame[:payload]
              return Message.new(opcode, buffer) if frame[:fin]
            when OPCODE_CONTINUATION
              raise ProtocolError, "continuation frame without a message" unless opcode

              buffer << frame[:payload]
              raise ProtocolError, "websocket message exceeds #{@max_message_bytes} bytes" if buffer.bytesize > @max_message_bytes
              return Message.new(opcode, buffer) if frame[:fin]
            else
              raise ProtocolError, "unsupported websocket opcode #{frame[:opcode]}"
            end
          end
        rescue IOError, SystemCallError
          @closed = true
          nil
        end

        # Yields every data message until the peer closes.
        def each_message
          while (message = read_message)
            yield message
          end
        end

        def write_message(payload, binary: true)
          write_frame(binary ? OPCODE_BINARY : OPCODE_TEXT, payload.to_s)
        end

        alias write_binary write_message

        def write_text(payload)
          write_frame(OPCODE_TEXT, payload.to_s)
        end

        def ping(payload = "")
          write_frame(OPCODE_PING, payload.to_s.b)
        end

        # Sends the close frame once; the socket itself is closed by the owner
        # after the peer's close arrives (or immediately with `shutdown: true`).
        def close(code = CLOSE_NORMAL, reason = "", shutdown: false)
          @write_mutex.synchronize do
            unless @close_sent
              @close_sent = true
              payload = [Integer(code)].pack("n") + reason.to_s.b
              begin
                write_raw(frame_bytes(OPCODE_CLOSE, payload))
              rescue IOError, SystemCallError
                nil
              end
            end
          end
          @pinger&.kill
          return unless shutdown

          @closed = true
          @socket.close if @socket.respond_to?(:close) && !(@socket.respond_to?(:closed?) && @socket.closed?)
        rescue IOError, SystemCallError
          @closed = true
        end

        private

        def start_pinger
          Thread.new do
            loop do
              sleep(@ping_interval)
              break if @closed || @close_sent

              begin
                ping
              rescue StandardError
                break
              end
            end
          end
        end

        def read_frame
          first, second = read_exact(2).bytes
          fin = first.anybits?(0x80)
          raise ProtocolError, "reserved websocket bits set" if first.anybits?(0x70)

          opcode = first & 0x0f
          masked = second.anybits?(0x80)
          length = second & 0x7f
          if opcode >= 0x8
            raise ProtocolError, "fragmented websocket control frame" unless fin
            raise ProtocolError, "websocket control frame exceeds 125 bytes" if length > 125
          end
          length = read_exact(2).unpack1("n") if length == 126
          length = read_exact(8).unpack1("Q>") if length == 127
          raise ProtocolError, "websocket frame exceeds #{@max_message_bytes} bytes" if length > @max_message_bytes
          raise ProtocolError, "client websocket frames must be masked" if !@client && !masked
          raise ProtocolError, "server websocket frames must not be masked" if @client && masked

          mask = masked ? read_exact(4) : nil
          payload = length.zero? ? "".b : read_exact(length)
          payload = unmask(payload, mask) if mask
          {fin: fin, opcode: opcode, payload: payload}
        end

        def unmask(payload, mask)
          # XOR in 4-byte words: the per-byte loop is far too slow for
          # multi-megabyte exec output.
          mask_word = mask.unpack1("N")
          words = payload.bytesize / 4
          result = payload.byteslice(0, words * 4).unpack("N*").map! { |word| word ^ mask_word }.pack("N*")
          tail = payload.byteslice(words * 4, payload.bytesize - (words * 4))
          tail.bytes.each_with_index { |byte, index| result << (byte ^ mask.getbyte(index)).chr } if tail && !tail.empty?
          result
        end

        def read_exact(length)
          data = "".b
          while data.bytesize < length
            chunk = @socket.read(length - data.bytesize)
            raise EOFError, "websocket peer closed the connection" if chunk.nil? || chunk.empty?

            data << chunk
          end
          data
        end

        def write_frame(opcode, payload)
          raise Closed.new(*(@close_received || [CLOSE_NORMAL, "closed"])) if @closed
          raise Closed.new(CLOSE_NORMAL, "close already sent") if @close_sent && opcode != OPCODE_CLOSE

          @write_mutex.synchronize { write_raw(frame_bytes(opcode, payload)) }
        end

        def frame_bytes(opcode, payload)
          bytes = payload.b
          header = [0x80 | opcode]
          mask_bit = @client ? 0x80 : 0
          if bytes.bytesize < 126
            header << (mask_bit | bytes.bytesize)
          elsif bytes.bytesize <= 0xffff
            header << (mask_bit | 126)
            header.concat([bytes.bytesize].pack("n").bytes)
          else
            header << (mask_bit | 127)
            header.concat([bytes.bytesize].pack("Q>").bytes)
          end
          frame = header.pack("C*")
          if @client
            mask = SecureRandom.random_bytes(4)
            frame << mask << unmask(bytes, mask)
          else
            frame << bytes
          end
          frame
        end

        def write_raw(bytes)
          remaining = bytes
          until remaining.empty?
            written = @socket.write(remaining)
            written = remaining.bytesize if written.nil?
            remaining = remaining.byteslice(written..) || "".b
          end
          @socket.flush if @socket.respond_to?(:flush)
          bytes.bytesize
        end
      end

      # A byte-stream view of a WebSocket carrying binary messages, as used by
      # the SPDY-over-WebSocket port-forward tunnel: each write is one binary
      # message and reads drain messages in order.
      class TunnelIO
        def initialize(connection)
          @connection = connection
          @buffer = "".b
          @eof = false
        end

        def read(length = nil)
          fill while !@eof && (@buffer.empty? || (length && @buffer.bytesize < length))
          return nil if @buffer.empty?

          size = length ? [length, @buffer.bytesize].min : @buffer.bytesize
          value = @buffer.byteslice(0, size)
          @buffer = @buffer.byteslice(size..) || "".b
          value
        end

        def readpartial(length)
          fill if @buffer.empty? && !@eof
          raise EOFError, "tunnel closed" if @buffer.empty?

          size = [length, @buffer.bytesize].min
          value = @buffer.byteslice(0, size)
          @buffer = @buffer.byteslice(size..) || "".b
          value
        end

        def write(data)
          @connection.write_message(data, binary: true)
          data.to_s.bytesize
        end

        def flush
          self
        end

        def close
          @connection.close(CLOSE_NORMAL, shutdown: true)
        end

        def closed?
          @connection.closed?
        end

        private

        def fill
          message = @connection.read_message
          if message.nil?
            @eof = true
          elsif message.binary?
            @buffer << message.payload
          else
            raise ProtocolError, "tunnel expects binary websocket messages"
          end
        end
      end
    end
  end
end
