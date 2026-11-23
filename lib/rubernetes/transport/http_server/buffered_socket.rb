# frozen_string_literal: true

module Rubernetes
  module Transport
    class HTTPServer
      # Bytes read together with an upgrade request belong to the upgraded
      # protocol, not to a subsequent HTTP request.  The parser keeps those
      # bytes in the connection buffer; this adapter makes them visible to
      # the duplex handler before reading from the socket.
      class BufferedSocket
        def initialize(socket, prefix)
          @socket = socket
          @prefix = String(prefix).b
        end

        def read(length = nil)
          return @socket.read(length) if @prefix.empty?
          return @prefix.tap { @prefix = "".b } if length.nil?

          length = Integer(length)
          return "".b if length.zero?

          prefix = @prefix.byteslice(0, length)
          if prefix.bytesize == length
            @prefix = @prefix.byteslice(length..)&.b || "".b
            prefix
          else
            @prefix = "".b
            suffix = @socket.read(length - prefix.bytesize)
            prefix + suffix.to_s.b
          end
        end

        def readpartial(length, buffer = nil)
          value = read(length)
          raise EOFError if value.nil? || value.empty?

          if buffer
            buffer.replace(value)
            buffer
          else
            value
          end
        end

        def write(data)
          @socket.write(data)
        end

        def flush = @socket.flush

        def write_nonblock(*, **)
          @socket.write_nonblock(*, **)
        end

        def to_io = @socket.to_io

        def closed?
          @socket.closed?
        end

        def close
          @socket.close
        end
      end
    end
  end
end
