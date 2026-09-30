# frozen_string_literal: true

require "digest"
require "openssl"
require "securerandom"
require "socket"

require_relative "cbor"
require_relative "errors"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # vsock message framing (spec/node/runtime.md 5.8.13): a big-endian
      # u32 length followed by a canonical CBOR payload.  The length is
      # checked against the 1 MiB bound before any allocation; a connection
      # carries at most 128 outstanding requests and every response is
      # awaited for at most 30 seconds.
      module Framing
        MAX_FRAME_BYTES = 1024 * 1024
        MAX_OUTSTANDING = 128
        RESPONSE_TIMEOUT = 30.0
        HEADER_BYTES = 4

        module_function

        def write_frame(io, payload)
          encoded = CBOR.encode(payload)
          raise FramingError, "frame of #{encoded.bytesize} bytes exceeds #{MAX_FRAME_BYTES}" if encoded.bytesize > MAX_FRAME_BYTES

          io.write([encoded.bytesize].pack("N") + encoded)
          io.flush if io.respond_to?(:flush)
          encoded.bytesize
        end

        # Returns the decoded payload, or nil at a clean end of stream.
        def read_frame(io, timeout: nil)
          header = read_exact(io, HEADER_BYTES, timeout: timeout, allow_eof: true)
          return nil if header.nil?

          length = header.unpack1("N")
          raise FramingError, "frame length #{length} exceeds #{MAX_FRAME_BYTES}" if length > MAX_FRAME_BYTES
          raise FramingError, "empty frame" if length.zero?

          CBOR.decode(read_exact(io, length, timeout: timeout), max_bytes: MAX_FRAME_BYTES)
        end

        def read_exact(io, length, timeout: nil, allow_eof: false)
          buffer = String.new(encoding: Encoding::BINARY)
          deadline = timeout && (Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout)
          while buffer.bytesize < length
            if deadline
              remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
              raise VsockError, "timed out waiting for #{length - buffer.bytesize} frame bytes" if remaining <= 0
              raise VsockError, "timed out waiting for #{length - buffer.bytesize} frame bytes" unless io.wait_readable(remaining)
            end
            chunk = io.readpartial(length - buffer.bytesize)
            buffer << chunk
          end
          buffer
        rescue EOFError
          return nil if allow_eof && buffer.empty?

          raise FramingError, "connection closed inside a frame"
        end
      end

      # Signed acknowledgements: HMAC-SHA256 over the canonical CBOR of the
      # acknowledged fields with the per-VM session key that the host
      # delivers with the identity.
      module Signature
        module_function

        def sign(key, fields)
          OpenSSL::HMAC.hexdigest("SHA256", key, CBOR.encode(fields))
        end

        def valid?(key, fields, signature)
          expected = sign(key, fields)
          signature.is_a?(String) && expected.bytesize == signature.bytesize && OpenSSL.fixed_length_secure_compare(expected, signature)
        end
      end

      # Request/response channel over one framed connection.  Requests carry
      # an id and a name; responses echo the id.  Frames that are not
      # responses to an outstanding request are rejected (unrequested
      # response) rather than buffered.
      class Channel
        def initialize(io, timeout: Framing::RESPONSE_TIMEOUT, max_outstanding: Framing::MAX_OUTSTANDING)
          @io = io
          @timeout = timeout
          @max_outstanding = max_outstanding
          @mutex = Mutex.new
          @outstanding = {}
          @sequence = 0
          @closed = false
        end

        attr_reader :io

        def closed?
          @closed
        end

        def close
          @closed = true
          @io.close unless @io.closed?
        rescue IOError
          nil
        end

        # Sends one request and waits for its response.  A lost connection
        # after the request was written is ambiguous (ResponseLost): the
        # remote side may have performed the effect.
        def call(name, params = {}, timeout: @timeout)
          id = nil
          @mutex.synchronize do
            raise VsockError, "channel is closed" if @closed
            raise VsockError, "more than #{@max_outstanding} outstanding requests" if @outstanding.length >= @max_outstanding

            @sequence += 1
            id = @sequence
            @outstanding[id] = name
          end
          begin
            Framing.write_frame(@io, {"id" => id, "request" => name.to_s, "params" => params})
          rescue IOError, SystemCallError => error
            @mutex.synchronize { @outstanding.delete(id) }
            raise VsockError, "request #{name} could not be sent: #{error.message}"
          end
          begin
            response = Framing.read_frame(@io, timeout: timeout)
          rescue FramingError, VsockError, IOError, SystemCallError => error
            @closed = true
            raise ResponseLost, "response to #{name} was lost: #{error.message}"
          end
          @mutex.synchronize { @outstanding.delete(id) }
          raise ResponseLost, "connection closed before the response to #{name}" if response.nil?
          raise ProtocolError, "unrequested response frame" unless response.is_a?(Hash) && response["id"] == id

          if response.key?("error")
            error = response["error"]
            raise ProtocolError, "#{name} failed: #{error.is_a?(Hash) ? error["message"] : error}"
          end
          response["result"]
        end
      end

      # Server side: reads requests and answers them through the handler.
      class Server
        def initialize(io, handler, timeout: Framing::RESPONSE_TIMEOUT)
          @io = io
          @handler = handler
          @timeout = timeout
        end

        def serve
          loop do
            request = Framing.read_frame(@io)
            return if request.nil?
            raise ProtocolError, "request frame must be a map" unless request.is_a?(Hash)

            id = request["id"]
            name = request["request"]
            raise ProtocolError, "request frame without id or name" unless id.is_a?(Integer) && name.is_a?(String)

            response = begin
              {"id" => id, "result" => @handler.call(name, request["params"] || {})}
            rescue StandardError => error
              {"id" => id, "error" => {"class" => error.class.name.split("::").last, "message" => error.message}}
            end
            Framing.write_frame(@io, response)
            return if response["result"].is_a?(Hash) && response["result"]["close"] == true
          end
        end
      end
    end
  end
end
