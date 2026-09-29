# frozen_string_literal: true

require "socket"
require "uri"

module Rubernetes
  module Node
    # kubelet's proxyStream: an exec, attach or port-forward whose container
    # runs in a CRI runtime is relayed, upgrade and all, to the URL the
    # runtime's streaming server handed out (Exec/Attach/PortForward).  The
    # client's upgrade headers go through unchanged, so the runtime
    # negotiates the protocol (SPDY or WebSocket) and computes the WebSocket
    # accept key itself; after its 101 the two connections are spliced.
    module StreamProxy
      FORWARDED = %w[upgrade connection sec-websocket-key sec-websocket-version sec-websocket-protocol
                     sec-websocket-extensions x-stream-protocol-version].freeze
      RESPONSE_HEADERS = %w[connection upgrade sec-websocket-accept sec-websocket-protocol sec-websocket-extensions
                            x-stream-protocol-version x-accepted-stream-protocol-versions content-type].freeze
      CHUNK = 64 * 1024

      class Error < StandardError; end

      module_function

      # A Transport::Response (101 with the relay) or the runtime's refusal.
      def response(url, request, timeout: 10)
        status, headers, upstream, leftover = dial(url, request, timeout: timeout)
        unless status == 101
          body = read_body(upstream, headers, leftover)
          upstream.close
          return [status, {"content-type" => headers["content-type"] || "text/plain"}, [body]]
        end

        relayed = headers.slice(*RESPONSE_HEADERS)
        callback = lambda do |client, _request|
          splice(client, upstream, leftover)
        end
        Transport::Response.new(status: 101, headers: relayed, body: "", upgrade: callback)
      end

      # [status, lower-case headers, socket, bytes read past the head].
      def dial(url, request, timeout:)
        uri = URI.parse(url.to_s)
        raise Error, "unsupported streaming URL #{url}" unless %w[http].include?(uri.scheme)

        socket = Socket.tcp(uri.host, uri.port, connect_timeout: timeout)
        head = +"#{request.method} #{uri.request_uri} HTTP/1.1\r\nHost: #{uri.host}:#{uri.port}\r\n"
        FORWARDED.each do |name|
          Array(request.headers.raw_values(name)).each { |value| head << "#{name}: #{value}\r\n" }
        end
        head << "\r\n"
        socket.write(head)
        buffer = +""
        until (index = buffer.index("\r\n\r\n"))
          raise Error, "streaming server response head too large" if buffer.bytesize > 64 * 1024
          raise Error, "streaming server did not answer" unless socket.wait_readable(timeout)

          buffer << socket.readpartial(CHUNK)
        end
        lines = buffer[0, index].split("\r\n")
        status = Integer(lines.shift.to_s.split(" ", 3)[1])
        headers = lines.each_with_object({}) do |line, result|
          name, value = line.split(":", 2)
          result[name.to_s.strip.downcase] = value.to_s.strip
        end
        [status, headers, socket, buffer.byteslice(index + 4, buffer.bytesize - index - 4).to_s]
      rescue EOFError, SystemCallError, ArgumentError => error
        socket&.close
        raise Error, "streaming server #{url} failed: #{error.message}"
      end

      def read_body(socket, headers, leftover)
        length = Integer(headers["content-length"] || 0, exception: false) || 0
        body = leftover.dup
        while body.bytesize < length && socket.wait_readable(5)
          body << socket.readpartial(CHUNK)
        end
        body.byteslice(0, length.positive? ? length : body.bytesize)
      rescue EOFError, IOError, SystemCallError
        body.to_s
      end

      # Bytes both ways until each side has finished; a side's EOF half
      # closes the other's writing end.
      def splice(client, upstream, leftover)
        client.write(leftover) unless leftover.empty?
        down = Thread.new { copy(upstream, client) }
        up = Thread.new { copy(client, upstream) }
        down.join
        up.join(1) || up.kill
      ensure
        [upstream, client].each do |io|
          io.close
        rescue IOError, SystemCallError
          nil
        end
      end

      def copy(from, to)
        loop { to.write(from.readpartial(CHUNK)) }
      rescue EOFError, IOError, SystemCallError
        begin
          to.close_write if to.respond_to?(:close_write)
        rescue IOError, SystemCallError
          nil
        end
      end
    end
  end
end
