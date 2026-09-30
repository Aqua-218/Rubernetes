# frozen_string_literal: true

require "openssl"
require "socket"

require_relative "errors"
require_relative "canonical"
require_relative "identity"
require_relative "messages"

module Rubernetes
  module Consensus
    # Raft RPC transport (spec 5.3.6).
    #
    # Frame: [u32 big-endian length][u8 type][payload].  The length is
    # validated against MAX_FRAME_BYTES before any payload buffer is
    # allocated; a peer that exceeds it is disconnected.  Connections are
    # mutually authenticated TLS; the caller identity (cluster ID and node ID)
    # is taken from the verified peer certificate and every inbound message
    # must agree with it.  Outbound messages are pipelined on one persistent
    # connection per peer; delivery is best effort and Raft retransmits at
    # the application layer.
    module Transport
      MAX_FRAME_BYTES = 16 * 1024 * 1024
      HEADER_BYTES = 5
      TYPE_MESSAGE = 1

      module Framing
        module_function

        def encode(type, payload)
          raise FrameTooLarge, "frame payload #{payload.bytesize} exceeds #{MAX_FRAME_BYTES}" if payload.bytesize > MAX_FRAME_BYTES

          # The header is BINARY; a payload carrying non-ASCII UTF-8 (a CRD description
          # with "—", say) raised Encoding::CompatibilityError here and killed the
          # leader's inbound thread, so every forwarded read timed out cluster-wide.
          [payload.bytesize, type].pack("NC") << payload.b
        end

        # Read exactly one frame from the IO.  Returns [type, payload] or nil at EOF.
        def read(io, max_bytes: MAX_FRAME_BYTES)
          header = read_exact(io, HEADER_BYTES)
          return nil if header.nil?

          length, type = header.unpack("NC")
          raise FrameTooLarge, "frame length #{length} exceeds #{max_bytes}" if length > max_bytes

          payload = length.zero? ? "".b : read_exact(io, length)
          raise ProtocolError, "connection closed inside a frame" if payload.nil?

          [type, payload]
        end

        def read_exact(io, count)
          buffer = "".b
          while buffer.bytesize < count
            chunk = io.read(count - buffer.bytesize)
            return nil if chunk.nil? || chunk.empty?

            buffer << chunk
          end
          buffer
        end
      end

      # Endpoint: listens for peers and keeps outbound connections.
      class Endpoint
        attr_reader :node_id, :cluster_id, :port, :host

        def initialize(node_id:, cluster_id:, bundle:, host: "127.0.0.1", port: 0, peers: {}, logger: nil,
                       reconnect_interval: 0.1, max_queue: 4096)
          @node_id = Identity.validate_id!(node_id, "node_id")
          @cluster_id = Identity.validate_id!(cluster_id, "cluster_id")
          @bundle = bundle
          @host = host
          @port = port
          @peers = peers.transform_keys(&:to_s)
          @logger = logger
          @reconnect_interval = reconnect_interval
          @max_queue = max_queue
          @handler = nil
          @connections = {}
          @mutex = Mutex.new
          @running = false
          @inbound_threads = []
          @stats = Hash.new(0)
        end

        def on_message(&block)
          @handler = block
          self
        end

        def add_peer(node_id, address)
          stale = @mutex.synchronize do
            previous = @peers[node_id.to_s]
            @peers[node_id.to_s] = address
            previous && previous != address ? @connections.delete(node_id.to_s) : nil
          end
          # A peer that restarted on a new address must not keep receiving
          # frames on the old connection.
          stale&.close
          address
        end

        def remove_peer(node_id)
          connection = @mutex.synchronize do
            @peers.delete(node_id.to_s)
            @connections.delete(node_id.to_s)
          end
          connection&.close
        end

        def peers
          @mutex.synchronize { @peers.dup }
        end

        def stats
          @mutex.synchronize { @stats.dup }
        end

        def start
          @server_context = build_server_context
          @listener = TCPServer.new(@host, @port)
          @port = @listener.addr[1]
          @running = true
          @accept_thread = Thread.new { accept_loop }
          @accept_thread.name = "raft-accept-#{@node_id}"
          self
        end

        def address
          "#{@host}:#{@port}"
        end

        def stop
          @running = false
          begin
            @listener&.close
          rescue IOError
            nil
          end
          @accept_thread&.join(1)
          connections = @mutex.synchronize { @connections.values.tap { @connections.clear } }
          connections.each(&:close)
          @inbound_threads.each { |thread| thread.join(0.5) }
          self
        end

        # Enqueue a message for its destination; never blocks the caller.
        def send(message)
          raise ProtocolError, "message from #{message.from} sent by #{@node_id}" unless message.from == @node_id

          connection = connection_for(message.to)
          return false unless connection

          @mutex.synchronize { @stats[:sent] += 1 }
          connection.enqueue(Framing.encode(TYPE_MESSAGE, message.encode))
        end

        private

        def connection_for(peer_id)
          @mutex.synchronize do
            address = @peers[peer_id]
            return nil unless address && @running

            @connections[peer_id] ||= PeerConnection.new(peer_id: peer_id, address: address, context: build_client_context,
                                                         reconnect_interval: @reconnect_interval, max_queue: @max_queue,
                                                         logger: @logger, expected_cluster: @cluster_id)
          end
        end

        def build_server_context
          context = OpenSSL::SSL::SSLContext.new
          context.cert = @bundle.certificate
          context.key = @bundle.key
          context.min_version = OpenSSL::SSL::TLS1_2_VERSION
          store = OpenSSL::X509::Store.new
          store.add_cert(@bundle.ca_certificate)
          context.cert_store = store
          context.verify_mode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
          context
        end

        def build_client_context
          context = OpenSSL::SSL::SSLContext.new
          context.cert = @bundle.certificate
          context.key = @bundle.key
          context.min_version = OpenSSL::SSL::TLS1_2_VERSION
          store = OpenSSL::X509::Store.new
          store.add_cert(@bundle.ca_certificate)
          context.cert_store = store
          context.verify_mode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
          context
        end

        def accept_loop
          while @running
            socket = begin
              @listener.accept
            rescue IOError, SystemCallError
              break
            end
            thread = Thread.new(socket) { |client| serve(client) }
            thread.name = "raft-inbound-#{@node_id}"
            @inbound_threads << thread
            @inbound_threads.reject! { |candidate| !candidate.alive? }
          end
        end

        def serve(socket)
          tls = OpenSSL::SSL::SSLSocket.new(socket, @server_context)
          tls.sync_close = true
          tls.accept
          identity = Identity.peer_identity(tls.peer_cert)
          raise PeerIdentityMismatch, "peer belongs to cluster #{identity[:cluster_id]}" unless identity[:cluster_id] == @cluster_id

          loop do
            frame = Framing.read(tls)
            break if frame.nil?

            type, payload = frame
            raise ProtocolError, "unknown frame type #{type}" unless type == TYPE_MESSAGE

            message = Messages.decode(payload, max_bytes: MAX_FRAME_BYTES)
            unless message.from == identity[:node_id]
              raise PeerIdentityMismatch,
                    "message claims node #{message.from} but the connection is #{identity[:node_id]}"
            end
            raise PeerIdentityMismatch, "message claims cluster #{message.cluster_id}" unless message.cluster_id == @cluster_id
            raise ProtocolError, "message addressed to #{message.to}" unless message.to == @node_id

            @mutex.synchronize { @stats[:received] += 1 }
            begin
              @handler&.call(message, identity)
            rescue OpenSSL::SSL::SSLError, TransportError, IOError, SystemCallError
              raise
            rescue StandardError => error
              # A defect while handling one message must not end this connection:
              # Raft retransmits what was lost, but a dead inbound thread on the
              # leader is a silent cluster-wide outage.  Fail-closed conditions
              # are the handler's own decision (Server#fail_closed!).
              @mutex.synchronize { @stats[:handler_errors] += 1 }
              @logger&.error("consensus.transport.handler_error", error: "#{error.class}: #{error.message}",
                                                                  backtrace: Array(error.backtrace).first(6))
            end
          end
        rescue OpenSSL::SSL::SSLError, TransportError, IOError, SystemCallError => error
          @mutex.synchronize { @stats[:rejected_connections] += 1 } unless error.is_a?(IOError) || error.is_a?(EOFError)
          @logger&.warn("consensus.transport.inbound_closed", error: "#{error.class}: #{error.message}")
        ensure
          begin
            tls&.close
          rescue StandardError
            nil
          end
          begin
            socket.close unless socket.closed?
          rescue StandardError
            nil
          end
        end
      end

      # Outbound pipelined connection with automatic reconnect.
      class PeerConnection
        def initialize(peer_id:, address:, context:, reconnect_interval:, max_queue:, logger:, expected_cluster:)
          @peer_id = peer_id
          @host, port = address.rpartition(":").values_at(0, 2)
          @host = @host.delete_prefix("[").delete_suffix("]")
          @port = Integer(port)
          @context = context
          @reconnect_interval = reconnect_interval
          @max_queue = max_queue
          @logger = logger
          @expected_cluster = expected_cluster
          @queue = Queue.new
          @closed = false
          @thread = Thread.new { writer_loop }
          @thread.name = "raft-outbound-#{peer_id}"
        end

        def enqueue(frame)
          return false if @closed

          # Drop the oldest frames when the peer is unreachable for long: a
          # bounded queue is what keeps a dead peer from exhausting memory.
          @queue.pop(true) while @queue.length >= @max_queue
          @queue << frame
          true
        rescue ThreadError
          false
        end

        def close
          @closed = true
          @queue << :close
          @thread.join(1)
          close_socket
        end

        private

        def writer_loop
          until @closed
            frame = @queue.pop
            break if frame == :close

            deliver(frame)
          end
        rescue StandardError => error
          @logger&.warn("consensus.transport.outbound_failed", peer: @peer_id, error: "#{error.class}: #{error.message}")
        end

        def deliver(frame)
          attempts = 0
          until @closed
            socket = ensure_connected
            if socket.nil?
              attempts += 1
              # Give up on this frame after a few attempts; Raft will resend.
              return if attempts > 3

              sleep(@reconnect_interval)
              next
            end
            begin
              socket.write(frame)
              socket.flush
              return
            rescue OpenSSL::SSL::SSLError, IOError, SystemCallError
              close_socket
              attempts += 1
              return if attempts > 3
            end
          end
        end

        def ensure_connected
          return @socket if @socket

          raw = Socket.tcp(@host, @port, connect_timeout: 1.0)
          raw.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
          tls = OpenSSL::SSL::SSLSocket.new(raw, @context)
          tls.sync_close = true
          tls.hostname = nil
          tls.connect
          identity = Identity.peer_identity(tls.peer_cert)
          unless identity[:cluster_id] == @expected_cluster && identity[:node_id] == @peer_id
            tls.close
            raise PeerIdentityMismatch,
                  "peer at #{@host}:#{@port} is #{identity[:cluster_id]}/#{identity[:node_id]}, expected #{@expected_cluster}/#{@peer_id}"
          end
          @socket = tls
        rescue PeerIdentityMismatch => error
          @logger&.warn("consensus.transport.peer_identity_mismatch", peer: @peer_id, error: error.message)
          nil
        rescue OpenSSL::SSL::SSLError, IOError, SystemCallError, Errno::ETIMEDOUT
          nil
        end

        def close_socket
          @socket&.close
        rescue StandardError
          nil
        ensure
          @socket = nil
        end
      end
    end
  end
end
