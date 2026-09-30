# frozen_string_literal: true

# Cluster DNS server: UDP and TCP listeners in front of DNS::Resolver.
#
# The server owns sockets and threads only; record semantics live in the
# resolver so the same zone logic is testable without a socket.  Every
# thread is created in #start (R-3.3) and joined in #stop so shutdown is
# provably complete.  Upstream forwarding regenerates the transaction ID,
# binds the reply to the generated ID, the question, and the upstream
# address, and rejects oversized or looping traffic before decoding it.
require "socket"
require "securerandom"

require_relative "errors"
require_relative "support"
require_relative "dns_wire"

module Rubernetes
  module Network
    module DNS
      # Real UDP/TCP client used by the resolver for cluster-external names.
      # It never trusts a reply that does not come from the queried server
      # address/port with the generated transaction ID and identical question.
      class UpstreamClient
        DEFAULT_TIMEOUT = 2.0

        def initialize(port: 53, timeout: DEFAULT_TIMEOUT, max_packet_bytes: Resolver::MAX_PACKET_BYTES)
          @port = Support.integer(port, "upstream DNS port", min: 1, max: 65_535)
          @timeout = Float(timeout)
          raise ArgumentError, "upstream timeout must be positive" unless @timeout.positive?

          @max_packet_bytes = Support.integer(max_packet_bytes, "DNS packet size", min: 512, max: 65_535)
        end

        # `packet` already carries the regenerated transaction ID (the
        # resolver substitutes it before calling).  Returns a hash the
        # resolver's response normalizer understands.
        def query(packet:, server:, client_address: nil, tcp: false, **_options)
          bytes = String(packet).b
          question = Wire.decode(bytes).questions.first
          raise DNSUpstreamError, "upstream query must carry exactly one question" if question.nil?

          address = Support.ip(server, name: "upstream DNS server").to_s
          response = tcp ? query_tcp(bytes, address) : query_udp(bytes, address)
          if !tcp && Wire.decode(response).tc
            # RFC 1035 §4.2.1: a truncated UDP answer is retried over TCP so
            # the client receives the complete record set.
            response = query_tcp(bytes, address)
          end
          verify_reply!(response, bytes, question)
          {"packet" => response, "source" => address, "size" => response.bytesize, "transport" => tcp ? "tcp" : "udp"}
        rescue Wire::FormatError => error
          raise DNSUpstreamError, "upstream reply is malformed: #{error.message}"
        rescue SystemCallError, IOError => error
          raise DNSUpstreamError, "upstream query failed: #{error.message}"
        end

        alias call query

        private

        def query_udp(bytes, address)
          family = IPAddr.new(address).ipv6? ? Socket::AF_INET6 : Socket::AF_INET
          socket = UDPSocket.new(family)
          socket.connect(address, @port)
          socket.send(bytes, 0)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @timeout
          loop do
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            raise DNSUpstreamError, "upstream #{address} did not answer within #{@timeout}s" if remaining <= 0 || IO.select([socket], nil,
                                                                                                                            nil, remaining).nil?

            reply, sender = socket.recvfrom(@max_packet_bytes + 1)
            # A connected UDP socket already filters foreign sources in the
            # kernel; the explicit check documents the spoof boundary and
            # protects against sockets that lost their connect state.
            next unless sender && sender[3] == address && sender[1] == @port
            raise DNSUpstreamError, "upstream reply exceeds #{@max_packet_bytes} bytes" if reply.bytesize > @max_packet_bytes

            return reply
          end
        ensure
          socket&.close
        end

        def query_tcp(bytes, address)
          socket = Socket.tcp(address, @port, connect_timeout: @timeout)
          socket.write([bytes.bytesize].pack("n") + bytes)
          header = read_exactly(socket, 2)
          length = header.unpack1("n")
          raise DNSUpstreamError, "upstream TCP reply exceeds #{@max_packet_bytes} bytes" if length > @max_packet_bytes

          read_exactly(socket, length)
        ensure
          socket&.close
        end

        def read_exactly(socket, length)
          buffer = "".b
          while buffer.bytesize < length
            raise DNSUpstreamError, "upstream TCP reply timed out" if IO.select([socket], nil, nil, @timeout).nil?

            chunk = socket.read_nonblock(length - buffer.bytesize, exception: false)
            raise DNSUpstreamError, "upstream closed the TCP connection" if chunk.nil?
            next if chunk == :wait_readable

            buffer << chunk
          end
          buffer
        end

        def verify_reply!(reply, request, question)
          raise DNSUpstreamError, "upstream reply is shorter than a DNS header" if reply.bytesize < Wire::HEADER_BYTES
          raise DNSUpstreamError, "upstream reply transaction ID mismatch" unless reply.byteslice(0, 2) == request.byteslice(0, 2)

          decoded = Wire.decode(reply)
          raise DNSUpstreamError, "upstream reply is not a response" unless decoded.qr

          answered = decoded.questions.first
          return if answered && answered.name == question.name && answered.type == question.type && answered.klass == question.klass

          raise DNSUpstreamError, "upstream reply question does not match the query"
        end
      end

      # The authoritative cluster DNS server.
      class Server
        DEFAULT_PORT = 53
        MAX_TCP_MESSAGE_BYTES = Resolver::MAX_PACKET_BYTES
        TCP_IDLE_TIMEOUT = 5.0
        MAX_CNAME_DEPTH = 8

        Counters = %w[queries udp_queries tcp_queries authoritative nxdomain nodata forwarded refused
                      formerr notimp truncated oversized loops upstream_errors].freeze

        attr_reader :resolver, :port, :bind_addresses, :udp_sockets, :tcp_servers

        def initialize(resolver:, bind_addresses: ["127.0.0.1"], port: DEFAULT_PORT, udp: true, tcp: true,
                       upstream_client: nil, logger: nil, max_packet_bytes: Resolver::MAX_PACKET_BYTES)
          @resolver = resolver
          @bind_addresses = Array(bind_addresses).map { |address| Support.ip(address, name: "DNS bind address").to_s }.uniq.freeze
          raise ArgumentError, "at least one DNS bind address is required" if @bind_addresses.empty?

          @port = Support.integer(port, "DNS port", min: 0, max: 65_535)
          @udp = udp == true
          @tcp = tcp == true
          raise ArgumentError, "DNS server requires UDP or TCP" unless @udp || @tcp

          @upstream_client = upstream_client
          @logger = logger
          @max_packet_bytes = Support.integer(max_packet_bytes, "DNS packet size", min: 512, max: 65_535)
          @udp_sockets = [].freeze
          @tcp_servers = [].freeze
          @threads = [].freeze
          @running = false
          @mutex = Mutex.new
          @counter_mutex = Mutex.new
          @counters = Counters.to_h { |name| [name, 0] }
          @transcript = []
          @transcript_limit = 512
        end

        def running?
          @mutex.synchronize { @running }
        end

        def counters
          @counter_mutex.synchronize { @counters.dup.freeze }
        end

        # Bounded record of served queries for evidence bundles.
        def transcript
          @counter_mutex.synchronize { @transcript.map(&:dup).freeze }
        end

        # Addresses actually bound (the ephemeral port is resolved here).
        def endpoints
          udp = @udp_sockets.map do |socket|
            {"transport" => "udp", "address" => socket.local_address.ip_address, "port" => socket.local_address.ip_port}
          end
          tcp = @tcp_servers.map do |socket|
            {"transport" => "tcp", "address" => socket.local_address.ip_address, "port" => socket.local_address.ip_port}
          end
          (udp + tcp).freeze
        end

        def start
          @mutex.synchronize do
            raise "DNS server is already running" if @running

            udp_sockets = []
            tcp_servers = []
            begin
              bound_port = @port
              @bind_addresses.each do |address|
                family = IPAddr.new(address).ipv6? ? Socket::AF_INET6 : Socket::AF_INET
                if @udp
                  socket = UDPSocket.new(family)
                  socket.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_V6ONLY, 1) if family == Socket::AF_INET6
                  socket.bind(address, bound_port)
                  # Port 0 picks one ephemeral port; every other listener must
                  # share it so a single nameserver entry reaches all of them.
                  bound_port = socket.local_address.ip_port if bound_port.zero?
                  udp_sockets << socket
                end
                next unless @tcp

                server = Socket.new(family, Socket::SOCK_STREAM, 0)
                server.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
                server.setsockopt(Socket::IPPROTO_IPV6, Socket::IPV6_V6ONLY, 1) if family == Socket::AF_INET6
                server.bind(Socket.sockaddr_in(bound_port, address))
                server.listen(128)
                bound_port = server.local_address.ip_port if bound_port.zero?
                tcp_servers << server
              end
            rescue SystemCallError
              (udp_sockets + tcp_servers).each do |socket|
                socket.close
              rescue StandardError
                nil
              end
              raise
            end
            @port = bound_port
            @udp_sockets = udp_sockets.freeze
            @tcp_servers = tcp_servers.freeze
            @running = true
            # R-3.3: all server threads are created here and only here.
            threads = udp_sockets.map { |socket| Thread.new(socket) { |udp| serve_udp(udp) } }
            threads.concat(tcp_servers.map { |server| Thread.new(server) { |tcp| serve_tcp(tcp) } })
            @threads = threads.freeze
          end
          self
        end

        def stop
          threads = @mutex.synchronize do
            return true unless @running

            @running = false
            (@udp_sockets + @tcp_servers).each do |socket|
              socket.close
            rescue StandardError
              nil
            end
            @threads
          end
          threads.each { |thread| thread.join(TCP_IDLE_TIMEOUT + 1) }
          @mutex.synchronize do
            @udp_sockets = [].freeze
            @tcp_servers = [].freeze
            @threads = [].freeze
          end
          true
        end

        alias close stop

        # Build the response bytes for one request.  `max_size` is the UDP
        # payload limit (nil for TCP).  Exposed so the wire behaviour can be
        # unit-tested without sockets.
        def respond(bytes, client:, transport:, max_size: nil)
          request = String(bytes).b
          increment("queries")
          increment(transport == :udp ? "udp_queries" : "tcp_queries")
          if request.bytesize > @max_packet_bytes
            increment("oversized")
            return error_response(request, Wire::RCODE_FORMERR, max_size: max_size)
          end
          message = begin
            Wire.decode(request)
          rescue Wire::FormatError
            increment("formerr")
            return error_response(request, Wire::RCODE_FORMERR, max_size: max_size)
          end
          # A response arriving on the query socket is a reflection loop or a
          # spoof attempt, never a legitimate question.
          if message.qr
            increment("loops")
            return nil
          end
          if message.opcode != Wire::OPCODE_QUERY
            increment("notimp")
            return encode_response(message, rcode: Wire::RCODE_NOTIMP, max_size: max_size)
          end
          if message.questions.length != 1 || message.edns&.version.to_i.positive?
            increment("formerr")
            return encode_response(message, rcode: Wire::RCODE_FORMERR, max_size: max_size)
          end
          question = message.questions.first
          if own_address?(client)
            # A query from one of our own listener addresses/ports can only be
            # a forwarding loop back to this server.
            increment("loops")
            return encode_response(message, rcode: Wire::RCODE_REFUSED, max_size: max_size)
          end
          if question.klass != Wire::CLASS_IN && question.klass != Wire::CLASS_ANY
            increment("refused")
            return encode_response(message, rcode: Wire::RCODE_REFUSED, max_size: max_size)
          end

          response = if @resolver.authoritative?(question.name)
                       increment("authoritative")
                       authoritative_response(message, question)
                     else
                       forward_response(message, question, client: client, transport: transport)
                     end
          record_transcript(message, question, response, client, transport)
          encode_message(response, max_size: max_size)
        rescue DNSQueryError
          increment("formerr")
          error_response(request, Wire::RCODE_FORMERR, max_size: max_size)
        end

        private

        def authoritative_response(message, question)
          response = base_response(message, aa: true)
          response.edns = edns_reply(message)
          type_name = Wire::TYPE_NAMES[question.type]
          if type_name.nil? || (!Resolver::SUPPORTED_TYPES.include?(type_name) && type_name != "ANY")
            # Types the zone never contains (NS, TXT, MX, ...) are NODATA for
            # existing names and NXDOMAIN otherwise.
            exists = @resolver.name_exists?(question.name)
            response.rcode = exists ? Wire::RCODE_NOERROR : Wire::RCODE_NXDOMAIN
            response.authority << soa_wire_record(question.name)
            increment(exists ? "nodata" : "nxdomain")
            return response
          end

          types = type_name == "ANY" ? %w[A AAAA CNAME SRV PTR] : [type_name]
          answers = []
          exists = false
          types.each do |type|
            result = @resolver.resolve(question.name, type: type)
            exists ||= result.rcode == "NOERROR"
            answers.concat(result.records.map { |record| wire_record(record) })
          end
          answers.uniq!
          if answers.empty?
            response.rcode = exists ? Wire::RCODE_NOERROR : Wire::RCODE_NXDOMAIN
            response.authority << soa_wire_record(question.name)
            increment(exists ? "nodata" : "nxdomain")
            return response
          end
          response.answers.concat(answers)
          chase_cname(response, question, answers)
          response
        end

        # RFC 1034 §4.3.2 step 3a: when the answer is a CNAME and the query
        # asked for something else, restart the lookup at the canonical name
        # and append.  Cluster-internal targets are answered here; external
        # ExternalName targets are fetched through the upstream (RA=1).
        def chase_cname(response, question, answers)
          return if question.type == Wire::TYPE_CNAME

          depth = 0
          current = answers.find { |record| record.type == Wire::TYPE_CNAME }
          seen = [question.name]
          while current && depth < MAX_CNAME_DEPTH
            target = String(current.rdata)
            break if seen.include?(target)

            seen << target
            depth += 1
            if @resolver.authoritative?(target)
              result = @resolver.resolve(target, type: Wire::TYPE_NAMES.fetch(question.type))
              records = result.records.map { |record| wire_record(record) }
              response.answers.concat(records)
              current = records.find { |record| record.type == Wire::TYPE_CNAME }
            else
              upstream = upstream_records(target, question.type)
              response.ra = true if upstream
              response.answers.concat(upstream || [])
              current = nil
            end
          end
        end

        def upstream_records(name, type)
          return nil unless upstream_available?

          query = Wire::Message.new(id: SecureRandom.random_number(65_536), rd: true,
                                    questions: [Wire::Question.new(name: name, type: type, klass: Wire::CLASS_IN)],
                                    edns: Wire::EDNS.new(udp_payload: Wire::EDNS_UDP_PAYLOAD, extended_rcode: 0, version: 0, flags: 0, options: []))
          reply = @resolver.forward(Wire.encode(query))
          decoded = Wire.decode(reply)
          increment("forwarded")
          decoded.answers
        rescue DNSUpstreamError, Wire::FormatError => error
          increment("upstream_errors")
          log(:warn, "dns.upstream_error", name: name, error: error.message)
          nil
        end

        def forward_response(message, question, client:, transport:)
          response = base_response(message, aa: false)
          response.edns = edns_reply(message)
          unless upstream_available? && message.rd
            # No recursion service is offered without an upstream; REFUSED is
            # the RFC 1035 signal for a query outside our authority.
            increment("refused")
            response.rcode = Wire::RCODE_REFUSED
            return response
          end
          outbound = Wire::Message.new(id: message.id, rd: true, questions: [question],
                                       edns: Wire::EDNS.new(udp_payload: Wire::EDNS_UDP_PAYLOAD, extended_rcode: 0, version: 0,
                                                            flags: 0, options: []))
          begin
            reply_bytes = @resolver.forward(Wire.encode(outbound), client_address: client && client[0], tcp: transport == :tcp)
            reply = Wire.decode(reply_bytes)
            increment("forwarded")
            response.ra = true
            response.rcode = reply.rcode
            response.answers.concat(reply.answers)
            response.authority.concat(reply.authority)
            response.additional.concat(reply.additional)
            response.tc = false
          rescue DNSUpstreamError, Wire::FormatError => error
            increment("upstream_errors")
            log(:warn, "dns.upstream_error", name: question.name, error: error.message)
            response.rcode = Wire::RCODE_SERVFAIL
          end
          response
        end

        def upstream_available?
          @resolver.upstreams.any? || !@upstream_client.nil?
        end

        def base_response(message, aa:)
          Wire::Message.new(id: message.id, qr: true, opcode: message.opcode, aa: aa, rd: message.rd, ra: false,
                            questions: message.questions.dup)
        end

        def edns_reply(message)
          return nil unless message.edns

          Wire::EDNS.new(udp_payload: Wire::EDNS_UDP_PAYLOAD, extended_rcode: 0, version: 0, flags: 0, options: [])
        end

        def wire_record(record)
          type = Wire.type_value(record.type)
          rdata = case record.type
                  when "SRV"
                    {"priority" => record.priority.to_i, "weight" => record.weight.to_i, "port" => record.port.to_i,
                     "target" => record.data}
                  when "SOA"
                    record.data
                  else
                    record.data
                  end
          Wire::Record.new(name: record.name, type: type, klass: Wire::CLASS_IN, ttl: record.ttl || @resolver.positive_ttl, rdata: rdata)
        end

        def soa_wire_record(name)
          wire_record(@resolver.soa_record(@resolver.soa_zone_for(name)))
        end

        def encode_response(message, rcode:, max_size:)
          response = base_response(message, aa: false)
          response.rcode = rcode
          response.edns = edns_reply(message)
          encode_message(response, max_size: max_size)
        end

        def encode_message(response, max_size:)
          bytes = Wire.encode(response, max_size: max_size)
          increment("truncated") if max_size && Wire.decode(bytes).tc && !response.tc
          bytes
        end

        # FORMERR for a packet we could not decode: echo the client ID when
        # the header is long enough to hold one, otherwise stay silent.
        def error_response(request, rcode, max_size:)
          id = Wire.peek_id(request)
          return nil if id.nil?

          Wire.encode(Wire::Message.new(id: id, qr: true, rcode: rcode), max_size: max_size)
        end

        def udp_limit(message)
          return Wire::CLASSIC_UDP_PAYLOAD unless message&.edns

          [[message.edns.udp_payload.to_i, Wire::CLASSIC_UDP_PAYLOAD].max, @max_packet_bytes].min
        end

        def serve_udp(socket)
          Thread.current.report_on_exception = false
          while running?
            ready = begin
              IO.select([socket], nil, nil, 0.5)
            rescue IOError
              # #stop closes the socket from another thread; the select
              # wakes with IOError and the loop condition ends the thread.
              break
            end
            next unless ready

            begin
              request, sender = socket.recvfrom(@max_packet_bytes + 1)
            rescue IOError, SystemCallError
              break
            end
            client = [sender[3], sender[1]]
            limit = begin
              udp_limit(Wire.decode(request))
            rescue Wire::FormatError
              Wire::CLASSIC_UDP_PAYLOAD
            end
            response = safe_respond(request, client: client, transport: :udp, max_size: limit)
            next unless response

            begin
              socket.send(response, 0, sender[3], sender[1])
            rescue SystemCallError => error
              log(:warn, "dns.udp_send_failed", client: client, error: error.message)
            end
          end
        end

        def serve_tcp(server)
          Thread.current.report_on_exception = false
          while running?
            ready = begin
              IO.select([server], nil, nil, 0.5)
            rescue IOError
              break
            end
            next unless ready

            begin
              connection, address = server.accept_nonblock(exception: false)
            rescue IOError, SystemCallError
              break
            end
            next if connection == :wait_readable || connection.nil?

            handle_tcp_connection(connection, [address.ip_address, address.ip_port])
          end
        end

        # RFC 7766: length-prefixed messages, several per connection; the
        # connection is closed after an idle period or an oversized length.
        def handle_tcp_connection(connection, client)
          loop do
            header = read_tcp(connection, 2)
            break if header.nil?

            length = header.unpack1("n")
            if length > MAX_TCP_MESSAGE_BYTES || length < Wire::HEADER_BYTES
              increment("oversized")
              break
            end
            request = read_tcp(connection, length)
            break if request.nil?

            response = safe_respond(request, client: client, transport: :tcp, max_size: nil)
            break if response.nil?

            connection.write([response.bytesize].pack("n") + response)
          end
        rescue IOError, SystemCallError => error
          log(:debug, "dns.tcp_connection_closed", client: client, error: error.message)
        ensure
          begin
            connection.close
          rescue StandardError
            nil
          end
        end

        def read_tcp(connection, length)
          buffer = "".b
          while buffer.bytesize < length
            return nil if IO.select([connection], nil, nil, TCP_IDLE_TIMEOUT).nil?

            chunk = connection.read_nonblock(length - buffer.bytesize, exception: false)
            return nil if chunk.nil?
            next if chunk == :wait_readable

            buffer << chunk
          end
          buffer
        end

        def safe_respond(request, client:, transport:, max_size:)
          respond(request, client: client, transport: transport, max_size: max_size)
        rescue StandardError => error
          # R-2.1: the failure is logged and answered with SERVFAIL; a server
          # thread must not die on one hostile packet.
          log(:error, "dns.query_failed", client: client, error: "#{error.class}: #{error.message}")
          error_response(request, Wire::RCODE_SERVFAIL, max_size: max_size)
        end

        def own_address?(client)
          return false unless client.is_a?(Array) && client.length == 2

          endpoints.any? { |entry| entry["address"] == client[0] && entry["port"] == client[1] }
        end

        def increment(name)
          @counter_mutex.synchronize { @counters[name] += 1 }
        end

        def record_transcript(message, question, response, client, transport)
          entry = {"id" => message.id, "name" => question.name, "type" => question.type_name,
                   "rcode" => response.rcode_name, "answers" => response.answers.map(&:to_h),
                   "authority" => response.authority.map(&:to_h), "aa" => response.aa,
                   "client" => client, "transport" => transport.to_s}
          @counter_mutex.synchronize do
            @transcript << entry
            @transcript.shift while @transcript.length > @transcript_limit
          end
        end

        def log(level, event, **fields)
          return unless @logger.respond_to?(level)

          @logger.public_send(level, event, **fields)
        rescue StandardError
          nil
        end
      end
    end
  end
end
