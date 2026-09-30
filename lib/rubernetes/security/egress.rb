# frozen_string_literal: true

require "net/http"
require "openssl"
require "socket"
require "uri"
require "yaml"

module Rubernetes
  module Security
    # k8s.io/apiserver/pkg/server/egressselector (--egress-selector-config-file):
    # an EgressSelectorConfiguration names, per traffic kind (cluster,
    # controlplane, etcd), how the API server reaches out: directly, or
    # through a proxy with HTTP CONNECT over TCP (TLS) or a Unix socket.
    # Every proxied dial is counted in apiserver_egress_dialer_dial_start_total,
    # timed in _dial_duration_seconds and its failures staged (connect to
    # the proxy, or the proxy's CONNECT) in _dial_failure_count.
    module Egress
      class Error < Security::Error; end
      class DialError < Error; end

      KINDS = %w[controlplane etcd cluster].freeze
      API_VERSIONS = %w[apiserver.k8s.io/v1beta1 apiserver.k8s.io/v1alpha1 apiserver.config.k8s.io/v1beta1].freeze
      PROTOCOLS = %w[HTTPConnect GRPC Direct].freeze
      METRIC_LABELS = {protocol: {"HTTPConnect" => "http-connect", "GRPC" => "grpc"}}.freeze

      class << self
        # The process-wide selector (nil: everything dials directly) and the
        # registry the dial metrics go to.
        attr_accessor :selector, :metrics

        def dialer(kind) = selector&.dialer(kind)

        # Net::HTTP for +uri+ that dials through the kind's proxy when one is
        # configured (a plain Net::HTTP otherwise).  +ipaddr+: the resolved
        # address to connect to instead of the host name.
        def http(uri, kind, ipaddr: nil, port: nil)
          dialer = dialer(kind)
          target_port = port || uri.port
          http = if dialer
                   proxied = ProxiedHTTP.new(uri.hostname, target_port, nil)
                   proxied.egress_dialer = dialer
                   proxied.egress_connect_host = ipaddr || uri.hostname
                   proxied
                 else
                   Net::HTTP.new(uri.hostname, target_port, nil)
                 end
          http.ipaddr = ipaddr if ipaddr && !dialer && http.respond_to?(:ipaddr=)
          http
        end

        # A connected TCP-like socket to host:port for +kind+ (through the
        # proxy when configured).
        def tcp_socket(host, port, kind, connect_timeout: 10)
          dialer = dialer(kind)
          return dialer.dial(host, port, timeout: connect_timeout) if dialer

          Socket.tcp(host, port, connect_timeout: connect_timeout)
        end

        def record_start(protocol, transport)
          metrics&.increment("apiserver_egress_dialer_dial_start_total", {"protocol" => protocol, "transport" => transport})
        rescue StandardError
          nil
        end

        def record_failure(protocol, transport, stage)
          metrics&.increment("apiserver_egress_dialer_dial_failure_count",
                             {"protocol" => protocol, "stage" => stage, "transport" => transport})
        rescue StandardError
          nil
        end

        def record_latency(protocol, transport, seconds)
          metrics&.observe("apiserver_egress_dialer_dial_duration_seconds", seconds, {"protocol" => protocol, "transport" => transport})
        rescue StandardError
          nil
        end
      end

      # One egressSelection's connection: opens the proxy connection and
      # asks it to CONNECT to the target.
      class Dialer
        attr_reader :protocol, :transport, :proxy_address

        def initialize(protocol:, transport:, proxy_address: nil, uds_name: nil, tls: nil)
          @protocol = protocol
          @transport = transport
          @proxy_address = proxy_address
          @uds_name = uds_name
          @tls = tls
        end

        def metric_protocol = METRIC_LABELS[:protocol].fetch(@protocol)

        def dial(host, port, timeout: 10)
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          Egress.record_start(metric_protocol, @transport)
          proxy = begin
            connect_proxy(timeout)
          rescue StandardError => error
            Egress.record_failure(metric_protocol, @transport, "connect")
            raise DialError, "egress proxy #{@proxy_address || @uds_name}: #{error.message}"
          end
          begin
            tunnel(proxy, host, port, timeout)
          rescue StandardError => error
            begin
              proxy.close
            rescue StandardError
              nil
            end
            Egress.record_failure(metric_protocol, @transport, "proxy")
            raise DialError, error.message
          end
          Egress.record_latency(metric_protocol, @transport, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
          proxy
        end

        private

        def connect_proxy(timeout)
          if @transport == "uds"
            Socket.unix(@uds_name)
          else
            host, port = split_address(@proxy_address)
            tcp = Socket.tcp(host, port, connect_timeout: timeout)
            tcp.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
            return tcp unless @tls

            ssl = OpenSSL::SSL::SSLSocket.new(tcp, @tls[:context])
            ssl.hostname = @tls[:server_name] if @tls[:server_name]
            ssl.sync_close = true
            ssl.connect
            ssl
          end
        end

        # tunnelHTTPConnect: CONNECT host:port, a 200, nothing buffered after it.
        def tunnel(proxy, host, port, timeout)
          address = host.to_s.include?(":") && !host.to_s.start_with?("[") ? "[#{host}]:#{port}" : "#{host}:#{port}"
          proxy.write("CONNECT #{address} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
          status_line = read_line(proxy, timeout)
          raise DialError, "reading HTTP response from CONNECT to #{address} via proxy failed" if status_line.nil?

          code = status_line.split(" ", 3)[1].to_i
          loop do
            line = read_line(proxy, timeout)
            raise DialError, "CONNECT response from proxy truncated" if line.nil?
            break if line.strip.empty?
          end
          raise DialError, "proxy error while dialing #{address}, code #{code}: #{status_line.strip}" unless code == 200

          proxy
        end

        def read_line(io, timeout)
          line = +""
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          loop do
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            raise DialError, "CONNECT response timed out" if remaining <= 0

            byte = io.respond_to?(:read_nonblock) ? read_byte(io, remaining) : io.read(1)
            return nil if byte.nil?

            line << byte
            return line if line.end_with?("\n")
            raise DialError, "CONNECT response line too long" if line.bytesize > 8192
          end
        end

        def read_byte(io, remaining)
          io.read_nonblock(1)
        rescue IO::WaitReadable
          IO.select([io], nil, nil, remaining) ? retry : raise(DialError, "CONNECT response timed out")
        rescue EOFError
          nil
        end

        def split_address(address)
          if address.start_with?("[")
            host, port = address[1..].split("]:", 2)
            [host, Integer(port)]
          else
            host, port = address.rpartition(":").values_at(0, 2)
            [host, Integer(port)]
          end
        end
      end

      # Net::HTTP whose TCP connection comes from the egress dialer; the TLS
      # handshake and everything above it are Net::HTTP's own.
      class ProxiedHTTP < Net::HTTP
        attr_accessor :egress_dialer, :egress_connect_host

        private

        def connect
          @ssl_context = OpenSSL::SSL::SSLContext.new if use_ssl?
          s = @egress_dialer.dial(@egress_connect_host || @address, port, timeout: @open_timeout || 10)
          if use_ssl?
            ssl_parameters = {}
            iv_list = instance_variables
            SSL_IVNAMES.each_with_index do |ivname, i|
              next unless iv_list.include?(ivname)

              value = instance_variable_get(ivname)
              ssl_parameters[SSL_ATTRIBUTES[i]] = value unless value.nil?
            end
            @ssl_context.set_params(ssl_parameters)
            verify_hostname = @ssl_context.verify_hostname
            ssl_host_address = nil
            case @address
            when Resolv::IPv4::Regex, Resolv::IPv6::Regex then @ssl_context.verify_hostname = false
            else ssl_host_address = @address
            end
            s = OpenSSL::SSL::SSLSocket.new(s, @ssl_context)
            s.sync_close = true
            s.hostname = ssl_host_address if ssl_host_address
            ssl_socket_connect(s, @open_timeout)
            s.post_connection_check(@address) if @ssl_context.verify_mode != OpenSSL::SSL::VERIFY_NONE && verify_hostname
          end
          @socket = Net::BufferedIO.new(s, read_timeout: @read_timeout, write_timeout: @write_timeout,
                                           continue_timeout: @continue_timeout, debug_output: @debug_output)
          @last_communicated = nil
          on_connect
        rescue StandardError
          begin
            s&.close
          rescue StandardError
            nil
          end
          raise
        end
      end

      # The parsed EgressSelectorConfiguration.
      class Selector
        attr_reader :dialers

        def self.load(path) = from_bytes(File.binread(path))

        def self.from_bytes(bytes)
          document = YAML.safe_load(bytes.to_s, permitted_classes: [], aliases: false)
          raise Error, "egress selector configuration must be a YAML/JSON object" unless document.is_a?(Hash)

          from_h(document)
        rescue Psych::Exception => error
          raise Error, "egress selector configuration is not valid YAML: #{error.message}"
        end

        def self.from_h(document)
          kind = document["kind"].to_s
          raise Error, "kind must be EgressSelectorConfiguration, got #{kind.inspect}" unless kind == "EgressSelectorConfiguration"
          unless API_VERSIONS.include?(document["apiVersion"].to_s)
            raise Error,
                  "apiVersion #{document["apiVersion"].inspect} is not one of #{API_VERSIONS.join(", ")}"
          end

          selections = document["egressSelections"]
          raise Error, "egressSelections must be a list" unless selections.is_a?(Array)

          dialers = {}
          selections.each_with_index do |selection, index|
            path = "egressSelections[#{index}]"
            raise Error, "#{path}: must be an object" unless selection.is_a?(Hash)

            name = selection["name"].to_s.downcase
            unless KINDS.include?(name)
              raise Error,
                    "#{path}.name: unrecognized service name #{selection["name"].inspect} (controlplane, etcd or cluster)"
            end
            raise Error, "#{path}.name: Duplicate value: #{name.inspect}" if dialers.key?(name)

            dialers[name] = build_dialer(selection["connection"] || {}, "#{path}.connection")
          end
          new(dialers)
        end

        def self.build_dialer(connection, path)
          protocol = connection["proxyProtocol"].to_s
          transport = connection["transport"] || {}
          unless PROTOCOLS.include?(protocol)
            raise Error,
                  "#{path}.proxyProtocol: unrecognized service connection protocol #{protocol.inspect}"
          end

          case protocol
          when "Direct"
            if connection.key?("transport") && !connection["transport"].nil? && !connection["transport"].empty?
              raise Error,
                    "#{path}.transport: must not be set for Direct"
            end

            nil
          when "GRPC"
            raise Error, "#{path}: the GRPC (konnectivity) proxy protocol is not supported here; use HTTPConnect (tcp or uds)"
          else
            if transport["uds"]
              name = transport.dig("uds", "udsName").to_s
              raise Error, "#{path}.transport.uds.udsName: Required value" if name.empty?

              Dialer.new(protocol: protocol, transport: "uds", uds_name: name)
            elsif transport["tcp"]
              tcp = transport["tcp"]
              url = URI.parse(tcp["url"].to_s)
              if url.host.to_s.empty? || url.port.nil?
                raise Error,
                      "#{path}.transport.tcp.url: invalid proxy server url #{tcp["url"].inspect}"
              end

              tls_config = tcp["tlsConfig"]
              raise Error, "#{path}.transport.tcp.tlsConfig: Required value (clientKey and clientCert)" unless tls_config.is_a?(Hash)

              Dialer.new(protocol: protocol, transport: "tcp", proxy_address: "#{url.host}:#{url.port}",
                         tls: tls_settings(tls_config, path))
            else
              raise Error, "#{path}.transport: Either a TCP or UDS transport must be specified"
            end
          end
        end

        def self.tls_settings(config, path)
          client_cert = config["clientCert"].to_s
          client_key = config["clientKey"].to_s
          raise Error, "#{path}.transport.tcp.tlsConfig: clientCert and clientKey are required" if client_cert.empty? || client_key.empty?

          context = OpenSSL::SSL::SSLContext.new
          context.cert = OpenSSL::X509::Certificate.new(File.binread(client_cert))
          context.key = OpenSSL::PKey.read(File.binread(client_key))
          ca = config["caBundle"].to_s
          if ca.empty?
            context.verify_mode = OpenSSL::SSL::VERIFY_PEER
          else
            store = OpenSSL::X509::Store.new
            File.binread(ca).scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m).each { |pem| store.add_cert(OpenSSL::X509::Certificate.new(pem)) }
            context.cert_store = store
            context.verify_mode = OpenSSL::SSL::VERIFY_PEER
          end
          {context: context, server_name: config["tlsServerName"].to_s.empty? ? nil : config["tlsServerName"].to_s}
        rescue SystemCallError, OpenSSL::OpenSSLError => error
          raise Error, "#{path}.transport.tcp.tlsConfig: #{error.message}"
        end

        def initialize(dialers)
          @dialers = dialers.freeze
        end

        # The dialer for a kind, nil for direct (or an unlisted kind).
        def dialer(kind) = @dialers[kind.to_s]
      end
    end
  end
end
