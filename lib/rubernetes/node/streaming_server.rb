# frozen_string_literal: true

require "cgi"
require "etc"
require "fileutils"
require "tmpdir"
require "json"
require_relative "../observability/metrics"
require_relative "../observability/zpages"
require_relative "system_logs"
require_relative "../transport/http_server"
require_relative "../transport/websocket"
require_relative "resource_metrics"
require_relative "../transport/spdy"
require_relative "streaming_session"
require_relative "stream_proxy"

module Rubernetes
  module Node
    # The kubelet-style streaming endpoint.
    #
    # Serves the four Pod streaming subresources the API server proxies to a
    # node, on the kubelet's own paths and protocols:
    #
    #   GET  /containerLogs/{ns}/{pod}/{container}   plain HTTP (chunked)
    #   GET|POST /exec/{ns}/{pod}/{container}        WebSocket channel protocols
    #                                                 or SPDY/3.1 httpstream
    #   GET|POST /attach/{ns}/{pod}/{container}      same as exec
    #   GET|POST /portForward/{ns}/{pod}[/{uid}]     SPDY/3.1 (portforward.k8s.io),
    #                                                 WebSocket channels, or the
    #                                                 SPDY-over-WebSocket tunnel
    #
    # A non-upgrading POST to /exec still answers with the command's output
    # as one body (the earlier result-retrieval contract).
    class StreamingServer
      LOG_PATH = %r{\A/containerLogs/(?<namespace>[^/]+)/(?<pod>[^/]+)/(?<container>[^/?]+)\z}
      # {podNamespace}/{podID}[/{uid}]/{containerName}, as kubelet routes them.
      EXEC_PATH = %r{\A/exec/(?<namespace>[^/]+)/(?<pod>[^/]+)(?:/(?<uid>[^/]+))?/(?<container>[^/?]+)\z}
      ATTACH_PATH = %r{\A/attach/(?<namespace>[^/]+)/(?<pod>[^/]+)(?:/(?<uid>[^/]+))?/(?<container>[^/?]+)\z}
      RUN_PATH = %r{\A/run/(?<namespace>[^/]+)/(?<pod>[^/]+)(?:/(?<uid>[^/]+))?/(?<container>[^/?]+)\z}
      PORT_FORWARD_PATH = %r{\A/portForward/(?<namespace>[^/]+)/(?<pod>[^/]+)(?:/(?<uid>[^/?]+))?\z}
      CHECKPOINT_PATH = %r{\A/checkpoint/(?<namespace>[^/]+)/(?<pod>[^/]+)/(?<container>[^/?]+)\z}

      attr_reader :server

      def initialize(log_service:, host: "0.0.0.0", port: 10_250, logger: nil,
                     exec_service: nil, attach_service: nil, port_forward_service: nil,
                     lifecycle: nil, stream_creation_timeout: Streaming::STREAM_CREATION_TIMEOUT, stats_provider: nil,
                     system_logs: nil, flags: {}, checkpoint_dir: nil, auth: nil, tls: nil, configz: nil,
                     log_level_setter: nil, kubelet_metrics: nil)
        @stats_provider = stats_provider
        # /logs/ (SystemLogs); nil when enableSystemLogHandler is off.
        @system_logs = system_logs
        @flags = flags
        # ContainerCheckpoint archives land here (kubelet <root>/checkpoints).
        @checkpoint_dir = checkpoint_dir
        @started_at = Observability::ZPages.process_start_time
        @log_service = log_service
        @lifecycle = lifecycle
        @exec_service = exec_service
        @attach_service = attach_service
        @port_forward_service = port_forward_service
        @logger = logger
        @stream_creation_timeout = stream_creation_timeout
        # /configz: {"kubeletconfig" => KubeletConfiguration} (KubeletConfigz).
        @configz = configz
        # KubeletMetrics: /metrics fed by the lifecycle.
        @kubelet_metrics = kubelet_metrics
        # /debug/flags/v: klog verbosity 4 and above is this process's debug.
        @log_level_setter = log_level_setter
        # KubeletAuth: every request authenticated and authorized first, as
        # kubelet's InstallAuthFilter does for the whole container.
        @auth = auth
        @server = Transport::HTTPServer.new(method(:call), host: host, port: port, logger: logger, tls: tls)
      end

      def start(background: true)
        @server.start(background: background)
        self
      end

      def stop(**)
        @server.stop(**)
        self
      end

      def port
        @server.port
      end

      # Server.ServeHTTP: kubelet_http_requests_total, _duration_seconds and
      # kubelet_http_inflight_requests by method, path bucket, server type
      # and whether the path is long-running -- around authentication too.
      METRIC_BUCKETS = Set.new(%w[healthz pods stats metrics metrics/cadvisor metrics/probes metrics/resource run exec attach
                                  portForward containerLogs configz runningpods checkpoint pprof logs flagz statusz]).freeze
      METRIC_METHODS = Set.new(%w[OPTIONS GET HEAD POST PUT DELETE TRACE CONNECT]).freeze
      LONG_RUNNING_PATHS = Set.new(%w[exec attach portforward debug]).freeze

      def self.metric_path(path)
        parts = path.to_s.delete_prefix("/").split("/", 3)
        root = parts.first == "metrics" && parts.length > 1 ? "#{parts[0]}/#{parts[1]}" : parts.first.to_s
        METRIC_BUCKETS.include?(root) ? root : "other"
      end

      def call(request)
        registry = @kubelet_metrics&.registry
        return serve(request) unless registry

        path = self.class.metric_path(request.path)
        labels = {"method" => METRIC_METHODS.include?(request.method.to_s) ? request.method.to_s : "other", "path" => path,
                  "server_type" => @auth ? "readwrite" : "readonly", "long_running" => LONG_RUNNING_PATHS.include?(path).to_s}
        registry.increment("kubelet_http_requests_total", labels)
        registry.increment("kubelet_http_inflight_requests", labels)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        begin
          serve(request)
        ensure
          registry.increment("kubelet_http_inflight_requests", labels, by: -1)
          registry.observe("kubelet_http_requests_duration_seconds", Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, labels)
        end
      end

      def serve(request)
        if @auth && (denied = @auth.filter(request))
          return denied
        end

        path = request.path.to_s
        return healthz if %w[/healthz /readyz].include?(path)
        return pod_list if path == "/pods" && request.method == "GET"
        return running_pods if %w[/runningpods /runningpods/].include?(path) && request.method == "GET"
        return configz if path == "/configz" && request.method == "GET"
        return debug_flags(request) if path == "/debug/flags/v"
        # enableProfilingHandler: Go's pprof has no counterpart here, which is
        # upstream's disabled-endpoint answer.
        return [405, {"content-type" => "text/plain"}, ["profiling endpoint is disabled."]] if path.start_with?("/debug/pprof")
        return stats_summary(request) if path == "/stats/summary" && request.method == "GET"
        return resource_metrics if path == "/metrics/resource" && request.method == "GET" && @stats_provider
        return probe_metrics if path == "/metrics/probes" && request.method == "GET"
        return cadvisor_metrics if path == "/metrics/cadvisor" && request.method == "GET"
        return metrics if METRICS_PATHS.include?(path) && request.method == "GET"
        return zpage(path, request) if %w[/statusz /flagz].include?(path) && request.method == "GET"
        return [301, {"location" => "/logs/"}, [""]] if path == "/logs" && request.method == "GET"
        return system_logs(path, request) if path.start_with?("/logs/") && request.method == "GET"

        if (match = LOG_PATH.match(path)) && request.method == "GET"
          return container_logs(match, request)
        end
        if (match = EXEC_PATH.match(path)) && %w[GET POST].include?(request.method)
          return remote_command(:exec, match, request)
        end
        if (match = ATTACH_PATH.match(path)) && %w[GET POST].include?(request.method)
          return remote_command(:attach, match, request)
        end
        return run_in_container(match, request) if (match = RUN_PATH.match(path)) && request.method == "POST"
        if (match = PORT_FORWARD_PATH.match(path)) && %w[GET POST].include?(request.method)
          return port_forward(match, request)
        end
        return checkpoint(match, request) if (match = CHECKPOINT_PATH.match(path)) && request.method == "POST"

        [404, {"content-type" => "text/plain"}, ["not found: #{request.method} #{path}\n"]]
      rescue Transport::WebSocket::ProtocolError, Streaming::Error => error
        [400, {"content-type" => "text/plain"}, ["#{error.message}\n"]]
      rescue StandardError => error
        log(:error, "streaming.failed", error: error.class.name, message: error.message)
        [500, {"content-type" => "text/plain"}, ["#{error.class}: #{error.message}\n"]]
      end

      private

      def log(level, event, **fields)
        return unless @logger

        if @logger.respond_to?(:call)
          @logger.call(level, event, **fields)
        elsif @logger.respond_to?(level)
          @logger.public_send(level, event, **fields)
        end
      rescue StandardError
        nil
      end

      def healthz
        [200, {"content-type" => "text/plain"}, ["ok\n"]]
      end

      def system_logs(path, request)
        return [405, {"content-type" => "text/plain; charset=utf-8"}, ["logs endpoint is disabled.\n"]] if @system_logs.nil?

        @system_logs.call(path.delete_prefix("/logs/"), params: request.respond_to?(:query) ? request.query : {},
                                                        headers: request.respond_to?(:headers) ? request.headers : {})
      end

      # The kubelet's top-level paths, as /statusz lists them.
      KUBELET_PATHS = %w[/attach /checkpoint /containerLogs /exec /flagz /healthz /logs /metrics /pods /portForward /readyz /stats].freeze

      # kubelet server checkpoint (ContainerCheckpoint, Beta, on): POST
      # /checkpoint/{namespace}/{pod}/{container}[?timeout=seconds] asks the
      # container's runtime for a checkpoint archive and answers its path.
      def checkpoint(match, request)
        namespace = CGI.unescape(match[:namespace])
        pod_name = CGI.unescape(match[:pod])
        container_name = CGI.unescape(match[:container])
        record = pod_record(namespace, pod_name)
        pod = record.is_a?(Hash) ? (record[:pod] || record["pod"]) : nil
        return text_error(404, "pod does not exist") if pod.nil?

        spec = pod["spec"] || pod[:spec] || {}
        names = %w[containers initContainers ephemeralContainers].flat_map do |field|
          Array(spec[field]).map do |container|
            container["name"].to_s
          end
        end
        return text_error(404, "container #{container_name} does not exist") unless names.include?(container_name)

        timeouts = request.respond_to?(:query_values) ? Array(request.query_values("timeout")) : []
        timeout = nil
        unless timeouts.empty?
          return text_error(404, "cannot parse value of timeout parameter") unless timeouts.last.to_s.match?(/\A[+-]?\d+\z/)

          timeout = Integer(timeouts.last, 10)
        end
        runtime = @exec_service.respond_to?(:runtime) ? @exec_service.runtime : nil
        begin
          raise "checkpoint/restore support not available: no runtime" unless runtime.respond_to?(:checkpoint_container)

          container_id = resolve_container_id(namespace, pod_name, container_name)
          raise "container #{container_name} not found" if container_id.to_s.empty?

          directory = @checkpoint_dir || File.join(Dir.tmpdir, "rubernetes-checkpoints")
          FileUtils.mkdir_p(directory)
          # kubecontainer.GetPodFullName is name_namespace.
          location = File.join(directory,
                               "checkpoint-#{pod_name}_#{namespace}-#{container_name}-#{Time.now.strftime("%Y-%m-%dT%H:%M:%S%:z").sub(
                                 "+00:00", "Z"
                               )}.tar")
          runtime.checkpoint_container(container_id, location: location, timeout: timeout)
        rescue StandardError => error
          return text_error(500, "checkpointing of #{namespace}/#{pod_name}/#{container_name} failed (#{error.message})")
        end
        [200, {"content-type" => "application/json"}, [JSON.generate("items" => [location])]]
      end

      def text_error(status, message) = [status, {"content-type" => "text/plain; charset=utf-8"}, ["#{message}\n"]]

      def zpage(path, request)
        accept = request.respond_to?(:header) ? request.header("accept") : nil
        status, headers, body = if path == "/statusz"
                                  Observability::ZPages.statusz(component: "kubelet", start_time: @started_at,
                                                                binary_version: Observability::ZPages::KUBERNETES_VERSION,
                                                                emulation_version: Observability::ZPages::KUBERNETES_VERSION.split(".").first(2).join("."),
                                                                paths: KUBELET_PATHS, accept: accept)
                                else
                                  Observability::ZPages.flagz(component: "kubelet", flags: @flags || {}, accept: accept)
                                end
        [status, headers, [body]]
      end

      # kubelet/apiserver behaviour for a container that exists but has not
      # started: a 400 whose message names the state.  Clients (hydrophone
      # included) branch on this instead of on a generic 5xx.
      NOT_STARTED = /unknown container|not running|no such container/i

      # kubelet waits for a container that is still being created when the
      # request is a follow; only a non-follow request is answered with the
      # "waiting to start" 400.  Clients stream a pod's logs the moment it is
      # scheduled and rely on that wait.
      FOLLOW_START_TIMEOUT = Float(ENV.fetch("RUBERNETES_LOG_FOLLOW_TIMEOUT", "300"))
      FOLLOW_POLL_INTERVAL = 0.5
      SHORT_START_TIMEOUT = Float(ENV.fetch("RUBERNETES_LOG_START_TIMEOUT", "30"))

      # Both PodLogOptions forms name a moment, never a byte offset.
      def log_since(request)
        seconds = request.query_value("sinceSeconds").to_s
        return (Time.now.utc - Integer(seconds)).iso8601(9) unless seconds.empty?

        time = request.query_value("sinceTime").to_s
        time.empty? ? nil : Time.iso8601(time).utc.iso8601(9)
      end

      def container_logs(match, request)
        follow = query_bool(request, "follow")
        container = await_container(CGI.unescape(match[:namespace]),
                                    CGI.unescape(match[:pod]),
                                    CGI.unescape(match[:container]),
                                    follow: follow)
        result = @log_service.logs(
          container,
          follow: follow,
          since: log_since(request),
          tail: request.query_value("tailLines"),
          stream: request.query_value("stream"),
          timestamps: query_bool(request, "timestamps"),
          limit_bytes: request.query_value("limitBytes"),
          request_id: request.query_value("requestID"),
          identity: "node-streaming"
        )
        {status: 200, headers: {"content-type" => "text/plain; charset=utf-8"}, body: body_for(result), stream: true}
      rescue StandardError => error
        raise unless NOT_STARTED.match?(error.message)

        pod = CGI.unescape(match[:pod])
        namespace = CGI.unescape(match[:namespace])
        container = CGI.unescape(match[:container])
        [400, {"content-type" => "text/plain"},
         ["container #{container.inspect} in pod #{pod.inspect} is waiting to start: ContainerCreating " \
          "(namespace #{namespace})\n"]]
      end

      # ------------------------------------------------------------ exec/attach

      # Query names: the kubelet's (input/output/error/tty=1) and the API's
      # (stdin/stdout/stderr/tty=true) are both accepted, so the API server
      # can forward a client's query untouched.
      def stream_options(request, operation)
        stdin = query_bool(request, "input") || query_bool(request, "stdin")
        stdout = query_bool(request, "output") || query_bool(request, "stdout")
        stderr = query_bool(request, "error") || query_bool(request, "stderr")
        tty = query_bool(request, "tty")
        stderr = false if tty
        raise Streaming::Error, "you must specify at least 1 of stdin, stdout, stderr" unless stdin || stdout || stderr

        command = request.respond_to?(:query_values) ? Array(request.query_values("command")) : []
        raise Streaming::Error, "exec requires a command" if operation == :exec && command.empty?

        {stdin: stdin, stdout: stdout, stderr: stderr, tty: tty, command: command}
      end

      def remote_command(operation, match, request)
        service = operation == :exec ? @exec_service : @attach_service
        return [400, {"content-type" => "text/plain"}, ["#{operation} service is not configured\n"]] unless service

        namespace = CGI.unescape(match[:namespace])
        pod = CGI.unescape(match[:pod])
        container_name = CGI.unescape(match[:container])
        if Transport::WebSocket.upgrade_request?(request) || spdy_upgrade_request?(request)
          proxied = proxy_to_runtime(service, operation, request, namespace, pod, container_name)
          return proxied if proxied
        end
        if Transport::WebSocket.upgrade_request?(request)
          options = stream_options(request, operation)
          protocol = negotiate_websocket(request, Streaming::EXEC_WEBSOCKET_PROTOCOLS)
          container = await_container(namespace, pod, container_name, follow: false)
          duplex = open_duplex(service, operation, container, options)
          headers = Transport::WebSocket.handshake_headers(request, protocol: protocol.empty? ? nil : protocol)
          return upgrade(headers) do |socket|
            serve_websocket_command(socket, protocol, duplex, options)
          end
        end
        if spdy_upgrade_request?(request)
          options = stream_options(request, operation)
          protocol = negotiate_spdy(request, Streaming::EXEC_SPDY_PROTOCOLS)
          return protocol if protocol.is_a?(Array)

          container = await_container(namespace, pod, container_name, follow: false)
          duplex = open_duplex(service, operation, container, options)
          headers = {"connection" => "Upgrade", "upgrade" => Transport::SPDY::HEADER_SPDY31,
                     Streaming::HEADER_PROTOCOL_VERSION => protocol}
          return upgrade(headers) do |socket|
            serve_spdy_command(socket, protocol, duplex, options)
          end
        end
        return [400, {"content-type" => "text/plain"}, ["attach requires a connection upgrade\n"]] if operation == :attach

        container_exec_once(request, namespace, pod, container_name)
      end

      def open_duplex(service, operation, container, options)
        arguments = {tty: options[:tty], stdin: options[:stdin], stdout: options[:stdout], stderr: options[:stderr],
                     identity: "node-streaming"}
        arguments[:command] = options[:command] if operation == :exec
        service.public_send(operation, container, **arguments)
      end

      def serve_websocket_command(socket, protocol, duplex, options)
        connection = Transport::WebSocket::Connection.new(socket, protocol: protocol)
        channels = Streaming::WebSocketChannels.new(connection, protocol: protocol, stdin: options[:stdin],
                                                                stdout: options[:stdout], stderr: options[:stderr], logger: method(:log))
        channels.announce
        json = [Streaming::WS_V4_BINARY, Streaming::WS_V4_BASE64, Streaming::WS_V5_BINARY].include?(protocol)
        Streaming::RemoteCommand.new(duplex: duplex, channels: channels, tty: options[:tty], stdin: options[:stdin],
                                     stdout: options[:stdout], stderr: options[:stderr], json_status: json,
                                     logger: method(:log)).run
      end

      def serve_spdy_command(socket, protocol, duplex, options)
        session = Streaming::SPDYRemoteCommandSession.new(socket, protocol: protocol, stdin: options[:stdin],
                                                                  stdout: options[:stdout], stderr: options[:stderr],
                                                                  tty: options[:tty], logger: method(:log)) do |channels, json_status:|
          Streaming::RemoteCommand.new(duplex: duplex, channels: channels, tty: options[:tty], stdin: options[:stdin],
                                       stdout: options[:stdout], stderr: options[:stderr], json_status: json_status,
                                       logger: method(:log)).run
        end
        return if session.run(timeout: @stream_creation_timeout)

        begin
          duplex.terminate if duplex.respond_to?(:terminate)
          duplex.close if duplex.respond_to?(:close)
        rescue StandardError
          nil
        end
      end

      # Non-interactive exec without an upgrade: the command runs and its
      # output is returned as one body.
      def container_exec_once(request, namespace, pod, container_name)
        command = request.respond_to?(:query_values) ? Array(request.query_values("command")) : []
        return [400, {"content-type" => "text/plain"}, ["exec requires a command\n"]] if command.empty?

        container = await_container(namespace, pod, container_name, follow: false)
        result = @exec_service.exec(container, command: command, tty: false, stdin: false,
                                               stdout: true, stderr: true, identity: "node-streaming")
        {status: 200, headers: {"content-type" => "application/octet-stream"},
         body: exec_body(result), stream: true}
      rescue StandardError => error
        [500, {"content-type" => "text/plain"}, ["#{error.class}: #{error.message}\n"]]
      end

      def exec_body(result)
        return [result.b] if result.is_a?(String)

        stdout = if result.respond_to?(:stdout)
                   result.stdout
                 else
                   (result.is_a?(Hash) ? (result["stdout"] || result[:stdout]) : nil)
                 end
        return body_for(stdout) if stdout

        body_for(result)
      end

      # ------------------------------------------------------------ port-forward

      def port_forward(match, request)
        return [400, {"content-type" => "text/plain"}, ["port-forward service is not configured\n"]] unless @port_forward_service

        namespace = CGI.unescape(match[:namespace])
        pod = CGI.unescape(match[:pod])
        if Transport::WebSocket.upgrade_request?(request) || spdy_upgrade_request?(request)
          proxied = proxy_to_runtime(@port_forward_service, :port_forward, request, namespace, pod, nil)
          return proxied if proxied
        end
        uid = match[:uid] ? CGI.unescape(match[:uid]) : pod_uid(namespace, pod)
        container = any_running_container(namespace, pod)
        connector = lambda do |port|
          @port_forward_service.port_forward(container, [port], identity: "node-streaming")
        end

        if Transport::WebSocket.upgrade_request?(request)
          offered = Transport::WebSocket.offered_protocols(request)
          tunnel = offered.find { |name| name.start_with?(Streaming::TUNNEL_PREFIX) && name.end_with?(Streaming::TUNNEL_SUFFIX) }
          if tunnel
            spdy_protocol = tunnel.delete_prefix(Streaming::TUNNEL_PREFIX)
            unless Streaming::PORT_FORWARD_SPDY_PROTOCOLS.include?(spdy_protocol)
              return [403, {"content-type" => "text/plain"},
                      ["unable to upgrade: unable to negotiate protocol: client supports #{[spdy_protocol].inspect}, server accepts #{Streaming::PORT_FORWARD_SPDY_PROTOCOLS.inspect}\n"]]
            end

            headers = Transport::WebSocket.handshake_headers(request, protocol: tunnel)
            return upgrade(headers) do |socket|
              connection = Transport::WebSocket::Connection.new(socket, protocol: tunnel)
              io = Transport::WebSocket::TunnelIO.new(connection)
              Streaming::SPDYPortForwardSession.new(io, pod: pod, uid: uid, logger: method(:log), &connector).run
            end
          end

          ports = port_forward_ports(request)
          protocol = negotiate_websocket(request, Streaming::PORT_FORWARD_WEBSOCKET_PROTOCOLS)
          headers = Transport::WebSocket.handshake_headers(request, protocol: protocol.empty? ? nil : protocol)
          return upgrade(headers) do |socket|
            connection = Transport::WebSocket::Connection.new(socket, protocol: protocol)
            Streaming::WebSocketPortForwardSession.new(connection, protocol: protocol, ports: ports, pod: pod, uid: uid,
                                                                   logger: method(:log), &connector).run
          end
        end
        if spdy_upgrade_request?(request)
          protocol = negotiate_spdy(request, Streaming::PORT_FORWARD_SPDY_PROTOCOLS)
          return protocol if protocol.is_a?(Array)

          headers = {"connection" => "Upgrade", "upgrade" => Transport::SPDY::HEADER_SPDY31,
                     Streaming::HEADER_PROTOCOL_VERSION => protocol}
          return upgrade(headers) do |socket|
            Streaming::SPDYPortForwardSession.new(socket, pod: pod, uid: uid, logger: method(:log), &connector).run
          end
        end

        [400, {"content-type" => "text/plain"}, ["port-forward requires a connection upgrade\n"]]
      end

      # kubelet's proxyStream: a container of a runtime with its own
      # streaming server (a CRI runtime) is streamed by that server; the node
      # relays the upgraded connection.  Only a runtime with such a backend is
      # asked at all.
      def proxy_to_runtime(service, operation, request, namespace, pod, container_name)
        runtime = service.respond_to?(:runtime) ? service.runtime : nil
        return nil unless runtime.respond_to?(:streaming_backends?) && runtime.streaming_backends?

        options = operation == :port_forward ? {} : stream_options(request, operation)
        container = container_name ? await_container(namespace, pod, container_name, follow: false) : any_running_container(namespace, pod)
        url = runtime.streaming_url(operation, container, **options.slice(:command, :tty, :stdin, :stdout, :stderr))
        return nil if url.nil?

        StreamProxy.response(url, request)
      end

      # wsstream port-forward names its ports in the query (`port=80,8080`).
      def port_forward_ports(request)
        values = request.respond_to?(:query_values) ? Array(request.query_values("port")) : []
        values = Array(request.query_values("ports")) if values.empty? && request.respond_to?(:query_values)
        raise Streaming::Error, "query parameter \"port\" is required" if values.empty?

        values.flat_map { |value| value.to_s.split(",") }.map do |value|
          raise Streaming::Error, "query parameter \"port\" cannot be empty" if value.strip.empty?
          raise Streaming::Error, "unable to parse #{value.inspect} as a port" unless value.strip.match?(/\A\d+\z/)

          port = value.strip.to_i
          raise Streaming::Error, "port #{value.inspect} must be > 0" if port < 1
          raise Streaming::Error, "port #{value.inspect} is out of range" if port > 65_535

          port
        end
      end

      # ------------------------------------------------------------ negotiation

      def spdy_upgrade_request?(request)
        connection = request.header("connection").to_s.downcase.split(",").map(&:strip)
        connection.include?("upgrade") && request.header("upgrade").to_s.downcase.include?("spdy/3.1")
      end

      # wsstream: the first of the client's offers the server supports; an
      # empty offer selects the unnamed default (binary channels).
      def negotiate_websocket(request, supported)
        offered = Transport::WebSocket.offered_protocols(request)
        return "" if offered.empty?

        selected = Transport::WebSocket.select_protocol(offered, supported)
        unless selected
          raise Transport::WebSocket::ProtocolError,
                "requested protocol(s) are not supported: #{offered.inspect}; supports #{supported.inspect}"
        end

        selected
      end

      # httpstream.Handshake: X-Stream-Protocol-Version lists the client's
      # protocols; the first one (client order) the server accepts wins, a
      # missing header is 400, no common protocol is 403 with the server's
      # list in X-Accepted-Stream-Protocol-Versions.
      def negotiate_spdy(request, supported)
        offered = Transport::WebSocket.header_values(request, Streaming::HEADER_PROTOCOL_VERSION)
        if offered.empty?
          return [400, {"content-type" => "text/plain"},
                  ["unable to upgrade: header X-Stream-Protocol-Version does not exist in request\n"]]
        end
        selected = offered.find { |candidate| supported.include?(candidate) }
        return selected if selected

        [403, {"content-type" => "text/plain", Streaming::HEADER_ACCEPTED_PROTOCOL_VERSIONS => supported.join(", ")},
         ["unable to upgrade: unable to negotiate protocol: client supports #{offered.inspect}, server accepts #{supported.inspect}\n"]]
      end

      def upgrade(headers, &)
        callback = lambda do |socket, _request|
          yield(socket)
        rescue StandardError => error
          log(:warn, "streaming.session_failed", error: error.class.name, message: error.message)
        end
        Transport::Response.new(status: 101, headers: headers, body: "", upgrade: callback)
      end

      # ------------------------------------------------------------ containers

      # The request names the container the way the Pod spec does; the runtime
      # keys its logs by its own sandbox-scoped id, and only this node knows
      # the mapping.
      # Resolves the container, waiting for it to exist when the caller is
      # following.  Returns the runtime id; raises the same error as before
      # when the wait times out or the caller is not following.
      def await_container(namespace, pod_name, container_name, follow:)
        # A follow waits for as long as the container may take to be created;
        # a one-shot read waits only briefly, so a genuinely absent container
        # still answers quickly.  Not conditioned on the caller's flag beyond
        # the timeout: the wait is what makes "stream a pod's logs as soon as
        # it is scheduled" work at all.
        timeout = follow ? FOLLOW_START_TIMEOUT : SHORT_START_TIMEOUT
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        loop do
          id = resolve_container_id(namespace, pod_name, container_name)
          return id unless id == container_name
          return id unless @lifecycle.respond_to?(:records)
          return id if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

          sleep(FOLLOW_POLL_INTERVAL)
        end
      end

      # kubelet's /metrics (and its cadvisor/resource/probes variants): the
      # e2e framework's MetricsGrabber reads nodes/<name>:<port>/proxy/metrics
      # after every failure (HighLatencyKubeletOperations) and retries a 404
      # for two minutes before giving up, so a missing endpoint turned each
      # failure into a two-minute stall and a second failed cleanup step.
      METRICS_PATHS = %w[/metrics /metrics/cadvisor /metrics/resource /metrics/probes].freeze

      # /stats/summary (stats/v1alpha1 Summary); ?only_cpu_and_memory=true
      # keeps just the node's and every Pod/container's cpu and memory.
      def stats_summary(request)
        return [404, {"content-type" => "text/plain"}, ["404 page not found\n"]] unless @stats_provider

        summary = @stats_provider.summary
        if request.query_value("only_cpu_and_memory").to_s == "true"
          keep = ->(entry, fields) { entry.slice(*fields) }
          summary = {"node" => keep.call(summary["node"], %w[nodeName startTime cpu memory]),
                     "pods" => Array(summary["pods"]).map do |pod|
                       keep.call(pod, %w[podRef startTime cpu memory]).merge(
                         "containers" => Array(pod["containers"]).map { |container| keep.call(container, %w[name startTime cpu memory]) }
                       )
                     end}
        end
        [200, {"content-type" => "application/json"}, [JSON.generate(summary)]]
      rescue StandardError => error
        [500, {"content-type" => "text/plain"}, ["failed to get summary stats: #{error.message}\n"]]
      end

      # /metrics/probes: prober_probe_total and prober_probe_duration_seconds.
      def probe_metrics
        probes = @lifecycle.respond_to?(:probes) ? @lifecycle.probes : nil
        body = probes.respond_to?(:metrics) ? probes.metrics.render : ""
        [200, {"content-type" => Observability::Metrics::CONTENT_TYPE}, [body]]
      end

      # /metrics/cadvisor from the Summary.
      # /metrics/cadvisor: rendered from every running Pod's raw cgroup
      # accounting when the stats provider has runtime access, else from
      # the Summary.
      def cadvisor_metrics
        body = if @stats_provider.respond_to?(:raw_pod_usages)
                 CadvisorMetrics.render(@stats_provider.raw_pod_usages, machine: machine_info)
               else
                 summary = begin
                   @stats_provider.respond_to?(:summary) ? @stats_provider.summary : {"pods" => []}
                 rescue StandardError
                   {"pods" => []}
                 end
                 CadvisorMetrics.render(summary, machine: machine_info, images: container_images)
               end
        [200, {"content-type" => Observability::Metrics::CONTENT_TYPE}, [body]]
      rescue StandardError => error
        [500, {"content-type" => "text/plain"}, ["failed to render cadvisor metrics: #{error.message}\n"]]
      end

      def container_images
        images = {}
        records = @lifecycle.respond_to?(:records) ? @lifecycle.records.values : []
        records.each do |record|
          pod = record.is_a?(Hash) ? (record[:pod] || record["pod"]) : nil
          next unless pod.is_a?(Hash)

          uid = pod.dig("metadata", "uid").to_s
          (Array(pod.dig("spec", "initContainers")) + Array(pod.dig("spec", "containers"))).each do |container|
            images[[uid, container["name"].to_s]] = container["image"].to_s
          end
        end
        images
      end

      def machine_info
        @machine_info ||= CadvisorMetrics.machine_info
      end

      def resource_metrics
        summary = begin
          @stats_provider.summary
        rescue StandardError
          nil
        end
        body = ResourceMetrics.render(summary || {"node" => {}, "pods" => []}, scrape_error: summary.nil?)
        [200, {"content-type" => Observability::Metrics::CONTENT_TYPE}, [body]]
      end

      def metrics
        if @kubelet_metrics
          records = @lifecycle.respond_to?(:records) ? @lifecycle.records.values : []
          body = @kubelet_metrics.render(records) { |registry| volume_stats_metrics(registry) }
          return [200, {"content-type" => Observability::Metrics::CONTENT_TYPE}, [body]]
        end

        registry = Observability::Metrics.new(apiserver: false, component: "kubelet")
        registry.register("kubelet_running_pods", type: :gauge,
                                                  help: "Number of pods that have a running pod sandbox")
        registry.register("kubelet_running_containers", type: :gauge,
                                                        help: "Number of containers currently running")
        registry.register("kubelet_runtime_operations_duration_seconds", type: :histogram,
                                                                         help: "Duration in seconds of runtime operations. Broken down by operation type.",
                                                                         buckets: Observability::Metrics::REQUEST_DURATION_BUCKETS)
        records = @lifecycle.respond_to?(:records) ? @lifecycle.records.values : []
        registry.set("kubelet_running_pods", records.count { |record| record.is_a?(Hash) && (record[:pod] || record["pod"]).is_a?(Hash) })
        registry.set("kubelet_running_containers", records.sum do |record|
          record_containers(record).length
        end, {"container_state" => "running"})
        volume_stats_metrics(registry)
        [200, {"content-type" => Observability::Metrics::CONTENT_TYPE}, [registry.render]]
      rescue StandardError => error
        @logger&.warn("node.metrics.failed", error: error.class.name, message: error.message) if @logger.respond_to?(:warn)
        [200, {"content-type" => Observability::Metrics::CONTENT_TYPE}, [""]]
      end

      VOLUME_STATS_METRICS = {
        "kubelet_volume_stats_capacity_bytes" => ["capacityBytes", "Capacity in bytes of the volume"],
        "kubelet_volume_stats_available_bytes" => ["availableBytes", "Number of available bytes in the volume"],
        "kubelet_volume_stats_used_bytes" => ["usedBytes", "Number of used bytes in the volume"],
        "kubelet_volume_stats_inodes" => ["inodes", "Maximum number of inodes in the volume"],
        "kubelet_volume_stats_inodes_free" => ["inodesFree", "Number of free inodes in the volume"],
        "kubelet_volume_stats_inodes_used" => ["inodesUsed", "Number of used inodes in the volume"]
      }.freeze

      # collectors/volume_stats.go: one set of gauges per PVC the node's Pods
      # mount, from the Summary's volume stats (the first Pod's wins).
      def volume_stats_metrics(registry)
        return unless @stats_provider.respond_to?(:summary)

        VOLUME_STATS_METRICS.each { |name, (_field, help)| registry.register(name, type: :gauge, help: help) }
        seen = {}
        Array(@stats_provider.summary["pods"]).each do |pod|
          Array(pod["volume"]).each do |volume|
            ref = volume["pvcRef"]
            next unless ref.is_a?(Hash)

            labels = {"namespace" => ref["namespace"].to_s, "persistentvolumeclaim" => ref["name"].to_s}
            next if seen[labels]

            seen[labels] = true
            VOLUME_STATS_METRICS.each do |name, (field, _help)|
              registry.set(name, volume[field].to_i, labels) unless volume[field].nil?
            end
            # kubelet_volume_stats_health_status_abnormal: the CSI driver's
            # volume condition (0 for a volume with stats and no condition).
            condition = volume["volumeCondition"]
            abnormal = condition.is_a?(Hash) && (condition["abnormal"] || condition[:abnormal]) ? 1 : 0
            unless registry.registered?("kubelet_volume_stats_health_status_abnormal")
              registry.register("kubelet_volume_stats_health_status_abnormal",
                                type: :gauge)
            end
            registry.set("kubelet_volume_stats_health_status_abnormal", abnormal, labels)
          end
          container_log_metrics(registry, pod)
        end
      rescue StandardError => error
        @logger&.warn("node.volume_metrics.failed", error: error.class.name, message: error.message) if @logger.respond_to?(:warn)
      end

      # /runningpods/: the Pods the runtime has containers for, as
      # kubecontainer.Pod.ToAPIPod renders them -- name, namespace, UID and
      # each running container's name and image.
      # kubelet_container_log_filesystem_used_bytes{uid, namespace, pod, container}
      # (log_metrics collector): the bytes each container's log directory uses.
      def container_log_metrics(registry, pod)
        ref = pod["podRef"] || {}
        Array(pod["containers"]).each do |container|
          logs = container["logs"]
          next unless logs.is_a?(Hash) && logs["usedBytes"]

          unless registry.registered?("kubelet_container_log_filesystem_used_bytes")
            registry.register("kubelet_container_log_filesystem_used_bytes",
                              type: :gauge)
          end
          registry.set("kubelet_container_log_filesystem_used_bytes", logs["usedBytes"].to_i,
                       {"uid" => ref["uid"].to_s, "namespace" => ref["namespace"].to_s, "pod" => ref["name"].to_s, "container" => container["name"].to_s})
        end
      end

      def running_pods
        records = @lifecycle.respond_to?(:records) ? @lifecycle.records.values : []
        items = records.filter_map do |record|
          next unless record.is_a?(Hash)

          pod = record[:pod] || record["pod"]
          next unless pod.is_a?(Hash)

          state = (record[:state] || record["state"]).to_s
          next if %w[Removed Stopped Failed Succeeded].include?(state)

          running = record_containers(record).select do |entry|
            (entry[:started] || entry["started"]) && !(entry[:exited] || entry["exited"])
          end
          next if running.empty?

          metadata = pod["metadata"] || {}
          images = Array(pod.dig("spec", "containers")).to_h { |container| [container["name"].to_s, container["image"].to_s] }
          {"metadata" => {"name" => metadata["name"], "namespace" => metadata["namespace"], "uid" => metadata["uid"]}.compact,
           "spec" => {"containers" => running.map do |entry|
             name = (entry[:name] || entry["name"]).to_s
             {"name" => name, "image" => images.fetch(name, ""), "resources" => {}}
           end},
           "status" => {}}
        end
        body = JSON.generate({"kind" => "PodList", "apiVersion" => "v1", "metadata" => {}, "items" => items})
        [200, {"content-type" => "application/json"}, [body]]
      end

      def configz
        return [404, {"content-type" => "text/plain"}, ["not found: GET /configz\n"]] unless @configz

        value = @configz.respond_to?(:call) ? @configz.call : @configz
        [200, {"content-type" => "application/json"}, [JSON.generate(value)]]
      end

      # /debug/flags/v (enableDebugFlagsHandler): PUT sets the log verbosity,
      # answering the new value.
      def debug_flags(request)
        return [405, {"content-type" => "text/plain"}, ["only PUT is supported\n"]] unless request.method == "PUT"

        value = request.body.to_s.strip
        return [400, {"content-type" => "text/plain"}, ["error: invalid verbosity #{value.inspect}\n"]] unless value.match?(/\A\d+\z/)

        @verbosity = Integer(value)
        @log_level_setter&.call(@verbosity >= 4 ? "debug" : "info")
        [200, {"content-type" => "text/plain"}, ["successfully set klog.logging.verbosity to #{value}"]]
      end

      # POST /run/{podNamespace}/{podID}[/{uid}]/{containerName}?cmd=...: the
      # command's combined output, the legacy "cmd" query split on spaces.
      def run_in_container(match, request)
        return [400, {"content-type" => "text/plain"}, ["exec service is not configured\n"]] unless @exec_service

        namespace = CGI.unescape(match[:namespace])
        pod = CGI.unescape(match[:pod])
        record = pod_record(namespace, pod)
        return [404, {"content-type" => "text/plain"}, ["pod does not exist\n"]] unless record

        cmd = request.respond_to?(:query_value) ? request.query_value("cmd").to_s : ""
        container = await_container(namespace, pod, CGI.unescape(match[:container]), follow: false)
        result = @exec_service.exec(container, command: cmd.split(" "), tty: false, stdin: false,
                                               stdout: true, stderr: true, identity: "node-streaming")
        output = exec_body(result).map(&:to_s).join
        [200, {"content-type" => "application/json"}, [output]]
      rescue StandardError => error
        [500, {"content-type" => "text/plain"}, ["#{error.class}: #{error.message}\n"]]
      end

      # kubelet's /pods: the Pods this node is running, as a v1 PodList.  The
      # e2e framework reads it through nodes/<name>/proxy/pods whenever a spec
      # fails, to show what the node itself believed.
      def pod_list
        records = @lifecycle.respond_to?(:records) ? @lifecycle.records.values : []
        items = records.filter_map do |record|
          pod = record.is_a?(Hash) ? (record[:pod] || record["pod"]) : nil
          pod.is_a?(Hash) ? pod : nil
        end
        body = JSON.generate({"kind" => "PodList", "apiVersion" => "v1", "metadata" => {}, "items" => items})
        [200, {"content-type" => "application/json"}, [body]]
      end

      def pod_record(namespace, pod_name)
        return nil unless @lifecycle.respond_to?(:records)

        # The lifecycle is keyed by pod UID, which the kubelet-style URL does
        # not carry; the node resolves namespace/name itself, as the real
        # kubelet does from its own pod manager.
        matching = @lifecycle.records.values.select do |candidate|
          pod = candidate.is_a?(Hash) ? (candidate[:pod] || candidate["pod"]) : nil
          metadata = (pod && (pod["metadata"] || pod[:metadata])) || {}
          (metadata["namespace"] || metadata[:namespace]).to_s == namespace &&
            (metadata["name"] || metadata[:name]).to_s == pod_name
        end
        # A StatefulSet recreates a Pod under the same name: while the old
        # record is still being torn down, the new one is the target.  Taking
        # the first match sent "kubectl exec ss2-1" to the removed Pod's
        # container ("unknown container ...-1") for the whole five minutes the
        # rolling-update spec kept retrying.
        matching.min_by do |candidate|
          state = (candidate[:state] || candidate["state"]).to_s
          %w[Removed Stopped Stopping Failed Succeeded].include?(state) ? 1 : 0
        end
      rescue StandardError
        nil
      end

      def record_containers(record)
        containers = if record.is_a?(Hash)
                       record[:containers] || record["containers"]
                     elsif record.respond_to?(:containers)
                       record.containers
                     end
        Array(containers)
      end

      def resolve_container_id(namespace, pod_name, container_name)
        return container_name unless @lifecycle.respond_to?(:records)

        record = pod_record(namespace, pod_name)
        entry = record_containers(record).find do |candidate|
          (candidate[:name] || candidate["name"]).to_s == container_name
        end
        return container_name unless entry

        # Between an exit and the replacement's start the previous
        # container is the one with a log (kubelet: the latest terminated
        # instance); the new id has none until it starts.
        retired = entry[:retired_id] || entry["retired_id"]
        started = entry.key?(:started) ? entry[:started] : entry["started"]
        return retired.to_s if retired && !started

        (entry[:id] || entry["id"]).to_s
      rescue StandardError
        container_name
      end

      def pod_uid(namespace, pod_name)
        record = pod_record(namespace, pod_name)
        pod = record.is_a?(Hash) ? (record[:pod] || record["pod"]) : nil
        metadata = (pod && (pod["metadata"] || pod[:metadata])) || {}
        (metadata["uid"] || metadata[:uid]).to_s
      end

      # Port-forward addresses the Pod's network namespace, which every
      # container shares; any running container of the Pod reaches it.
      def any_running_container(namespace, pod_name)
        return pod_name unless @lifecycle.respond_to?(:records)

        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + SHORT_START_TIMEOUT
        loop do
          record = pod_record(namespace, pod_name)
          containers = record_containers(record)
          entry = containers.find { |candidate| (candidate[:state] || candidate["state"]).to_s == "running" } || containers.first
          return (entry[:id] || entry["id"]).to_s if entry
          unless @lifecycle.respond_to?(:records)
            raise Streaming::Error,
                  "pod #{namespace}/#{pod_name} has no running container on this node"
          end
          if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
            raise Streaming::Error,
                  "pod #{namespace}/#{pod_name} is not running on this node"
          end

          sleep(FOLLOW_POLL_INTERVAL)
        end
      end

      def body_for(result)
        return [result.b] if result.is_a?(String)
        return result if result.respond_to?(:each)

        [String(result).b]
      end

      def query_bool(request, name)
        %w[1 true yes].include?(request.query_value(name).to_s.downcase)
      end
    end
  end
end
