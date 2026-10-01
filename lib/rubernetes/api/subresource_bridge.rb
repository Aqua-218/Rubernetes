# frozen_string_literal: true

require "base64"
require "stringio"
require "digest/sha1"
require "openssl"
require "securerandom"
require_relative "../security/authorization/attributes"

module Rubernetes
  module API
    # Bridges Pod streaming subresources from the API server to one explicitly
    # selected node endpoint.  The API server never accepts a caller supplied
    # container id: the id is resolved from the node lifecycle record for the
    # stored Pod, which prevents cross-Pod runtime access through an IDOR.
    class SubresourceBridge
      STREAMING_SUBRESOURCES = %w[log exec attach portforward].freeze
      DUPLEX_SUBRESOURCES = %w[exec attach portforward].freeze
      HTTP_UPGRADE = "rubernetes.duplex.v1"
      WEBSOCKET_UPGRADE = "websocket"
      WEBSOCKET_VERSION = "13"
      WEBSOCKET_ACCEPT_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
      MAX_COMMAND_ARGUMENTS = 128
      MAX_ARGUMENT_BYTES = 4096
      MAX_PORT_VALUES = 128

      # Thread-safe node endpoint registry used by the production API
      # assembler. Endpoints are AgentService-compatible objects; a missing
      # or unregistered node is an explicit routing failure, never a fallback
      # to an arbitrary local runtime.
      class NodeResolver
        def initialize(initial = {})
          @mutex = Mutex.new
          @endpoints = {}
          initial.each { |name, endpoint| register(name, endpoint) }
        end

        def register(node_name, endpoint)
          name = validate_name(node_name)
          raise ArgumentError, "node endpoint must expose Pod subresources" unless endpoint_capable?(endpoint)

          @mutex.synchronize { @endpoints[name] = endpoint }
          endpoint
        end

        def unregister(node_name, endpoint: nil)
          @mutex.synchronize do
            name = validate_name(node_name)
            current = @endpoints[name]
            return current if endpoint && !current.equal?(endpoint)

            @endpoints.delete(name)
          end
        end

        def resolve(node_name: nil, **options)
          value = node_name || options[:name]
          endpoint = @mutex.synchronize { @endpoints[validate_name(value)] }
          if endpoint.respond_to?(:ready?)
            begin
              return nil unless endpoint.ready?
            rescue StandardError
              return nil
            end
          end

          endpoint
        end

        def call(node_name = nil, **options)
          resolve(node_name: node_name || options[:node_name] || options[:name])
        end

        def names
          @mutex.synchronize { @endpoints.keys.sort.freeze }
        end

        private

        def validate_name(value)
          name = String(value)
          raise ArgumentError, "node name must not be empty" if name.empty?
          raise ArgumentError, "node name contains a control character" if name.match?(/[\x00-\x1f\x7f]/)

          name.freeze
        end

        def endpoint_capable?(endpoint)
          return true if endpoint.respond_to?(:subresource)

          %i[logs exec attach port_forward].any? { |name| endpoint.respond_to?(name) }
        end
      end

      AuthorizationContext = Data.define(
        :identity, :verb, :group, :version, :resource, :namespace, :name, :subresource,
        :request_id
      ) do
        def to_h
          {
            identity: identity,
            verb: verb,
            group: group,
            version: version,
            resource: resource,
            namespace: namespace,
            name: name,
            subresource: subresource,
            request_id: request_id
          }
        end
      end

      # A transport-neutral marker consumed by Transport::HTTPServer.  The
      # marker keeps API core independent from a concrete socket implementation
      # while still allowing HTTP/1.1 upgrades when the transport supports it.
      class Upgrade
        attr_reader :protocol

        def initialize(protocol:, handler:)
          @protocol = String(protocol).dup.freeze
          raise ArgumentError, "upgrade handler must respond to call" unless handler.respond_to?(:call)

          @handler = handler
        end

        def call(socket, request = nil)
          @handler.call(socket, request)
        end
      end

      def initialize(node_resolver: nil, authorizer: nil, trusted_mode: false,
                     request_id_generator: -> { SecureRandom.uuid })
        @node_resolver = node_resolver
        @authorizer = authorizer
        @trusted_mode = !!trusted_mode
        @request_id_generator = request_id_generator
      end

      attr_reader :node_resolver, :authorizer

      def handles?(route)
        route&.resource_route? && route.resource.resource == "pods" &&
          route.resource.group.empty? && route.resource.version == "v1" &&
          STREAMING_SUBRESOURCES.include?(route.subresource.to_s)
      end

      # Resolve and invoke one of the four Pod streaming subresources.
      def call(request, route, pod:)
        raise Status::BadRequest.new("streaming subresources do not support watch") if watch?(request)

        identity = request.respond_to?(:identity) ? request.identity : nil
        correlation_id = request_id(request)
        authorize!(request, route, identity, correlation_id)
        refuse_waiting_container!(pod, request) if route.subresource.to_s == "log"
        node = resolve_node(pod, request)
        operation = route.subresource.to_s
        if DUPLEX_SUBRESOURCES.include?(operation) && upgrade_requested?(request) && node.respond_to?(:upgrade_proxy)
          return proxy_upgrade(node, operation, request)
        end

        service = resolve_service(node, route.subresource)
        container_id = resolve_container_id(node, pod, request)
        operation = route.subresource.to_s
        result = invoke_service(service, operation, container_id, request, identity, correlation_id)
        response_for(result, operation, request)
      rescue Status::Error
        raise
      rescue StandardError => error
        map_runtime_error(error, operation: route.subresource.to_s)
      end

      private

      # pkg/registry/core/pod/strategy.go LogLocation: a container that has
      # not started is refused from the Pod's own status, at once, without
      # asking the node.  Asking the node first made the node wait up to 30s
      # for the container to appear before it answered the same 400.
      def refuse_waiting_container!(pod, request)
        spec = pod["spec"] || {}
        containers = Array(spec["containers"]) + Array(spec["initContainers"]) + Array(spec["ephemeralContainers"])
        name = request.query_value("container").to_s
        name = (containers.first || {})["name"].to_s if name.empty?
        return if name.empty? || containers.none? { |entry| entry["name"].to_s == name }

        status_root = pod["status"] || {}
        statuses = Array(status_root["containerStatuses"]) + Array(status_root["initContainerStatuses"]) +
                   Array(status_root["ephemeralContainerStatuses"])
        status = statuses.find { |entry| entry["name"].to_s == name }
        # No status yet says nothing about the node; the node answers then.
        waiting = status&.dig("state", "waiting")
        return if waiting.nil?
        # kubelet validateContainerLogStatus: a container waiting with a
        # previous run (CrashLoopBackOff) serves that run's log; only one that
        # never ran is refused.
        return if status.dig("lastState", "terminated")

        reason = waiting["reason"].to_s.empty? ? "ContainerCreating" : waiting["reason"].to_s
        raise Status::BadRequest.new("container #{name.inspect} in pod #{pod.dig("metadata",
                                                                                 "name").to_s.inspect} is waiting to start: #{reason}")
      end

      def watch?(request)
        request.method == "GET" && %w[1 true yes].include?(request.query_value("watch").to_s.downcase)
      end

      # kube-apiserver's UpgradeAwareHandler: the upgrade request goes to the
      # node as-is, the node's 101 (with its negotiated protocol headers)
      # goes back to the client, and from then on bytes are copied both ways
      # until either side hangs up.  The API server never interprets the
      # WebSocket/SPDY framing itself.
      def proxy_upgrade(node, operation, request)
        result = node.upgrade_proxy(operation, request, container_name: request.query_value("container"))
        unless result.upgraded?
          message = result.body.to_s.strip
          message = "node rejected the #{operation} upgrade (#{result.status})" if message.empty?
          case result.status
          when 400 then raise Status::BadRequest.new(message)
          when 403 then raise Status::Forbidden.new(message)
          when 404 then raise Status::NotFound.new(message)
          else raise Status::ServiceUnavailable.new(message)
          end
        end

        headers = {}
        result.headers.each do |name, values|
          next if %w[content-length transfer-encoding].include?(name)

          headers[name] = values.length == 1 ? values.first : values
        end
        headers["connection"] ||= "Upgrade"
        node_socket = result.socket
        leftover = result.body.to_s.b
        protocol = request.header("upgrade").to_s
        Response.new(status: 101, headers: headers, body: "",
                     upgrade: Upgrade.new(protocol: protocol, handler: splice_handler(node_socket, leftover)))
      end

      SPLICE_CHUNK = 64 * 1024

      def splice_handler(node_socket, leftover)
        lambda do |client_socket, _request|
          client_socket.write(leftover) unless leftover.empty?
          copies = [
            Thread.new { copy_bytes(client_socket, node_socket) },
            Thread.new { copy_bytes(node_socket, client_socket) }
          ]
          # The first side to finish ends the session: half-open proxies keep
          # kubectl waiting on a peer that has already gone.
          finished = Queue.new
          copies.each do |thread|
            Thread.new do
              thread.join
              finished << thread
            end
          end
          finished.pop
          copies.each { |thread| thread.join(1) }
        ensure
          copies&.each { |thread| thread.kill if thread.alive? }
          begin
            node_socket.close unless node_socket.closed?
          rescue IOError, SystemCallError
            nil
          end
        end
      end

      def copy_bytes(from, to)
        loop do
          chunk = from.readpartial(SPLICE_CHUNK)
          to.write(chunk)
          to.flush if to.respond_to?(:flush)
        end
      rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
        nil
      ensure
        begin
          to.close_write if to.respond_to?(:close_write)
        rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
          nil
        end
      end

      def authorize!(request, route, identity, correlation_id)
        raise Status::Unauthorized.new("authentication is required for Pod #{route.subresource} subresources") if identity.nil? || identity.to_s.empty?
        raise Status::ServiceUnavailable.new("Pod streaming subresource authorization is not configured") unless @trusted_mode || @authorizer
        return if @trusted_mode

        context = AuthorizationContext.new(
          identity: identity,
          verb: request.method == "GET" ? "get" : "create",
          group: route.resource.group,
          version: route.resource.version,
          resource: "pods",
          namespace: route.namespace,
          name: route.name,
          subresource: route.subresource,
          request_id: correlation_id
        ).freeze
        verdict = invoke_authorizer(context)
        return if authorization_allowed?(verdict)

        raise Status::Forbidden.new("request is not authorized for Pod #{route.subresource}")
      end

      # authorization.k8s.io SubjectAccessReviewSpec for this streaming request.
      def subject_access_review_spec(context)
        {
          "resourceAttributes" => {
            "verb" => context.verb.to_s,
            "group" => context.group.to_s,
            "version" => context.version.to_s,
            "resource" => context.resource.to_s,
            "subresource" => context.subresource.to_s,
            "namespace" => context.namespace.to_s,
            "name" => context.name.to_s
          }
        }
      end

      def authorization_attributes(context)
        Rubernetes::Security::Authorization::Attributes.new(
          user: context.identity, verb: context.verb,
          path: "/api/#{context.version}/namespaces/#{context.namespace}/pods/#{context.name}/#{context.subresource}",
          namespace: context.namespace, api_group: context.group, api_version: context.version,
          resource: context.resource, subresource: context.subresource, name: context.name,
          resource_request: true
        )
      end

      def invoke_authorizer(context)
        # Two production shapes exist and neither takes this bridge's own
        # context struct, which is why every `kubectl logs`/`exec`/`attach`/
        # `port-forward` used to fail closed with "could not be evaluated":
        #   * ReviewAdapter#authorize(identity, SubjectAccessReview spec)
        #   * an authorizer#authorize(Authorization::Attributes)
        if @authorizer.respond_to?(:authorize)
          arity = @authorizer.method(:authorize).arity
          return @authorizer.authorize(context.identity, subject_access_review_spec(context)) if arity == 2 || arity < -1

          return @authorizer.authorize(authorization_attributes(context))
        end

        callable = if @authorizer.respond_to?(:authorize)
                     @authorizer.method(:authorize)
                   elsif @authorizer.respond_to?(:call)
                     @authorizer.respond_to?(:parameters) ? @authorizer : @authorizer.method(:call)
                   else
                     raise Status::ServiceUnavailable.new("Pod streaming subresource authorizer is invalid")
                   end
        parameters = callable.parameters
        accepts_keywords = parameters.any? { |kind, _| %i[key keyreq keyrest].include?(kind) }
        return callable.call(**context.to_h) if accepts_keywords
        return callable.call if parameters.empty?

        callable.call(context)
      rescue ArgumentError => error
        raise Status::ServiceUnavailable.new(
          "Pod streaming subresource authorizer could not be evaluated: #{error.class}: #{error.message}"
        ), cause: error
      end

      def authorization_allowed?(verdict)
        return true if verdict == true
        return verdict.allowed? if verdict.respond_to?(:allowed?)
        return verdict.fetch(:allowed) if verdict.is_a?(Hash) && verdict.key?(:allowed)
        return verdict.fetch("allowed") if verdict.is_a?(Hash) && verdict.key?("allowed")

        false
      end

      def resolve_node(pod, request)
        raise Status::ServiceUnavailable.new("Pod node routing is not configured") unless @node_resolver

        node_name = pod.dig("spec", "nodeName").to_s
        raise Status::ServiceUnavailable.new("Pod is not assigned to a node") if node_name.empty?

        value = if @node_resolver.is_a?(Hash)
                  @node_resolver[node_name] || @node_resolver[node_name.to_sym]
                else
                  invoke_resolver(@node_resolver, pod, node_name, request)
                end
        raise Status::ServiceUnavailable.new("Pod node #{node_name.inspect} is unavailable") if value.nil?

        value
      end

      def invoke_resolver(resolver, pod, node_name, request)
        callable = resolver.respond_to?(:call) ? resolver.method(:call) : resolver.method(:resolve)
        parameters = callable.parameters
        if parameters.any? { |kind, _| %i[key keyreq keyrest].include?(kind) }
          keywords = {pod: pod, node_name: node_name, request: request}
          accepts_keywords = parameters.any? { |kind, _| kind == :keyrest }
          unless accepts_keywords
            accepted = parameters.filter_map { |kind, name| name if %i[key keyreq].include?(kind) }
            keywords.select! { |key, _| accepted.include?(key) }
          end
          callable.call(**keywords)
        elsif parameters.empty?
          callable.call
        elsif parameters.length == 1
          parameter_name = parameters.first.last
          callable.call(%i[pod pod_object request].include?(parameter_name) ? pod : node_name)
        else
          positional = parameters.select { |kind, _| %i[req opt rest].include?(kind) }
          values = {pod: pod, pod_object: pod, request: request, node_name: node_name, name: node_name}
          if positional.any? { |kind, _| kind == :rest }
            callable.call(node_name, pod)
          else
            callable.call(*positional.map { |_kind, name| values.fetch(name, node_name) })
          end
        end
      rescue ArgumentError => error
        raise Status::ServiceUnavailable.new("Pod node routing failed"), cause: error
      end

      def resolve_service(node, subresource)
        if node.respond_to?(:subresource)
          begin
            return node.subresource(subresource)
          rescue KeyError
            alternate = {"log" => "logs", "portforward" => "port-forward"}.fetch(subresource.to_s, nil)
            return node.subresource(alternate) if alternate
          end
        end

        method_name = case subresource.to_s
                      when "log" then :logs
                      when "portforward" then :port_forward
                      else subresource.to_sym
                      end
        return node.public_send(method_name) if node.respond_to?(method_name)

        raise Status::ServiceUnavailable.new("node endpoint does not expose Pod #{subresource}")
      rescue KeyError, NoMethodError
        raise Status::ServiceUnavailable.new("node endpoint does not expose Pod #{subresource}")
      end

      def resolve_container_id(node, pod, request)
        name = request.query_value("container")
        if node.respond_to?(:container_id_for)
          value = invoke_container_resolver(node, pod, name)
          return ensure_container_id(value)
        end

        lifecycle = if node.respond_to?(:lifecycle)
                      node.lifecycle
                    elsif node.respond_to?(:node_agent) && node.node_agent.respond_to?(:lifecycle)
                      node.node_agent.lifecycle
                    end
        record = lifecycle&.record(pod)
        containers = if record.is_a?(Hash)
                       record[:containers] || record["containers"]
                     elsif record.respond_to?(:containers)
                       record.containers
                     end
        containers = Array(containers)
        raise Status::ServiceUnavailable.new("Pod has no running container record on its node") if containers.empty?

        requested_name = name.to_s
        default_name = Array(pod.dig("spec", "containers")).first
        default_name = default_name.is_a?(Hash) ? (default_name["name"] || default_name[:name]).to_s : ""
        selected_name = requested_name.empty? ? default_name : requested_name
        selected = if selected_name.empty?
                     containers.first
                   else
                     containers.find { |entry| entry[:name].to_s == selected_name || entry["name"].to_s == selected_name }
                   end
        raise Status::NotFound.new("container #{name.inspect} was not found in Pod") if selected.nil?

        ensure_container_id(selected[:id] || selected["id"])
      rescue NoMethodError
        raise Status::ServiceUnavailable.new("node endpoint cannot resolve Pod containers")
      end

      def invoke_container_resolver(node, pod, name)
        callable = node.method(:container_id_for)
        parameters = callable.parameters
        if parameters.any? { |kind, _| %i[key keyreq keyrest].include?(kind) }
          values = {pod: pod, container_name: name, container: name}
          return callable.call(**values) if parameters.any? { |kind, _| kind == :keyrest }

          accepted = parameters.filter_map { |kind, parameter| parameter if %i[key keyreq].include?(kind) }
          return callable.call(**values.select { |key, _| accepted.include?(key) })
        end
        return callable.call(pod, name) if parameters.length > 1

        callable.call(pod)
      end

      def ensure_container_id(value)
        normalized = String(value)
        raise Status::ServiceUnavailable.new("Pod container identity is unavailable") if normalized.empty? || normalized.include?("\0")

        normalized.freeze
      rescue TypeError
        raise Status::ServiceUnavailable.new("Pod container identity is unavailable")
      end

      def invoke_service(service, operation, container_id, request, identity, correlation_id)
        case operation
        when "log"
          invoke_log(service, container_id, request, identity, correlation_id)
        when "exec", "attach"
          invoke_duplex(service, operation, container_id, request, identity, correlation_id)
        when "portforward"
          invoke_portforward(service, container_id, request, identity, correlation_id)
        else
          raise Status::NotImplemented.new("Pod subresource #{operation.inspect} is not implemented")
        end
      end

      def invoke_log(service, container_id, request, identity, correlation_id)
        callable = service.respond_to?(:logs) ? service.method(:logs) : service.method(:call)
        invoke_with_keywords(callable, [container_id], {
                               follow: boolean_query(request, "follow", default: false),
                               since: log_since(request),
                               tail: request.query_value("tailLines"),
                               timestamps: boolean_query(request, "timestamps", default: false),
                               limit_bytes: request.query_value("limitBytes"),
                               stream: normalize_log_stream(request.query_value("stream")),
                               request_id: correlation_id,
                               identity: identity
                             })
      end

      # sinceSeconds and sinceTime both mean "log written from this moment"
      # (PodLogOptions); neither is a byte offset, which is what the runtime
      # takes an integer for.
      def log_since(request)
        seconds = request.query_value("sinceSeconds")
        unless seconds.nil? || seconds.to_s.empty?
          value = Integer(seconds, exception: false)
          raise Status::BadRequest.new("sinceSeconds must be a positive integer") if value.nil? || value <= 0

          return (Time.now.utc - value).iso8601(9)
        end
        time = request.query_value("sinceTime")
        return nil if time.nil? || time.to_s.empty?

        Time.iso8601(time.to_s).utc.iso8601(9)
      rescue ArgumentError
        raise Status::BadRequest.new("sinceTime must be an RFC 3339 time")
      end

      def invoke_duplex(service, operation, container_id, request, identity, correlation_id)
        callable = service.respond_to?(operation) ? service.method(operation) : service.method(:call)
        command = request.query_values("command")
        command = request.query_values("cmd") if command.empty?
        if operation == "exec"
          raise Status::BadRequest.new("exec requires at least one command argument") if command.empty?
          raise Status::BadRequest.new("exec command has too many arguments") if command.length > MAX_COMMAND_ARGUMENTS

          command.each { |argument| validate_argument!(argument, "exec command argument") }
        end
        invoke_with_keywords(callable, [container_id], {
          command: operation == "exec" ? command : nil,
          tty: boolean_query(request, "tty", default: false),
          stdin: boolean_query(request, "stdin", default: false),
          stdout: boolean_query(request, "stdout", default: true),
          stderr: boolean_query(request, "stderr", default: false),
          request_id: correlation_id,
          identity: identity
        }.compact)
      end

      def invoke_portforward(service, container_id, request, identity, correlation_id)
        ports = request.query_values("ports")
        ports = request.query_values("port") if ports.empty?
        raise Status::BadRequest.new("portforward requires at least one port") if ports.empty?
        raise Status::BadRequest.new("portforward accepts at most #{MAX_PORT_VALUES} ports") if ports.length > MAX_PORT_VALUES

        callable = service.respond_to?(:port_forward) ? service.method(:port_forward) : service.method(:call)
        invoke_with_keywords(callable, [container_id, ports], {
                               timeout: request.query_value("timeout") || 30.0,
                               request_id: correlation_id,
                               identity: identity
                             })
      end

      def invoke_with_keywords(callable, positional, keywords)
        parameters = callable.parameters
        return callable.call(*positional, **keywords) if parameters.any? { |kind, _| kind == :keyrest }

        accepted = parameters.filter_map { |kind, name| name if %i[key keyreq].include?(kind) }
        callable.call(*positional, **keywords.select { |key, _| accepted.include?(key) })
      rescue ArgumentError => error
        raise Status::BadRequest.new("Pod subresource request is invalid"), cause: error
      end

      def response_for(result, operation, request)
        # A plain log read; a log requested over a WebSocket upgrade takes the
        # reader-stream path below, as upstream's StreamObject does.  The
        # early return used to swallow the upgrade, so "[sig-node] Pods should
        # support retrieving logs from the container over websockets" got a
        # 200 text body instead of a 101.
        if operation == "log" && !upgrade_requested?(request)
          body = result.is_a?(String) ? [result.b] : result
          return Response.new(status: 200, headers: {"content-type" => "text/plain; charset=utf-8"}, body: body, stream: true)
        end

        unless result.is_a?(String) || result.is_a?(Hash) || result.respond_to?(:read) || result.respond_to?(:each) || result.respond_to?(:stdout)
          raise Status::ServiceUnavailable.new("node subresource returned no stream")
        end

        if upgrade_requested?(request)
          # Upstream serves ANY stream over a WebSocket when the client asks
          # for one (responsewriters.WriteStream -> wsstream.IsWebSocketRequest
          # with NewDefaultReaderProtocols), which is what
          # "[sig-node] Pods should support retrieving logs from the container
          # over websockets" uses.  Rejecting the upgrade for logs made that
          # conformance spec fail with "websocket.Dial ...: bad status".
          return upgrade_response(result, operation, request)
        end

        output = stream_output(result)
        output = ["".b] if output.nil?
        Response.new(status: 200, headers: stream_headers(operation), body: output, stream: true)
      end

      def stream_output(result)
        return result.stdout if result.respond_to?(:stdout)
        return result[:stdout] || result["stdout"] || result[:stderr] || result["stderr"] if result.is_a?(Hash)

        result.is_a?(String) ? [result.b] : result
      end

      def stream_headers(operation)
        {
          "content-type" => operation == "portforward" ? "application/octet-stream" : "application/vnd.kubernetes.remotecommand",
          "cache-control" => "no-store",
          "x-content-type-options" => "nosniff"
        }
      end

      def upgrade_requested?(request)
        connection = request.header("connection").to_s.split(",").map { |value| value.strip.downcase }
        connection.include?("upgrade") && !request.header("upgrade").to_s.empty?
      end

      def upgrade_response(result, operation, request)
        requested = request.header("upgrade").to_s.downcase
        case requested
        when WEBSOCKET_UPGRADE
          version = request.header("sec-websocket-version").to_s
          key = request.header("sec-websocket-key").to_s
          unless version == WEBSOCKET_VERSION && valid_websocket_key?(key)
            raise Status::BadRequest.new("websocket upgrade requires version 13 and a valid key")
          end

          protocol = select_websocket_protocol(request.header("sec-websocket-protocol"), operation)
          raise Status::BadRequest.new("websocket upgrade does not offer a supported Kubernetes channel protocol") unless protocol

          headers = stream_headers(operation).merge(
            "connection" => "Upgrade",
            "upgrade" => "websocket",
            "sec-websocket-accept" => websocket_accept(key)
          )
          # An empty negotiated protocol must not be echoed back as a header.
          headers["sec-websocket-protocol"] = protocol unless protocol.to_s.empty?
          handler = if DUPLEX_SUBRESOURCES.include?(operation)
                      websocket_handler(result)
                    else
                      websocket_reader_handler(result, base64: protocol == BASE64_BINARY_WEBSOCKET_PROTOCOL)
                    end
          Response.new(status: 101, headers: headers,
                       body: "", upgrade: Upgrade.new(protocol: "websocket", handler: handler))
        when HTTP_UPGRADE
          Response.new(status: 101, headers: stream_headers(operation).merge(
            "connection" => "Upgrade", "upgrade" => HTTP_UPGRADE
          ), body: "", upgrade: Upgrade.new(protocol: HTTP_UPGRADE, handler: framed_handler(result)))
        when "spdy/3.1"
          raise Status::NotImplemented.new("SPDY upgrade is not supported by this transport")
        else
          raise Status::BadRequest.new("unsupported streaming upgrade protocol")
        end
      end

      def websocket_handler(result)
        lambda do |socket, _request|
          WebSocketDuplex.new(result).serve(socket)
        end
      end

      def websocket_reader_handler(result, base64:)
        stream = readable_stream(result)
        lambda do |socket, _request|
          WebSocketReader.new(stream, base64: base64).serve(socket)
        end
      end

      # A log body is a String (one-shot read) or an enumerable of chunks (a
      # follow); the reader wants something with #read.  Handing it the raw
      # body sent an empty websocket stream.
      def readable_stream(result)
        return result if result.respond_to?(:read)
        return StringIO.new(result.b) if result.is_a?(String)
        return ChunkStream.new(result) if result.respond_to?(:each)

        result
      end

      class ChunkStream
        def initialize(enumerable)
          @enumerator = enumerable.each
          @closed = false
        end

        def read(_length = nil)
          return nil if @closed

          chunk = @enumerator.next
          chunk.nil? ? nil : chunk.to_s.b
        rescue StopIteration
          nil
        end

        def close
          @closed = true
          @enumerator.instance_variable_get(:@__nothing) # no-op; the source closes itself
          nil
        end

        def closed?
          @closed
        end
      end

      def framed_handler(result)
        lambda do |socket, _request|
          FramedDuplex.new(result).serve(socket)
        end
      end

      def valid_websocket_key?(value)
        decoded = Base64.strict_decode64(value)
        decoded.bytesize == 16
      rescue ArgumentError
        false
      end

      def websocket_accept(key)
        Base64.strict_encode64(Digest::SHA1.digest(key + WEBSOCKET_ACCEPT_GUID))
      end

      # A simplex stream (Pod logs) speaks the reader protocols, not the
      # channel protocols: "" and binary.k8s.io are raw binary frames,
      # base64.binary.k8s.io is base64 in text frames
      # (wsstream.NewDefaultReaderProtocols).
      BINARY_WEBSOCKET_PROTOCOL = "binary.k8s.io"
      BASE64_BINARY_WEBSOCKET_PROTOCOL = "base64.binary.k8s.io"
      READER_WEBSOCKET_PROTOCOLS = [BINARY_WEBSOCKET_PROTOCOL, BASE64_BINARY_WEBSOCKET_PROTOCOL].freeze

      def select_websocket_protocol(header, operation)
        offered = header.to_s.split(",").map(&:strip)
        unless DUPLEX_SUBRESOURCES.include?(operation)
          # An absent subprotocol is valid for a reader stream and means binary.
          return "" if offered.empty? || offered == [""]

          return READER_WEBSOCKET_PROTOCOLS.find { |candidate| offered.include?(candidate) }
        end

        supported = if operation == "portforward"
                      %w[v4.channel.k8s.io v3.channel.k8s.io]
                    else
                      %w[v5.channel.k8s.io v4.channel.k8s.io v3.channel.k8s.io]
                    end
        supported.find { |candidate| offered.include?(candidate) }
      end

      def boolean_query(request, name, default:)
        value = request.query_value(name)
        return default if value.nil? || value.to_s.empty?
        return true if %w[1 true yes].include?(value.to_s.downcase)
        return false if %w[0 false no].include?(value.to_s.downcase)

        raise Status::BadRequest.new("query parameter #{name} must be boolean")
      end

      # PodLogOptions.Stream defaults to "All" (core/v1 types.go): a
      # container's log is BOTH of its streams, and kubelet returns whatever
      # the container wrote to either.  Defaulting to Stdout instead dropped
      # every diagnostic a workload writes to stderr -- "[sig-node] Security
      # Context should run the container as unprivileged when false" reads the
      # log for the "Operation not permitted" that `ip link add` prints there,
      # and read an empty log.
      def normalize_log_stream(value)
        normalized = value.to_s.downcase
        return :all if normalized.empty? || normalized == "all"
        return :stdout if normalized == "stdout"
        return :stderr if normalized == "stderr"

        raise Status::BadRequest.new("query parameter stream must be All, Stdout, or Stderr")
      end

      def validate_argument!(value, name)
        raise Status::BadRequest.new("#{name} must not contain NUL") if value.to_s.include?("\0")
        raise Status::BadRequest.new("#{name} is too large") if value.to_s.bytesize > MAX_ARGUMENT_BYTES
      end

      def request_id(request)
        header = request.header("x-request-id") if request.respond_to?(:header)
        return header.to_s unless header.to_s.empty?

        @request_id_generator.call.to_s
      end

      def map_runtime_error(error, operation:)
        return raise(error) if error.is_a?(Status::Error)

        name = error.class.name.to_s
        if name.end_with?("::AuthorizationError")
          raise Status::Forbidden.new("request is not authorized for Pod #{operation}"), cause: error
        end
        if name.end_with?("::InvalidRequest", "::ConfigurationError")
          raise Status::BadRequest.new("Pod #{operation} request is invalid"), cause: error
        end
        if name.end_with?("::RuntimeUnavailable", "::CapabilityError")
          raise Status::ServiceUnavailable.new("Pod #{operation} runtime is unavailable"), cause: error
        end

        raise Status::ServiceUnavailable.new(
          "Pod #{operation} stream is unavailable: #{error.class}: #{error.message}"
        ), cause: error
      end

      # Minimal RFC 6455 server for the Kubernetes channel subprotocols. It
      # deliberately rejects fragmented and unmasked client frames so a
      # malformed peer cannot desynchronize the binary stream.
      # A one-way WebSocket stream: the server writes the log, the client only
      # ever closes.  wsstream.Reader with NewDefaultReaderProtocols.
      class WebSocketReader
        MAX_FRAME_BYTES = 1_048_576
        CHUNK_BYTES = 16 * 1024

        def initialize(stream, base64: false)
          @stream = stream
          @base64 = base64
          @write_mutex = Mutex.new
          @closed = false
        end

        def serve(socket)
          reader = Thread.new { drain_client(socket) }
          write_loop(socket)
          close_frame(socket)
          reader.join(1)
        rescue IOError, SystemCallError
          nil
        ensure
          @stream.close if @stream.respond_to?(:close) && !(@stream.respond_to?(:closed?) && @stream.closed?)
          reader&.kill if reader&.alive?
        end

        private

        # The client sends nothing but control frames; reading them is what
        # notices a disconnect promptly.
        def drain_client(socket)
          loop do
            header = socket.read(2)
            break if header.nil? || header.bytesize < 2

            first, second = header.bytes
            opcode = first & 0x0f
            length = second & 0x7f
            masked = second.anybits?(0x80)
            length = socket.read(2).unpack1("n") if length == 126
            length = socket.read(8).unpack1("Q>") if length == 127
            break if length.nil? || length > MAX_FRAME_BYTES

            socket.read(4) if masked
            socket.read(length) if length.positive?
            break if opcode == 0x8
          end
        rescue IOError, SystemCallError
          nil
        ensure
          @write_mutex.synchronize { @closed = true }
        end

        def write_loop(socket)
          loop do
            break if @write_mutex.synchronize { @closed }

            payload = read_chunk
            break if payload.nil?
            next if payload.empty?

            if @base64
              write_frame(socket, [payload].pack("m0"), opcode: 0x1)
            else
              write_frame(socket, payload, opcode: 0x2)
            end
          end
        end

        def read_chunk
          return @stream.read(CHUNK_BYTES) if @stream.respond_to?(:read)

          nil
        rescue (defined?(Rubernetes::Node::StreamTimeout) ? Rubernetes::Node::StreamTimeout : IOError), IO::WaitReadable
          "".b
        rescue IOError, SystemCallError
          nil
        end

        def close_frame(socket)
          write_frame(socket, [1000].pack("n"), opcode: 0x8)
        rescue IOError, SystemCallError
          nil
        end

        def write_frame(socket, payload, opcode:)
          bytes = payload.b
          header = [0x80 | opcode]
          if bytes.bytesize < 126
            header << bytes.bytesize
          elsif bytes.bytesize <= 0xffff
            header << 126
            header.concat([bytes.bytesize].pack("n").bytes)
          else
            header << 127
            header.concat([bytes.bytesize].pack("Q>").bytes)
          end
          @write_mutex.synchronize do
            socket.write(header.pack("C*") + bytes)
            socket.flush if socket.respond_to?(:flush)
          end
        end
      end

      class WebSocketDuplex
        MAX_FRAME_BYTES = 1_048_576

        def initialize(stream)
          @stream = stream
          @write_mutex = Mutex.new
        end

        def serve(socket)
          reader = Thread.new { read_loop(socket) }
          writer = Thread.new { write_loop(socket) }
          reader.join
          @stream.close_write if @stream.respond_to?(:close_write)
          writer.join(5)
          writer.kill if writer.alive?
        ensure
          @stream.close if @stream.respond_to?(:close)
          reader&.kill if reader&.alive?
          writer&.kill if writer&.alive?
        end

        private

        def read_loop(socket)
          loop do
            first, second = read_bytes(socket, 2).bytes
            fin = first.anybits?(0x80)
            opcode = first & 0x0f
            masked = second.anybits?(0x80)
            length = second & 0x7f
            raise IOError, "fragmented websocket frames are not supported" unless fin
            raise IOError, "client websocket frames must be masked" unless masked

            if length == 126
              length = read_bytes(socket, 2).unpack1("n")
            elsif length == 127
              length = read_bytes(socket, 8).unpack1("Q>")
            end
            raise IOError, "websocket control frame exceeds 125 bytes" if opcode >= 0x8 && length > 125
            raise IOError, "websocket frame exceeds configured limit" if length > MAX_FRAME_BYTES

            mask = read_bytes(socket, 4).bytes
            payload = read_bytes(socket, length).bytes
            payload.map!.with_index { |byte, index| byte ^ mask[index % 4] }
            case opcode
            when 0x2
              @stream.write(payload.pack("C*"))
            when 0x8
              write_frame(socket, "", opcode: 0x8)
              break
            when 0x9
              write_frame(socket, payload.pack("C*"), opcode: 0xa)
            when 0xa
              next
            when 0x1
              raise IOError, "text websocket frames are not supported"
            else
              raise IOError, "unsupported websocket opcode"
            end
          end
        end

        def write_loop(socket)
          loop do
            payload = @stream.read(16 * 1024)
            break if payload.nil?

            write_frame(socket, payload, opcode: 0x2)
          end
        rescue (defined?(Rubernetes::Node::StreamTimeout) ? Rubernetes::Node::StreamTimeout : IOError), IO::WaitReadable
          retry
        end

        def read_bytes(socket, length)
          value = socket.read(length)
          raise EOFError if value.nil? || value.bytesize != length

          value.b
        end

        def write_frame(socket, payload, opcode:)
          bytes = payload.b
          header = [0x80 | opcode]
          if bytes.bytesize < 126
            header << bytes.bytesize
          elsif bytes.bytesize <= 0xffff
            header << 126
            header.concat([bytes.bytesize].pack("n").bytes)
          else
            header << 127
            header.concat([bytes.bytesize].pack("Q>").bytes)
          end
          @write_mutex.synchronize { socket.write(header.pack("C*") + bytes) }
        end
      end

      # Length-prefixed binary upgrade used by in-process clients that do not
      # implement WebSocket. Each frame is a four-byte big-endian length.
      class FramedDuplex
        MAX_FRAME_BYTES = 1_048_576

        def initialize(stream)
          @stream = stream
        end

        def serve(socket)
          reader = Thread.new { read_loop(socket) }
          writer = Thread.new { write_loop(socket) }
          reader.join
          @stream.close_write if @stream.respond_to?(:close_write)
          writer.join(5)
          writer.kill if writer.alive?
        ensure
          @stream.close if @stream.respond_to?(:close)
          reader&.kill if reader&.alive?
          writer&.kill if writer&.alive?
        end

        private

        def read_loop(socket)
          loop do
            length = socket.read(4)
            raise EOFError if length.nil? || length.bytesize != 4

            size = length.unpack1("N")
            raise IOError, "duplex frame exceeds configured limit" if size > MAX_FRAME_BYTES
            break if size.zero?

            payload = socket.read(size)
            raise EOFError if payload.nil? || payload.bytesize != size

            @stream.write(payload)
          end
        end

        def write_loop(socket)
          loop do
            payload = @stream.read(16 * 1024)
            break if payload.nil?

            socket.write([payload.bytesize].pack("N") + payload.b)
          end
        end
      end
    end
  end
end
