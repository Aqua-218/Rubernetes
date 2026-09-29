# frozen_string_literal: true

require "ipaddr"
require "json"
require "socket"
require "thread"
require "time"
require_relative "metrics"
require "timeout"

module Rubernetes
  module Proxy
    # Result of a Service translation.  The original destination is retained
    # for observability while target_endpoint is the selected Pod address.
    class Route
      attr_reader :service, :rule, :packet, :target_endpoint, :connection,
                  :kind, :source_preserved, :original_destination, :translated_destination,
                  :translated_port, :external, :metadata

      def initialize(service:, rule:, packet:, target_endpoint: nil, connection: nil,
                     kind: nil, source_preserved: false, original_destination: nil,
                     translated_destination: nil, translated_port: nil, external: false,
                     metadata: {})
        @service = service
        @rule = rule
        @packet = packet
        @target_endpoint = target_endpoint
        @connection = connection
        @kind = (kind || rule&.kind || "Service").to_s.freeze
        @source_preserved = !!source_preserved
        @original_destination = (original_destination || packet.destination_ip)&.to_s
        @translated_destination = (translated_destination || target_endpoint&.address)&.to_s
        @translated_port = translated_port || target_endpoint&.port
        @external = !!external
        @metadata = ModelSupport.immutable(metadata || {})
        freeze
      end

      def backend
        target_endpoint
      end

      alias endpoint target_endpoint

      def address
        translated_destination
      end

      def port
        translated_port
      end

      def external?
        external
      end

      def success?
        return true if service.external_name?
        return metadata.dig("health", "status").to_i == 200 if kind == "HealthCheckNodePort"

        !target_endpoint.nil?
      end

      def to_h
        {
          "service" => service.key,
          "kind" => kind,
          "protocol" => packet.protocol,
          "originalDestination" => original_destination,
          "translatedDestination" => translated_destination,
          "translatedPort" => translated_port,
          "sourcePreserved" => source_preserved,
          "external" => external,
          "endpoint" => target_endpoint&.to_h,
          "connection" => connection && {
            "key" => connection.key.to_h,
            "backend" => connection.backend.respond_to?(:identity) ? connection.backend.identity : connection.backend.to_s,
            "affinity" => connection.affinity
          },
          "externalName" => service.external_name,
          "metadata" => ModelSupport.deep_copy(metadata)
        }.compact
      end
    end

    class ExternalNameRoute < Route
      def initialize(service:, packet:, **options)
        super(service: service, rule: nil, packet: packet, kind: "ExternalName", **options)
      end

      def hostname
        service.external_name
      end
    end

    HealthCheckResult = Struct.new(:service_key, :node_name, :node_port, :healthy,
                                   :status, :endpoints, :checked_at, keyword_init: true) do
      def initialize(**attributes)
        super(**attributes)
        freeze
      end

      def healthy?
        !!healthy
      end

      def ok?
        status.to_i == 200
      end

      def to_h
        {"serviceKey" => service_key, "nodeName" => node_name, "nodePort" => node_port,
         "healthy" => !!healthy, "status" => status, "endpoints" => endpoints.map(&:to_h),
         "checkedAt" => checked_at}
      end
    end

    # Node-local HTTP responder for Service healthCheckNodePort.  TC leaves
    # this traffic local; the responder owns the Kubernetes health contract
    # and answers from the current local EndpointSlice state.  A listener is
    # created for every reserved health port and is refreshed when Services
    # are added or removed, while endpoint health is read per request.
    class HealthCheckResponder
      DEFAULT_BIND_ADDRESS = "0.0.0.0"
      REQUEST_TIMEOUT = 2
      MAX_HEADER_BYTES = 16 * 1024

      attr_reader :proxy, :bind_address

      def initialize(proxy:, bind_address: DEFAULT_BIND_ADDRESS)
        raise ArgumentError, "proxy is required" unless proxy

        @proxy = proxy
        @bind_address = String(bind_address)
        raise ArgumentError, "health responder bind address must not be empty" if @bind_address.empty?

        @mutex = Mutex.new
        @listeners = {}
        @started = false
        @closed = false
      end

      def start
        @mutex.synchronize do
          return self if @started && !@closed

          @closed = false
          @started = true
          refresh_locked
        end
        self
      rescue StandardError
        @started = false
        close_listeners(@listeners.values)
        @listeners = {}
        raise
      end

      def refresh
        @mutex.synchronize do
          refresh_locked if @started && !@closed
        end
        self
      end

      def close
        listeners = @mutex.synchronize do
          @closed = true
          @started = false
          current = @listeners.values
          @listeners = {}
          current
        end
        close_listeners(listeners)
        self
      end

      alias stop close

      def running?
        @mutex.synchronize { @started && !@closed }
      end

      def ports
        @mutex.synchronize { @listeners.keys.sort.freeze }
      end

      private

      def refresh_locked
        desired = @proxy.services.each_with_object({}) do |service, result|
          port = service.health_check_node_port
          next unless port

          result[Integer(port)] ||= service.key
        end
        stale = @listeners.keys - desired.keys
        close_listeners(stale.filter_map { |port| @listeners.delete(port) })
        desired.each do |port, service_key|
          listener = @listeners[port]
          if listener
            listener[:service_key] = service_key
            next
          end

          server = TCPServer.new(@bind_address, port)
          server.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
          listener = {server: server, service_key: service_key}
          listener[:thread] = Thread.new { serve(port, listener) }
          listener[:thread].name = "rubernetes-health-#{port}" if listener[:thread].respond_to?(:name=)
          @listeners[port] = listener
        end
      rescue StandardError
        close_listeners(@listeners.values)
        @listeners = {}
        raise
      end

      def serve(port, listener)
        loop do
          client = listener.fetch(:server).accept
          handle(client, port)
        rescue IOError, Errno::EBADF
          break
        rescue SystemCallError
          break if @mutex.synchronize { @closed }
        ensure
          client&.close rescue nil
        end
      end

      def handle(client, port)
        request_line = nil
        Timeout.timeout(REQUEST_TIMEOUT) do
          request_line = client.gets(MAX_HEADER_BYTES)
          bytes = request_line.to_s.bytesize
          while request_line && request_line != "\r\n" && request_line != "\n"
            line = client.gets(MAX_HEADER_BYTES)
            break unless line

            bytes += line.bytesize
            raise IOError, "health request headers exceed limit" if bytes > MAX_HEADER_BYTES
            break if line == "\r\n" || line == "\n"
          end
        end
        method, path, = request_line.to_s.split(" ", 3)
        status, reason, body = health_response(port, method, path)
        client.write("HTTP/1.1 #{status} #{reason}\r\nContent-Type: text/plain\r\n" \
                     "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
      rescue Timeout::Error, IOError, SystemCallError
        nil
      end

      def health_response(port, method, path)
        return [405, "Method Not Allowed", ""] unless %w[GET HEAD].include?(method)
        return [404, "Not Found", ""] unless path == "/healthz"

        service = @proxy.services.find { |candidate| candidate.health_check_node_port.to_i == port }
        return [503, "Service Unavailable", "FAIL\n"] unless service

        result = @proxy.health_check(service: service, node: @proxy.local_node)
        if result.healthy?
          [200, "OK", method == "HEAD" ? "" : "OK\n"]
        else
          [503, "Service Unavailable", method == "HEAD" ? "" : "FAIL\n"]
        end
      rescue StandardError
        [503, "Service Unavailable", method == "HEAD" ? "" : "FAIL\n"]
      end

      def close_listeners(listeners)
        listeners.each do |listener|
          listener.fetch(:server).close rescue nil
        end
        listeners.each do |listener|
          thread = listener[:thread]
          thread.join(REQUEST_TIMEOUT + 1) if thread && thread != Thread.current
        end
      end
    end

    # A watch subscription owns its reconnect thread and stream.  The proxy
    # must not leave a blocked enumerator behind when it is stopped, and every
    # reconnect is preceded by an authoritative list/snapshot resync.
    class WatchSubscription
      DEFAULT_BACKOFF = 0.005
      MAX_BACKOFF = 30.0
      CallbackError = Class.new(StandardError)

      attr_reader :thread

      def initialize(source:, callback:, resync: nil, key_extractor: nil, options: {},
                     min_backoff: DEFAULT_BACKOFF, max_backoff: MAX_BACKOFF, error_handler: nil)
        raise ArgumentError, "watch source is required" unless source
        # Every watch failure is reported here as it happens (kube-proxy logs
        # them); last_error alone leaves a dead subscription invisible.
        @error_handler = error_handler
        raise ArgumentError, "watch callback must respond to call" unless callback.respond_to?(:call)
        raise ArgumentError, "watch resync must respond to call" if resync && !resync.respond_to?(:call)
        raise ArgumentError, "watch key extractor must respond to call" if key_extractor && !key_extractor.respond_to?(:call)

        @source = source
        @callback = callback
        @resync = resync
        @key_extractor = key_extractor
        @options = options.dup
        @min_backoff = positive_float(min_backoff, "min_backoff")
        @max_backoff = Float(max_backoff)
        raise ArgumentError, "max_backoff must be at least min_backoff" if @max_backoff < @min_backoff
        raise ArgumentError, "max_backoff must be finite" unless @max_backoff.finite?
        @mutex = Mutex.new
        @condition = ConditionVariable.new
        @closed = false
        @stream = nil
        @stream_handle = nil
        @thread = nil
        @last_error = nil
        @resource_version = initial_resource_version
        @known_keys = {}
      end

      def start
        @mutex.synchronize do
          return self if @thread&.alive?

          @closed = false
          @thread = Thread.new { run }
        end
        self
      rescue StandardError
        @closed = true
        raise
      end

      def close
        thread, stream, handle = @mutex.synchronize do
          @closed = true
          @condition.broadcast
          [@thread, @stream, @stream_handle]
        end
        closed_stream = close_resource(handle)
        closed_stream ||= close_resource(stream) unless stream.equal?(handle)
        unless closed_stream || @source.equal?(stream) || @source.equal?(handle)
          close_resource(@source)
        end
        thread.join if thread && thread != Thread.current
        self
      end

      alias stop close

      def closed?
        @mutex.synchronize { @closed }
      end

      def running?
        thread = @mutex.synchronize { @thread }
        thread&.alive? == true
      end

      def resource_version
        @mutex.synchronize { @resource_version }
      end

      def last_error
        @mutex.synchronize { @last_error }
      end

      private

      def run
        backoff = @min_backoff
        loop do
          break if closed?

          stream = nil
          fatal = false
          begin
            stream = open_stream
            register_stream(stream)
            consume(stream)
          rescue CallbackError => error
            record_error(error.cause || error)
            fatal = true
          rescue StandardError => error
            record_error(error)
          ensure
            unregister_stream(stream)
            close_resource(stream)
          end
          break if closed? || fatal

          begin
            result = @resync.call(resource_version, known_keys) if @resync
            apply_resync_result(result)
            backoff = @min_backoff
          rescue StandardError => error
            record_error(error)
          end
          break if closed?

          wait(backoff)
          backoff = [backoff * 2.0, @max_backoff].min
        end
      ensure
        @mutex.synchronize do
          @stream = nil
          @stream_handle = nil
        end
      end

      def open_stream
        options = @options.dup
        version = resource_version
        if version
          if options.key?(:resourceVersion)
            options[:resourceVersion] = version
          elsif options.key?("resourceVersion")
            options["resourceVersion"] = version
          else
            options[:resource_version] = version
          end
        end
        stream = @source.watch(**options)
        raise IOError, "watch source returned no stream" if stream.nil?

        stream
      end

      def consume(stream)
        if stream.respond_to?(:each)
          stream.each do |event|
            break if closed?

            process_event(event)
          end
        elsif stream.respond_to?(:on_event)
          handle = stream.on_event { |event| process_event(event) }
          @mutex.synchronize { @stream_handle = handle }
          wait_until_closed
        elsif stream.respond_to?(:next)
          loop do
            break if closed?
            event = stream.next
            break if event.nil?

            process_event(event)
          end
        else
          raise ArgumentError, "watch source must return an Enumerable, next-capable stream, or event subscription"
        end
      end

      def process_event(event)
        normalized_event = normalize_event(event)
        begin
          @callback.call(normalized_event)
        rescue StandardError => error
          # One object the model refuses (a Service port outside 1..65535, a
          # slice without a port) is reported and skipped; kube-proxy keeps
          # consuming the stream.  Ending the watch here left the node with
          # whatever rules it had, forever.
          record_error(CallbackError.new("watch event callback failed: #{error.message}"))
        end
        advance_resource_version(event_resource_version(normalized_event))
        remember_key(@key_extractor.call(normalized_event)) if @key_extractor
      end

      def normalize_event(event)
        return JSON.parse(event, create_additions: false) if event.is_a?(String)

        event
      rescue JSON::ParserError => error
        raise ArgumentError, "watch event is not valid JSON: #{error.message}"
      end

      def wait_until_closed
        @mutex.synchronize do
          @condition.wait(@mutex) until @closed
        end
      end

      def wait(seconds)
        @mutex.synchronize { @condition.wait(@mutex, seconds) unless @closed }
      end

      def register_stream(stream)
        @mutex.synchronize { @stream = stream }
        close_resource(stream) if closed?
      end

      def unregister_stream(stream)
        @mutex.synchronize do
          @stream = nil if @stream.equal?(stream)
          @stream_handle = nil if @stream_handle && @stream_handle.equal?(stream)
        end
      end

      def close_resource(resource)
        return false unless resource&.respond_to?(:close) || resource&.respond_to?(:stop)

        if resource.respond_to?(:close)
          resource.close
        else
          resource.stop
        end
        true
      rescue StandardError => error
        record_error(error)
        true
      end

      def record_error(error)
        @mutex.synchronize { @last_error = error }
        begin
          @error_handler&.call(error)
        rescue StandardError
          nil
        end
      end

      def remember_key(key)
        return if key.nil?

        @mutex.synchronize { @known_keys[key] = true }
      end

      def known_keys
        @mutex.synchronize { @known_keys.keys.dup.freeze }
      end

      def apply_resync_result(result)
        return unless result.is_a?(Hash)

        keys = result[:keys] || result["keys"]
        version = result[:resource_version] || result["resource_version"] || result[:resourceVersion] || result["resourceVersion"]
        @mutex.synchronize { @known_keys = Array(keys).each_with_object({}) { |key, map| map[key] = true } } if keys
        advance_resource_version(version)
      end

      def initial_resource_version
        @options[:resource_version] || @options["resource_version"] || @options[:resourceVersion] || @options["resourceVersion"]
      end

      def event_resource_version(event)
        return nil if event.nil?

        version = if event.respond_to?(:resource_version)
                    event.resource_version
                  elsif event.respond_to?(:resourceVersion)
                    event.resourceVersion
                  elsif event.respond_to?(:revision)
                    event.revision
                  elsif event.is_a?(Hash)
                    ModelSupport.key(event, "resourceVersion", ModelSupport.key(event, "resource_version", nil))
                  end
        return version unless version.nil?

        object = event.respond_to?(:object) ? event.object : ModelSupport.key(event, "object", nil)
        if object.respond_to?(:resource_version)
          object.resource_version
        elsif object.is_a?(Hash)
          metadata = ModelSupport.key(object, "metadata", {}) || {}
          ModelSupport.key(metadata, "resourceVersion", ModelSupport.key(metadata, "resource_version", nil))
        end
      end

      def advance_resource_version(version)
        return if version.nil?

        candidate = version.to_s
        @mutex.synchronize do
          previous = @resource_version
          @resource_version = candidate if previous.nil? || newer_version?(candidate, previous)
        end
      end

      def newer_version?(candidate, previous)
        candidate_number = Integer(candidate)
        previous_number = Integer(previous)
        candidate_number > previous_number
      rescue ArgumentError, TypeError
        candidate != previous.to_s
      end

      def positive_float(value, name)
        number = Float(value)
        raise ArgumentError, "#{name} must be positive and finite" unless number.positive? && number.finite?

        number
      end
    end

    # Service proxy controller.  It watches/accepts Service and EndpointSlice
    # updates, compiles only changed rules, publishes a backend-neutral diff,
    # and routes packets with deterministic conntrack selection.
    class Proxy
      attr_reader :endpoint_store, :compiler, :rule_set, :conntrack,
                  :node_port_allocator, :local_node, :backend, :clock,
                  :last_compilation, :node_zone, :health_check_responder,
                  :connection_probe, :connection_tracker

      # Optional callable told about every watch event the proxy applied:
      # kind, type, key and what the Service compiles to afterwards.  A
      # Service whose ClusterIP answers nothing looks the same whether the
      # event never arrived, the compiler produced no rule or the datapath
      # rejected it; this tells them apart on a live node.
      attr_accessor :trace
      # Proxy::Metrics (kubeproxy_*); nil records nothing.
      attr_reader :metrics

      def metrics=(observer)
        @metrics = observer
      end

      def initialize(local_node: nil, node_name: nil, node: nil, node_addresses: [], node_ips: nil,
                     node_zone: nil, zone: nil,
                     endpoint_store: nil, service_store: nil, compiler: nil,
                     conntrack: nil, node_port_allocator: nil, allocator: nil,
                     backend: :auto, ebpf: nil, nftables: nil, capability_probe: nil,
                     node_status: nil, connection_probe: nil, connection_tracker: nil,
                     clock: -> { Time.now.utc }, attach: false)
        @clock = clock
        @local_node = (local_node || node_name || node)&.to_s
        @node_zone = (node_zone || zone)&.to_s
        address_values = Array(node_addresses)
        address_values = Array(node_ips) if address_values.empty? && node_ips
        @node_addresses = address_values.map { |ip| ModelSupport.canonical_ip(ip) }.compact.freeze
        @endpoint_store = endpoint_store || EndpointStore.new(clock: clock)
        @service_store = service_store
        @compiler = compiler || RuleCompiler.new(local_node: @local_node, node_addresses: @node_addresses,
                                                  node_zone: @node_zone)
        @conntrack = conntrack || ConntrackTable.new(clock: -> { monotonic_now })
        @node_port_allocator = node_port_allocator || allocator || NodePortAllocator.new
        @rule_set = RuleSet.new
        @compiled = {}
        @mutex = Mutex.new
        @publish_mutex = Mutex.new
        @subscriptions = []
        @endpoint_store_subscribed = false
        @service_store_subscribed = false
        @last_compilation = nil
        @connection_measurements = []
        @connection_measurements_mutex = Mutex.new
        @health_check_responder = nil
        @connection_probe = connection_probe
        @connection_tracker = connection_tracker
        @backend = build_backend(backend, ebpf: ebpf, nftables: nftables,
                                  capability_probe: capability_probe, node_status: node_status,
                                  connection_probe: @connection_probe,
                                  connection_tracker: @connection_tracker || @conntrack)
        subscribe_store(@endpoint_store)
        subscribe_store(@service_store) if @service_store && !@service_store.equal?(@endpoint_store)
        attach_backend if attach
      end

      def apply_service(value)
        service = value.is_a?(Service) ? value : Service.new(value)
        previous = @endpoint_store.service(service.key)
        release_previous = previous&.node_port? && !service.node_port?
        service = @node_port_allocator.allocate_for_service(service) if service.node_port?
        # Counted before the store publishes: the sync that follows resets
        # the pending count.
        @metrics&.service_changed
        @endpoint_store.apply_service(service)
        @node_port_allocator.release_service(previous) if release_previous
        compile_service(service) unless @endpoint_store_subscribed
        @health_check_responder&.refresh
        service
      end

      alias upsert_service apply_service
      alias add_service apply_service

      def apply(value)
        case value
        when Service then apply_service(value)
        when EndpointSlice then apply_endpoint_slice(value)
        else
          object = ModelSupport.string_keys(value || {})
          kind = ModelSupport.key(object, "kind", "")
          kind.to_s == "EndpointSlice" ? apply_endpoint_slice(object) : apply_service(object)
        end
      end

      def delete_service(value, namespace: nil)
        key = value.is_a?(Service) ? value.key : normalize_service_key(value, namespace: namespace)
        service = @endpoint_store.service(key)
        @node_port_allocator.release(service_key: key) if service&.node_port?
        @metrics&.service_changed if service
        @endpoint_store.delete_service(key)
        @mutex.synchronize { @compiled.delete(key) }
        schedule_publish
        @health_check_responder&.refresh
        service
      end

      def apply_endpoint_slice(value)
        slice = value.is_a?(EndpointSlice) ? value : EndpointSlice.new(value)
        @metrics&.endpoint_changed(trigger_time: slice_trigger_time(slice))
        @endpoint_store.apply_endpoint_slice(slice)
        service = @endpoint_store.service(slice.key)
        compile_service(service) if service && !@endpoint_store_subscribed
        slice
      end

      # The EndpointSlice's endpoints.kubernetes.io/last-change-trigger-time
      # annotation (what kubeproxy_network_programming_duration_seconds is
      # measured from), nil when absent or unparsable.
      def slice_trigger_time(slice)
        raw = slice.respond_to?(:raw) ? slice.raw : nil
        annotations = raw.is_a?(Hash) ? ((raw["metadata"] || raw[:metadata] || {})["annotations"] || {}) : {}
        value = annotations[Metrics::LAST_CHANGE_TRIGGER_TIME]
        value && Time.iso8601(value.to_s)
      rescue ArgumentError, TypeError
        nil
      end
      private :slice_trigger_time

      alias upsert_endpoint_slice apply_endpoint_slice
      alias add_endpoint_slice apply_endpoint_slice
      alias apply_slice apply_endpoint_slice

      def delete_endpoint_slice(value, namespace: nil, name: nil)
        slice = value.is_a?(EndpointSlice) ? value : nil
        key = slice&.key
        removed = @endpoint_store.delete_endpoint_slice(value, namespace: namespace, name: name)
        @metrics&.endpoint_changed if removed
        key ||= removed&.key
        compile_service(@endpoint_store.service(key)) if key && @endpoint_store.service(key)
        removed
      end

      def service(key, namespace: nil)
        @endpoint_store.service(normalize_service_key(key, namespace: namespace))
      end

      alias find_service service

      def services
        @endpoint_store.services
      end

      def endpoint_slices(service_key = nil, namespace: nil)
        @endpoint_store.endpoint_slices(service_key, namespace: namespace)
      end

      def endpoints(service_key, namespace: nil)
        @endpoint_store.endpoints_for(normalize_service_key(service_key, namespace: namespace))
      end

      def compiled_service(key, namespace: nil)
        normalized = normalize_service_key(key, namespace: namespace)
        @mutex.synchronize { @compiled[normalized] }
      end

      alias compiled compiled_service

      def compile(value, endpoint_slices: nil, endpoints: nil, revision: nil)
        service_object = value.is_a?(Service) ? value : Service.new(value)
        @compiler.compile(service_object,
                          endpoint_slices || @endpoint_store.endpoint_slices(service_object.key),
                          endpoints: endpoints || @endpoint_store.endpoints_for(service_object.key),
                          revision: revision || @endpoint_store.revision,
                          compiled_at: @clock.call)
      end

      def compiled_services
        @mutex.synchronize { @compiled.values.sort_by(&:service_key).freeze }
      end

      def rules
        @rule_set.snapshot
      end

      def rule_diff
        @rule_set.last_diff
      end

      alias last_diff rule_diff

      def sync
        @endpoint_store.services.each { |service| compile_service(service) }
        publish_rules
      end

      # Route a packet to a healthy endpoint.  `service:` is useful for
      # headless Services, which intentionally have no ClusterIP rule.
      def route(value = nil, service: nil, namespace: nil, now: @clock.call,
                source_ip: nil, source_port: nil, destination_ip: nil,
                destination_port: nil, protocol: nil, node_name: nil, zone: nil,
                external: nil, connection_id: nil, **metadata)
        packet = value.is_a?(Packet) ? value : Packet.new(value || {}, source_ip: source_ip,
                                                           source_port: source_port,
                                                           destination_ip: destination_ip,
                                                           destination_port: destination_port,
                                                           protocol: protocol, node_name: node_name,
                                                           zone: zone, external: external,
                                                           connection_id: connection_id,
                                                           metadata: metadata)
        normalized_service = service && (service.is_a?(Service) ? service : self.service(service, namespace: namespace))
        if normalized_service&.external_name?
          return ExternalNameRoute.new(service: normalized_service, packet: packet, external: true,
                                       original_destination: packet.destination_ip,
                                       translated_destination: nil, translated_port: nil,
                                       metadata: {"hostname" => normalized_service.external_name})
        end
        candidates = matching_rules(packet, service: normalized_service)
        if candidates.empty? && normalized_service&.headless?
          headless = headless_rule(normalized_service, packet)
          candidates = headless ? [headless] : []
        end
        return nil if candidates.empty?

        rule = choose_rule(candidates, packet)
        service_object = normalized_service || self.service(rule.service_key)
        return nil unless service_object
        return health_route(service_object, rule, packet, now: now) if rule.health_check
        return nil unless source_allowed?(service_object, rule, packet)

        candidate_endpoints = eligible_endpoints(rule, service_object, packet)
        return nil if candidate_endpoints.empty?
        healthy_endpoints = candidate_endpoints.select(&:healthy?)
        selectable_endpoints = if healthy_endpoints.empty?
                                if service_object.publish_not_ready_addresses
                                  candidate_endpoints
                                else
                                  candidate_endpoints.select { |endpoint| endpoint.eligible?(allow_terminating: true) }
                                end
                              else
                                candidate_endpoints
                              end
        return nil if selectable_endpoints.empty?
        selector = lambda do |all_candidates|
          preferred = healthy_endpoints & all_candidates
          hasher.select(packet_hash_key(packet), preferred.empty? ? all_candidates : preferred)
        end
        connection_key = ConnectionKey.new(packet)
        connection = @conntrack.find_or_select(
          connection_key,
          service_key: service_object.key,
          backends: selectable_endpoints,
          selector: selector,
          session_affinity: service_object.session_affinity,
          source_ip: packet.source_ip,
          timeout_seconds: service_object.session_affinity_timeout_seconds,
          generation: @rule_set.revision,
          now: monotonic_value(now)
        )
        endpoint = connection.backend
        external_flow = external_flow?(packet, rule)
        Route.new(
          service: service_object, rule: rule, packet: packet, target_endpoint: endpoint,
          connection: connection, kind: rule.kind,
          source_preserved: external_flow && service_object.external_traffic_policy == "Local",
          external: external_flow,
          translated_destination: endpoint.address, translated_port: endpoint.port,
          metadata: {"backend" => backend_name, "ruleDigest" => @rule_set.last_diff.digest}
        )
      rescue ValidationError
        raise
      rescue NoRoute
        nil
      end

      alias translate route
      alias forward route
      alias dispatch route
      alias route_packet route

      def route!(value = nil, **options)
        route(value, **options) || raise(NoRoute, "no healthy endpoint matched packet")
      end

      def health_check(service: nil, namespace: nil, node: @local_node, port: nil, now: @clock.call)
        service_object = service.is_a?(Service) ? service : self.service(service, namespace: namespace)
        raise NoRoute, "service is required for health check" unless service_object
        endpoint_set = @endpoint_store.endpoints_for(service_object.key).select { |endpoint| endpoint.local_to?(node) }
        endpoint_set = endpoint_set.select(&:healthy?)
        selected_port = service_object.health_check_node_port || port
        HealthCheckResult.new(service_key: service_object.key, node_name: node,
                              node_port: selected_port, healthy: endpoint_set.any?,
                              status: endpoint_set.any? ? 200 : 503,
                              endpoints: endpoint_set, checked_at: now)
      end

      alias health health_check

      def start_health_check_responder(bind_address: HealthCheckResponder::DEFAULT_BIND_ADDRESS)
        @health_check_responder ||= HealthCheckResponder.new(proxy: self, bind_address: bind_address)
        @health_check_responder.start
      end

      def stop_health_check_responder
        @health_check_responder&.close
        @health_check_responder = nil
        self
      end

      def backend_name
        @backend.respond_to?(:name) ? @backend.name : @backend.backend_name
      end

      def backend_status
        @backend.respond_to?(:status) ? @backend.status : BackendStatus.new(backend: backend_name, state: "ready", reason: "selected", checked_at: @clock.call)
      end

      def backend_rules
        @backend.respond_to?(:rules) ? @backend.rules : rules
      end

      def attach_backend(**options)
        @backend.attach(**options)
      end

      # Detach, counting a failure as a cleanup failure
      # (kubeproxy_sync_proxy_rules_nftables_cleanup_failures_total).
      def detach_backend(**options)
        @backend.detach(**options)
      rescue StandardError
        @metrics&.cleanup_failed
        raise
      end

      def switch_backend(target = nil, reason: "manual switch")
        unless @backend.respond_to?(:switch!)
          raise BackendError, "backend does not support automatic switching"
        end
        measurement = @backend.switch!(target: target, reason: reason)
        @connection_measurements_mutex.synchronize { @connection_measurements << measurement }
        measurement
      end

      def connection_measurements
        @connection_measurements_mutex.synchronize { @connection_measurements.dup.freeze }
      end

      alias failover switch_backend

      def start_watch(service_source: nil, endpoint_slice_source: nil, **options)
        subscriptions = []
        if service_source&.respond_to?(:watch)
          subscriptions << watch_source(service_source, kind: :service, **options)
        end
        if endpoint_slice_source&.respond_to?(:watch)
          subscriptions << watch_source(endpoint_slice_source, kind: :endpoint_slice, **options)
        end
        @subscriptions.concat(subscriptions.compact)
        subscriptions
      end

      def watch(source, kind: :auto, **options)
        selected_kind = if kind == :auto
                          options.delete(:resource).to_s.downcase.include?("endpoint") ? :endpoint_slice : :service
                        else
                          kind.to_sym
                        end
        watch_source(source, kind: selected_kind, **options)
      end

      def stop_watch
        @subscriptions.each { |subscription| subscription.close if subscription.respond_to?(:close) }
        @subscriptions.clear
        self
      end

      def close
        stop_watch
        flush_publish! if @publish_coalescing_seconds
        stop_health_check_responder
      end

      private

      def build_backend(value, ebpf:, nftables:, capability_probe:, node_status:, connection_probe:, connection_tracker:)
        case value
        when nil, :auto, "auto", AutoBackend
          if value.is_a?(AutoBackend)
            value
          else
            AutoBackend.new(ebpf: ebpf || EBPFBackend.new, nftables: nftables || NftablesBackend.new,
                            capability_probe: capability_probe, node_status: node_status,
                            clock: @clock, connection_tracker: connection_tracker,
                            connection_probe: connection_probe)
          end
        when :ebpf, "ebpf", :bpf, "bpf"
          ebpf || EBPFBackend.new
        when :nftables, "nftables", :nft, "nft"
          nftables || NftablesBackend.new
        else
          value.respond_to?(:apply) ? value : raise(ArgumentError, "unsupported proxy backend #{value.inspect}")
        end
      end

      def subscribe_store(store)
        return unless store.respond_to?(:subscribe)

        @endpoint_store_subscribed = true if store.equal?(@endpoint_store)
        @service_store_subscribed = true if store.equal?(@service_store)
        @subscriptions << store.subscribe do |event|
          next if event.kind == :service_deleted || event.kind == :endpoint_slice_deleted
          case event.kind
          when :service
            compile_service(event.object)
          when :endpoint_slice
            service_object = @endpoint_store.service(event.object.key)
            service_object ||= @service_store.service(event.object.key) if @service_store&.respond_to?(:service)
            compile_service(service_object) if service_object
          end
        end
      end

      def compile_service(service)
        return unless service

        compiled = @compiler.compile(service, endpoints: @endpoint_store.endpoints_for(service.key),
                                     revision: @endpoint_store.revision, compiled_at: @clock.call)
        @mutex.synchronize { @compiled[service.key] = compiled }
        schedule_publish
        @last_compilation = compiled
        compiled
      end

      # Publishing after every watch event costs a full datapath update each
      # time -- the eBPF backend regenerates its program on every diff -- so a
      # burst of Service events (150 Services created by one spec) queued the
      # events behind those updates and a Service changed during the burst
      # reached the datapath tens of seconds after the API; "same port and
      # different protocols" gives the switch to UDP-only thirty seconds.
      # With a coalescing interval the compiled state is published once per
      # burst, by a publisher thread; nil (the default, and what the unit
      # tests use) publishes synchronously.
      public

      attr_reader :publish_coalescing_seconds, :last_publish_error

      def publish_coalescing_seconds=(seconds)
        @publish_coalescing_seconds = seconds.nil? ? nil : Float(seconds)
        @coalesce_mutex ||= Mutex.new
      end

      def schedule_publish
        @metrics&.sync_queued
        interval = @publish_coalescing_seconds
        return publish_rules if interval.nil?

        @coalesce_mutex.synchronize do
          @publish_pending = true
          unless @publisher_running
            @publisher_running = true
            @publisher = Thread.new { publisher_loop(interval) }
          end
        end
        nil
      end

      # Publish anything still pending, now.  Tests and shutdown use it.
      def flush_publish!
        pending = @coalesce_mutex&.synchronize { was = @publish_pending; @publish_pending = false; was }
        publish_rules if pending
        @publisher&.join(1) unless Thread.current.equal?(@publisher)
        nil
      end

      def publisher_loop(interval)
        Thread.current.name = "proxy-publisher"
        loop do
          sleep(interval)
          pending = @coalesce_mutex.synchronize do
            was = @publish_pending
            @publish_pending = false
            @publisher_running = false unless was
            was
          end
          break unless pending

          begin
            publish_rules
            @last_publish_error = nil
          rescue StandardError => error
            @last_publish_error = error
            @trace&.call(kind: "publish", type: "ERROR", key: nil, service_key: nil, rules: [], published: 0, error: error.message)
          end
        end
      end

      private

      # Computing a diff and committing it to the datapath has to be one
      # critical section.  The Service and the EndpointSlice watch publish
      # concurrently, and each half is locked on its own, so two threads can
      # interleave: the later diff reaches the backend first, is rejected as
      # stale, and the backend then trails the RuleSet by one revision for
      # good — every later diff starts at a revision it never reached and the
      # datapath freezes.  The rescue stays because a backend can also roll
      # itself back after failing to commit a diff.
      def publish_rules
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        full = false
        failed = false
        @publish_mutex.synchronize do
          all_rules = @mutex.synchronize { @compiled.values.flat_map(&:rules) }
          full = @rule_set.revision.zero?
          diff = @rule_set.apply(all_rules, revision: @endpoint_store.revision)
          begin
            @backend.apply(diff)
          rescue StaleRevisionError
            full = true
            resynchronize_backend(all_rules, @rule_set.revision)
          end
          diff
        end
      rescue StandardError
        failed = true
        raise
      ensure
        record_publish(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
      end

      # How long the datapath publishes took since the last call: count,
      # total and worst seconds.  A proxy whose events queue behind slow
      # publishes programs a Service tens of seconds after the API did, and
      # nothing else on the node says so.
      public

      def publish_stats(reset: false)
        @publish_stats_mutex ||= Mutex.new
        @publish_stats_mutex.synchronize do
          stats = (@publish_stats ||= {count: 0, seconds: 0.0, max: 0.0}).dup
          @publish_stats = {count: 0, seconds: 0.0, max: 0.0} if reset
          stats
        end
      end

      private

      def record_publish(seconds)
        @publish_stats_mutex ||= Mutex.new
        @publish_stats_mutex.synchronize do
          @publish_stats ||= {count: 0, seconds: 0.0, max: 0.0}
          @publish_stats[:count] += 1
          @publish_stats[:seconds] += seconds
          @publish_stats[:max] = seconds if seconds > @publish_stats[:max]
        end
      end

      # Bring a backend that trails the compiled RuleSet back in step by
      # replaying the whole desired rule set as a single diff anchored at the
      # revision the backend actually reached.
      def resynchronize_backend(rules, revision)
        raise unless @backend.respond_to?(:rules) && @backend.respond_to?(:revision)

        backend_revision = Integer(@backend.revision)
        catch_up = RuleSet.new
        catch_up.apply(@backend.rules, revision: backend_revision)
        catch_up.apply(rules, revision: [Integer(revision), backend_revision].max)
        @backend.apply(catch_up.last_diff)
      end

      def matching_rules(packet, service: nil)
        candidates = @rule_set.snapshot.select do |rule|
          next false unless rule.protocol == packet.protocol
          next false if rule.health_check && packet.destination_port != rule.node_port
          next false unless rule.health_check || packet.destination_port == rule.port || packet.destination_port == rule.node_port
          next false if service && rule.service_key != service.key
          if rule.virtual_ip
            rule.virtual_ip == packet.destination_ip
          else
            node_port_destination?(packet)
          end
        end
        candidates
      end

      def choose_rule(candidates, packet)
        candidates.sort_by do |rule|
          [rule.health_check ? 0 : 1, rule.virtual_ip ? 0 : 1, rule.node_port == packet.destination_port ? 0 : 1, rule.key]
        end.first
      end

      def node_port_destination?(packet)
        return true if @node_addresses.empty?
        return true if packet.destination_ip.nil?

        @node_addresses.include?(packet.destination_ip)
      end

      def eligible_endpoints(rule, service, packet)
        endpoints = rule.backends.select { |endpoint| endpoint.protocol == packet.protocol }
        if packet.destination_ip
          family = ModelSupport.ip_family(packet.destination_ip)
          endpoints = endpoints.select { |endpoint| endpoint.family == family } if family && rule.kind != "HealthCheckNodePort"
        end
        external = external_flow?(packet, rule)
        policy = external ? service.external_traffic_policy : service.internal_traffic_policy
        if policy == "Local"
          endpoints = endpoints.select { |endpoint| endpoint.local_to?(@local_node || packet.node_name) }
        end
        endpoints = if service.publish_not_ready_addresses
                      non_terminating = endpoints.reject(&:terminating?)
                      non_terminating.empty? ? endpoints.select { |endpoint| endpoint.terminating? && endpoint.serving? } : non_terminating
                    else
                      endpoints.select { |endpoint| endpoint.healthy? || (endpoint.terminating? && endpoint.serving?) }
                    end
        if service.topology_aware_hints && packet.zone && policy != "Local"
          hinted = endpoints.select { |endpoint| endpoint.in_zone?(packet.zone) }
          all_endpoints_hinted = !endpoints.empty? && endpoints.all? { |endpoint| !endpoint.hints.empty? }
          endpoints = hinted if all_endpoints_hinted && !hinted.empty?
        end
        endpoints
      end

      def headless_rule(service, packet)
        service_port = service.port_for(port: packet.destination_port, protocol: packet.protocol)
        return nil unless service_port

        endpoint_set = @endpoint_store.endpoints_for(service.key).select do |endpoint|
          endpoint.port_compatible?(service_port)
        end
        Rule.new(service_key: service.key, service_type: service.service_type, kind: "Headless",
                 virtual_ip: nil, port: service_port.port, protocol: service_port.protocol,
                 backends: endpoint_set, internal_traffic_policy: service.internal_traffic_policy,
                 external_traffic_policy: service.external_traffic_policy,
                 session_affinity: service.session_affinity,
                 session_affinity_timeout_seconds: service.session_affinity_timeout_seconds)
      end

      def external_flow?(packet, rule)
        return packet.external unless packet.external.nil?
        return true if %w[NodePort LoadBalancer ExternalIP].include?(rule.kind)

        false
      end

      def source_allowed?(service, rule, packet)
        return true unless rule.kind == "LoadBalancer" && !service.load_balancer_source_ranges.empty?
        return false if packet.source_ip.to_s.empty?

        source = ModelSupport.parse_ip(packet.source_ip)
        service.load_balancer_source_ranges.any? { |range| IPAddr.new(range).include?(source) }
      rescue IPAddr::InvalidAddressError
        false
      end

      def packet_hash_key(packet)
        [packet.protocol, packet.source_ip, packet.source_port, packet.destination_ip, packet.destination_port].join("|")
      end

      def health_route(service, rule, packet, now:)
        result = health_check(service: service, node: @local_node, port: rule.node_port, now: now)
        Route.new(service: service, rule: rule, packet: packet, kind: "HealthCheckNodePort",
                  source_preserved: true, external: true,
                  metadata: {"health" => result.to_h}, translated_port: result.status)
      end

      def normalize_service_key(value, namespace: nil)
        return value.key if value.is_a?(Service)

        # A DELETED watch event carries the Service object itself; keying it
        # by its Hash#to_s deleted nothing, and the rule lived on until the
        # next 45 s resync noticed the Service was gone.
        if value.is_a?(Hash)
          metadata = ModelSupport.key(ModelSupport.string_keys(value), "metadata", {}) || {}
          name = ModelSupport.key(metadata, "name", "").to_s
          return ModelSupport.service_key(ModelSupport.key(metadata, "namespace", namespace || "default").to_s, name) unless name.empty?
        end

        text = value.to_s
        text.include?("/") ? text : ModelSupport.service_key(namespace || "default", text)
      end

      def watch_source(source, kind:, **options)
        raise ArgumentError, "watch source must implement watch" unless source.respond_to?(:watch)

        watch_options = options.dup
        min_backoff = watch_options.delete(:min_backoff) || watch_options.delete("min_backoff") || WatchSubscription::DEFAULT_BACKOFF
        max_backoff = watch_options.delete(:max_backoff) || watch_options.delete("max_backoff") || WatchSubscription::MAX_BACKOFF
        error_handler = watch_options.delete(:error_handler) || watch_options.delete("error_handler")
        callback = lambda do |event|
          object = if event.respond_to?(:object)
                     event.object
                   elsif event.is_a?(Hash)
                     ModelSupport.key(event, "object", event)
                   else
                     event
                   end
          type = event.respond_to?(:type) ? event.type.to_s : ModelSupport.key(event || {}, "type", "MODIFIED").to_s
          # A BOOKMARK carries no object, only the resourceVersion a restart
          # should resume from (which the subscription records whatever this
          # callback does).  Feeding it to apply_service/apply_endpoint_slice
          # produced "service name is required" 183 times per proxy in one
          # conformance round -- noise that hid real validation failures.
          next if type == "BOOKMARK"

          begin
            if kind == :service
              type == "DELETED" ? delete_service(object) : apply_service(object)
            else
              type == "DELETED" ? delete_endpoint_slice(object) : apply_endpoint_slice(object)
            end
            trace_event(kind, type, object) if @trace
          rescue ValidationError => error
            # ONE unusable object must not stop the proxy from programming
            # every other one.  kube-proxy skips a Service whose ports it
            # cannot use and carries on (pkg/proxy/service.go newServiceInfo
            # returns nil for it); ours let the exception out of the watch
            # callback, so the watch restarted on the same object for ever and
            # every Service created afterwards was never programmed at all --
            # its ClusterIP answered nothing.
            error_handler&.call(error)
          end
        end
        subscription = WatchSubscription.new(
          source: source,
          callback: callback,
          key_extractor: ->(event) { watch_key_for(event, kind) },
          resync: ->(resource_version, known_keys) {
            resync_watch_source(source, kind: kind, resource_version: resource_version, known_keys: known_keys)
          },
          options: watch_options,
          min_backoff: min_backoff,
          max_backoff: max_backoff,
          error_handler: error_handler
        )
        subscription.start
      end

      def trace_event(kind, type, object)
        key = watch_key_for({"object" => object}, kind)
        service_key = if kind == :service
                        key
                      else
                        labels = ModelSupport.key(ModelSupport.key(ModelSupport.string_keys(object || {}), "metadata", {}), "labels", {}) || {}
                        owner = ModelSupport.key(labels, "kubernetes.io/service-name", "").to_s
                        owner.empty? ? nil : "#{key.to_s.split("/").first}/#{owner}"
                      end
        compiled = service_key && @mutex.synchronize { @compiled[service_key] }
        rules = compiled ? compiled.rules.map { |rule| "#{rule.protocol}/#{rule.port}->#{rule.backends.length}" } : []
        @trace.call(kind: kind.to_s, type: type, key: key, service_key: service_key,
                    rules: rules, published: @rule_set.snapshot.count { |rule| rule.service_key == service_key })
      rescue StandardError
        nil
      end

      def resync_watch_source(source, kind:, resource_version:, known_keys:)
        snapshot = watch_snapshot(source, resource_version)
        return {keys: known_keys, resource_version: resource_version} unless snapshot

        objects, snapshot_version = normalize_watch_snapshot(snapshot, kind)
        current_keys = objects.each_with_object({}) do |object, keys|
          key = watch_object_key(object, kind)
          keys[key] = true unless key.nil?
        end
        Array(known_keys).each do |key|
          delete_watch_key(key, kind) unless current_keys.key?(key)
        end
        objects.each do |object|
          # Same reason the incremental callback tolerates ValidationError: a
          # resync that aborts on one unusable object leaves every object
          # after it in the list unprogrammed.
          kind == :service ? apply_service(object) : apply_endpoint_slice(object)
        rescue ValidationError
          next
        end
        {keys: current_keys.keys, resource_version: snapshot_version || resource_version}
      end

      def watch_snapshot(source, resource_version)
        return source.snapshot if source.respond_to?(:snapshot)
        return invoke_watch_list(source, resource_version) if source.respond_to?(:list)

        nil
      end

      # A resync must see the CURRENT state, never the state as of the watch's
      # last resourceVersion: listed at that old version, the snapshot omitted
      # every Service created since, and the resync pruned them all -- the
      # three proxies dropped from 54 known Services to 1 in the same minute
      # (their quiet watches had hit the 60 s client read timeout together),
      # and existing ClusterIPs went dark until each Service changed again.
      def invoke_watch_list(source, _resource_version)
        options = {}
        method = source.method(:list)
        parameters = method.parameters
        if parameters.any? { |kind, _| kind == :keyrest }
          method.call(**options)
        elsif parameters.any? { |kind, _| %i[key keyreq].include?(kind) }
          accepted = parameters.filter_map { |parameter_kind, name| name if %i[key keyreq].include?(parameter_kind) }
          method.call(**options.select { |key, _| accepted.include?(key) })
        elsif method.arity.zero?
          method.call
        else
          method.call
        end
      end

      def normalize_watch_snapshot(snapshot, kind)
        if snapshot.is_a?(Hash)
          object_key = kind == :service ? "services" : "endpoint_slices"
          objects = ModelSupport.key(snapshot, object_key, nil)
          objects ||= ModelSupport.key(snapshot, kind == :service ? "service" : "endpointSlices", nil)
          objects ||= ModelSupport.key(snapshot, "items", nil)
          version = ModelSupport.key(snapshot, "resourceVersion", ModelSupport.key(snapshot, "resource_version", nil))
          metadata = ModelSupport.key(snapshot, "metadata", {}) || {}
          version ||= ModelSupport.key(metadata, "resourceVersion", ModelSupport.key(metadata, "resource_version", nil))
          version ||= ModelSupport.key(snapshot, "revision", nil)
          return [Array(objects), version]
        end
        if kind == :service && snapshot.respond_to?(:services)
          return [Array(snapshot.services), snapshot.respond_to?(:revision) ? snapshot.revision : nil]
        end
        if kind == :endpoint_slice && snapshot.respond_to?(:endpoint_slices)
          return [Array(snapshot.endpoint_slices), snapshot.respond_to?(:revision) ? snapshot.revision : nil]
        end
        if snapshot.respond_to?(:items)
          version = snapshot.respond_to?(:resource_version) ? snapshot.resource_version : nil
          return [Array(snapshot.items), version]
        end

        [Array(snapshot), nil]
      end

      def watch_key_for(event, kind)
        watch_object_key(watch_event_object(event), kind)
      end

      # nil for an object the proxy cannot use (an EndpointSlice without the
      # kubernetes.io/service-name label, as the mirroring and endpointslice
      # specs create by hand).  Raising here escaped both the resync and the
      # per-event key bookkeeping: every resync aborted while such a slice
      # existed, the watch failed, backed off (up to 30 s) and reconnected,
      # and a Service created in that gap was programmed only afterwards --
      # too late for a spec that gives the ClusterIP 30 s to answer.
      def watch_object_key(object, kind)
        if kind == :service
          (object.is_a?(Service) ? object : Service.new(object)).key
        else
          slice = object.is_a?(EndpointSlice) ? object : EndpointSlice.new(object)
          [slice.key, slice.name].freeze
        end
      rescue ValidationError
        nil
      end

      def watch_event_object(event)
        return event.object if event.respond_to?(:object)
        return ModelSupport.key(event, "object", event) if event.is_a?(Hash)

        event
      end

      def delete_watch_key(key, kind)
        if kind == :service
          delete_service(key)
          return
        end

        service_key, name = Array(key)
        namespace, service_name = service_key.to_s.split("/", 2)
        return if namespace.to_s.empty? || service_name.to_s.empty? || name.to_s.empty?

        # Braces matter: without them Ruby 3 took this Hash for keyword
        # arguments of delete_endpoint_slice(value, namespace:, name:) and
        # raised "wrong number of arguments (given 0, expected 1)" -- so a
        # watch resync never removed the slices that had gone while the watch
        # was down, and the error repeated on every resync.
        delete_endpoint_slice({
          "metadata" => {
            "name" => name,
            "namespace" => namespace,
            "labels" => {"kubernetes.io/service-name" => service_name}
          }
        })
      end

      def monotonic_now
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      def monotonic_value(value)
        value.is_a?(Numeric) ? value : monotonic_now
      end

      def hasher
        @hasher ||= DeterministicHash.new
      end
    end

    ServiceProxy = Proxy
    ProxyEngine = Proxy
  end
end
