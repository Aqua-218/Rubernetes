# frozen_string_literal: true

require "timeout"
require "uri"
require "time"

require_relative "status"
require_relative "../observability/metrics"

module Rubernetes
  module Node
    # Executes startup, liveness, and readiness probes without owning a
    # network stack.  Runtime, HTTP, and TCP operations are injected so a
    # probe cannot accidentally escape the node-agent test boundary.
    class ProbeManager
      PROBE_TYPES = %w[startup liveness readiness].freeze
      ACTIONS = %w[exec httpGet tcpSocket grpc].freeze
      DEFAULT_FAILURE_THRESHOLD = 3
      DEFAULT_SUCCESS_THRESHOLD = 1
      DEFAULT_PERIOD_SECONDS = 10
      DEFAULT_TIMEOUT_SECONDS = 1

      Result = Data.define(
        :container_id, :type, :success, :state, :failure_count, :success_count,
        :action, :message, :observed_at, :deferred
      ) do
        def success?
          success == true
        end

        def failed?
          success == false
        end

        def to_h
          {
            "containerID" => container_id,
            "type" => type,
            "success" => success,
            "state" => state,
            "failureCount" => failure_count,
            "successCount" => success_count,
            "action" => action,
            "message" => message,
            "observedAt" => observed_at,
            "deferred" => deferred
          }
        end
      end

      def initialize(runtime: nil, http_client: nil, tcp_client: nil, grpc_client: nil,
                     clock: -> { Time.now.utc }, sleeper: ->(seconds) { sleep(seconds) })
        @runtime = runtime
        @http_client = http_client
        @tcp_client = tcp_client
        @grpc_client = grpc_client
        @clock = clock
        @sleeper = sleeper
        @mutex = Mutex.new
        @states = {}
        @registered_at = {}
        # Each container's serialized probe state, rebuilt only after that
        # container's state changed; see #snapshot.
        @snapshot_cache = {}
        @metrics = nil
      end

      PROBE_TYPE_NAMES = {"liveness" => "Liveness", "readiness" => "Readiness", "startup" => "Startup"}.freeze
      # prometheus.DefBuckets, component-base's default.
      DURATION_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10].freeze

      # /metrics/probes (prober_manager.go ProberResults / ProberDuration).
      def metrics
        @mutex.synchronize do
          @metrics ||= Observability::Metrics.new(apiserver: false).tap do |registry|
            registry.register("prober_probe_total", type: :counter,
                                                    help: "Cumulative number of a liveness, readiness or startup probe for a container by result.")
            registry.register("prober_probe_duration_seconds", type: :histogram, help: "Duration in seconds for a probe response.",
                                                               buckets: DURATION_BUCKETS)
          end
        end
      end

      attr_reader :runtime, :http_client, :tcp_client

      def register(container_id, probes: {}, started_at: nil)
        identifier = normalize_id(container_id)
        timestamp = time_value(started_at)
        normalized = Helpers.string_keys(probes || {})
        @mutex.synchronize do
          @registered_at[identifier] = timestamp
          @snapshot_cache.delete(identifier)
          @states[identifier] = {}
          PROBE_TYPES.each do |type|
            definition = normalized["#{type}Probe"] || normalized[type]
            @states.fetch(identifier)[type] = initial_state(definition)
          end
        end
        self
      end

      alias register_container register

      def unregister(container_id)
        identifier = normalize_id(container_id)
        @mutex.synchronize do
          @states.delete(identifier)
          @registered_at.delete(identifier)
          @snapshot_cache.delete(identifier)
        end
      end

      # Run one probe.  `probe` may be a full `{startupProbe: ...}` object or
      # the action body itself.  The explicit type takes precedence.
      def check(container_id, probe_value = nil, probe: nil, type: nil, kind: nil, now: nil, context: {}, **options)
        identifier = normalize_id(container_id)
        probe = probe_value if probe.nil?
        probe_type = normalize_type(type || kind || infer_type(probe, options))
        definition = extract_probe(probe, probe_type, options)
        ensure_registered(identifier, probe_type, definition, now)
        timestamp = time_value(now)
        if definition.nil? || definition.empty?
          return apply_result(identifier, probe_type, true, "Success", "no probe configured", timestamp,
                              action: nil, deferred: false)
        end
        state = @mutex.synchronize { @states.fetch(identifier).fetch(probe_type) }
        delay = state.fetch(:initial_delay_seconds)
        registered_at = @mutex.synchronize { @registered_at.fetch(identifier) }
        if delay.positive? && elapsed_seconds(timestamp, registered_at) < delay
          return apply_result(identifier, probe_type, nil, "InitialDelay", "initial delay has not elapsed", timestamp,
                              action: action_name(definition), deferred: true)
        end

        period = state.fetch(:period_seconds)
        last_checked_at = state.fetch(:last_checked_at)
        if state.fetch(:period_configured, false) && last_checked_at && elapsed_seconds(timestamp, last_checked_at) < period
          return apply_result(identifier, probe_type, nil, "Period", "probe period has not elapsed", timestamp,
                              action: action_name(definition), deferred: true)
        end

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        success, message, action = execute(identifier, definition, context: context)
        record_probe_metrics(probe_type, success, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, context)
        apply_result(identifier, probe_type, success, success ? "Success" : "Failure", message, timestamp,
                     action: action, deferred: false)
      rescue ArgumentError => error
        probe_type = "liveness" unless PROBE_TYPES.include?(probe_type.to_s)
        apply_result(identifier, probe_type, false, "Failure", error.message,
                     time_value(now), action: nil, deferred: false)
      end

      alias run check
      alias probe check
      alias check_probe check

      # Evaluate all configured probes in Kubernetes order.  Startup must
      # become healthy before liveness/readiness are allowed to run.
      def evaluate(container_id, probes_value = nil, probes: nil, context: {}, now: nil)
        identifier = normalize_id(container_id)
        probes = probes_value if probes.nil?
        definitions = Helpers.string_keys(probes || {})
        startup = check(identifier, probe: definitions["startupProbe"], type: "startup",
                                    context: context, now: now)
        return {"startup" => startup, "liveness" => nil, "readiness" => nil} unless startup_ready?(identifier)

        liveness = check(identifier, probe: definitions["livenessProbe"], type: "liveness",
                                     context: context, now: now)
        readiness = check(identifier, probe: definitions["readinessProbe"], type: "readiness",
                                      context: context, now: now)
        {"startup" => startup, "liveness" => liveness, "readiness" => readiness}
      end

      def startup_succeeded?(container_id)
        state_value(container_id, "startup").fetch(:healthy)
      rescue KeyError
        false
      end

      alias startup_ready? startup_succeeded?

      def liveness_failed?(container_id)
        state_value(container_id, "liveness").fetch(:failed)
      rescue KeyError
        false
      end

      def ready?(container_id)
        identifier = normalize_id(container_id)
        startup = state_value(identifier, "startup")
        readiness = state_value(identifier, "readiness")
        startup.fetch(:healthy) && readiness.fetch(:healthy) && !readiness.fetch(:failed)
      rescue KeyError
        false
      end

      def failure_count(container_id, type:)
        state_value(container_id, normalize_type(type)).fetch(:failure_count)
      end

      def result(container_id, type:)
        state_value(container_id, normalize_type(type)).fetch(:last_result)
      end

      def state(container_id)
        identifier = normalize_id(container_id)
        @mutex.synchronize do
          Helpers.deep_copy(@states.fetch(identifier)).freeze
        end
      end

      # Durable state is deliberately limited to counters, thresholds and the
      # last schedule timestamp. Probe actions are re-read from the Pod spec
      # after restart; no runtime handles or executable payloads are trusted
      # from this snapshot.
      # The node agent persists this with its lifecycle state on every
      # change of any Pod.  Converting every container's probe state each time
      # was half of what a 30-Pod start allocated (and grew with the Pods on
      # the node); unchanged containers now reuse their converted state.
      def snapshot
        @mutex.synchronize do
          {
            "states" => @states.to_h do |identifier, probes|
              [identifier, (@snapshot_cache[identifier] ||= serialize_probes(probes))]
            end,
            "registered_at" => @registered_at.transform_keys(&:to_s)
          }
        end
      end

      def serialize_probes(probes)
        probes.transform_values do |state|
          state.each_with_object({}) do |(key, value), result|
            result[key.to_s] = if value.nil?
                                 nil
                               elsif value.is_a?(Time)
                                 value.utc.iso8601(6)
                               elsif value.respond_to?(:to_h)
                                 value.to_h
                               else
                                 value
                               end
          end
        end.freeze
      end
      private :serialize_probes

      def restore(payload)
        value = Helpers.string_keys(payload || {})
        states = Helpers.key(value, "states", {})
        registered = Helpers.key(value, "registered_at", {})
        @mutex.synchronize do
          @states = {}
          @snapshot_cache = {}
          states.each do |container_id, probes|
            @states[container_id.to_s] = {}
            Helpers.string_keys(probes || {}).each do |type, raw_state|
              item = Helpers.string_keys(raw_state || {})
              last_result = item["last_result"]
              last_result = restore_result(last_result, container_id, type) if last_result.is_a?(Hash)
              @states.fetch(container_id.to_s)[type.to_s] = {
                configured: !!item["configured"],
                healthy: !!item.fetch("healthy", false),
                failed: !!item["failed"],
                failure_count: Integer(item.fetch("failure_count", 0)),
                success_count: Integer(item.fetch("success_count", 0)),
                failure_threshold: Integer(item.fetch("failure_threshold", DEFAULT_FAILURE_THRESHOLD)),
                success_threshold: Integer(item.fetch("success_threshold", DEFAULT_SUCCESS_THRESHOLD)),
                initial_delay_seconds: Integer(item.fetch("initial_delay_seconds", 0)),
                period_seconds: Integer(item.fetch("period_seconds", DEFAULT_PERIOD_SECONDS)),
                period_configured: !!item.fetch("period_configured", false),
                timeout_seconds: Integer(item.fetch("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
                last_checked_at: restore_time(item["last_checked_at"]),
                last_result: last_result
              }
            end
          end
          @registered_at = registered.transform_keys(&:to_s).transform_values { |timestamp| restore_time(timestamp) }
        end
        self
      rescue ArgumentError, TypeError => error
        raise ArgumentError, "invalid persisted probe state: #{error.message}"
      end

      private

      def normalize_id(value)
        identifier = value.is_a?(Hash) ? Helpers.key(value, "id", Helpers.key(value, "containerID", nil)) : value
        identifier = identifier.to_s
        raise ArgumentError, "container id must not be empty" if identifier.empty?

        identifier
      end

      def normalize_type(value)
        normalized = value.to_s
        normalized = normalized.downcase
        normalized = "startup" if normalized == "startupprobe"
        normalized = "liveness" if normalized == "livenessprobe"
        normalized = "readiness" if normalized == "readinessprobe"
        raise ArgumentError, "probe type must be startup, liveness, or readiness" unless PROBE_TYPES.include?(normalized)

        normalized
      end

      def infer_type(probe, options)
        return options.keys.find { |key| PROBE_TYPES.include?(key.to_s.downcase) } if options.any?
        return "startup" if probe.to_s.downcase.include?("startup")

        "liveness"
      end

      def extract_probe(probe, type, options)
        value = probe
        if value.is_a?(Hash)
          string = Helpers.string_keys(value)
          value = string["#{type}Probe"] || string[type.to_s] || string
        end
        value = options["#{type}Probe"] || options[type] || value
        value.nil? ? {} : Helpers.string_keys(value)
      end

      def ensure_registered(identifier, type, definition, now)
        return if @mutex.synchronize { @states.key?(identifier) }

        register(identifier, probes: {"#{type}Probe" => definition}, started_at: now)
      end

      def initial_state(definition)
        configured = definition.is_a?(Hash) && !definition.empty?
        {
          configured: configured,
          healthy: !configured,
          failed: false,
          failure_count: 0,
          success_count: 0,
          failure_threshold: integer_value(definition || {}, "failureThreshold", DEFAULT_FAILURE_THRESHOLD),
          success_threshold: integer_value(definition || {}, "successThreshold", DEFAULT_SUCCESS_THRESHOLD),
          initial_delay_seconds: nonnegative_integer(definition || {}, "initialDelaySeconds", 0),
          period_seconds: positive_integer(definition || {}, "periodSeconds", DEFAULT_PERIOD_SECONDS),
          period_configured: definition.is_a?(Hash) && definition.key?("periodSeconds"),
          timeout_seconds: positive_integer(definition || {}, "timeoutSeconds", DEFAULT_TIMEOUT_SECONDS),
          last_checked_at: nil,
          last_result: nil
        }
      end

      def execute(container_id, definition, context:)
        action = action_name(definition)
        case action
        when "exec"
          command = Array(Helpers.key(definition, "exec", Helpers.key(definition, "Exec", {}))).then do |value|
            value.is_a?(Hash) ? Array(Helpers.key(value, "command", [])) : value
          end
          command = Array(Helpers.key(Helpers.key(definition, "exec", Helpers.key(definition, "Exec", {})), "command", command))
          raise ArgumentError, "exec probe command must not be empty" if command.empty?

          result = resolve_exec_result(invoke_exec(container_id, command, timeout_seconds(definition)), timeout_seconds(definition))
          [probe_success?(result, action: "exec"), result_message(result), "exec"]
        when "httpGet"
          action_definition = Helpers.key(definition, "httpGet", Helpers.key(definition, "http_get", definition))
          result = invoke_http(container_id, Helpers.string_keys(action_definition), context, timeout_seconds(definition))
          [probe_success?(result, action: "httpGet"), result_message(result), "httpGet"]
        when "tcpSocket"
          action_definition = Helpers.key(definition, "tcpSocket", Helpers.key(definition, "tcp_socket", definition))
          result = invoke_tcp(container_id, Helpers.string_keys(action_definition), context, timeout_seconds(definition))
          [probe_success?(result, action: "tcpSocket"), result_message(result), "tcpSocket"]
        when "grpc"
          action_definition = Helpers.key(definition, "grpc", definition)
          result = invoke_grpc(container_id, Helpers.string_keys(action_definition), context, timeout_seconds(definition))
          [probe_success?(result, action: "grpc"), result_message(result), "grpc"]
        else
          raise ArgumentError, "probe must define exactly one of exec, httpGet, tcpSocket, or grpc"
        end
      rescue StandardError => error
        [false, "probe execution failed: #{Helpers.failure_message(error)}", action]
      end

      def action_name(definition)
        aliases = {"http_get" => "httpGet", "tcp_socket" => "tcpSocket"}
        normalized = definition.each_with_object({}) do |(name, value), result|
          result[aliases.fetch(name.to_s, name.to_s)] = value
        end
        actions = ACTIONS.select { |name| Helpers.key(normalized, name, nil) }
        return nil if actions.empty?
        raise ArgumentError, "probe must define exactly one of exec, httpGet, tcpSocket, or grpc" if actions.length > 1

        actions.first
      end

      def timeout_seconds(definition)
        integer_value(definition, "timeoutSeconds", DEFAULT_TIMEOUT_SECONDS).clamp(1, 60)
      end

      def integer_value(value, name, default)
        Integer(Helpers.key(value, name, default) || default)
      rescue ArgumentError, TypeError
        default
      end

      def nonnegative_integer(value, name, default)
        integer = integer_value(value, name, default)
        integer.negative? ? default : integer
      end

      def positive_integer(value, name, default)
        integer = integer_value(value, name, default)
        integer.positive? ? integer : default
      end

      # A Native exec returns duplex streams plus a status queue; the probe
      # outcome is the process exit status, never the mere presence of
      # streams.  Streams are drained and closed so the exec cannot leak
      # descriptors into the agent.
      def resolve_exec_result(result, timeout)
        return result unless result.is_a?(Hash) || (result.respond_to?(:to_h) && !result.is_a?(Integer) && !result.is_a?(String))

        value = result.respond_to?(:to_h) ? result.to_h : result
        status = Helpers.key(value, :status, nil)
        return result unless status.respond_to?(:pop)

        stdin = Helpers.key(value, :stdin, nil)
        stdin.close if stdin.respond_to?(:close) && !(stdin.respond_to?(:closed?) && stdin.closed?)
        wait = status.pop(timeout: Float(timeout) + 1.0)
        %i[stdout stderr].each do |name|
          stream = Helpers.key(value, name, nil)
          next unless stream.respond_to?(:read)

          begin
            stream.read_nonblock(64 * 1024, exception: false) if stream.respond_to?(:read_nonblock)
          rescue IOError, SystemCallError
            nil
          end
          stream.close if stream.respond_to?(:close) && !(stream.respond_to?(:closed?) && stream.closed?)
        end
        return {"success" => false, "message" => "exec probe did not report an exit status"} if wait.nil?
        raise wait if wait.is_a?(Exception)

        exit_code = if wait.respond_to?(:exitstatus)
                      wait.exited? ? wait.exitstatus : 128 + wait.termsig.to_i
                    elsif wait.respond_to?(:exit_status)
                      wait.exit_status.nil? ? 128 + wait.term_signal.to_i : Integer(wait.exit_status)
                    else
                      Integer(wait)
                    end
        {"exit_code" => exit_code, "success" => exit_code.zero?, "message" => "exec exited with #{exit_code}"}
      end

      def invoke_exec(container_id, command, timeout)
        raise ArgumentError, "runtime is required for exec probes" unless @runtime

        raise ArgumentError, "runtime does not implement exec" unless @runtime.respond_to?(:exec)

        invoke_with_timeout(timeout) do
          @runtime.exec(container_id, command, tty: false, timeout: timeout)
        rescue ArgumentError => error
          raise unless signature_error?(error)

          @runtime.exec(container_id, command, tty: false)
        end
      end

      def invoke_http(container_id, definition, context, timeout)
        host = Helpers.key(definition, "host", Helpers.key(context, "host", "127.0.0.1"))
        port = resolve_port(Helpers.key(definition, "port", 80), context)
        path = Helpers.key(definition, "path", "/").to_s
        path = "/#{path}" unless path.start_with?("/")
        scheme = Helpers.key(definition, "scheme", "HTTP").to_s.downcase
        headers = Array(Helpers.key(definition, "httpHeaders", [])).each_with_object({}) do |header, result|
          item = Helpers.string_keys(header)
          result[Helpers.key(item, "name", "")] = Helpers.key(item, "value", "")
        end
        # probe/http formatURL: the host and port joined as net.JoinHostPort
        # does, so an IPv6 Pod IP is bracketed (URI() rejects a bare one).
        uri = URI("#{scheme}://#{Helpers.join_host_port(host, port)}#{path}")
        if @http_client.nil? && @runtime.respond_to?(:http_get)
          # The connector runs inside the sandbox and knows nothing about the
          # container's named ports: hand it the resolved number (a named port
          # such as "healthcheck" failed every probe and restarted the container).
          resolved = definition.merge("port" => port)
          return invoke_with_timeout(timeout) do
            @runtime.http_get(container_id, resolved, timeout: timeout, context: context)
          rescue ArgumentError => error
            raise unless signature_error?(error)

            @runtime.http_get(container_id, resolved, timeout: timeout)
          end
        end
        raise ArgumentError, "http_client is required for httpGet probes" unless @http_client

        if @http_client.respond_to?(:get)
          invoke_with_timeout(timeout) do
            @http_client.get(uri, headers: headers, timeout: timeout, container_id: container_id)
          rescue ArgumentError => error
            raise unless signature_error?(error)

            @http_client.get(uri, headers: headers, timeout: timeout)
          end
        elsif @http_client.respond_to?(:request)
          invoke_with_timeout(timeout) do
            @http_client.request(method: "GET", uri: uri, headers: headers, timeout: timeout, container_id: container_id)
          end
        else
          raise ArgumentError, "http_client does not implement get or request"
        end
      end

      def invoke_tcp(container_id, definition, context, timeout)
        host = Helpers.key(definition, "host", Helpers.key(context, "host", "127.0.0.1"))
        port = resolve_port(Helpers.key(definition, "port", nil), context)
        raise ArgumentError, "tcpSocket probe port is required" if port.nil?
        if @tcp_client.nil? && @runtime.respond_to?(:tcp_socket)
          return invoke_with_timeout(timeout) do
            @runtime.tcp_socket(container_id, definition.merge("port" => port), timeout: timeout, context: context)
          rescue ArgumentError => error
            raise unless signature_error?(error)

            @runtime.tcp_socket(container_id, definition.merge("port" => port), timeout: timeout)
          end
        end
        raise ArgumentError, "tcp_client is required for tcpSocket probes" unless @tcp_client

        if @tcp_client.respond_to?(:connect)
          invoke_with_timeout(timeout) do
            @tcp_client.connect(host, port, timeout: timeout, container_id: container_id)
          rescue ArgumentError => error
            raise unless signature_error?(error)

            @tcp_client.connect(host, port, timeout: timeout)
          end
        elsif @tcp_client.respond_to?(:check)
          invoke_with_timeout(timeout) do
            @tcp_client.check(host: host, port: port, timeout: timeout, container_id: container_id)
          end
        else
          raise ArgumentError, "tcp_client does not implement connect or check"
        end
      end

      # gRPC health probe (grpc.health.v1.Health/Check against the Pod IP).
      def invoke_grpc(container_id, definition, context, timeout)
        host = Helpers.key(definition, "host", Helpers.key(context, "host", "127.0.0.1"))
        port = resolve_port(Helpers.key(definition, "port", nil), context)
        raise ArgumentError, "grpc probe port is required" if port.nil?

        service = Helpers.key(definition, "service", "")
        # A runtime that can probe from inside the Pod's namespace is
        # preferred over a client dialing from the agent's own.
        if @runtime.respond_to?(:grpc_check)
          return invoke_with_timeout(timeout) do
            @runtime.grpc_check(container_id, definition.merge("port" => port), timeout: timeout, context: context)
          end
        end
        raise ArgumentError, "grpc_client is required for grpc probes" unless @grpc_client

        invoke_with_timeout(timeout + 1) do
          @grpc_client.check(host, port, service: service, timeout: timeout, container_id: container_id)
        end
      end

      def resolve_port(value, context)
        return value if value.is_a?(Numeric)

        value = value.to_s
        return value.to_i if value.match?(/\A\d+\z/)

        ports = Helpers.key(context, "ports", {})
        if ports.is_a?(Array)
          ports = ports.to_h do |entry|
            [Helpers.key(entry, "name", ""), Helpers.key(entry, "containerPort", nil)]
          end
        end
        resolved = Helpers.key(ports, value, nil)
        raise ArgumentError, "named probe port #{value.inspect} is not defined" if resolved.nil?

        resolved
      end

      def invoke_with_timeout(seconds, &)
        Timeout.timeout(seconds, Timeout::Error, &)
      end

      def signature_error?(error)
        message = error.message.to_s
        message.include?("wrong number") || message.include?("unknown keyword") || message.include?("missing keyword")
      end

      def probe_success?(result, action:)
        return result if [true, false].include?(result)
        return result.to_i.zero? if action == "exec" && result.is_a?(Numeric)

        if result.is_a?(Numeric)
          return result.to_i.between?(200, 399) if action == "httpGet"
          return result.to_i.zero? if action == "tcpSocket"
        end
        return result.status.to_i.between?(200, 399) if result.respond_to?(:status) && !result.is_a?(Hash) && (action == "httpGet")

        Helpers.success_result?(result)
      end

      # worker.doProbe: every executed probe counts by result; a successful
      # (or unknown) one also observes its duration.
      def record_probe_metrics(probe_type, success, seconds, context)
        labels = Helpers.string_keys((context || {})["metric_labels"] || {})
        return if labels.empty?

        base = {"probe_type" => PROBE_TYPE_NAMES.fetch(probe_type.to_s, probe_type.to_s.capitalize),
                "container" => labels["container"].to_s, "pod" => labels["pod"].to_s, "namespace" => labels["namespace"].to_s}
        result = if success == true then "successful"
                 elsif success == false then "failed"
                 else "unknown"
                 end
        metrics.increment("prober_probe_total", base.merge("result" => result, "pod_uid" => labels["pod_uid"].to_s))
        metrics.observe("prober_probe_duration_seconds", seconds, base) unless result == "failed"
      rescue StandardError
        nil
      end

      def apply_result(identifier, type, success, state_name, message, timestamp, action:, deferred:)
        normalized = normalize_type(type)
        @mutex.synchronize do
          @snapshot_cache.delete(identifier)
          @states[identifier] ||= {}
          @states[identifier][normalized] ||= initial_state({})
          state = @states.fetch(identifier).fetch(normalized)
          if deferred
            result = Result.new(
              container_id: identifier, type: normalized, success: nil, state: state_name,
              failure_count: state.fetch(:failure_count), success_count: state.fetch(:success_count),
              action: action, message: message, observed_at: timestamp, deferred: true
            ).freeze
            state[:last_result] = result
            return result
          end
          state[:last_checked_at] = timestamp
          if success
            state[:success_count] += 1
            state[:failure_count] = 0
            threshold = state.fetch(:success_threshold)
            state[:healthy] = true if state[:success_count] >= threshold
            state[:failed] = false
          else
            state[:failure_count] += 1
            state[:success_count] = 0
            threshold = state.fetch(:failure_threshold)
            state[:failed] = true if state[:failure_count] >= threshold
            state[:healthy] = false if state[:failed]
          end
          result = Result.new(
            container_id: identifier, type: normalized, success: success, state: state_name,
            failure_count: state.fetch(:failure_count), success_count: state.fetch(:success_count),
            action: action, message: message, observed_at: timestamp, deferred: false
          ).freeze
          state[:last_result] = result
          result
        end
      end

      def success_threshold(_state, result_definition:)
        integer_value(result_definition || {}, "successThreshold", DEFAULT_SUCCESS_THRESHOLD)
      end

      def failure_threshold(_state, result_definition:)
        integer_value(result_definition || {}, "failureThreshold", DEFAULT_FAILURE_THRESHOLD)
      end

      def state_value(container_id, type)
        identifier = normalize_id(container_id)
        @mutex.synchronize { @states.fetch(identifier).fetch(type) }
      end

      def result_message(result)
        return "probe succeeded" if result == true
        return "probe failed" if result == false || result.nil?
        return result.message.to_s if result.respond_to?(:message) && !result.message.to_s.empty?
        return Helpers.key(result, "message", "probe completed").to_s if result.is_a?(Hash)

        "probe completed"
      end

      def restore_result(value, container_id, type)
        Result.new(
          container_id: String(value["containerID"] || value["container_id"] || container_id),
          type: String(value["type"] || type),
          success: value["success"],
          state: String(value["state"] || "Unknown"),
          failure_count: Integer(value["failureCount"] || value["failure_count"] || 0),
          success_count: Integer(value["successCount"] || value["success_count"] || 0),
          action: value["action"],
          message: String(value["message"] || ""),
          observed_at: restore_time(value["observedAt"] || value["observed_at"]),
          deferred: !!value["deferred"]
        ).freeze
      end

      def restore_time(value)
        return nil if value.nil?
        return nil if value.is_a?(Hash) && value.empty?
        return value if value.is_a?(Numeric) || value.is_a?(Time)

        Time.parse(value.to_s)
      rescue ArgumentError
        value.to_f
      end

      def elapsed_seconds(current, previous)
        current.to_f - previous.to_f
      end

      def time_value(value)
        return value if value.is_a?(Numeric) || value.is_a?(Time)

        sampled = @clock.call
        sampled.respond_to?(:utc) ? sampled.utc : sampled.to_f
      end
    end
  end
end
