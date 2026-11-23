# frozen_string_literal: true

require_relative "../schema/probe_timing"
require_relative "../http_probe_headers"

module Rubernetes
  module Manifest
    module Workload
      module ContainerProbes
        FIELDS = {"readiness" => "readinessProbe", "startup" => "startupProbe", "liveness" => "livenessProbe"}.freeze
        TIMING = %i[initial_delay_seconds period_seconds timeout_seconds success_threshold failure_threshold termination_grace_period_seconds].freeze

        def http_probe(kind, port:, path: "/", scheme: :http, headers: {}, **timing)
          scheme = scheme.to_s.upcase
          raise Error, "http_probe scheme must be HTTP or HTTPS" unless %w[HTTP HTTPS].include?(scheme)
          raise Error, "http_probe path must start with /" unless path.is_a?(String) && path.start_with?("/")

          options = {path: path, port: network_probe_port(__method__, port), scheme: scheme}
          raise Error, "http_probe headers must be a hash of header names to strings or arrays of strings" unless headers.is_a?(Hash)

          options[:httpHeaders] = probe_header_entries(headers) unless headers.empty?
          declare_probe(kind, __method__, "httpGet", options, timing)
        end

        def tcp_probe(kind, port:, **timing)
          declare_probe(kind, __method__, "tcpSocket", {port: network_probe_port(__method__, port)}, timing)
        end

        def grpc_probe(kind, port:, service: nil, **timing)
          raise Error, "grpc_probe port must be an integer from 1 to 65535" unless port.is_a?(Integer) && port.between?(1, 65_535)
          raise Error, "grpc_probe service must be a string" unless service.nil? || service.is_a?(String)

          declare_probe(kind, __method__, "grpc", {port: port, service: service}.compact, timing)
        end

        def exec_probe(kind, command:, **timing)
          raise Error, "exec_probe command must be a non-empty array of strings" unless command.is_a?(Array) && !command.empty? && command.all?(String)

          declare_probe(kind, __method__, "exec", {command: command}, timing)
        end

        private

        def probe_header_entries(headers)
          headers.flat_map do |name, value|
            unless (name.is_a?(String) || name.is_a?(Symbol)) && HTTPProbeHeaders::NAME.match?(name.to_s)
              raise Error, "http_probe header names must contain only letters, numbers or hyphens"
            end

            values = value.is_a?(Array) ? value : [value]
            unless !values.empty? && values.all? { |item| HTTPProbeHeaders.valid_value?(item) }
              raise Error, "http_probe header #{name.inspect} needs a string or a nonempty array of HTTP field values"
            end

            values.map { |item| {"name" => name.to_s, "value" => item} }
          end
        end

        def network_probe_port(helper, port)
          port = port.to_s if port.is_a?(Symbol)
          if port.is_a?(String)
            messages = Rubernetes::Schema::KubernetesValidator.port_name_messages(port)
            raise Error, "invalid #{helper} port #{port.inspect}: #{messages.join(", ")}" unless messages.empty?
          elsif !port.is_a?(Integer) || !port.between?(1, 65_535)
            raise Error, "#{helper} port must be a named port or an integer from 1 to 65535"
          end
          port
        end

        def declare_probe(kind, helper, action, options, timing)
          probe = FIELDS.fetch(kind.to_s) { raise Error, "#{helper} expects :readiness, :startup or :liveness" }
          unknown = timing.keys - TIMING
          raise Error, "unknown #{helper} option #{unknown.first.inspect}. Available: #{TIMING.join(", ")}" unless unknown.empty?

          result = field(probe, timing.merge(action => options))
          if (issue = Rubernetes::Schema::ProbeTiming.errors(result, [probe]).first)
            raise Error, "#{issue.path.join(".")} #{issue.message} (got #{issue.value.inspect})"
          end

          # Names can refer to a port declared later in this container's block.
          if options[:port].is_a?(String)
            location = caller(2, 1)
            at_finish { validate_probe_port(probe, action, options.fetch(:port), location) }
          end
          result
        end

        def validate_probe_port(probe, action, name, location)
          return unless @object.dig(probe, action, "port") == name

          ports = Array(@object["ports"]).compact.select { |entry| entry["protocol"].to_s.empty? || entry["protocol"] == "TCP" }
          names = ports.filter_map { |entry| entry["name"] }
          return if names.count(name) == 1

          available = names.empty? ? "(none)" : names.join(", ")
          raise Error, "#{probe} port #{name.inspect} must name one TCP port on container #{@object["name"].inspect}. Available: #{available}", location
        end
      end
    end
  end
end
