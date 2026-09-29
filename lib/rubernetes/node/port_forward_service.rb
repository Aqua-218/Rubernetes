# frozen_string_literal: true

require_relative "service"

module Rubernetes
  module Node
    # Port-forward is a long-lived duplex stream.  PortForwardStream exposes
    # bounded writes, explicit half-close, and per-operation deadlines while
    # leaving socket ownership with the runtime adapter.
    class PortForwardStream < DuplexStream
      attr_reader :timeout

      def initialize(timeout: nil, **options)
        @timeout = timeout
        super(**options, read_timeout: options.fetch(:read_timeout, timeout), write_timeout: options.fetch(:write_timeout, timeout))
      end

      def read(length = nil, timeout: @timeout)
        super(length, timeout: timeout)
      end

      def write(value, timeout: @timeout)
        super(value, timeout: timeout)
      end

      def with_request_id(value)
        self.class.new(
          input: stdin,
          output: stdout,
          error: stderr,
          status: status,
          request_id: value,
          metadata: metadata,
          timeout: timeout,
          clock: instance_variable_get(:@clock),
          resizer: resizer,
          terminator: terminator
        )
      end
    end

    class PortForwardService < Service
      DEFAULT_TIMEOUT = 30.0
      MAX_PORTS = 128

      def port_forward(container_id = nil, ports = nil, timeout: DEFAULT_TIMEOUT, stream: nil,
                       request_id: nil, identity: nil, **options)
        container_id ||= options.delete(:container_id) || options.delete(:id) || options.delete(:container)
        ports ||= options.delete(:ports) || options.delete(:port)
        request = context(
          operation: "portforward",
          container_id: container_id,
          request_id: request_id,
          identity: identity,
          metadata: options
        )
        normalized_ports = normalize_ports(ports)
        timeout = normalize_timeout(timeout, name: "timeout")
        timeout = DEFAULT_TIMEOUT if timeout.nil?
        authorize!(request)

        result = invoke_runtime(
          runtime_method,
          [request.container_id, normalized_ports],
          {
            timeout: timeout,
            stream: stream,
            request_id: request.request_id,
            identity: request.identity
          },
          request_id: request.request_id
        )
        normalize_port_stream(result, request, normalized_ports, timeout)
      end

      alias call port_forward
      alias open port_forward
      alias forward port_forward

      private

      def runtime_method
        return :port_forward if runtime.respond_to?(:port_forward)
        return :forward if runtime.respond_to?(:forward)

        :port_forward
      end

      def normalize_ports(value)
        values = value.is_a?(Array) ? value : [value]
        raise InvalidRequest, "port-forward requires at least one port" if values.empty?
        raise InvalidRequest, "port-forward accepts at most #{MAX_PORTS} ports" if values.length > MAX_PORTS

        normalized = values.map do |port|
          if port.is_a?(Range)
            normalize_port_range(port)
          else
            [normalize_port(port)]
          end
        end.flatten
        raise InvalidRequest, "port-forward port list must not be empty" if normalized.empty?

        normalized.freeze
      end

      def normalize_port_range(range)
        first = normalize_port(range.begin)
        last = normalize_port(range.end)
        last -= 1 if range.exclude_end?
        raise InvalidRequest, "port-forward range must be ascending" if last < first
        raise InvalidRequest, "port-forward range is too large" if last - first + 1 > MAX_PORTS

        (first..last).to_a
      end

      def normalize_port(value)
        integer = if value.is_a?(String) && value.include?(":")
                    remote = value.split(":", 2).last
                    Integer(remote)
                  else
                    Integer(value)
                  end
        raise InvalidRequest, "port-forward ports must be between 1 and 65535" unless integer.between?(1, 65_535)

        integer
      rescue TypeError, ArgumentError => error
        raise InvalidRequest, "port-forward port must be an integer: #{error.message}"
      end

      def normalize_port_stream(value, request, ports, timeout)
        if value.is_a?(PortForwardStream)
          return value.with_request_id(request.request_id) if value.request_id.nil?

          return value
        end

        duplex = normalize_duplex(value, request, tty: false, metadata: {operation: "portforward", ports: ports})
        PortForwardStream.new(
          input: duplex.stdin,
          output: duplex.stdout,
          error: duplex.stderr,
          status: duplex.status,
          request_id: request.request_id,
          metadata: duplex.metadata.merge(ports: ports),
          timeout: timeout,
          clock: clock
        )
      end
    end

    PortforwardService = PortForwardService
    PortForward = PortForwardService
  end
end
