# frozen_string_literal: true

require_relative "status"

module Rubernetes
  module Node
    # kubelet uses the action's host when specified, otherwise the Pod IP.
    # Named ports belong to the container on which the action was declared.
    module ProbeEndpoint
      module_function

      def host(action, pod_ip)
        explicit = Helpers.key(action, "host", "").to_s
        return explicit unless explicit.empty?

        pod_ip.to_s.empty? ? "127.0.0.1" : pod_ip
      end

      def port(value, ports)
        if value.is_a?(String) && !value.empty?
          named = if ports.is_a?(Array)
                    entry = ports.find { |item| Helpers.key(item, "name", nil) == value }
                    Helpers.key(entry, "containerPort", nil)
                  else
                    Helpers.key(ports, value, nil)
                  end
          value = named || value
        end
        value = Integer(value, 10) if value.is_a?(String) && value.match?(/\A[+-]?\d+\z/)
        return value if value.is_a?(Integer) && value.between?(1, 65_535)

        raise ArgumentError, "named probe port #{value.inspect} is not defined" if value.is_a?(String)

        raise ArgumentError, "invalid probe port #{value.inspect}"
      end
    end
  end
end
