# frozen_string_literal: true

module Rubernetes
  module Controller
    module InfrastructureStorageSupport
      MANAGED_ROUTE_CONTROLLER = "rubernetes-node-route-controller"

      protected

      def normalize_time(value)
        parsed = Support.parse_time(value)
        raise ArgumentError, "clock must return Time or RFC3339 value" unless parsed

        parsed
      end

      def list_storage_objects(adapter, descriptor, namespace: :all)
        return [] unless adapter

        adapter.list(descriptor, namespace: namespace)
      end

      def provider_from(explicit = nil)
        explicit || @cloud_provider
      end

      # Select a provider call form from the method signature so an
      # ArgumentError raised by the provider itself is never swallowed.
      def call_provider(provider, names, positional:, keywords: {})
        if provider.nil?
          raise ProviderUnavailableError,
                "cloud provider is not configured for #{name}; configure an injected provider before reconciliation"
        end

        method_name = Array(names).find { |candidate| InfrastructureCapability.implements?(provider, candidate) }
        unless method_name
          raise ProviderUnavailableError,
                "cloud provider for #{name} does not implement any of #{Array(names).join(", ")}"
        end

        callable = provider.method(method_name)
        parameters = callable.parameters
        positional_parameters = parameters.select { |type, _name| %i[req opt rest].include?(type) }
        arguments = positional_parameters.any? { |type, _name| type == :rest } ? positional : positional.first(positional_parameters.length)
        return callable.call(*arguments) unless parameters.any? { |type, _name| %i[key keyreq keyrest].include?(type) }

        callable.call(*arguments, **accepted_keywords(parameters, keywords))
      end

      # The offered keywords the provider method declares (all of them when it
      # takes **options).
      def accepted_keywords(parameters, keywords)
        return keywords if parameters.any? { |type, _name| type == :keyrest }

        accepted_names = parameters.filter_map { |type, parameter_name| parameter_name if %i[key keyreq].include?(type) }
        keywords.select { |key, _value| accepted_names.include?(key.to_sym) }
      end

      def hash_value(value)
        return value if value.is_a?(Hash)
        return value.to_h if InfrastructureCapability.hash_like?(value)

        {}
      end

      def provider_ingress(value)
        return value if value.is_a?(Array)
        return [] if value.nil? || value == false

        hash = hash_value(value)
        candidate = Support.value(hash, "ingress", nil) ||
                    Support.value(Support.value(hash, "status", {}), "ingress", nil) ||
                    Support.value(Support.value(hash, "loadBalancer", {}), "ingress", nil) ||
                    Support.value(Support.value(Support.value(hash, "status", {}), "loadBalancer", {}), "ingress", nil)
        return Array(candidate) unless candidate.nil?

        ip = Support.value(hash, "ip", nil)
        hostname = Support.value(hash, "hostname", nil)
        return [{"ip" => ip.to_s}] unless ip.to_s.empty?
        return [{"hostname" => hostname.to_s}] unless hostname.to_s.empty?

        []
      end

      def canonical_rule(rule)
        Support.canonical(rule)
      end

      def quantity_base(value)
        Support.quantity_to_base(value)
      end

      def descriptor_from(value, api_version:, resource:, scope:)
        ResourceDescriptor.parse({"apiVersion" => api_version, "kind" => value},
                                 resource: resource, scope: scope)
      end

      def upsert_condition(conditions, type, status, reason, message: nil)
        values = Array(conditions).map { |condition| Support.deep_copy(condition) }
        current = values.find { |condition| Support.value(condition, "type", "").to_s == type.to_s }
        if current
          current["status"] = status.to_s
          current["reason"] = reason.to_s
          current["message"] = message.to_s if message
        else
          condition = {"type" => type.to_s, "status" => status.to_s, "reason" => reason.to_s}
          condition["message"] = message.to_s if message
          values << condition
        end
        values
      end

      def remove_conditions(conditions, *types)
        rejected = types.map(&:to_s)
        Array(conditions).filter_map do |condition|
          next if rejected.include?(Support.value(condition, "type", "").to_s)

          Support.deep_copy(condition)
        end
      end

      def workload_pod?(pod)
        return false unless Support.kind(pod) == "Pod"
        return false unless Support.value(Support.spec(pod), "nodeName", nil)
        return false if Support.value(Support.metadata(pod), "deletionTimestamp", nil)

        !%w[Succeeded Failed].include?(Support.value(Support.status(pod), "phase", "").to_s)
      end

      def name_key(object)
        [Support.namespace(object), Support.name(object)].compact.join("/")
      end
    end
  end
end
