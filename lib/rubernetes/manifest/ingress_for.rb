# frozen_string_literal: true

require_relative "../schema/kubernetes_validator/formats"
require_relative "../schema/kubernetes_validator/ip_fields"

module Rubernetes
  module Manifest
    module IngressFor
      PATH_TYPES = {"Prefix" => "Prefix", "prefix" => "Prefix", "Exact" => "Exact", "exact" => "Exact"}.freeze
      INVALID_PATH_PARTS = %w[// /./ /../ %2f %2F].freeze
      Validator = Rubernetes::Schema::KubernetesValidator

      def ingress_for(service, host:, path: "/", port: nil, class_name: nil, path_type: "Prefix")
        unless result.any? { |entry| entry.equal?(service) } && service.values_at("apiVersion", "kind") == %w[v1 Service]
          raise Error, "ingress_for expects a Service declared in this manifest"
        end

        name, namespace = service.fetch("metadata").values_at("name", "namespace")
        messages = Validator.dns1123_label_messages(name)
        raise Error, "invalid Ingress backend Service name #{name.inspect}: #{messages.join(", ")}" unless messages.empty?

        validate_ingress_host(host)
        validate_ingress_path(path)
        type = PATH_TYPES.fetch(path_type.to_s) { raise Error, "ingress_for path_type: must be Prefix or Exact (got #{path_type.inspect})" }
        backend = {service: {name: name, port: ingress_service_port(service, port)}}
        settings = {rules: [{host: host, http: {paths: [{path: path, path_type: type, backend: backend}]}}]}
        settings[:ingress_class_name] = validate_ingress_class_name(class_name) unless class_name.nil?
        resource(api_version: "networking.k8s.io/v1", kind: "Ingress", name: name, namespace: namespace) { spec settings }
      end

      private

      def validate_ingress_host(host)
        raise Error, "ingress_for host: must be a DNS name" unless host.is_a?(String)
        raise Error, "ingress_for host: must be a DNS name, not an IP address" if Validator.sloppy_ip(host)

        messages = Validator.dns1123_subdomain_messages(host.delete_prefix("*."))
        messages << "must be no more than 253 characters" if host.length > 253 && messages.empty?
        raise Error, "invalid ingress_for host #{host.inspect}: #{messages.join(", ")}" unless messages.empty?
      end

      def validate_ingress_path(path)
        raise Error, "ingress_for path: must be an absolute path starting with '/'" unless path.is_a?(String) && path.start_with?("/")

        invalid = INVALID_PATH_PARTS.find { |part| path.include?(part) }
        raise Error, "ingress_for path: must not contain #{invalid.inspect}" if invalid
        raise Error, "ingress_for path: cannot end with '/.' or '/..'" if path.end_with?("/.", "/..")
      end

      def validate_ingress_class_name(name)
        raise Error, "ingress_for class_name: must be an IngressClass name" unless name.is_a?(String) || name.is_a?(Symbol)

        messages = Validator.dns1123_subdomain_messages(name)
        raise Error, "invalid ingress_for class_name #{name.inspect}: #{messages.join(", ")}" unless messages.empty?

        name.to_s
      end

      def ingress_service_port(service, port)
        ports = Array(service.dig("spec", "ports")).grep(Hash)
        tcp = ports.select { |entry| (entry["protocol"] || "TCP") == "TCP" }
        target = "Service/#{service.dig("metadata", "name")}"
        raise Error, "#{target} has no TCP Service ports for ingress_for" if tcp.empty?

        if port.nil? && ports.one?
          entry = tcp.first
          name = entry["name"].to_s
          number = validated_ingress_port_number(entry["port"])
          return {name: name} if Validator.port_name_messages(name).empty?

          return {number: number}
        end

        choices = tcp.map { |entry| entry["name"] ? "#{entry["name"]} (#{entry["port"]})" : entry["port"].to_s }.join(", ")
        raise Error, "#{target} has multiple ports. Set ingress_for port: to a TCP Service port name or number. Available TCP ports are #{choices}" if port.nil?

        field, value = ingress_port_selector(port)
        matches = tcp.select { |entry| entry[field] == value }
        raise Error, "#{target} has no TCP Service port #{port.inspect}. Available TCP ports are #{choices}" if matches.empty?
        raise Error, "#{target} declares TCP Service port #{port.inspect} more than once" unless matches.one?

        validated_ingress_port_number(matches.first["port"])
        field == "port" ? {number: value} : {name: value}
      end

      def ingress_port_selector(port)
        case port
        when Integer
          ["port", validated_ingress_port_number(port)]
        when String, Symbol
          name = port.to_s
          messages = Validator.port_name_messages(name)
          raise Error, "invalid ingress_for port name #{name.inspect}: #{messages.join(", ")}" unless messages.empty?

          ["name", name]
        else
          raise Error, "ingress_for port: must be a Service port name or an integer from 1 to 65535"
        end
      end

      def validated_ingress_port_number(number)
        raise Error, "ingress_for needs a Service port number from 1 to 65535" unless number.is_a?(Integer) && number.between?(1, 65_535)

        number
      end
    end
  end
end
