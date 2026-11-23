# frozen_string_literal: true

require_relative "../service_fields"

module Rubernetes
  module Schema
    module KubernetesValidator
      SERVICE_TYPES = %w[ClusterIP ExternalName LoadBalancer NodePort].freeze
      SERVICE_AFFINITIES = %w[ClientIP None].freeze
      SERVICE_PROTOCOLS = %w[SCTP TCP UDP].freeze
      SERVICE_DISTRIBUTIONS = %w[PreferClose PreferSameZone PreferSameNode].freeze
      SERVICE_PORT_RANGE_ERROR = "must be between 1 and 65535, inclusive"

      module_function

      def external_name_service?(spec) = fetch(spec, "type") == "ExternalName"

      def service_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        ports = fetch(spec, "ports")
        ports = [] unless ports.is_a?(Array)
        headless = headless_service?(spec)
        type = fetch(spec, "type")
        issues = []
        issues << issue(%w[spec ports], :required, "") if ports.empty? && !headless && !external_name_service?(spec)
        if external_name_service?(spec)
          issues.concat(service_external_name_errors(fetch(spec, "externalName")))
        elsif headless && %w[LoadBalancer NodePort].include?(type)
          issues << valued_issue(%w[spec clusterIPs 0], "None", "may not be set to 'None' for #{type} services")
        end

        names = Set.new
        ports.each_with_index do |port, index|
          issues.concat(service_port_errors(port, index, multiple: ports.length > 1, names: names)) if port.is_a?(Hash)
        end
        issues.concat(service_affinity_errors(spec))
        issues.concat(service_enum_errors(%w[spec type], type, SERVICE_TYPES)) unless blank?(type)
        issues.concat(service_duplicate_port_errors(ports))
      end

      def headless_service?(spec)
        cluster_ips = fetch(spec, "clusterIPs")
        return cluster_ips == ["None"] if cluster_ips.is_a?(Array) && !cluster_ips.empty?

        fetch(spec, "clusterIP") == "None"
      end

      def service_external_name_errors(value)
        actual = value.to_s.delete_suffix(".")
        path = %w[spec externalName]
        return [issue(path, :required, "")] if actual.empty?

        dns1123_subdomain_messages(actual.b).map { |message| valued_issue(path, actual, message) }
      end

      def service_port_errors(port, index, multiple:, names:)
        path = ["spec", "ports", index.to_s]
        issues = service_port_name_errors(path + ["name"], fetch(port, "name"), multiple, names)
        number = fetch(port, "port")
        issues.concat(service_port_number_errors(path + ["port"], number))
        protocol = fetch(port, "protocol")
        issues.concat(service_enum_errors(path + ["protocol"], protocol, SERVICE_PROTOCOLS)) unless blank?(protocol)
        target = fetch(port, "targetPort")
        target = number if ServiceFields.default_target?(target)
        target_path = path + ["targetPort"]
        issues.concat(target.is_a?(String) ? invalid_messages(target_path, port_name_messages(target)) : service_port_number_errors(target_path, target))
        app = fetch(port, "appProtocol")
        issues.concat(invalid_messages(path + ["appProtocol"], qualified_name_messages(app, label_key: true))) if app.is_a?(String)
        issues
      end

      def service_port_name_errors(path, name, multiple, names)
        return multiple ? [issue(path, :required, "")] : [] if blank?(name)
        return [] unless name.is_a?(String)

        messages = dns1123_label_messages(name.b)
        messages[-1] = "must not contain dots" if messages.include?(DNS1123_LABEL_MSG) && !dns1123_subdomain_messages(name.b).include?(DNS1123_SUBDOMAIN_MSG)
        issues = invalid_messages(path, messages)
        issues << issue(path, :duplicate, "") unless names.add?(name)
        issues
      end

      def service_port_number_errors(path, number)
        return [] unless number.is_a?(Integer) && !number.between?(1, 65_535)

        [valued_issue(path, number, SERVICE_PORT_RANGE_ERROR)]
      end

      def service_affinity_errors(spec)
        affinity = fetch(spec, "sessionAffinity")
        return [] if blank?(affinity)
        return service_enum_errors(%w[spec sessionAffinity], affinity, SERVICE_AFFINITIES) unless affinity == "ClientIP"

        config = fetch(spec, "sessionAffinityConfig")
        timeout = fetch(fetch(config, "clientIP"), "timeoutSeconds")
        limit = ServiceFields::MAX_AFFINITY_TIMEOUT
        return [] unless timeout.is_a?(Integer) && !timeout.between?(1, limit)

        [valued_issue(%w[spec sessionAffinityConfig clientIP timeoutSeconds], timeout, "must be greater than 0 and less than #{limit}")]
      end

      def service_duplicate_port_errors(ports)
        seen = Set.new
        ports.each_with_index.filter_map do |port, index|
          number = fetch(port, "port")
          next unless number.is_a?(Integer)

          protocol = fetch(port, "protocol")
          protocol = "TCP" if blank?(protocol)
          next if seen.add?([protocol, number])

          key = {"Name" => "", "Protocol" => protocol, "AppProtocol" => nil, "Port" => number, "TargetPort" => 0, "NodePort" => 0}
          ValidationIssue.new(path: ["spec", "ports", index.to_s], code: :duplicate, value: key, message: "", kubernetes_type: "Duplicate value")
        end
      end

      def service_distribution_errors(root)
        distribution = fetch(fetch(root, "spec"), "trafficDistribution")
        service_enum_errors(%w[spec trafficDistribution], distribution, SERVICE_DISTRIBUTIONS)
      end

      def service_enum_errors(path, value, supported)
        return [] unless value.is_a?(String) && !supported.include?(value)

        [issue(path, :unsupported, unsupported_detail(supported))]
      end
    end
  end
end
