# frozen_string_literal: true

module Rubernetes
  module Schema
    # Service, Endpoints, EndpointSlice, Ingress, IngressClass, ServiceCIDR
    # and NetworkPolicy.
    module KubernetesValidator
      module_function

      # validation.go ValidateServiceSpec: every Service needs at least one
      # port except an ExternalName, which is a DNS alias and carries none.
      def external_name_service?(spec)
        fetch(spec, "type").to_s == "ExternalName"
      end

      def service_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        ports = fetch(spec, "ports")
        return [] if external_name_service?(spec) && (ports.nil? || (ports.is_a?(Array) && ports.empty?))
        return [issue(%w[spec ports], :required, "")] unless ports.is_a?(Array) && !ports.empty?

        # validateServicePort (validation.go:6890-6910): with more than one
        # port each needs a NAME and the names must be unique; every port
        # number must be in range and every port needs a protocol.  Only the
        # empty-name case was checked, so a Service could be stored with two
        # ports sharing a name -- which no EndpointSlice can then address.
        issues = []
        seen_names = {}
        multiple = ports.length > 1
        ports.each_with_index do |port, index|
          next unless port.is_a?(Hash)

          path = ["spec", "ports", index.to_s]
          name = fetch(port, "name")
          if name.is_a?(String) && name.empty?
            issues << issue(path + ["name"], :invalid, "name part must be non-empty")
          elsif multiple && blank?(name)
            issues << issue(path + ["name"], :required, "")
          elsif !blank?(name)
            issues << issue(path + ["name"], :duplicate, name.to_s) if seen_names.key?(name.to_s)
            seen_names[name.to_s] = true
          end
          number = fetch(port, "port")
          issues << issue(path + ["port"], :invalid, "must be between 1 and 65535, inclusive") if number.is_a?(Integer) && !number.between?(1, 65_535)
          protocol = fetch(port, "protocol")
          issues << issue(path + ["protocol"], :required, "") if protocol.is_a?(String) && protocol.empty?
        end
        issues
      end

      # validateUpgradeDowngradeClusterIPs (pkg/apis/core/validation): a
      # Service's clusterIP may not change once set, and the primary may not be
      # unset.  Nothing enforced it, so an update could move a live Service to
      # a different address while every client kept using the old one.
      def service_update_errors(root, old, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        old_spec = fetch(old, "spec")
        new_spec = fetch(root, "spec")
        return [] unless old_spec.is_a?(Hash) && new_spec.is_a?(Hash)
        # A Service moving to or from ExternalName legitimately gains or loses
        # its address; that transition is handled by the registry.
        return [] if external_name_service?(old_spec) || external_name_service?(new_spec)

        old_ips = Array(fetch(old_spec, "clusterIPs") || [fetch(old_spec, "clusterIP")].compact)
        new_ips = Array(fetch(new_spec, "clusterIPs") || [fetch(new_spec, "clusterIP")].compact)
        return [] if old_ips.empty?
        # An update that simply omits the field keeps what was allocated.
        return [] if new_ips.empty?

        return [] if new_ips.first.to_s == old_ips.first.to_s

        [issue(%w[spec clusterIPs 0], :invalid, "may not change once set")]
      end

      def endpoints_errors(root, operation = :create)
        return [] unless operation == :create

        subsets = fetch(root, "subsets")
        return [] unless subsets.is_a?(Array)

        subsets.each_with_index.flat_map do |subset, index|
          next [] unless subset.is_a?(Hash)

          issues = []
          addresses = fetch(subset, "addresses")
          not_ready = fetch(subset, "notReadyAddresses")
          if (!addresses.is_a?(Array) || addresses.empty?) &&
             (!not_ready.is_a?(Array) || not_ready.empty?)
            issues << issue(["subsets", index.to_s], :required,
                            "must specify `addresses` or `notReadyAddresses`")
          end
          %w[addresses notReadyAddresses].each do |field|
            entries = fetch(subset, field)
            next unless entries.is_a?(Array)

            entries.each_with_index do |address, address_index|
              next unless address.is_a?(Hash)

              ip = fetch(address, "ip")
              ip_path = ["subsets", index.to_s, field, address_index.to_s, "ip"]
              messages = legacy_ip_messages(ip)
              next if messages.empty?

              if messages == [INVALID_IP]
                # validateEpAddress: IsValidIPForLegacyField, then
                # ValidateEndpointIP's own parse failure.
                issues << issue(ip_path, :invalid, "must be a valid IP address")
                issues << issue(ip_path, :invalid, INVALID_IP)
              else
                issues.concat(invalid_messages(ip_path, messages))
              end
            end
          end
          issues
        end
      end

      def endpoint_slice_errors(root, operation = :create)
        issues = []
        address_type = fetch(root, "addressType")
        if root.key?("addressType") && blank?(address_type)
          issues << issue(%w[addressType], :required, "")
        elsif root.key?("addressType") && !%w[FQDN IPv4 IPv6].include?(address_type.to_s)
          issues << issue(%w[addressType], :unsupported, "supported values: \"FQDN\", \"IPv4\", \"IPv6\"")
        end
        # Endpoint contents are validated on create.  Update validation keeps
        # the old endpoint payload and checks object metadata only.
        return issues unless operation == :create

        endpoints = fetch(root, "endpoints")
        if endpoints.is_a?(Array)
          endpoints.each_with_index do |endpoint, index|
            next unless endpoint.is_a?(Hash)

            addresses = fetch(endpoint, "addresses")
            next if addresses.is_a?(Array) && !addresses.empty?

            issues << issue(["endpoints", index.to_s, "addresses"], :required, "must contain at least 1 address")
          end
        end
        issues
      end

      def service_cidr_errors(root, operation)
        return [] unless operation == :create

        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        cidrs = fetch(spec, "cidrs")
        return [] if cidrs.is_a?(Array) && !cidrs.empty?

        [issue(%w[spec cidrs], :required, "at least one CIDR required")]
      end

      def ingress_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        default_backend = fetch(spec, "defaultBackend")
        rules = fetch(spec, "rules")
        issues = []
        if default_backend.nil? && (!rules.is_a?(Array) || rules.empty?)
          issues << issue(%w[spec], :invalid, "either `defaultBackend` or `rules` must be specified")
        end
        issues.concat(ingress_backend_errors(default_backend, %w[spec defaultBackend])) if default_backend.is_a?(Hash)
        return issues unless rules.is_a?(Array)

        rules.each_with_index do |rule, rule_index|
          next unless rule.is_a?(Hash)

          http = fetch(rule, "http")
          next unless http.is_a?(Hash)

          paths = fetch(http, "paths")
          if !paths.is_a?(Array) || paths.empty?
            issues << issue(["spec", "rules", rule_index.to_s, "http", "paths"], :required, "")
            next
          end
          paths.each_with_index do |path, path_index|
            next unless path.is_a?(Hash)

            path_base = ["spec", "rules", rule_index.to_s, "http", "paths", path_index.to_s]
            path_type = fetch(path, "pathType")
            if blank?(path_type)
              issues << issue(path_base + ["pathType"], :required, "pathType must be specified")
            elsif !%w[Exact ImplementationSpecific Prefix].include?(path_type.to_s)
              issues << issue(path_base + ["pathType"], :unsupported,
                              "supported values: \"Exact\", \"ImplementationSpecific\", \"Prefix\"")
            end
            backend = fetch(path, "backend")
            issues.concat(ingress_backend_errors(backend, path_base + ["backend"]))
          end
        end
        issues
      end

      def ingress_backend_errors(backend, path)
        backend = {} unless backend.is_a?(Hash)
        resource = fetch(backend, "resource")
        service = fetch(backend, "service")
        return [issue(path, :invalid, "cannot set both resource and service backends")] if resource.is_a?(Hash) && service.is_a?(Hash)
        return [issue(path, :invalid, "resource or service backend is required")] unless resource.is_a?(Hash) || service.is_a?(Hash)

        issues = []
        if service.is_a?(Hash)
          name = fetch(service, "name")
          if blank?(name)
            issues << issue(path + %w[service name], :required, "")
          else
            # RelaxedServiceNameValidation: the backend Service name is a
            # DNS label, the same rule as the Service's own name.
            issues.concat(invalid_messages(path + %w[service name], dns1123_label_messages(name)))
          end
          port = fetch(service, "port")
          port = {} unless port.is_a?(Hash)
          port_name = fetch(port, "name")
          port_number = fetch(port, "number")
          has_name = provided?(port_name) && !port_name.to_s.empty?
          has_number = provided?(port_number) && port_number != 0
          if has_name && has_number
            issues << issue(path, :invalid, "cannot set both port name & port number")
          elsif has_name
            issues.concat(invalid_messages(path + %w[service port name], port_name_messages(port_name.to_s)))
          elsif has_number
            unless port_number.is_a?(Integer) && port_number.between?(1, 65_535)
              issues << issue(path + %w[service port number], :invalid, "must be between 1 and 65535, inclusive")
            end
          else
            issues << issue(path, :required, "port name or number is required")
          end
        end
        issues
      end

      def ingress_class_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)
        return [] unless blank?(fetch(spec, "controller"))

        [issue(%w[spec controller], :required, "")]
      end

      def network_policy_errors(root, _operation = :create, old = nil)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        # AllowCIDRsEvenIfInvalid: any CIDR the old policy held stays valid.
        allowed = []
        if old.is_a?(Hash)
          walk(old) do |value, path|
            next unless value.is_a?(Hash) && path.last.to_s == "ipBlock"

            allowed << fetch(value, "cidr").to_s
            allowed.concat(Array(fetch(value, "except")).map(&:to_s))
          end
        end
        issues = []
        walk(root) do |value, path|
          if value.is_a?(Hash) && path.last.to_s == "ipBlock"
            issues.concat(ip_block_errors(value, path, allowed))
          elsif value.is_a?(Array) && path.last.to_s == "to"
            value.each_with_index do |peer, index|
              next unless peer.is_a?(Hash)

              sources = %w[podSelector namespaceSelector ipBlock].count { |name| fetch(peer, name).is_a?(Hash) }
              if sources.zero?
                issues << issue(path + [index.to_s], :required,
                                "must specify a peer")
              end
            end
          end
        end
        issues
      end

      # ValidateIPBlock.
      def ip_block_errors(block, path, allowed)
        cidr = fetch(block, "cidr").to_s
        return [issue(path + ["cidr"], :required, "")] if cidr.empty?

        issues = cidr_field_issues(path + ["cidr"], cidr, allowed)
        network = sloppy_cidr(cidr)
        return issues unless network

        Array(fetch(block, "except")).each_with_index do |except, index|
          except_path = path + ["except", index.to_s]
          issues.concat(cidr_field_issues(except_path, except, allowed))
          inner = sloppy_cidr(except)
          next unless inner

          unless network[0].family == inner[0].family && network[0].include?(inner[0]) && network[1] < inner[1]
            issues << issue(except_path, :invalid, "must be a strict subset of `cidr`")
          end
        end
        issues
      end

      # netutils.ParseCIDRSloppy: [masked network, prefix length] or nil.
      def sloppy_cidr(value)
        address_text, slash, length_text = value.to_s.rpartition("/")
        return nil if slash.empty? || !length_text.match?(/\A\d+\z/)

        address, = sloppy_ip(address_text)
        return nil unless address

        length = length_text.to_i
        return nil if length > (address.ipv4? ? 32 : 128)

        [address.mask(length), length]
      end
    end
  end
end
