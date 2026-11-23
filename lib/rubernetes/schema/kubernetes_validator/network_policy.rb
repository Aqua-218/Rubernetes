# frozen_string_literal: true

module Rubernetes
  module Schema
    module KubernetesValidator
      module_function

      NETWORK_POLICY_PEER_FIELDS = {"ingress" => "from", "egress" => "to"}.freeze
      NETWORK_POLICY_PROTOCOLS = %w[TCP UDP SCTP].freeze
      NETWORK_POLICY_TYPES = %w[Ingress Egress].freeze
      VALID_PORT_RANGE = "must be between 1 and 65535, inclusive"

      # pkg/apis/networking/validation.ValidateNetworkPolicySpec.
      def network_policy_errors(root, operation = :create, old = nil)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        old_spec = fetch(old, "spec") if operation == :update
        path = %w[spec podSelector]
        allow_old_labels = !label_selector_errors(fetch(old_spec, "podSelector"), path).empty?
        issues = label_selector_errors(fetch(spec, "podSelector"), path, allow_invalid_expression_values: allow_old_labels)
        allowed_cidrs = network_policy_cidrs(old_spec)
        NETWORK_POLICY_PEER_FIELDS.each do |direction, peer_field|
          Array(fetch(spec, direction)).each_with_index do |rule, index|
            rule_path = ["spec", direction, index.to_s]
            Array(fetch(rule, "ports")).each_with_index do |port, port_index|
              issues.concat(network_policy_port_errors(port, rule_path + ["ports", port_index.to_s]))
            end
            Array(fetch(rule, peer_field)).each_with_index do |peer, peer_index|
              issues.concat(network_policy_peer_errors(peer, rule_path + [peer_field, peer_index.to_s], allowed_cidrs, allow_old_labels))
            end
          end
        end
        issues.concat(network_policy_type_errors(fetch(spec, "policyTypes")))
      end

      def network_policy_port_errors(port, path)
        return [] unless port.is_a?(Hash)

        issues = []
        protocol = fetch(port, "protocol")
        if protocol.is_a?(String) && !NETWORK_POLICY_PROTOCOLS.include?(protocol)
          issues << issue(path + ["protocol"], :unsupported, unsupported_detail(NETWORK_POLICY_PROTOCOLS))
        end
        first = fetch(port, "port")
        last = fetch(port, "endPort")
        end_path = path + ["endPort"]
        case first
        when Integer
          issues << issue(path + ["port"], :invalid, VALID_PORT_RANGE) unless first.between?(1, 65_535)
          if last.is_a?(Integer)
            issues << valued_issue(end_path, first, "must be greater than or equal to `port`") if last < first
            issues << issue(end_path, :invalid, VALID_PORT_RANGE) unless last.between?(1, 65_535)
          end
        when String
          issues << issue(end_path, :invalid, "may not be specified when `port` is non-numeric") if last.is_a?(Integer)
          issues.concat(invalid_messages(path + ["port"], port_name_messages(first)))
        when nil
          issues << issue(end_path, :invalid, "may not be specified when `port` is not specified") if last.is_a?(Integer)
        end
        issues
      end

      def network_policy_peer_errors(peer, path, allowed_cidrs, allow_invalid_expression_values)
        return [] unless peer.is_a?(Hash)

        issues = []
        selectors = %w[podSelector namespaceSelector].select { |name| fetch(peer, name).is_a?(Hash) }
        selectors.each do |name|
          issues.concat(label_selector_errors(fetch(peer, name), path + [name], allow_invalid_expression_values: allow_invalid_expression_values))
        end
        block = fetch(peer, "ipBlock")
        if block.is_a?(Hash)
          issues.concat(ip_block_errors(block, path + ["ipBlock"], allowed_cidrs))
          issues << issue(path, :forbidden, "may not specify both ipBlock and another peer") unless selectors.empty?
        elsif selectors.empty?
          issues << issue(path, :required, "must specify a peer")
        end
        issues
      end

      def network_policy_type_errors(types)
        return [] unless types.is_a?(Array)

        path = %w[spec policyTypes]
        return [issue(path, :invalid, "may not specify more than two policyTypes")] if types.length > NETWORK_POLICY_TYPES.length

        types.each_with_index.filter_map do |type, index|
          next unless type.is_a?(String) && !NETWORK_POLICY_TYPES.include?(type)

          issue(path + [index.to_s], :unsupported, unsupported_detail(NETWORK_POLICY_TYPES))
        end
      end

      # AllowCIDRsEvenIfInvalid: any CIDR in the old policy remains usable.
      def network_policy_cidrs(spec)
        NETWORK_POLICY_PEER_FIELDS.flat_map do |direction, peer_field|
          Array(fetch(spec, direction)).flat_map do |rule|
            Array(fetch(rule, peer_field)).flat_map do |peer|
              block = fetch(peer, "ipBlock")
              block.is_a?(Hash) ? [fetch(block, "cidr"), *Array(fetch(block, "except"))].map(&:to_s) : []
            end
          end
        end
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
