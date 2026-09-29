# frozen_string_literal: true

require "ipaddr"

module Rubernetes
  module Schema
    # IsValidIPForLegacyField / IsValidCIDRForLegacyField (apimachinery
    # util/validation/ip.go, v1.36.2) with StrictIPCIDRValidation (Beta, on):
    # a legacy IP or CIDR field still parses "sloppily" (as net.ParseIP did),
    # but a new value may not have leading zeros or be an IPv4-mapped IPv6
    # address, and a CIDR may not have bits set past its prefix length.  A
    # value the old object already held stays valid, so stored objects can
    # still be updated.
    module KubernetesValidator
      module_function

      INVALID_IP = "must be a valid IP address, (e.g. 10.9.8.7 or 2001:db8::ffff)"
      INVALID_CIDR = "must be a valid CIDR value, (e.g. 10.9.8.0/24 or 2001:db8::/64)"
      LB_SOURCE_RANGES = "service.beta.kubernetes.io/load-balancer-source-ranges"
      SLOPPY_IPV4 = /\A(\d+)\.(\d+)\.(\d+)\.(\d+)\z/

      # [IPAddr, leading_zeros?] for a net.ParseIP-acceptable address, else nil.
      def sloppy_ip(value)
        text = value.to_s
        return nil if text.empty? || text.include?("%") || text.include?("/")

        if (match = SLOPPY_IPV4.match(text))
          octets = match.captures
          return nil unless octets.all? { |octet| octet.to_i <= 255 }

          return [IPAddr.new(octets.map(&:to_i).join(".")), octets.any? { |octet| octet.length > 1 && octet.start_with?("0") }]
        end
        return nil unless text.include?(":")

        # An embedded IPv4 tail may itself carry leading zeros.
        head, _, tail = text.rpartition(":")
        leading = false
        if tail.include?(".")
          octets = SLOPPY_IPV4.match(tail)&.captures
          return nil unless octets && octets.all? { |octet| octet.to_i <= 255 }

          leading = octets.any? { |octet| octet.length > 1 && octet.start_with?("0") }
          text = "#{head}:#{octets.map(&:to_i).join(".")}"
        end
        [IPAddr.new(text), leading]
      rescue IPAddr::Error, ArgumentError
        nil
      end

      def legacy_ip_messages(value, valid_old = [])
        text = value.to_s
        return [] if valid_old.include?(text)

        parsed = sloppy_ip(text)
        return [INVALID_IP] unless parsed

        address, leading = parsed
        messages = []
        messages << "must not have leading 0s" if leading
        messages << "must not be an IPv4-mapped IPv6 address" if address.ipv6? && address.ipv4_mapped?
        messages
      end

      def legacy_cidr_messages(value, valid_old = [])
        text = value.to_s
        return [] if valid_old.include?(text)

        address_text, slash, length_text = text.rpartition("/")
        return [INVALID_CIDR] if slash.empty? || !length_text.match?(/\A\d+\z/)

        parsed = sloppy_ip(address_text)
        return [INVALID_CIDR] unless parsed

        address, leading = parsed
        length = length_text.to_i
        maximum = address.ipv4? ? 32 : 128
        return [INVALID_CIDR] if length > maximum

        if leading || (length_text.length > 1 && length_text.start_with?("0"))
          ["must not have leading 0s in IP or prefix length"]
        elsif address.ipv6? && address.ipv4_mapped?
          ["must not have an IPv4-mapped IPv6 address"]
        elsif address.mask(length) != address
          ["must not have bits set beyond the prefix length"]
        else
          []
        end
      end

      def ip_field_issues(path, value, valid_old = [])
        invalid_messages(path, legacy_ip_messages(value, valid_old))
      end

      def cidr_field_issues(path, value, valid_old = [])
        invalid_messages(path, legacy_cidr_messages(value, valid_old))
      end

      def ip_field_errors(root, kind, old)
        case kind
        when "Pod" then pod_ip_field_errors(root, old)
        when "Service" then service_ip_field_errors(root, old)
        when "Node" then node_ip_field_errors(root)
        when "EndpointSlice" then endpoint_slice_ip_field_errors(root)
        when "Ingress" then load_balancer_ip_errors(root, old)
        else
          template = POD_TEMPLATE_PATHS[kind]
          template ? pod_spec_ip_field_errors(dig_path(root, template + ["spec"]), template + ["spec"]) : []
        end
      end

      # dig_path comes from label_keys.rb.

      # validatePodDNSConfig nameservers and validateHostAliases.
      def pod_spec_ip_field_errors(spec, base)
        return [] unless spec.is_a?(Hash)

        issues = []
        nameservers = dig_path(spec, %w[dnsConfig nameservers])
        Array(nameservers).each_with_index do |nameserver, index|
          issues.concat(ip_field_issues(base + ["dnsConfig", "nameservers", index.to_s], nameserver))
        end
        issues
      end

      def pod_ip_field_errors(root, old)
        issues = pod_spec_ip_field_errors(fetch(root, "spec"), ["spec"])
        status = fetch(root, "status")
        # ValidatePodStatusUpdate only: a create's status is reset by
        # PrepareForCreate before ValidatePodCreate runs.
        return issues unless status.is_a?(Hash) && old.is_a?(Hash)

        old_status = old.is_a?(Hash) ? fetch(old, "status") : nil
        %w[podIPs hostIPs].each do |field|
          existing = Array(old_status.is_a?(Hash) ? fetch(old_status, field) : nil).filter_map { |entry| entry.is_a?(Hash) ? fetch(entry, "ip").to_s : nil }
          Array(fetch(status, field)).each_with_index do |entry, index|
            next unless entry.is_a?(Hash)

            issues.concat(ip_field_issues(["status", field, index.to_s, "ip"], fetch(entry, "ip"), existing))
          end
        end
        issues
      end

      def service_ip_field_errors(root, old)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        old_spec = old.is_a?(Hash) ? fetch(old, "spec") : nil
        old_spec = {} unless old_spec.is_a?(Hash)
        issues = []
        existing = Array(fetch(old_spec, "clusterIPs")).map(&:to_s)
        Array(fetch(spec, "clusterIPs")).each_with_index do |ip, index|
          next if ip.to_s.empty? || ip.to_s == "None"

          issues.concat(ip_field_issues(["spec", "clusterIPs", index.to_s], ip, existing))
        end
        existing = Array(fetch(old_spec, "externalIPs")).map(&:to_s)
        Array(fetch(spec, "externalIPs")).each_with_index do |ip, index|
          issues.concat(ip_field_issues(["spec", "externalIPs", index.to_s], ip, existing))
        end
        ranges = fetch(spec, "loadBalancerSourceRanges")
        if ranges.is_a?(Array) && !ranges.empty?
          # Space-padding is a historical allowance from the annotation.
          existing = Array(fetch(old_spec, "loadBalancerSourceRanges")).map { |value| value.to_s.strip }
          ranges.each_with_index do |value, index|
            issues.concat(cidr_field_issues(["spec", "loadBalancerSourceRanges", index.to_s], value.to_s.strip, existing))
          end
        else
          annotations = dig_path(root, %w[metadata annotations])
          value = annotations.is_a?(Hash) ? annotations[LB_SOURCE_RANGES] : nil
          unless value.nil?
            path = ["metadata", "annotations", LB_SOURCE_RANGES]
            unless fetch(spec, "type").to_s == "LoadBalancer"
              issues << issue(path, :forbidden, "may only be used when `type` is 'LoadBalancer'")
            end
            old_annotations = old.is_a?(Hash) ? dig_path(old, %w[metadata annotations]) : nil
            old_value = old_annotations.is_a?(Hash) ? old_annotations[LB_SOURCE_RANGES] : nil
            if old.nil? || old_value != value
              text = value.to_s.strip
              text.split(",").each { |cidr| issues.concat(cidr_field_issues(path, cidr.strip)) } unless text.empty?
            end
          end
        end
        issues.concat(load_balancer_ip_errors(root, old))
        issues
      end

      # status.loadBalancer.ingress[*].ip of a Service or an Ingress.
      # Only on update: PrepareForCreate resets a new object's status.
      def load_balancer_ip_errors(root, old)
        ingress = dig_path(root, %w[status loadBalancer ingress])
        return [] unless ingress.is_a?(Array) && old.is_a?(Hash)

        existing = Array(old.is_a?(Hash) ? dig_path(old, %w[status loadBalancer ingress]) : nil)
                   .filter_map { |entry| entry.is_a?(Hash) ? fetch(entry, "ip").to_s : nil }
        ingress.each_with_index.flat_map do |entry, index|
          next [] unless entry.is_a?(Hash)

          ip = fetch(entry, "ip")
          next [] if ip.to_s.empty?

          ip_field_issues(["status", "loadBalancer", "ingress", index.to_s, "ip"], ip, existing)
        end
      end

      def node_ip_field_errors(root)
        Array(dig_path(root, %w[spec podCIDRs])).each_with_index.flat_map do |cidr, index|
          cidr_field_issues(["spec", "podCIDRs", index.to_s], cidr)
        end
      end

      # validateEndpoints for the IPv4/IPv6 address types.
      def endpoint_slice_ip_field_errors(root)
        type = fetch(root, "addressType").to_s
        return [] unless %w[IPv4 IPv6].include?(type)

        issues = []
        Array(fetch(root, "endpoints")).each_with_index do |endpoint, index|
          next unless endpoint.is_a?(Hash)

          Array(fetch(endpoint, "addresses")).each_with_index do |address, address_index|
            path = ["endpoints", index.to_s, "addresses", address_index.to_s]
            messages = legacy_ip_messages(address)
            if messages.empty?
              parsed, = sloppy_ip(address)
              family_ok = type == "IPv4" ? parsed.ipv4? : parsed.ipv6?
              issues << issue(["endpoints", index.to_s, "addresses"], :invalid, "must be an #{type} address") unless family_ok
            else
              issues.concat(invalid_messages(path, messages))
            end
          end
        end
        issues
      end
    end
  end
end
