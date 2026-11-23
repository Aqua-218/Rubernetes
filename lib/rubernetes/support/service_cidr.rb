# frozen_string_literal: true

module Rubernetes
  module Support
    module ServiceCIDR
      MANAGED_BY_LABEL = "ipaddress.kubernetes.io/managed-by"
      FAMILY_LABEL = "ipaddress.kubernetes.io/ip-family"
      MANAGER = "ipallocator.k8s.io"
      LEGACY_MANAGER = "ipallocator.kubernetes.io"

      # Mirrors pkg/api/servicecidr.PrefixContainsIP. IPv6 has no broadcast.
      def self.usable_address?(cidr, address)
        cidr.include?(address) && cidr.to_i != address.to_i && !(cidr.ipv4? && cidr.to_range.last == address)
      end
    end
  end
end
