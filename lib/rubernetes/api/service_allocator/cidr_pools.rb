# frozen_string_literal: true

module Rubernetes
  module API
    class ServiceAllocator
      private

      # A single catalog snapshot serves a whole allocation or repair pass.
      # The same prefix can belong to several ServiceCIDRs.
      def service_cidr_pools
        objects = servicecidr_resource ? list_items(servicecidr_resource, namespace: :cluster) : []
        fallback = @pool_mutex.synchronize do
          @default_pool_seen ||= objects.any? { |object| object.dig("metadata", "name") == DEFAULT_SERVICE_CIDR_NAME }
          !@default_pool_seen
        end
        families = @service_cidrs.map(&:family).uniq
        pools = fallback ? @service_cidrs.select { |cidr| supported_pool?(cidr, families) }.to_h { |cidr| [cidr, true] } : {}
        objects.each do |object|
          ready = Array(object.dig("status", "conditions")).find { |condition| condition.is_a?(Hash) && condition["type"] == "Ready" }
          usable = object.dig("metadata", "deletionTimestamp").nil? && (ready.nil? || ready["status"] == "True")
          Array(object.dig("spec", "cidrs")).each do |value|
            cidr = IPAddr.new(value)
            next unless supported_pool?(cidr, families)

            pools[cidr] ||= usable
          rescue IPAddr::Error, TypeError
            next # Ignore malformed legacy entries.
          end
        end
        # Keep the configured ranges first so they are preferred when usable.
        (@service_cidrs & pools.keys).concat(pools.keys - @service_cidrs).to_h { |cidr| [cidr, pools.fetch(cidr)] }
      end

      def supported_pool?(cidr, families)
        families.include?(cidr.family) && (!cidr.ipv6? || cidr.prefix >= 64)
      end
    end
  end
end
