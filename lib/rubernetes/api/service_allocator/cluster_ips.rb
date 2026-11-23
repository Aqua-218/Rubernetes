# frozen_string_literal: true

module Rubernetes
  module API
    class ServiceAllocator
      # Storage may still contain Services from before clusterIPs and
      # ipFamilies existed. Reading one must not allocate or write anything.
      def default_service_on_read(object)
        spec = object["spec"]
        return object unless spec.is_a?(Hash)

        rendered = spec.dup
        if spec["ports"]
          rendered["ports"] = spec["ports"].map do |port|
            port.dup.tap { |copy| Schema::ServiceFields.default_port(copy) }
          end
        end
        Schema::ServiceFields.default_spec(rendered)
        Schema::ServiceFields.default_traffic(rendered)
        rendered["clusterIPs"] = [spec["clusterIP"]] if !spec["clusterIP"].to_s.empty? && Array(spec["clusterIPs"]).empty?
        if rendered["type"] != "ExternalName" && Array(rendered["ipFamilies"]).empty?
          families = stored_ip_families(rendered)
          unless families.empty?
            rendered["ipFamilies"] = families
            rendered["ipFamilyPolicy"] = families.length == 1 ? "SingleStack" : "RequireDualStack"
          end
        end
        object.merge("spec" => rendered)
      end

      private

      def stored_ip_families(spec)
        return Array(spec["clusterIPs"]).map { |ip| family_name(IPAddr.new(ip)) } unless spec["clusterIP"] == "None"

        primary = family_name(@service_cidrs.first)
        return [primary] unless spec.fetch("selector", {}).to_h.empty?

        [primary, primary == "IPv4" ? "IPv6" : "IPv4"]
      end

      def allocate_cluster_ips!(service, dry_run:, allocation:, existing_ips: [])
        return unless needs_cluster_ip?(service)

        spec = service["spec"]
        requested = service_ips(service)
        families, policy = cluster_ip_families(service, requested)
        ready_by_family = service_cidr_pools.select { |_, ready| ready }.keys.group_by { |cidr| family_name(cidr) }
        allocated = families.map.with_index do |family, index|
          configured = @service_cidrs.find { |candidate| family_name(candidate) == family }
          if configured.nil?
            raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ipFamilies[#{index}]: Invalid value: \"#{family}\": not " \
                                      "configured on this cluster",
                                      details: {"kind" => "Service", "name" => name_of(service)})
          end
          pools = ready_by_family.fetch(family, [])
          wanted = requested[index]
          next wanted if wanted && wanted == existing_ips[index]

          if wanted
            allocate_static_ip(wanted, pools, configured, service, allocation, dry_run: dry_run)
          else
            allocate_dynamic_ip(pools, service, allocation, dry_run: dry_run)
          end
        end
        spec["clusterIPs"] = allocated
        spec["clusterIP"] = allocated.first
        spec["ipFamilies"] = families
        spec["ipFamilyPolicy"] = policy
      end

      def cluster_ip_families(service, requested)
        spec = service["spec"]
        families = Array(spec["ipFamilies"]).map(&:to_s)
        policy = spec["ipFamilyPolicy"].to_s
        families = requested.map { |ip| family_name(IPAddr.new(ip)) } if families.empty? && !requested.empty?
        if families.empty?
          families = case policy
                     when "RequireDualStack", "PreferDualStack"
                       @service_cidrs.map { |cidr| family_name(cidr) }.uniq
                     else
                       [family_name(@service_cidrs.first)]
                     end
        end
        # initIPFamilyFields: an absent policy is SingleStack whatever else the
        # spec carries; two families or two cluster IPs under it are rejected.
        policy = "SingleStack" if policy.empty?
        if policy == "SingleStack" && requested.length == 2
          raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ipFamilyPolicy: Invalid value: \"SingleStack\": must be " \
                                    "'RequireDualStack' or 'PreferDualStack' when multiple cluster IPs are specified",
                                    details: {"kind" => "Service", "name" => name_of(service)})
        end
        cluster_families = @service_cidrs.map { |cidr| family_name(cidr) }.uniq
        if policy == "RequireDualStack" && cluster_families.length < 2
          raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ipFamilyPolicy: Invalid value: \"RequireDualStack\": this cluster is " \
                                    "not configured for dual-stack services",
                                    details: {"kind" => "Service", "name" => name_of(service)})
        end
        if policy == "SingleStack" && families.length == 2
          raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ipFamilyPolicy: Invalid value: \"SingleStack\": must be " \
                                    "'RequireDualStack' or 'PreferDualStack' when multiple IP families are specified",
                                    details: {"kind" => "Service", "name" => name_of(service)})
        end
        # initIPFamilyFields: one explicit family under a dual-stack policy on
        # a dual-stack cluster is completed with the other family.
        if policy != "SingleStack" && families.length == 1 && cluster_families.length == 2 && requested.length < 2
          families << (families.first == "IPv4" ? "IPv6" : "IPv4")
        end
        [families, policy]
      end

      def update_cluster_ips!(service, existing, dry_run:, allocation:)
        old_ips = needs_cluster_ip?(existing) ? service_ips(existing) : []
        if needs_cluster_ip?(service)
          spec = service.fetch("spec")
          old_spec = existing.fetch("spec", {})
          spec["ipFamilyPolicy"] ||= old_spec["ipFamilyPolicy"] if old_spec["ipFamilyPolicy"]
          spec["ipFamilies"] ||= old_spec["ipFamilies"] if old_spec["ipFamilies"]
          if spec["ipFamilyPolicy"] == "SingleStack"
            spec["clusterIPs"] = old_ips.take(1) if old_ips.length == 2 && service_ips(service) == old_ips
            spec["ipFamilies"] = Array(spec["ipFamilies"]).take(1) if spec["ipFamilies"] == old_spec["ipFamilies"] && old_ips.length == 2
          end
          requested = service_ips(service)
          validate_retained_ips!(service, old_ips, requested)
          if old_ips.empty? || requested != old_ips || spec.values_at("ipFamilyPolicy", "ipFamilies") != old_spec.values_at("ipFamilyPolicy", "ipFamilies")
            allocate_cluster_ips!(service, dry_run: dry_run, allocation: allocation, existing_ips: old_ips)
          end
        end
        released = old_ips - service_ips(service)
        allocation.release_on_commit = existing.merge("spec" => {"clusterIPs" => released}) unless dry_run || released.empty?
      end

      def validate_retained_ips!(service, old_ips, requested)
        name = name_of(service)
        old_ips.zip(requested).each_with_index do |(old_ip, requested_ip), index|
          next if requested_ip.nil? || requested_ip == old_ip

          raise Status::Invalid.new("Service \"#{name}\" is invalid: spec.clusterIPs[#{index}]: may not change once set",
                                    details: {"kind" => "Service", "name" => name})
        end
        return unless requested.length < old_ips.length && service.dig("spec", "ipFamilyPolicy") != "SingleStack"

        raise Status::Invalid.new("Service \"#{name}\" is invalid: spec.ipFamilyPolicy: must be 'SingleStack' to release the secondary cluster IP",
                                  details: {"kind" => "Service", "name" => name})
      end

      def service_ips(service)
        spec = service["spec"] || {}
        ips = Array(spec["clusterIPs"]).map(&:to_s).reject(&:empty?)
        ips.empty? && !spec["clusterIP"].to_s.empty? ? [spec["clusterIP"].to_s] : ips
      end

      def allocate_static_ip(ip, pools, configured, service, allocation, dry_run:)
        address = begin
          IPAddr.new(ip)
        rescue IPAddr::Error
          raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.clusterIPs: Invalid value: #{ip.inspect}: must be a valid IP",
                                    details: {"kind" => "Service", "name" => name_of(service)})
        end
        cidr = pools.find { |pool| Support::ServiceCIDR.usable_address?(pool, address) }
        reject_ip_out_of_range(ip, pools.first || configured, service) unless cidr
        return ip if dry_run

        if create_reservation(ip, service, allocation)
          count_allocation(:ip, "static", cidr: cidr)
          return ip
        end
        owner = service_reference(service)
        # Another attempt for the same name cannot borrow an uncommitted IP.
        # An existing Service that already holds the reservation can retry.
        return ip if ipaddress_owner(ip) == owner && service_holds_ip?(owner, ip)

        reject_static_ip(ip, service, "provided IP is already allocated")
      rescue Status::Error
        count_allocation(:ip, "static", cidr: cidr || configured, error: true) unless dry_run
        raise
      end

      def reject_ip_out_of_range(ip, cidr, service)
        reject_static_ip(ip, service, "the provided IP (#{ip}) is not in the valid range. The range of valid IPs is #{cidr_label(cidr)}")
      end

      def reject_static_ip(ip, service, reason)
        message = "Invalid value: #{JSON.generate(service_ips(service))}: failed to allocate IP #{ip}: #{reason}"
        cause = {"reason" => "FieldValueInvalid", "message" => message, "field" => "spec.clusterIPs"}
        raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.clusterIPs: #{message}",
                                  details: {"kind" => "Service", "name" => name_of(service)}, causes: [cause])
      end

      def allocate_dynamic_ip(pools, service, allocation, dry_run:)
        return pools.first.to_s if dry_run && !pools.empty?

        pools.each do |cidr|
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          if (ip = allocate_from_pool(cidr, service, allocation))
            @metrics&.observe("kube_apiserver_clusterip_allocator_allocation_duration_seconds",
                              Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, {"cidr" => cidr_label(cidr)})
            count_allocation(:ip, "dynamic", cidr: cidr)
            return ip
          end
          count_allocation(:ip, "dynamic", cidr: cidr, error: true)
        rescue Status::Error
          count_allocation(:ip, "dynamic", cidr: cidr, error: true)
          raise
        end

        raise Status::InternalError, "failed to allocate a serviceIP for Service #{name_of(service).inspect}: range is full"
      end

      def allocate_from_pool(cidr, service, allocation)
        size = 1 << ((cidr.ipv4? ? 32 : 128) - cidr.prefix)
        offset = size <= STATIC_SUBRANGE_MIN ? 0 : [[STATIC_SUBRANGE_MIN, size / 16].max, STATIC_SUBRANGE_MAX].min
        first = cidr.to_i + 1
        last = cidr.to_i + hosts_per_network(cidr)
        allocate_from_range((first + offset)..last, cidr.family, service, allocation) ||
          allocate_from_range(first...(first + offset), cidr.family, service, allocation)
      end

      def allocate_from_range(range, family, service, allocation)
        span = range.size
        return if span.zero?

        start = SecureRandom.random_number(span)
        span.times do |step|
          candidate = IPAddr.new(range.begin + ((start + step) % span), family).to_s
          return candidate if create_reservation(candidate, service, allocation)
        end
        nil
      end

      def create_reservation(ip, service, allocation)
        record = create_ipaddress(ip, service)
        allocation.reservations << record if record.is_a?(Hash)
        record
      end
    end
  end
end
