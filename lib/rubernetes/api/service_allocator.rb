# frozen_string_literal: true

require "json"
require "ipaddr"
require "securerandom"

require_relative "status"

module Rubernetes
  module API
    # The Service REST strategy's allocation side (pkg/registry/core/service
    # in kube-apiserver): Go-level Service defaults, ClusterIP allocation from
    # the cluster's ServiceCIDRs backed by IPAddress objects (the
    # MultiCIDRServiceAllocator model, GA in v1.33), and NodePort allocation
    # from the node port range.
    #
    # IPAddress objects are the durable allocation table: creating one is the
    # compare-and-set that makes two API servers agree, and a Service that is
    # deleted releases its addresses by deleting them.  NodePorts are read off
    # the Services themselves under one allocator lock.
    class ServiceAllocator
      DEFAULT_SERVICE_CIDRS = ["10.96.0.0/12"].freeze
      DEFAULT_NODE_PORT_RANGE = (30_000..32_767)
      MANAGED_BY_LABEL = "ipaddress.kubernetes.io/managed-by"
      MANAGED_BY = "ipallocator.kubernetes.io"
      DEFAULT_SERVICE_CIDR_NAME = "kubernetes"
      # KEP-3070: the low part of every ServiceCIDR is reserved for static
      # assignment; dynamic allocation starts after min(max(16, size/16), 256).
      STATIC_SUBRANGE_MIN = 16
      STATIC_SUBRANGE_MAX = 256

      attr_reader :service_cidrs, :node_port_range

      def initialize(store:, registry:, service_cidrs: DEFAULT_SERVICE_CIDRS, node_port_range: DEFAULT_NODE_PORT_RANGE,
                     clock: -> { Time.now.utc }, metadata_preparer: nil)
        @store = store
        @registry = registry
        # The API server's PrepareForCreate metadata (uid, creationTimestamp)
        # for the objects the allocator writes directly to the store.
        @metadata_preparer = metadata_preparer
        @service_cidrs = Array(service_cidrs).map { |cidr| IPAddr.new(String(cidr)) }.freeze
        raise ArgumentError, "at least one service CIDR is required" if @service_cidrs.empty?

        @node_port_range = if node_port_range.is_a?(Range)
                             node_port_range
                           else
                             Range.new(*Array(node_port_range).map do |value|
                               Integer(value)
                             end)
                           end
        @clock = clock
        @mutex = Mutex.new
      end

      # kube_apiserver_clusterip_allocator_* and
      # kube_apiserver_nodeport_allocator_* (ipallocator/portallocator
      # metrics.go): allocations and errors as they happen, the used and free
      # counts read at scrape time.
      def metrics=(registry)
        @metrics = registry
        registry&.add_collector { |metrics| collect_allocation_gauges(metrics) }
      end

      def cidr_label(cidr) = "#{cidr}/#{cidr.prefix}"

      # pkg/registry/core/service/ipallocator/controller + portallocator/
      # controller: the periodic repair sweep.  Every Service's ClusterIPs
      # must be inside a CIDR, unique, and backed by an IPAddress that
      # points at it; every managed IPAddress must have a Service; every
      # nodePort must be in range and unique.  Leaked allocations are
      # released, missing ones recreated, and each finding counts in
      # apiserver_{clusterip,nodeport}_repair_*_errors_total.  Returns the
      # findings; raises nothing (a failed sweep counts a reconcile error).
      REPAIR_INTERVAL_SECONDS = 180

      def repair!
        report = {"ip_errors" => Hash.new(0), "port_errors" => Hash.new(0), "released" => 0, "recreated" => 0}
        repair_cluster_ips!(report)
        repair_node_ports!(report)
        report
      end

      def repair_cluster_ips!(report)
        return if service_resource.nil?

        services = list_items(service_resource, namespace: :all)
        seen = {}
        services.each do |service|
          spec = service["spec"] || {}
          next if spec["type"].to_s == "ExternalName"

          Array(spec["clusterIPs"]).each do |raw|
            next if raw.to_s.empty? || raw == "None"

            ip = begin
              IPAddr.new(raw.to_s)
            rescue IPAddr::Error
              repair_ip_error(report, "invalid")
              next
            end
            cidr = @service_cidrs.find { |candidate| candidate.include?(ip) }
            unless cidr
              repair_ip_error(report, "outside_range")
              next
            end
            if seen.key?(raw.to_s)
              repair_ip_error(report, "duplicate")
              next
            end
            seen[raw.to_s] = service_reference(service)
            owner = ipaddress_owner(raw.to_s)
            if owner.nil?
              # The IPAddress leaked away (or predates it): recreate it.
              repair_ip_error(report, "repair")
              report["recreated"] += 1 if create_ipaddress(raw.to_s, service)
            elsif owner != service_reference(service)
              repair_ip_error(report, "duplicate")
            end
          end
        end
        return if ipaddress_resource.nil?

        list_items(ipaddress_resource, namespace: :cluster).each do |address|
          name = address.dig("metadata", "name").to_s
          next unless (address.dig("metadata", "labels") || {})[MANAGED_BY_LABEL] == MANAGED_BY
          next if seen.key?(name)

          repair_ip_error(report, "leak")
          delete_ipaddress(name)
          report["released"] += 1
        end
      rescue StandardError
        @metrics&.increment("apiserver_clusterip_repair_reconcile_errors_total")
      end

      def repair_node_ports!(report)
        return if service_resource.nil?

        used = {}
        list_items(service_resource, namespace: :all).each do |service|
          spec = service["spec"] || {}
          ports = Array(spec["ports"]).map { |port| port["nodePort"].to_i }.select(&:positive?)
          ports << spec["healthCheckNodePort"].to_i if spec["healthCheckNodePort"].to_i.positive?
          ports.each do |port|
            unless @node_port_range.cover?(port)
              repair_port_error(report, "outside_range")
              next
            end
            if used.key?(port) && used[port] != service_reference(service)
              repair_port_error(report, "duplicate")
              next
            end
            used[port] = service_reference(service)
          end
        end
      rescue StandardError
        @metrics&.increment("apiserver_nodeport_repair_reconcile_errors_total")
      end

      def repair_ip_error(report, type)
        report["ip_errors"][type] += 1
        @metrics&.increment("apiserver_clusterip_repair_ip_errors_total", {"type" => type})
      end

      def repair_port_error(report, type)
        report["port_errors"][type] += 1
        @metrics&.increment("apiserver_nodeport_repair_port_errors_total", {"type" => type})
      end

      def list_items(resource, namespace:)
        result = @store.list(resource: resource, namespace: namespace, selectors: nil)
        result.respond_to?(:items) ? Array(result.items) : Array(result)
      end

      # hostsPerNetwork: the network address is never used, nor an IPv4
      # broadcast address.
      def hosts_per_network(cidr)
        size = 1 << ((cidr.ipv4? ? 32 : 128) - cidr.prefix)
        size -= 1
        size -= 1 if cidr.ipv4? && size.positive?
        size
      end

      def collect_allocation_gauges(metrics)
        addresses = if ipaddress_resource
                      Array(@store.list(resource: ipaddress_resource, namespace: :cluster, selectors: nil).then do |r|
                              r.respond_to?(:items) ? r.items : r
                            end)
                    else
                      []
                    end
        @service_cidrs.each do |cidr|
          used = addresses.count do |address|
            IPAddr.new(address.dig("metadata", "name").to_s).then { |ip| cidr.include?(ip) }
          rescue IPAddr::Error
            false
          end
          size = hosts_per_network(cidr)
          metrics.set("kube_apiserver_clusterip_allocator_allocated_ips", used, {"cidr" => cidr_label(cidr)})
          metrics.set("kube_apiserver_clusterip_allocator_available_ips", [size - used, 0].max, {"cidr" => cidr_label(cidr)})
        end
        ports = used_node_ports(except: {}).uniq.count { |port| @node_port_range.cover?(port) }
        metrics.set("kube_apiserver_nodeport_allocator_allocated_ports", ports)
        metrics.set("kube_apiserver_nodeport_allocator_available_ports", @node_port_range.size - ports)
      rescue StandardError
        nil
      end

      def count_allocation(kind, scope, cidr: nil, error: false)
        return unless @metrics

        name = kind == :ip ? "kube_apiserver_clusterip_allocator_allocation" : "kube_apiserver_nodeport_allocator_allocation"
        labels = {"scope" => scope}
        labels["cidr"] = cidr_label(cidr) if cidr
        @metrics.increment(error ? "#{name}_errors_total" : "#{name}_total", labels)
      rescue StandardError
        nil
      end

      def service_resource
        @service_resource ||= @registry.find_gvr(group: "", version: "v1", resource: "services")
      end

      def ipaddress_resource
        @ipaddress_resource ||= @registry.find_gvr(group: "networking.k8s.io", version: "v1", resource: "ipaddresses")
      end

      def servicecidr_resource
        @servicecidr_resource ||= @registry.find_gvr(group: "networking.k8s.io", version: "v1", resource: "servicecidrs")
      end

      def service?(resource)
        resource.respond_to?(:kind) && resource.kind == "Service" && resource.respond_to?(:group) && resource.group.to_s.empty?
      end

      # The default ServiceCIDR object kube-apiserver publishes for its
      # --service-cluster-ip-range.
      def bootstrap!
        return false if servicecidr_resource.nil?

        object = {
          "apiVersion" => "networking.k8s.io/v1", "kind" => "ServiceCIDR",
          "metadata" => {"name" => DEFAULT_SERVICE_CIDR_NAME},
          "spec" => {"cidrs" => @service_cidrs.map { |cidr| "#{cidr}/#{cidr.prefix}" }},
          "status" => {"conditions" => [{"type" => "Ready", "status" => "True", "reason" => "KubernetesServiceCIDRIsReady",
                                         "message" => "Kubernetes Service CIDR is ready", "lastTransitionTime" => @clock.call.utc.iso8601}]}
        }
        @store.create(resource: servicecidr_resource, namespace: :cluster, object: prepared(object))
        true
      rescue MemoryStore::AlreadyExists
        false
      end

      # PrepareForCreate: Go defaults, then ClusterIP / NodePort allocation.
      def prepare_create(object)
        service = apply_defaults(deep_copy(object))
        allocate_cluster_ips!(service)
        allocate_node_ports!(service, existing: nil)
        service
      end

      # PrepareForUpdate: allocations follow type transitions; ClusterIPs are
      # immutable and validated elsewhere, but a Service upgraded to a type
      # that needs an address or a port receives one here.
      def prepare_update(existing, object)
        service = apply_defaults(deep_copy(object), existing: existing)
        preserve_allocations(service, existing)
        drop_type_dependent_fields(service, existing)
        allocate_cluster_ips!(service) if needs_cluster_ip?(service) && Array(service.dig("spec", "clusterIPs")).empty?
        if !needs_cluster_ip?(service) && needs_cluster_ip?(existing) && headless?(service) == false && external_name?(service)
          release_cluster_ips!(existing)
        end
        allocate_node_ports!(service, existing: existing)
        service
      end

      # Every allocation the Service holds is returned when it goes away.
      def release(object)
        release_cluster_ips!(object)
        true
      end

      private

      # pkg/apis/core/v1/defaults.go SetDefaults_Service and the strategy's
      # dual-stack normalisation.
      def apply_defaults(service, existing: nil)
        spec = (service["spec"] ||= {})
        spec["type"] ||= "ClusterIP"
        spec["sessionAffinity"] ||= "None"
        # SetDefaults_Service drops the config outright for None, so switching a
        # Service back from ClientIP does not leave a stale timeout behind.
        spec.delete("sessionAffinityConfig") if spec["sessionAffinity"] == "None"
        if spec["sessionAffinity"] == "ClientIP"
          spec["sessionAffinityConfig"] ||= {}
          spec["sessionAffinityConfig"]["clientIP"] ||= {}
          spec["sessionAffinityConfig"]["clientIP"]["timeoutSeconds"] ||= 10_800
        end
        Array(spec["ports"]).each do |port|
          port["protocol"] ||= "TCP"
          port["targetPort"] = port["port"] if port["targetPort"].nil? || port["targetPort"].to_s.empty?
        end
        if spec["type"] == "ExternalName"
          # ValidateServiceCreate: the family fields are forbidden on an
          # ExternalName Service (an update that leaves them untouched has
          # them dropped by dropTypeDependentFields instead).
          forbidden = %w[ipFamilies ipFamilyPolicy].select { |key| !spec[key].nil? && spec[key] != [] }
          if existing.nil? && !forbidden.empty?
            causes = forbidden.map { |key| "spec.#{key}: Forbidden: may not be set for ExternalName services" }
            raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: #{causes.length == 1 ? causes.first : "[#{causes.join(", ")}]"}",
                                      details: {"kind" => "Service", "name" => name_of(service)})
          end
          spec.delete("clusterIP")
          spec.delete("clusterIPs")
          spec.delete("ipFamilies")
          spec.delete("ipFamilyPolicy")
        else
          # ValidateServiceClusterIPsRelatedFields: clusterIPs is only
          # accepted alongside clusterIP (clusterIPs[0] == clusterIP).
          if spec["clusterIP"].to_s.empty? && !Array(spec["clusterIPs"]).empty? && existing.nil?
            raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.clusterIPs: Invalid value: #{JSON.generate(Array(spec["clusterIPs"]))}: must be empty when `clusterIP` is not specified",
                                      details: {"kind" => "Service", "name" => name_of(service)})
          end

          spec["internalTrafficPolicy"] ||= "Cluster"
        end
        # pkg/api/v1/service.ExternallyAccessible: a ClusterIP Service with
        # externalIPs is reachable from outside the cluster too, so it carries
        # an externalTrafficPolicy just like NodePort and LoadBalancer do.
        externally_accessible = %w[NodePort LoadBalancer].include?(spec["type"]) ||
                                (spec["type"] == "ClusterIP" && !Array(spec["externalIPs"]).empty?)
        spec["externalTrafficPolicy"] ||= "Cluster" if externally_accessible
        spec["allocateLoadBalancerNodePorts"] = true if spec["type"] == "LoadBalancer" && spec["allocateLoadBalancerNodePorts"].nil?
        if spec["clusterIP"] == "None" || Array(spec["clusterIPs"]).first == "None"
          spec["clusterIP"] = "None"
          spec["clusterIPs"] = ["None"]
          default_headless_families!(service)
        end
        service
      end

      # pkg/registry/core/service/storage/alloc.go initIPFamilyFields for a
      # headless Service.  A headless Service WITHOUT a selector defaults to
      # RequireDualStack and, unless SingleStack was asked for, always
      # carries both families -- the endpoints are the user's, not this
      # cluster's, so the cluster's own configured families do not limit
      # them.  A headless Service with a selector defaults to SingleStack
      # and, when a dual-stack policy is asked for, is completed with the
      # second family only when the cluster has it.
      def default_headless_families!(service)
        spec = service["spec"]
        selectorless = (spec["selector"] || {}).empty?
        spec["ipFamilyPolicy"] ||= selectorless ? "RequireDualStack" : "SingleStack"
        policy = spec["ipFamilyPolicy"].to_s
        families = Array(spec["ipFamilies"]).map(&:to_s)
        if policy == "SingleStack" && families.length == 2
          raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ipFamilyPolicy: Invalid value: \"SingleStack\": must be 'RequireDualStack' or 'PreferDualStack' when multiple IP families are specified",
                                    details: {"kind" => "Service", "name" => name_of(service)})
        end
        cluster_families = @service_cidrs.map { |cidr| family_name(cidr) }.uniq
        unless selectorless
          if policy == "RequireDualStack" && cluster_families.length < 2
            raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ipFamilyPolicy: Invalid value: \"RequireDualStack\": this cluster is not configured for dual-stack services",
                                      details: {"kind" => "Service", "name" => name_of(service)})
          end
          families.each_with_index do |family, index|
            next if cluster_families.include?(family)

            raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ipFamilies[#{index}]: Invalid value: \"#{family}\": not configured on this cluster",
                                      details: {"kind" => "Service", "name" => name_of(service)})
          end
        end
        families = [cluster_families.first] if families.empty?
        if families.length == 1 && policy != "SingleStack" && (selectorless || cluster_families.length == 2)
          families << (families.first == "IPv4" ? "IPv6" : "IPv4")
        end
        spec["ipFamilies"] = families
      end

      def needs_cluster_ip?(service)
        spec = service["spec"] || {}
        return false if spec["type"] == "ExternalName"
        return false if headless?(service)

        %w[ClusterIP NodePort LoadBalancer].include?(spec["type"].to_s)
      end

      def headless?(service)
        spec = service["spec"] || {}
        spec["clusterIP"] == "None" || Array(spec["clusterIPs"]).first == "None"
      end

      def external_name?(service)
        (service["spec"] || {})["type"] == "ExternalName"
      end

      # dropTypeDependentFields (pkg/registry/core/service/strategy.go): when a
      # Service moves to a type that no longer uses them, and the client did
      # not change them itself, the now-meaningless allocations are CLEARED so
      # they can be released -- NodePorts when leaving NodePort/LoadBalancer,
      # the ClusterIP when moving to ExternalName.  Keeping them left a Service
      # holding a node port nothing routes and a ClusterIP nothing answers,
      # which is what "[sig-network] Services should be able to change the type
      # from ExternalName to ClusterIP" and its siblings exercise.
      def drop_type_dependent_fields(service, existing)
        return if existing.nil?

        spec = service["spec"] || {}
        old = existing["spec"] || {}
        if needs_cluster_ip?(existing) && !needs_cluster_ip?(service) &&
           Array(spec["clusterIPs"]) == Array(old["clusterIPs"])
          spec.delete("clusterIP")
          spec.delete("clusterIPs")
          spec.delete("ipFamilies")
          spec.delete("ipFamilyPolicy")
        end
        return unless needs_node_port?(existing) && !needs_node_port?(service)

        same = Array(spec["ports"]).map { |port| port["nodePort"] } == Array(old["ports"]).map { |port| port["nodePort"] }
        return unless same

        Array(spec["ports"]).each { |port| port.delete("nodePort") }
      end

      def needs_node_port?(service)
        %w[NodePort LoadBalancer].include?((service["spec"] || {})["type"].to_s)
      end

      # The allocations of the stored object carry over; an update may not
      # silently drop the ClusterIP a client omitted from its PUT body.
      def preserve_allocations(service, existing)
        spec = service["spec"]
        old = existing["spec"] || {}
        return if external_name?(service) || headless?(service)

        if Array(spec["clusterIPs"]).empty? && !Array(old["clusterIPs"]).empty? && !headless?(existing)
          spec["clusterIPs"] = deep_copy(old["clusterIPs"])
          spec["clusterIP"] = old["clusterIP"]
          spec["ipFamilies"] = deep_copy(old["ipFamilies"]) if Array(spec["ipFamilies"]).empty?
          spec["ipFamilyPolicy"] ||= old["ipFamilyPolicy"]
        end
        old_ports = Array(old["ports"]).to_h { |port| [[port["port"], port["protocol"] || "TCP"], port["nodePort"]] }
        Array(spec["ports"]).each do |port|
          next unless port["nodePort"].nil? || port["nodePort"].to_i.zero?

          previous = old_ports[[port["port"], port["protocol"] || "TCP"]]
          port["nodePort"] = previous if previous && !previous.to_i.zero?
        end
        if old["healthCheckNodePort"] && spec["healthCheckNodePort"].nil? && spec["type"] == "LoadBalancer" && spec["externalTrafficPolicy"] == "Local"
          spec["healthCheckNodePort"] = old["healthCheckNodePort"]
        end
      end

      # ---------------------------------------------------------------- ClusterIP

      def allocate_cluster_ips!(service)
        return unless needs_cluster_ip?(service)

        spec = service["spec"]
        requested = Array(spec["clusterIPs"]).map(&:to_s).reject(&:empty?)
        requested = [spec["clusterIP"].to_s] if requested.empty? && !spec["clusterIP"].to_s.empty?
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
          raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ipFamilyPolicy: Invalid value: \"SingleStack\": must be 'RequireDualStack' or 'PreferDualStack' when multiple cluster IPs are specified",
                                    details: {"kind" => "Service", "name" => name_of(service)})
        end
        cluster_families = @service_cidrs.map { |cidr| family_name(cidr) }.uniq
        if policy == "RequireDualStack" && cluster_families.length < 2
          raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ipFamilyPolicy: Invalid value: \"RequireDualStack\": this cluster is not configured for dual-stack services",
                                    details: {"kind" => "Service", "name" => name_of(service)})
        end
        if policy == "SingleStack" && families.length == 2
          raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ipFamilyPolicy: Invalid value: \"SingleStack\": must be 'RequireDualStack' or 'PreferDualStack' when multiple IP families are specified",
                                    details: {"kind" => "Service", "name" => name_of(service)})
        end
        # initIPFamilyFields: one explicit family under a dual-stack policy on
        # a dual-stack cluster is completed with the other family.
        if policy != "SingleStack" && families.length == 1 && cluster_families.length == 2 && requested.length < 2
          families << (families.first == "IPv4" ? "IPv6" : "IPv4")
        end
        allocated = []
        begin
          families.each_with_index do |family, index|
            cidr = @service_cidrs.find { |candidate| family_name(candidate) == family }
            if cidr.nil?
              raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ipFamilies[#{index}]: Invalid value: \"#{family}\": not configured on this cluster",
                                        details: {"kind" => "Service", "name" => name_of(service)})
            end
            wanted = requested[index]
            allocated << (wanted ? reserve_ip(wanted, cidr, service) : allocate_ip(cidr, service))
            count_allocation(:ip, wanted ? "static" : "dynamic", cidr: cidr)
          end
        rescue StandardError
          allocated.each { |ip| delete_ipaddress(ip) }
          raise
        end
        spec["clusterIPs"] = allocated
        spec["clusterIP"] = allocated.first
        spec["ipFamilies"] = families
        spec["ipFamilyPolicy"] = policy
      end

      def reserve_ip(ip, cidr, service)
        reserve_ip_unmetered(ip, cidr, service)
      rescue Status::Error
        count_allocation(:ip, "static", cidr: cidr, error: true)
        raise
      end

      def reserve_ip_unmetered(ip, cidr, service)
        address = begin
          IPAddr.new(ip)
        rescue IPAddr::Error
          raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.clusterIPs: Invalid value: #{ip.inspect}: must be a valid IP",
                                    details: {"kind" => "Service", "name" => name_of(service)})
        end
        unless cidr.include?(address) && address != cidr && address != broadcast(cidr)
          raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.clusterIPs: Invalid value: #{ip.inspect}: the IP is not in the service CIDR #{cidr}/#{cidr.prefix}",
                                    details: {"kind" => "Service", "name" => name_of(service)})
        end
        return ip if create_ipaddress(ip, service)

        owner = ipaddress_owner(ip)
        if owner == service_reference(service)
          ip
        else
          raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.clusterIPs: Invalid value: #{ip.inspect}: failed to allocate IP #{ip}: provided IP is already allocated",
                                    details: {"kind" => "Service", "name" => name_of(service)})
        end
      end

      def allocate_ip(cidr, service)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        allocate_ip_unmetered(cidr, service).tap do
          @metrics&.observe("kube_apiserver_clusterip_allocator_allocation_duration_seconds",
                            Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, {"cidr" => cidr_label(cidr)})
        end
      rescue Status::Error
        count_allocation(:ip, "dynamic", cidr: cidr, error: true)
        raise
      end

      def allocate_ip_unmetered(cidr, service)
        size = 1 << ((cidr.ipv4? ? 32 : 128) - cidr.prefix)
        offset = [[STATIC_SUBRANGE_MIN, size / 16].max, STATIC_SUBRANGE_MAX].min
        # KEP-3070: the dynamic subrange starts rangeOffset past the first
        # usable address (the network address + 1).
        first = cidr.to_i + 1 + offset
        last = cidr.to_i + size - (cidr.ipv4? ? 2 : 1)
        if last < first
          raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.clusterIPs: Invalid value: []: failed to allocate a serviceIP: range is full")
        end

        span = last - first + 1
        start = SecureRandom.random_number(span)
        span.times do |step|
          candidate = IPAddr.new(first + ((start + step) % span), cidr.family).to_s
          return candidate if create_ipaddress(candidate, service)
        end
        raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.clusterIPs: Invalid value: []: failed to allocate a serviceIP: range is full",
                                  details: {"kind" => "Service", "name" => name_of(service)})
      end

      def release_cluster_ips!(service)
        Array((service["spec"] || {})["clusterIPs"]).each do |ip|
          next if ip.to_s == "None" || ip.to_s.empty?

          delete_ipaddress(ip) if ipaddress_owner(ip) == service_reference(service)
        end
      end

      def create_ipaddress(ip, service)
        return true if ipaddress_resource.nil?

        object = {
          "apiVersion" => "networking.k8s.io/v1", "kind" => "IPAddress",
          "metadata" => {"name" => ip, "labels" => {MANAGED_BY_LABEL => MANAGED_BY}},
          "spec" => {"parentRef" => service_reference(service)}
        }
        @store.create(resource: ipaddress_resource, namespace: :cluster, object: prepared(object))
        true
      rescue MemoryStore::AlreadyExists
        false
      end

      def delete_ipaddress(ip)
        return if ipaddress_resource.nil?

        @store.delete(resource: ipaddress_resource, namespace: :cluster, name: ip)
      rescue MemoryStore::NotFound
        nil
      end

      def ipaddress_owner(ip)
        return nil if ipaddress_resource.nil?

        object = @store.get(resource: ipaddress_resource, namespace: :cluster, name: ip)
        object.dig("spec", "parentRef")
      rescue MemoryStore::NotFound
        nil
      end

      def service_reference(service)
        metadata = service["metadata"] || {}
        {"group" => "", "resource" => "services", "namespace" => metadata["namespace"].to_s, "name" => metadata["name"].to_s}
      end

      # ---------------------------------------------------------------- NodePort

      def allocate_node_ports!(service, existing:)
        spec = service["spec"]
        wants_ports = %w[NodePort LoadBalancer].include?(spec["type"].to_s) &&
                      !(spec["type"] == "LoadBalancer" && spec["allocateLoadBalancerNodePorts"] == false)
        unless wants_ports
          Array(spec["ports"]).each { |port| port.delete("nodePort") }
          spec.delete("healthCheckNodePort") unless spec["type"] == "LoadBalancer"
          return
        end

        @mutex.synchronize do
          used = used_node_ports(except: service)
          Array(spec["ports"]).each do |port|
            requested = port["nodePort"].to_i
            if requested.positive?
              unless @node_port_range.cover?(requested)
                count_allocation(:port, "static", error: true)
                raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ports[#{Array(spec["ports"]).index(port)}].nodePort: Invalid value: #{requested}: provided port is not in the valid range. The range of valid ports is #{@node_port_range.first}-#{@node_port_range.last}",
                                          details: {"kind" => "Service", "name" => name_of(service)})
              end
              if used.include?(requested)
                count_allocation(:port, "static", error: true)
                raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ports[#{Array(spec["ports"]).index(port)}].nodePort: Invalid value: #{requested}: provided port is already allocated",
                                          details: {"kind" => "Service", "name" => name_of(service)})
              end
              count_allocation(:port, "static") unless existing_node_port?(existing, requested)
              used << requested
              next
            end
            port["nodePort"] = next_free_port(used, service)
            count_allocation(:port, "dynamic")
            used << port["nodePort"]
          end
          if spec["type"] == "LoadBalancer" && spec["externalTrafficPolicy"] == "Local"
            if spec["healthCheckNodePort"].to_i.zero?
              spec["healthCheckNodePort"] = next_free_port(used, service)
            elsif used.include?(spec["healthCheckNodePort"].to_i) && spec["healthCheckNodePort"].to_i != (existing && existing.dig("spec",
                                                                                                                                   "healthCheckNodePort")).to_i
              raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.healthCheckNodePort: Invalid value: #{spec["healthCheckNodePort"]}: provided port is already allocated",
                                        details: {"kind" => "Service", "name" => name_of(service)})
            end
          else
            spec.delete("healthCheckNodePort")
          end
        end
      end

      # A port the Service already held is kept, not allocated again.
      def existing_node_port?(existing, port)
        return false unless existing

        Array(existing.dig("spec", "ports")).any? { |item| item["nodePort"].to_i == port } ||
          existing.dig("spec", "healthCheckNodePort").to_i == port
      end

      def next_free_port(used, service)
        span = @node_port_range.size
        start = SecureRandom.random_number(span)
        span.times do |step|
          candidate = @node_port_range.first + ((start + step) % span)
          return candidate unless used.include?(candidate)
        end
        count_allocation(:port, "dynamic", error: true)
        raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ports: Invalid value: failed to allocate a nodePort: range is full",
                                  details: {"kind" => "Service", "name" => name_of(service)})
      end

      def used_node_ports(except:)
        return [] if service_resource.nil?

        skip = service_reference(except)
        result = @store.list(resource: service_resource, namespace: :all, selectors: nil)
        items = result.respond_to?(:items) ? result.items : Array(result)
        items.each_with_object([]) do |service, ports|
          next if service_reference(service) == skip

          Array((service["spec"] || {})["ports"]).each { |port| ports << port["nodePort"].to_i if port["nodePort"].to_i.positive? }
          health = (service["spec"] || {})["healthCheckNodePort"].to_i
          ports << health if health.positive?
        end
      end

      # ---------------------------------------------------------------- helpers

      def prepared(object)
        @metadata_preparer ? @metadata_preparer.call(object) : object
      end

      def family_name(address)
        address.ipv6? ? "IPv6" : "IPv4"
      end

      def broadcast(cidr)
        size = 1 << ((cidr.ipv4? ? 32 : 128) - cidr.prefix)
        IPAddr.new(cidr.to_i + size - 1, cidr.family)
      end

      def name_of(service)
        (service["metadata"] || {})["name"].to_s
      end

      def deep_copy(value)
        case value
        when Hash then value.each_with_object({}) { |(key, child), result| result[key] = deep_copy(child) }
        when Array then value.map { |child| deep_copy(child) }
        else value
        end
      end
    end
  end
end
