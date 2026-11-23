# frozen_string_literal: true

require_relative "../support/object_tree"

require "json"
require "ipaddr"
require "securerandom"

require_relative "../support/service_cidr"
require_relative "../schema/service_fields"
require_relative "status"
require_relative "service_allocator/cidr_pools"
require_relative "service_allocator/cluster_ips"
require_relative "service_allocator/node_port_reservations"
require_relative "service_allocator/transaction"
require_relative "../support/service_traffic"

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
    # deleted releases its addresses by deleting them. NodePorts use internal
    # reservation records shared by all API servers.
    class ServiceAllocator
      DEFAULT_SERVICE_CIDRS = ["10.96.0.0/12"].freeze
      DEFAULT_NODE_PORT_RANGE = (30_000..32_767)
      MANAGED_BY_LABEL = Support::ServiceCIDR::MANAGED_BY_LABEL
      MANAGED_BY = Support::ServiceCIDR::MANAGER
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
        @pool_mutex = Mutex.new
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
      # findings. The startup hook retries a failed sweep before becoming ready.
      REPAIR_INTERVAL_SECONDS = 180
      ADDRESS_ALLOCATION_GRACE_SECONDS = 60

      def repair!(raise_on_error: false)
        report = {"ip_errors" => Hash.new(0), "port_errors" => Hash.new(0), "released" => 0, "recreated" => 0}
        repair_cluster_ips!(report, raise_on_error: raise_on_error)
        repair_node_ports!(report, raise_on_error: raise_on_error)
        report
      end

      def repair_cluster_ips!(report, raise_on_error:)
        return if service_resource.nil?

        cidrs = service_cidr_pools.keys
        services = list_items(service_resource, namespace: :all)
        seen = {}
        services.each do |service|
          spec = service["spec"] || {}
          next if spec["type"].to_s == "ExternalName"

          service_ips(service).each do |raw|
            next if raw.to_s.empty? || raw == "None"

            ip = begin
              IPAddr.new(raw.to_s)
            rescue IPAddr::Error
              repair_ip_error(report, "invalid")
              next
            end
            if seen.key?(raw.to_s)
              repair_ip_error(report, "duplicate")
              next
            end
            seen[raw.to_s] = service_reference(service)
            unless cidrs.any? { |cidr| Support::ServiceCIDR.usable_address?(cidr, ip) }
              repair_ip_error(report, "outside_range")
              next
            end
            address = ipaddress_record(raw.to_s)
            if address.nil?
              # The IPAddress leaked away (or predates it): recreate it.
              repair_ip_error(report, "repair")
              report["recreated"] += 1 if create_ipaddress(raw.to_s, service, existing_version: service.dig("metadata", "resourceVersion"))
            elsif address.dig("spec", "parentRef") != service_reference(service)
              repair_ip_error(report, "duplicate")
            else
              repair_ipaddress_labels(address, ip)
            end
          end
        end
        return if ipaddress_resource.nil?

        list_items(ipaddress_resource, namespace: :cluster).each do |address|
          name = address.dig("metadata", "name").to_s
          next unless allocator_managed_ipaddress?(address)
          next if seen.key?(name)
          next if current_ip_allocation?(address)

          if release_ipaddress_if_unused(address)
            repair_ip_error(report, "leak")
            report["released"] += 1
          end
        end
      rescue StandardError
        @metrics&.increment("apiserver_clusterip_repair_reconcile_errors_total")
        raise if raise_on_error
      end

      def allocator_managed_ipaddress?(address)
        manager = address.dig("metadata", "labels", MANAGED_BY_LABEL)
        owner = address.dig("spec", "parentRef")
        [MANAGED_BY, Support::ServiceCIDR::LEGACY_MANAGER].include?(manager) && owner &&
          owner["group"].to_s.empty? && owner["resource"] == "services" &&
          !owner["namespace"].to_s.empty? && !owner["name"].to_s.empty?
      end

      def repair_ipaddress_labels(address, ip)
        return unless allocator_managed_ipaddress?(address)

        metadata = address.fetch("metadata")
        labels = metadata.fetch("labels").merge(MANAGED_BY_LABEL => MANAGED_BY, Support::ServiceCIDR::FAMILY_LABEL => family_name(ip))
        return if labels == metadata["labels"]

        @store.update(resource: ipaddress_resource, namespace: :cluster, name: metadata["name"],
                      object: address.merge("metadata" => metadata.merge("labels" => labels)), resource_version: metadata["resourceVersion"])
      rescue MemoryStore::Conflict, MemoryStore::NotFound
        nil
      end

      def current_ip_allocation?(address)
        timestamp = address.dig("metadata", "creationTimestamp")
        timestamp && @clock.call - Time.iso8601(timestamp) <= ADDRESS_ALLOCATION_GRACE_SECONDS
      end

      def repair_node_ports!(report, raise_on_error:)
        return if service_resource.nil?

        services = list_items(service_resource, namespace: :all).to_h do |service|
          [NodePortReservations.owner(service), [service, NodePortReservations.ports(service)]]
        end
        records = node_port_reservations.all.to_h { |record| [record.dig("metadata", "name").to_i, record] }
        records.delete_if do |port, record|
          next false if services.dig(record["owner"], 1)&.include?(port)

          released = node_port_reservations.reap(record)
          if released
            repair_port_error(report, "leak")
            report["released"] += 1
          end
          released
        end
        used = {}
        services.each do |owner, (service, ports)|
          ports.each do |port|
            unless @node_port_range.cover?(port)
              repair_port_error(report, "outside_range")
              next
            end
            if used.key?(port) || (records[port] && records[port]["owner"] != owner)
              repair_port_error(report, "duplicate")
            elsif !records[port] && node_port_reservations.claim(port, service, existing_version: service.dig("metadata", "resourceVersion"))
              repair_port_error(report, "repair")
              report["recreated"] += 1
            end
            used[port] = true
          end
        end
      rescue StandardError
        @metrics&.increment("apiserver_nodeport_repair_reconcile_errors_total")
        raise if raise_on_error
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
                      list_items(ipaddress_resource, namespace: :cluster).filter_map do |address|
                        IPAddr.new(address.dig("metadata", "name").to_s)
                      rescue IPAddr::Error
                        nil
                      end
                    else
                      []
                    end
        cidrs = service_cidr_pools.keys
        @pool_mutex.synchronize do
          (Array(@gauge_cidrs) - cidrs).each do |cidr|
            metrics.delete("kube_apiserver_clusterip_allocator_allocated_ips", {"cidr" => cidr_label(cidr)})
            metrics.delete("kube_apiserver_clusterip_allocator_available_ips", {"cidr" => cidr_label(cidr)})
          end
          cidrs.each do |cidr|
            used = addresses.count { |address| Support::ServiceCIDR.usable_address?(cidr, address) }
            size = hosts_per_network(cidr)
            metrics.set("kube_apiserver_clusterip_allocator_allocated_ips", used, {"cidr" => cidr_label(cidr)})
            metrics.set("kube_apiserver_clusterip_allocator_available_ips", [size - used, 0].max, {"cidr" => cidr_label(cidr)})
          end
          @gauge_cidrs = cidrs
        end
        ports = used_node_ports(except: {}).count { |port| @node_port_range.cover?(port) }
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
        result = begin
          @store.create(resource: servicecidr_resource, namespace: :cluster, object: prepared(object))
          true
        rescue MemoryStore::AlreadyExists
          false
        end
        @pool_mutex.synchronize { @default_pool_seen = true }
        result
      end

      # PrepareForCreate: Go defaults, then ClusterIP / NodePort allocation.
      def prepare_create(object, dry_run: false, allocation: nil)
        return committed_allocation { |attempt| prepare_create(object, dry_run: dry_run, allocation: attempt) } unless allocation

        service = apply_defaults(deep_copy(object))
        allocate_cluster_ips!(service, dry_run: dry_run, allocation: allocation)
        allocate_node_ports!(service, existing: nil, dry_run: dry_run, allocation: allocation)
        service
      end

      # PrepareForUpdate: allocations follow type transitions; ClusterIPs are
      # immutable and validated elsewhere, but a Service upgraded to a type
      # that needs an address or a port receives one here.
      def prepare_update(existing, object, dry_run: false, allocation: nil)
        return committed_allocation { |attempt| prepare_update(existing, object, dry_run: dry_run, allocation: attempt) } unless allocation

        existing = default_service_on_read(existing)
        service = apply_defaults(deep_copy(object), existing: existing)
        preserve_allocations(service, existing)
        drop_type_dependent_fields(service, existing)
        update_cluster_ips!(service, existing, dry_run: dry_run, allocation: allocation)
        allocate_node_ports!(service, existing: existing, dry_run: dry_run, allocation: allocation)
        if existing && !dry_run
          released = NodePortReservations.ports(existing) - NodePortReservations.ports(service)
          allocation.release_ports_on_commit = [existing, released] unless released.empty?
        end
        service
      end

      # Every allocation the Service holds is returned when it goes away.
      def release(object)
        release_cluster_ips!(object)
        true
      ensure
        release_committed_ports(object, NodePortReservations.ports(object))
      end

      private

      # pkg/apis/core/v1/defaults.go SetDefaults_Service and the strategy's
      # dual-stack normalisation.
      def apply_defaults(service, existing: nil)
        spec = (service["spec"] ||= {})
        Schema::ServiceFields.default_spec(spec)
        Schema::ServiceFields.default_traffic(spec)
        Array(spec["ports"]).each { |port| Schema::ServiceFields.default_port(port) if port.is_a?(Hash) }
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
            raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.clusterIPs: Invalid value: " \
                                      "#{JSON.generate(Array(spec["clusterIPs"]))}: must be empty when `clusterIP` is not specified",
                                      details: {"kind" => "Service", "name" => name_of(service)})
          end
        end
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
          raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ipFamilyPolicy: Invalid value: \"SingleStack\": must be " \
                                    "'RequireDualStack' or 'PreferDualStack' when multiple IP families are specified",
                                    details: {"kind" => "Service", "name" => name_of(service)})
        end
        cluster_families = @service_cidrs.map { |cidr| family_name(cidr) }.uniq
        unless selectorless
          if policy == "RequireDualStack" && cluster_families.length < 2
            raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ipFamilyPolicy: Invalid value: \"RequireDualStack\": this cluster " \
                                      "is not configured for dual-stack services",
                                      details: {"kind" => "Service", "name" => name_of(service)})
          end
          families.each_with_index do |family, index|
            next if cluster_families.include?(family)

            raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: spec.ipFamilies[#{index}]: Invalid value: \"#{family}\": not configured " \
                                      "on this cluster",
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
        if old["type"] == "LoadBalancer" && spec["type"] != "LoadBalancer"
          %w[allocateLoadBalancerNodePorts loadBalancerClass].each { |key| spec.delete(key) if spec[key] == old[key] }
        end
        spec.delete("externalTrafficPolicy") if Support::ServiceTraffic.drop_external_policy?(old, spec)
        spec.delete("healthCheckNodePort") if Support::ServiceTraffic.drop_health_port?(old, spec)
        return unless Support::ServiceTraffic.drop_node_ports?(old, spec)

        Array(spec["ports"]).each { |port| port.delete("nodePort") }
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
        if auto_node_ports?(old) && auto_node_ports?(spec)
          old_ports = Array(old["ports"]).to_h { |port| [port["name"].to_s, port["nodePort"]] }
          ports = Array(spec["ports"])
          requested = ports.filter_map { |port| port["nodePort"] }.to_set
          ports.each do |port|
            previous = old_ports[port["name"].to_s]
            port["nodePort"] = previous if port["nodePort"].to_i.zero? && previous.to_i.positive? && !requested.include?(previous)
          end
        end
        if old["healthCheckNodePort"] && spec["healthCheckNodePort"].to_i.zero? && spec["type"] == "LoadBalancer" && spec["externalTrafficPolicy"] == "Local"
          spec["healthCheckNodePort"] = old["healthCheckNodePort"]
        end
      end

      # ---------------------------------------------------------------- ClusterIP

      def release_cluster_ips!(service)
        owner = service_reference(service)
        service_ips(service).each do |ip|
          next if ip.to_s == "None" || ip.to_s.empty?

          address = ipaddress_record(ip)
          next unless address && address.dig("spec", "parentRef") == owner

          release_ipaddress_if_unused(address)
        end
      end

      def create_ipaddress(ip, service, existing_version: nil)
        return true if ipaddress_resource.nil?

        owner = service_reference(service)
        object = {
          "apiVersion" => "networking.k8s.io/v1", "kind" => "IPAddress",
          "metadata" => {"name" => ip, "labels" => {MANAGED_BY_LABEL => MANAGED_BY, Support::ServiceCIDR::FAMILY_LABEL => family_name(IPAddr.new(ip))}},
          "spec" => {"parentRef" => owner}
        }
        versions = existing_version ? {service_key(owner) => existing_version} : {}
        @store.create(resource: ipaddress_resource, namespace: :cluster, object: prepared(object), related_versions: versions)
      rescue MemoryStore::AlreadyExists, MemoryStore::Conflict
        false
      end

      def ipaddress_owner(ip)
        ipaddress_record(ip)&.dig("spec", "parentRef")
      end

      def ipaddress_record(ip)
        return nil if ipaddress_resource.nil?

        @store.get(resource: ipaddress_resource, namespace: :cluster, name: ip)
      rescue MemoryStore::NotFound
        nil
      end

      def service_reference(service)
        metadata = service["metadata"] || {}
        {"group" => "", "resource" => "services", "namespace" => metadata["namespace"].to_s, "name" => metadata["name"].to_s}
      end

      # ---------------------------------------------------------------- NodePort

      def allocate_node_ports!(service, existing:, dry_run:, allocation:)
        spec = service["spec"]
        return unless Support::ServiceTraffic.uses_node_ports?(spec)

        retained = existing ? NodePortReservations.ports(existing) : Set.new
        used = NodePortSelection.new(used_node_ports(except: service)) do |port|
          next true if retained.include?(port)

          dry_run ? node_port_reservations.record(port).nil? : allocation.claim_node_port(port, service)
        end
        preview_ports = [] if dry_run
        allocate_service_ports!(service, existing, used, preview_ports)
        if Support::ServiceTraffic.health_check?(spec)
          allocate_health_port!(service, existing, used, preview_ports)
        else
          spec.delete("healthCheckNodePort")
        end
      end

      def allocate_health_port!(service, existing, used, preview_ports)
        spec = service.fetch("spec")
        number = spec["healthCheckNodePort"].to_i
        if number.zero?
          spec["healthCheckNodePort"] = next_free_port(used, preview_ports: preview_ports, allocation: "a HealthCheck NodePort 0")
          return
        end
        return if number == existing&.dig("spec", "healthCheckNodePort")

        reason = if used.include?(number)
                   "provided port is already allocated"
                 elsif !preview_ports && !@node_port_range.cover?(number)
                   "provided port is not in the valid range. The range of valid ports is #{@node_port_range.first}-#{@node_port_range.last}"
                 elsif !used.claim(number)
                   "provided port is already allocated"
                 end
        raise Status::InternalError, "failed to allocate requested HealthCheck NodePort #{number}: #{reason}" if reason
      end

      def auto_node_ports?(spec)
        spec["type"] == "NodePort" || (spec["type"] == "LoadBalancer" && spec["allocateLoadBalancerNodePorts"] != false)
      end

      def allocate_service_ports!(service, existing, used, preview_ports)
        spec = service.fetch("spec")
        ports = Array(spec["ports"])
        preferred = {}
        if existing.nil?
          ports.each { |port| preferred[port["port"]] ||= port["nodePort"] if port["nodePort"].to_i.positive? }
        end
        shared = {}
        reserved = Set.new
        updated_ports = Set.new
        ports.each_with_index do |port, index|
          requested = port["nodePort"].to_i
          if requested.zero? && !auto_node_ports?(spec)
            port.delete("nodePort")
            next
          end

          # On create, UDP/TCP entries for the same Service port share the
          # first requested (or allocated) number unless explicitly distinct.
          number = port["port"]
          if existing.nil? && shared[number] && (requested.zero? || requested == shared[number])
            port["nodePort"] = shared[number]
            next
          end
          requested = preferred.fetch(number, 0) if requested.zero?
          if requested.zero?
            requested = next_free_port(used, preview_ports: preview_ports)
            count_allocation(:port, "dynamic") unless preview_ports
          elsif existing.nil? || !reserved.include?(requested)
            reserve_node_port(requested, index, service, existing: existing, used: used, preview_ports: preview_ports)
          end
          protocol = port["protocol"] || "TCP"
          if existing && !updated_ports.add?([protocol, requested])
            raise Status::Error.new(message: "duplicate nodePort: {#{protocol} #{requested}}", code: 500, reason: nil)
          end

          port["nodePort"] = requested
          shared[number] ||= requested
          reserved << requested
          used << requested
        end
      end

      def reserve_node_port(requested, index, service, existing:, used:, preview_ports:)
        reason = if preview_ports.nil? && !@node_port_range.cover?(requested)
                   "provided port is not in the valid range. The range of valid ports is #{@node_port_range.first}-#{@node_port_range.last}"
                 elsif !used.claim(requested)
                   "provided port is already allocated"
                 end
        if reason
          count_allocation(:port, "static", error: true) unless preview_ports
          field = "spec.ports[#{index}].nodePort"
          message = "Invalid value: #{requested}: #{reason}"
          cause = {"reason" => "FieldValueInvalid", "field" => field, "message" => message}
          raise Status::Invalid.new("Service \"#{name_of(service)}\" is invalid: #{field}: #{message}",
                                    details: {"kind" => "Service", "name" => name_of(service)}, causes: [cause])
        end

        unless existing_node_port?(existing, requested)
          preview_ports ? preview_ports << requested : count_allocation(:port, "static")
        end
        requested
      end

      # A port the Service already held is kept, not allocated again.
      def existing_node_port?(existing, port)
        existing && NodePortReservations.ports(existing).include?(port)
      end

      def next_free_port(used, preview_ports:, allocation: "a nodePort")
        if preview_ports
          # PortAllocationOperation.AllocateNext synthesizes NodePorts in dry run.
          first = (preview_ports.max || 32_768) + 1
          available = (first...100).find { |port| !used.include?(port) }
          preview_ports << (available || first)
          return preview_ports.last
        end

        span = @node_port_range.size
        # Kubernetes keeps the low band available for explicit NodePorts until the upper band fills.
        offset = span <= 16 ? 0 : (span / 32).clamp(16, 128)
        available = scan_port_band(@node_port_range.first + offset, span - offset, used) ||
                    scan_port_band(@node_port_range.first, offset, used)
        return available if available

        count_allocation(:port, "dynamic", error: true)
        raise Status::InternalError, "failed to allocate #{allocation}: range is full"
      end

      def scan_port_band(first, size, used)
        return if size.zero?

        start = SecureRandom.random_number(size)
        size.times do |step|
          candidate = first + ((start + step) % size)
          return candidate if used.claim(candidate)
        end
        nil
      end

      def used_node_ports(except:)
        return Set.new if service_resource.nil?

        skip = service_reference(except)
        result = @store.list(resource: service_resource, namespace: :all, selectors: nil)
        items = result.respond_to?(:items) ? result.items : Array(result)
        items.each_with_object(Set.new) do |service, ports|
          next if service_reference(service) == skip

          ports.merge(NodePortReservations.ports(service))
        end
      end

      # ---------------------------------------------------------------- helpers

      def prepared(object)
        @metadata_preparer ? @metadata_preparer.call(object) : object
      end

      def family_name(address)
        address.ipv6? ? "IPv6" : "IPv4"
      end

      def name_of(service)
        (service["metadata"] || {})["name"].to_s
      end

      def deep_copy(value) = ObjectTree.copy(value)
    end
  end
end
