# frozen_string_literal: true

require "fileutils"
require "ipaddr"
require "securerandom"
require "socket"

require_relative "errors"
require_relative "support"

module Rubernetes
  module Network
    module DNS
      Record = Struct.new(:name, :type, :data, :ttl, :priority, :weight, :port, keyword_init: true) do
        def to_h
          {"name" => name, "type" => type, "data" => data, "ttl" => ttl,
           "priority" => priority, "weight" => weight, "port" => port}.compact
        end

        alias value data
        alias target data
      end

      class RecordSet < Array
        attr_reader :rcode, :name, :type, :ttl

        def initialize(records, name:, type:, rcode: "NOERROR", ttl: nil)
          super(records)
          @name = name
          @type = type
          @rcode = rcode
          @ttl = ttl || (empty? ? nil : map(&:ttl).min)
          freeze
        end

        def records
          self
        end

        def negative?
          rcode == "NXDOMAIN" || empty?
        end

        def to_h
          {"name" => name, "type" => type, "rcode" => rcode, "ttl" => ttl,
           "records" => map { |record| record.respond_to?(:to_h) ? record.to_h : record }}
        end
      end

      Service = Struct.new(:name, :namespace, :domain, :cluster_ips, :headless,
                           :publish_not_ready, :external_name, :ports, :metadata,
                           keyword_init: true) do
        def fqdn
          "#{name}.#{namespace}.svc.#{domain}"
        end

        def to_h
          {"name" => name, "namespace" => namespace, "domain" => domain,
           "cluster_ips" => cluster_ips, "headless" => headless,
           "publish_not_ready" => publish_not_ready, "external_name" => external_name,
           "ports" => ports, "metadata" => metadata}
        end
      end

      Endpoint = Struct.new(:ip, :ready, :serving, :terminating, :hostname,
                            :pod_name, :pod_uid, :ports, :service_name,
                            :namespace, keyword_init: true) do
        def available?(publish_not_ready: false)
          return true if publish_not_ready
          return false if terminating

          serving.nil? ? ready != false : serving == true
        end

        def to_h
          {"ip" => ip, "ready" => ready, "serving" => serving, "terminating" => terminating,
           "hostname" => hostname, "pod_name" => pod_name, "pod_uid" => pod_uid,
           "ports" => ports, "service_name" => service_name, "namespace" => namespace}
        end
      end

      # A tiny authoritative resolver for the Kubernetes service zone.  The
      # resolver consumes watch-shaped objects, invalidates its cache on every
      # revision, and never shares mutable records with callers.
      class Resolver
        DEFAULT_DOMAIN = "cluster.local"
        DEFAULT_TTL = 5
        MAX_PACKET_BYTES = 4096
        SUPPORTED_TYPES = %w[A AAAA SRV PTR CNAME].freeze

        def initialize(domain: DEFAULT_DOMAIN, cluster_ip: "10.96.0.10", nameserver: nil,
                       positive_ttl: DEFAULT_TTL, negative_ttl: DEFAULT_TTL,
                       upstream: nil, upstreams: nil, adapter: nil, upstream_adapter: nil,
                       clock: -> { Time.now.utc }, max_packet_bytes: MAX_PACKET_BYTES,
                       **_options)
          @domain = normalize_domain(domain)
          @cluster_ip = Support.ip(cluster_ip, name: "cluster DNS IP").to_s
          @default_nameserver = nameserver ? Support.ip(nameserver, name: "DNS nameserver").to_s : @cluster_ip
          @positive_ttl = Support.integer(positive_ttl, "positive DNS TTL", min: 0, max: 86_400)
          @negative_ttl = Support.integer(negative_ttl, "negative DNS TTL", min: 0, max: 86_400)
          @max_packet_bytes = Support.integer(max_packet_bytes, "DNS packet size", min: 512, max: 65_535)
          @clock = clock
          @adapter = adapter
          @upstream_adapter = upstream_adapter || (adapter if adapter&.respond_to?(:query))
          @upstreams = validate_upstreams(Array(upstreams || upstream || []))
          @services = {}
          @endpoint_slices = {}
          @pods = {}
          @cache = {}
          @revision = 0
          @mutex = Mutex.new
        end

        attr_reader :domain, :cluster_ip, :upstreams

        def revision
          @mutex.synchronize { @revision }
        end

        def services
          @mutex.synchronize { @services.values.map(&:to_h).freeze }
        end

        def add_service(service)
          record = normalize_service(service)
          @mutex.synchronize do
            @services[[record.namespace, record.name]] = record
            bump_revision!
            invalidate!
          end
          record
        end

        alias update_service add_service

        def remove_service(name:, namespace: "default")
          @mutex.synchronize do
            @services.delete([String(namespace), String(name)])
            bump_revision!
            invalidate!
          end
          true
        end

        def add_endpoint_slice(slice)
          hash = slice.respond_to?(:to_h) ? slice.to_h : slice
          metadata = Support.fetch(hash, "metadata", default: {})
          labels = Support.fetch(metadata, "labels", default: {})
          service_name = Support.fetch(labels, "kubernetes.io/service-name", "service-name", default: nil) ||
            Support.fetch(hash, "service_name", "serviceName", default: nil)
          raise DNSQueryError, "EndpointSlice service name is required" if service_name.nil?
          namespace = Support.string(Support.fetch(metadata, "namespace", default: "default"), "EndpointSlice namespace")
          slice_name = Support.string(Support.fetch(metadata, "name", default: nil), "EndpointSlice name")
          key = [namespace, String(service_name)]
          endpoints = Array(Support.fetch(hash, "endpoints", default: [])).flat_map do |entry|
            normalize_endpoint(entry, service_name: service_name, namespace: namespace,
                               ports: Support.fetch(hash, "ports", default: []))
          end
          @mutex.synchronize do
            @endpoint_slices[[namespace, slice_name]] = {"service" => key, "endpoints" => endpoints.freeze}.freeze
            bump_revision!
            invalidate!
          end
          endpoints.freeze
        end

        alias update_endpoint_slice add_endpoint_slice
        alias add_endpoints add_endpoint_slice

        def remove_endpoint_slice(name:, namespace: "default")
          @mutex.synchronize do
            @endpoint_slices.delete([String(namespace), String(name)])
            bump_revision!
            invalidate!
          end
          true
        end

        def add_pod(pod)
          record = normalize_pod(pod)
          @mutex.synchronize do
            @pods[[record.fetch("namespace"), record.fetch("name")]] = record
            bump_revision!
            invalidate!
          end
          Support.immutable(record)
        end

        alias update_pod add_pod

        def remove_pod(name:, namespace: "default")
          @mutex.synchronize do
            @pods.delete([String(namespace), String(name)])
            bump_revision!
            invalidate!
          end
          true
        end

        # Consume Service/EndpointSlice/Pod watch events directly.
        def watch(event)
          hash = event.respond_to?(:to_h) ? event.to_h : event
          type = String(Support.fetch(hash, "type", "event_type", default: "MODIFIED")).upcase
          object = Support.fetch(hash, "object", "resource", default: hash)
          kind = String(Support.fetch(object, "kind", default: Support.fetch(hash, "kind", default: ""))).downcase
          if type == "DELETED"
            metadata = Support.fetch(object, "metadata", default: {})
            name = Support.fetch(metadata, "name", default: Support.fetch(object, "name", default: nil))
            namespace = Support.fetch(metadata, "namespace", default: "default")
            return remove_service(name: name, namespace: namespace) if kind == "service"
            return remove_pod(name: name, namespace: namespace) if kind == "pod"
            return remove_endpoint_slice(name: name, namespace: namespace) if kind == "endpointslice"
          end
          return add_service(object) if kind == "service"
          return add_pod(object) if kind == "pod"
          return add_endpoint_slice(object) if kind == "endpointslice"

          raise DNSQueryError, "unsupported DNS watch kind #{kind.inspect}"
        end

        def resolve(name, type: "A", now: nil, **_options)
          query_name = normalize_name(name)
          query_type = String(type).upcase
          raise DNSQueryError, "unsupported DNS record type #{type.inspect}" unless SUPPORTED_TYPES.include?(query_type)
          timestamp = monotonic_now(now)
          cache_key = [query_name, query_type]
          @mutex.synchronize do
            if (cached = @cache[cache_key]) && cached.fetch("expires_at") > timestamp
              return record_set_from_cache(cached)
            end
            records = resolve_uncached(query_name, query_type)
            # RFC 2308: an existing name with no records of the requested type
            # is NODATA (NOERROR, empty answer), not NXDOMAIN.  Resolvers cache
            # NXDOMAIN for every type, so conflating the two breaks AAAA/A
            # fallback for single-stack Services.
            rcode = if records.any?
                      "NOERROR"
                    else
                      name_exists_locked?(query_name) ? "NOERROR" : "NXDOMAIN"
                    end
            result = RecordSet.new(records, name: query_name, type: query_type, rcode: rcode,
                                   ttl: records.empty? ? @negative_ttl : @positive_ttl)
            ttl = result.empty? ? @negative_ttl : @positive_ttl
            @cache[cache_key] = {"expires_at" => timestamp + ttl, "result" => result.to_h}
            result
          end
        end

        alias query resolve
        alias lookup resolve

        attr_reader :positive_ttl, :negative_ttl

        # The server answers authoritatively for the cluster zone and for the
        # reverse names of addresses it knows; everything else is forwarded.
        def authoritative?(name)
          query_name = normalize_name(name)
          return true if query_name == @domain || query_name.end_with?(".#{@domain}")
          return false unless query_name.end_with?(".in-addr.arpa") || query_name.end_with?(".ip6.arpa")

          ip = begin
            reverse_name_to_ip(query_name)
          rescue DNSQueryError
            return false
          end
          @mutex.synchronize { known_address_locked?(ip) }
        end

        def name_exists?(name)
          query_name = normalize_name(name)
          @mutex.synchronize { name_exists_locked?(query_name) }
        end

        # Start of authority for negative answers (RFC 2308 §3).  The serial
        # is the resolver revision so a change in cluster state is visible to
        # a caching client; MINIMUM carries the negative TTL.
        def soa_record(zone = @domain)
          zone_name = normalize_name(zone)
          Record.new(name: zone_name, type: "SOA",
                     data: {"mname" => "ns.dns.#{@domain}", "rname" => "hostmaster.#{@domain}",
                            "serial" => revision, "refresh" => 7200, "retry" => 1800, "expire" => 86_400,
                            "minimum" => @negative_ttl}.freeze,
                     ttl: @negative_ttl).freeze
        end

        def soa_zone_for(name)
          query_name = normalize_name(name)
          return @domain if query_name == @domain || query_name.end_with?(".#{@domain}")
          return "in-addr.arpa" if query_name.end_with?(".in-addr.arpa")
          return "ip6.arpa" if query_name.end_with?(".ip6.arpa")

          @domain
        end

        def resolve_chain(name, type: "A", max_depth: 8)
          max_depth = Support.integer(max_depth, "DNS CNAME chain depth", min: 1, max: 64)
          current = normalize_name(name)
          seen = []
          depth = 0
          loop do
            raise DNSQueryError, "DNS CNAME loop detected" if seen.include?(current)
            raise DNSQueryError, "DNS CNAME chain exceeds #{max_depth}" if depth >= max_depth
            seen << current
            result = resolve(current, type: type)
            return result unless result.any? { |record| record.type == "CNAME" }

            current = result.find { |record| record.type == "CNAME" }.data
            depth += 1
          end
        end

        # Forward an external query through an injected upstream.  The client
        # transaction ID is never sent upstream; response source and size are
        # checked before the original ID is restored.
        def forward(packet, server: nil, client_address: nil, **options)
          bytes = String(packet).b
          raise DNSUpstreamError, "DNS packet exceeds #{@max_packet_bytes} bytes" if bytes.bytesize > @max_packet_bytes
          raise DNSUpstreamError, "DNS packet must contain a transaction ID" if bytes.bytesize < 2
          raise DNSUpstreamError, "DNS upstream is not configured" if @upstreams.empty? && @upstream_adapter.nil?
          incoming_id = bytes.byteslice(0, 2)
          generated_id = generated_transaction_id(incoming_id)
          outbound = generated_id + bytes.byteslice(2, bytes.bytesize - 2)
          target = server ? validate_upstream(server) : @upstreams.first
          if target && target.to_s == @cluster_ip.to_s
            raise DNSUpstreamError, "DNS upstream would loop back to the cluster resolver"
          end
          if server && !@upstreams.empty? && !@upstreams.include?(target)
            raise DNSUpstreamError, "DNS server is not in the configured upstream allowlist"
          end
          response = invoke_upstream(outbound, target, client_address: client_address, **options)
          normalize_upstream_response(response, generated_id: generated_id, client_id: incoming_id, target: target)
        end

        alias forward_query forward
        alias resolve_external forward

        # Render the pod's resolv.conf in a temporary file and atomically swap
        # it into place.  The target itself may not be a symlink.
        def project_resolv_conf(path:, namespace: "default", dns_policy: "ClusterFirst",
                                dns_config: nil, host_network: false, host_resolv_conf: "/etc/resolv.conf",
                                cluster_ip: @cluster_ip, fsync: true, **_options)
          target = safe_projection_path(path)
          policy = String(dns_policy || "ClusterFirst")
          policy = "ClusterFirstWithHostNet" if host_network && policy == "ClusterFirst"
          nameservers, search, options = resolv_components(policy, namespace: namespace, dns_config: dns_config,
                                                           host_resolv_conf: host_resolv_conf, cluster_ip: cluster_ip)
          content = (nameservers.map { |server| "nameserver #{server}" } +
                     (search.empty? ? [] : ["search #{search.join(" ")}"]) +
                     (options.empty? ? [] : ["options #{options.join(" ")}"])).join("\n") << "\n"
          atomic_write(target, content, fsync: fsync)
          content
        rescue DNSProjectionError
          raise
        rescue StandardError => error
          raise DNSProjectionError, "resolv.conf projection failed: #{error.message}"
        end

        alias project_resolv_conf! project_resolv_conf
        alias write_resolv_conf project_resolv_conf

        private

        def normalize_service(service)
          hash = service.respond_to?(:to_h) ? service.to_h : service
          metadata = Support.fetch(hash, "metadata", default: {})
          spec = Support.fetch(hash, "spec", default: hash)
          service_name = Support.fetch(metadata, "name", default: nil) || Support.fetch(spec, "name")
          service_namespace = Support.fetch(metadata, "namespace", default: nil) || Support.fetch(spec, "namespace", default: "default")
          name = Support.string(service_name, "service name")
          namespace = Support.string(service_namespace, "service namespace")
          cluster_ips = Array(Support.fetch(spec, "clusterIPs", "cluster_ips", default: nil))
          cluster_ip = Support.fetch(spec, "clusterIP", "cluster_ip", default: nil)
          cluster_ips = [cluster_ip] if cluster_ips.empty? && cluster_ip && cluster_ip != "None"
          cluster_ips = cluster_ips.reject { |value| value.to_s == "None" }.map { |value| Support.ip(value, name: "service clusterIP").to_s }.uniq
          headless = cluster_ip.to_s == "None" || cluster_ips.empty? && String(Support.fetch(spec, "clusterIP", default: "")) == "None"
          ports = Array(Support.fetch(spec, "ports", default: [])).map { |port| normalize_service_port(port) }
          Service.new(name: name, namespace: namespace, domain: @domain, cluster_ips: cluster_ips.freeze,
                      headless: headless, publish_not_ready: Support.bool(Support.fetch(spec, "publishNotReadyAddresses", "publish_not_ready", default: false)),
                      external_name: service_external_name(spec),
                      ports: ports.freeze, metadata: Support.immutable(metadata)).freeze
        rescue KeyError, ValidationError => error
          raise DNSQueryError, "invalid Service for DNS: #{error.message}"
        end

        # CoreDNS answers a CNAME only for `type: ExternalName`.  A Service
        # changed from ExternalName to ClusterIP keeps spec.externalName (the
        # apiserver does not clear it), and answering its A query with the old
        # CNAME made "[sig-network] DNS should provide DNS for ExternalName
        # services" wait forever for the new ClusterIP.
        def service_external_name(spec)
          type = Support.fetch(spec, "type", default: nil)
          return nil unless type.nil? || type.to_s == "ExternalName"

          normalize_external_name(Support.fetch(spec, "externalName", "external_name", default: nil))
        end

        def normalize_external_name(value)
          return nil if value.nil?

          normalize_name(value)
        rescue DNSQueryError => error
          raise DNSQueryError, "invalid ExternalName: #{error.message}"
        end

        def normalize_service_port(port)
          hash = port.respond_to?(:to_h) ? port.to_h : port
          name = Support.fetch(hash, "name", default: nil)&.to_s
          protocol = String(Support.fetch(hash, "protocol", default: "TCP")).downcase
          port_number = Support.integer(Support.fetch(hash, "port"), "service port", min: 1, max: 65_535)
          target = Support.fetch(hash, "targetPort", "target_port", default: port_number)
          {"name" => name, "protocol" => protocol, "port" => port_number, "target_port" => target}.compact.freeze
        end

        def normalize_endpoint(endpoint, service_name:, namespace:, ports:)
          hash = endpoint.respond_to?(:to_h) ? endpoint.to_h : endpoint
          conditions = Support.fetch(hash, "conditions", default: {})
          addresses = Array(Support.fetch(hash, "addresses", default: Support.fetch(hash, "ip", default: nil)))
          raise DNSQueryError, "EndpointSlice endpoint has no address" if addresses.empty?
          addresses.map do |ip|
            Endpoint.new(ip: Support.ip(ip, name: "endpoint IP").to_s,
                         ready: Support.fetch(conditions, "ready", default: Support.fetch(hash, "ready", default: nil)),
                         serving: Support.fetch(conditions, "serving", default: Support.fetch(hash, "serving", default: nil)),
                         terminating: Support.fetch(conditions, "terminating", default: Support.fetch(hash, "terminating", default: false)),
                         hostname: Support.fetch(hash, "hostname", default: nil),
                         pod_name: Support.fetch(Support.fetch(hash, "targetRef", default: {}), "name", default: Support.fetch(hash, "pod_name", default: nil)),
                         pod_uid: Support.fetch(Support.fetch(hash, "targetRef", default: {}), "uid", default: nil),
                         ports: normalize_endpoint_ports(ports), service_name: String(service_name), namespace: namespace).freeze
          end
        rescue KeyError, ValidationError => error
          raise DNSQueryError, "invalid EndpointSlice: #{error.message}"
        end

        def normalize_endpoint_ports(ports)
          Array(ports).filter_map do |port|
            hash = port.respond_to?(:to_h) ? port.to_h : port
            number = Support.fetch(hash, "port", default: nil)
            next if number.nil?
            {"name" => Support.fetch(hash, "name", default: nil),
             "protocol" => String(Support.fetch(hash, "protocol", default: "TCP")).downcase,
             "port" => Support.integer(number, "endpoint port", min: 1, max: 65_535)}.compact.freeze
          end.freeze
        end

        def normalize_pod(pod)
          hash = pod.respond_to?(:to_h) ? pod.to_h : pod
          metadata = Support.fetch(hash, "metadata", default: {})
          spec = Support.fetch(hash, "spec", default: {})
          status = Support.fetch(hash, "status", default: {})
          addresses = Array(Support.fetch(status, "podIPs", "pod_ips", default: []))
          addresses = Array(Support.fetch(status, "podIP", "pod_ip", default: nil)) if addresses.empty?
          ips = addresses.map { |entry| entry.is_a?(Hash) ? Support.fetch(entry, "ip") : entry }.map { |ip| Support.ip(ip, name: "pod IP").to_s }
          {"name" => Support.string(Support.fetch(metadata, "name"), "pod name"),
           "namespace" => String(Support.fetch(metadata, "namespace", default: "default")),
           "hostname" => Support.fetch(spec, "hostname", default: nil),
           "subdomain" => Support.fetch(spec, "subdomain", default: nil),
           "ips" => ips, "ready" => pod_ready?(status), "labels" => Support.fetch(metadata, "labels", default: {})}
        rescue KeyError, ValidationError => error
          raise DNSQueryError, "invalid Pod for DNS: #{error.message}"
        end

        def pod_ready?(status)
          conditions = Array(Support.fetch(status, "conditions", default: []))
          ready = conditions.find do |condition|
            Support.fetch(condition, "type", default: "") == "Ready"
          end
          ready.nil? || String(Support.fetch(ready, "status", default: "False")).downcase == "true"
        end

        def resolve_uncached(name, type)
          return resolve_ptr(name) if type == "PTR"
          if (srv = parse_srv(name))
            return resolve_srv(srv)
          end
          service = service_for_name(name)
          if service
            return [Record.new(name: name, type: "CNAME", data: service.external_name, ttl: @positive_ttl)].freeze if service.external_name && %w[A AAAA CNAME].include?(type)
            return [] if service.external_name
            if service.headless
              return resolve_headless(service, type)
            end
            return service.cluster_ips.filter_map do |ip|
              next unless (type == "A" && IPAddr.new(ip).ipv4?) || (type == "AAAA" && IPAddr.new(ip).ipv6?)
              Record.new(name: name, type: type, data: ip, ttl: @positive_ttl).freeze
            end.freeze
          end
          endpoint_records = resolve_endpoint_hostname(name, type)
          return endpoint_records unless endpoint_records.empty?

          resolve_pod_name(name, type)
        end

        # `<hostname>.<svc>.<ns>.svc.<domain>` (StatefulSet stable names via
        # EndpointSlice hostname) and the `<dashed-ip>.<svc>.<ns>.svc.<domain>`
        # synthesized name used as the SRV target when no hostname exists.
        def resolve_endpoint_hostname(name, type)
          return [].freeze unless %w[A AAAA].include?(type)

          suffix = ".svc.#{@domain}"
          return [].freeze unless name.end_with?(suffix)
          labels = name.delete_suffix(suffix).split(".")
          return [].freeze unless labels.length == 3

          host_label, service_name, namespace = labels
          service = @services[[namespace, service_name]]
          return [].freeze unless service

          endpoints_for(service).select { |endpoint| endpoint.available?(publish_not_ready: service.publish_not_ready) }.filter_map do |endpoint|
            next unless endpoint_host_label(endpoint) == host_label
            next unless (type == "A" && IPAddr.new(endpoint.ip).ipv4?) || (type == "AAAA" && IPAddr.new(endpoint.ip).ipv6?)

            Record.new(name: name, type: type, data: endpoint.ip, ttl: @positive_ttl).freeze
          end.freeze
        end

        def endpoint_host_label(endpoint)
          hostname = endpoint.hostname.to_s
          return hostname.downcase unless hostname.empty?

          # Kubernetes DNS spec §2.4.1: without a hostname the endpoint name
          # is the IP with dots (or colons) replaced by dashes.
          endpoint.ip.to_s.tr(".:", "--")
        end

        def endpoint_target_name(endpoint, service)
          "#{endpoint_host_label(endpoint)}.#{service.name}.#{service.namespace}.svc.#{@domain}"
        end

        def name_exists_locked?(name)
          return true if name == @domain || name == "svc.#{@domain}" || name == "pod.#{@domain}"
          suffix = ".svc.#{@domain}"
          if name.end_with?(suffix)
            labels = name.delete_suffix(suffix).split(".")
            case labels.length
            when 1
              return @services.each_key.any? { |(namespace, _service)| namespace == labels[0] }
            when 2
              return @services.key?([labels[1], labels[0]])
            when 3
              service = @services[[labels[2], labels[1]]]
              return false unless service
              return true if labels[0].start_with?("_") && %w[_tcp _udp _sctp].include?(labels[0])

              return endpoints_for(service).any? { |endpoint| endpoint_host_label(endpoint) == labels[0] }
            when 4
              srv = parse_srv(name)
              return srv ? service_port_exists?(srv) : false
            end
            return false
          end
          pod_suffix = ".pod.#{@domain}"
          if name.end_with?(pod_suffix)
            labels = name.delete_suffix(pod_suffix).split(".")
            return labels.length == 1 && @pods.each_key.any? { |(namespace, _pod)| namespace == labels[0] } if labels.length == 1
            return @pods.key?([labels[1], labels[0]]) if labels.length == 2

            return false
          end
          if name.end_with?(".in-addr.arpa") || name.end_with?(".ip6.arpa")
            begin
              return known_address_locked?(reverse_name_to_ip(name))
            rescue DNSQueryError
              return false
            end
          end
          false
        end

        def service_port_exists?(srv)
          service = @services[[srv.fetch("namespace"), srv.fetch("service")]]
          return false unless service

          service.ports.any? { |entry| entry["name"] == srv.fetch("port_name") && entry["protocol"] == srv.fetch("protocol") }
        end

        def known_address_locked?(ip)
          return true if @services.each_value.any? { |service| service.cluster_ips.include?(ip) }
          return true if @endpoint_slices.each_value.any? { |slice| slice.fetch("endpoints").any? { |endpoint| endpoint.ip == ip } }

          @pods.each_value.any? { |pod| pod.fetch("ips").include?(ip) }
        end

        def resolve_headless(service, type)
          return [] unless %w[A AAAA].include?(type)
          endpoints_for(service).select { |endpoint| endpoint.available?(publish_not_ready: service.publish_not_ready) }.filter_map do |endpoint|
            next unless (type == "A" && IPAddr.new(endpoint.ip).ipv4?) || (type == "AAAA" && IPAddr.new(endpoint.ip).ipv6?)
            Record.new(name: service.fqdn, type: type, data: endpoint.ip, ttl: @positive_ttl).freeze
          end.freeze
        end

        def endpoints_for(service)
          key = [service.namespace, service.name]
          @endpoint_slices.each_with_object([]) do |(slice_key, slice), result|
            next unless slice.fetch("service") == key

            result.concat(slice.fetch("endpoints"))
          end
        end

        def resolve_srv(srv)
          service = @services[[srv.fetch("namespace"), srv.fetch("service")]]
          return [] unless service
          port = service.ports.find { |entry| entry["name"] == srv.fetch("port_name") && entry["protocol"] == srv.fetch("protocol") }
          return [] unless port
          endpoints = endpoints_for(service).select { |endpoint| endpoint.available?(publish_not_ready: service.publish_not_ready) }
          if service.headless
            # Kubernetes DNS spec §2.4.1: a headless SRV target is the
            # endpoint's `<hostname>.<svc>.<ns>.svc.<domain>` name, which the
            # A/AAAA path above resolves to that single endpoint address.
            endpoints.map do |endpoint|
              Record.new(name: srv.fetch("name"), type: "SRV", data: endpoint_target_name(endpoint, service), ttl: @positive_ttl,
                         priority: 0, weight: 0, port: port.fetch("port")).freeze
            end.freeze
          else
            [Record.new(name: srv.fetch("name"), type: "SRV", data: service.fqdn, ttl: @positive_ttl,
                        priority: 0, weight: 0, port: port.fetch("port"))].freeze
          end
        end

        def resolve_ptr(name)
          ip = reverse_name_to_ip(name)
          matches = []
          @services.each_value do |service|
            if service.cluster_ips.include?(ip)
              matches << Record.new(name: name, type: "PTR", data: service.fqdn, ttl: @positive_ttl).freeze
            end
            endpoints_for(service).each do |endpoint|
              next unless endpoint.ip == ip

              matches << Record.new(name: name, type: "PTR", data: endpoint_target_name(endpoint, service), ttl: @positive_ttl).freeze
            end
          end
          @pods.each_value do |pod|
            next unless pod.fetch("ips").include?(ip)
            target = pod.fetch("hostname") || pod.fetch("name")
            if pod.fetch("subdomain")
              target = "#{target}.#{pod.fetch("subdomain")}.#{pod.fetch("namespace")}.svc.#{@domain}"
            end
            matches << Record.new(name: name, type: "PTR", data: target, ttl: @positive_ttl).freeze
          end
          matches.uniq { |record| record.data }.freeze
        rescue DNSQueryError
          [].freeze
        end

        def resolve_pod_name(name, type)
          return [].freeze unless %w[A AAAA].include?(type)
          @pods.each_value.filter_map do |pod|
            names = []
            if pod.fetch("hostname") && pod.fetch("subdomain")
              names << "#{pod.fetch("hostname")}.#{pod.fetch("subdomain")}.#{pod.fetch("namespace")}.svc.#{@domain}"
            end
            names << "#{pod.fetch("name")}.#{pod.fetch("namespace")}.pod.#{@domain}"
            next unless names.include?(name)
            pod.fetch("ips").filter_map do |ip|
              next unless (type == "A" && IPAddr.new(ip).ipv4?) || (type == "AAAA" && IPAddr.new(ip).ipv6?)
              Record.new(name: name, type: type, data: ip, ttl: @positive_ttl).freeze
            end
          end.flatten.freeze
        end

        def service_for_name(name)
          suffix = ".svc.#{@domain}"
          return nil unless name.end_with?(suffix)
          labels = name.delete_suffix(suffix).split(".")
          return nil unless labels.length == 2
          @services[[labels[1], labels[0]]]
        end

        def parse_srv(name)
          suffix = ".svc.#{@domain}"
          return nil unless name.end_with?(suffix)
          labels = name.delete_suffix(suffix).split(".")
          return nil unless labels.length == 4 && labels[0].start_with?("_") && labels[1].start_with?("_")
          {"name" => name, "port_name" => labels[0].delete_prefix("_"), "protocol" => labels[1].delete_prefix("_").downcase,
           "service" => labels[2], "namespace" => labels[3]}
        end

        def reverse_name_to_ip(name)
          normalized = name.delete_suffix(".")
          if normalized.end_with?(".in-addr.arpa")
            octets = normalized.delete_suffix(".in-addr.arpa").split(".").reverse
            raise DNSQueryError, "invalid PTR name" unless octets.length == 4
            Support.ip(octets.join("."), name: "PTR name").to_s
          elsif normalized.end_with?(".ip6.arpa")
            nibbles = normalized.delete_suffix(".ip6.arpa").split(".").reverse.join
            raise DNSQueryError, "invalid IPv6 PTR name" unless nibbles.length == 32 && nibbles.match?(/\A[0-9a-f]+\z/i)
            Support.ip(nibbles.scan(/.{4}/).join(":"), name: "PTR name").to_s
          else
            raise DNSQueryError, "unsupported PTR zone"
          end
        end

        def normalize_name(value)
          name = Support.string(value, "DNS name").downcase.delete_suffix(".")
          raise DNSQueryError, "DNS name exceeds 253 bytes" if name.bytesize > 253
          labels = name.split(".", -1)
          raise DNSQueryError, "DNS name contains an empty label" if labels.any?(&:empty?)
          labels.each do |label|
            raise DNSQueryError, "DNS label exceeds 63 bytes" if label.bytesize > 63
            raise DNSQueryError, "DNS name contains invalid characters" unless label.match?(/\A[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?\z/)
          end
          name
        end

        def normalize_domain(value)
          domain = normalize_name(value)
          raise DNSQueryError, "cluster domain must not be empty" if domain.empty?
          domain
        end

        def validate_upstreams(values)
          values.map do |value|
            text = Support.string(value, "DNS upstream")
            begin
              address = IPAddr.new(text)
              unspecified = address.to_i.zero?
              multicast = address.ipv4? ? address.to_i.between?(0xe000_0000, 0xefff_ffff) : ((address.to_i >> 120) & 0xff) == 0xff
              raise DNSUpstreamError, "DNS upstream must not be loopback, multicast, or unspecified" if address.loopback? || multicast || unspecified || address.link_local?
              address.to_s
            rescue IPAddr::InvalidAddressError
              raise DNSUpstreamError, "invalid DNS upstream #{text.inspect}" unless text.match?(/\A[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\z/) && text.downcase != "localhost"
              text.downcase
            end
          end.uniq.freeze
        end

        def validate_upstream(value)
          validate_upstreams([value]).first
        end

        def generated_transaction_id(original)
          32.times do
            candidate = [SecureRandom.random_number(65_536)].pack("n")
            return candidate unless candidate == original
          end
          raise DNSUpstreamError, "unable to generate a distinct DNS transaction ID"
        end

        def invoke_upstream(packet, target, client_address:, **options)
          adapter = @upstream_adapter
          raise DNSUpstreamError, "DNS upstream adapter is unavailable" unless adapter
          if adapter.respond_to?(:query)
            adapter.query(packet: packet, server: target, client_address: client_address, **options)
          elsif adapter.respond_to?(:call)
            adapter.call(packet: packet, server: target, client_address: client_address, **options)
          else
            raise DNSUpstreamError, "DNS upstream adapter must respond to query or call"
          end
        rescue DNSUpstreamError
          raise
        rescue StandardError => error
          raise DNSUpstreamError, "DNS upstream query failed: #{error.message}"
        end

        def normalize_upstream_response(response, generated_id:, client_id:, target:)
          if response.is_a?(Hash)
            source = Support.fetch(response, "source", "server", default: target)
            raise DNSUpstreamError, "DNS upstream response source mismatch" if source && source.to_s != target.to_s
            size = Support.fetch(response, "size", default: nil)
            payload = Support.fetch(response, "packet", "data", "response", default: nil)
            raise DNSUpstreamError, "DNS upstream response has no packet" if payload.nil?
            bytes = String(payload).b
            size = bytes.bytesize if size.nil?
          else
            bytes = String(response).b
            size = bytes.bytesize
          end
          begin
            size = Support.integer(size, "DNS upstream response size", min: 0, max: @max_packet_bytes)
          rescue ValidationError => error
            raise DNSUpstreamError, error.message
          end
          raise DNSUpstreamError, "DNS upstream response size does not match packet" unless size == bytes.bytesize
          raise DNSUpstreamError, "DNS upstream response exceeds #{@max_packet_bytes} bytes" if bytes.bytesize > @max_packet_bytes
          raise DNSUpstreamError, "DNS upstream response is missing transaction ID" if bytes.bytesize < 2
          raise DNSUpstreamError, "DNS upstream response transaction ID mismatch" unless bytes.byteslice(0, 2) == generated_id
          client_id + bytes.byteslice(2, bytes.bytesize - 2)
        end

        def record_set_from_cache(value)
          hash = value.fetch("result")
          records = Array(hash.fetch("records", [])).map { |entry| Record.new(**entry.transform_keys(&:to_sym)).freeze }
          RecordSet.new(records, name: hash.fetch("name"), type: hash.fetch("type"), rcode: hash.fetch("rcode", "NOERROR"), ttl: hash["ttl"])
        end

        def monotonic_now(value)
          return Float(value) if value
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end

        def bump_revision!
          @revision += 1
        end

        def invalidate!
          @cache.clear
        end

        def safe_projection_path(path)
          target = File.expand_path(String(path))
          raise DNSProjectionError, "resolv.conf target is a directory" if File.directory?(target)
          raise DNSProjectionError, "resolv.conf target must not be a symlink" if File.symlink?(target)
          relative = target.delete_prefix("/").split("/")
          current = "/"
          relative[0...-1].each do |component|
            current = File.join(current, component)
            raise DNSProjectionError, "resolv.conf parent path must not contain symlinks" if File.symlink?(current)
          end
          target
        rescue TypeError
          raise DNSProjectionError, "resolv.conf path must be a string"
        end

        def resolv_components(policy, namespace:, dns_config:, host_resolv_conf:, cluster_ip:)
          config = dns_config.respond_to?(:to_h) ? dns_config.to_h : (dns_config || {})
          nameservers = Array(Support.fetch(config, "nameservers", default: [])).map { |server| validate_upstream(server) }
          search = Array(Support.fetch(config, "searches", "search", default: [])).map { |entry| normalize_domain(entry) }
          options = Array(Support.fetch(config, "options", default: [])).map do |entry|
            hash = entry.respond_to?(:to_h) ? entry.to_h : entry
            name = Support.string(Support.fetch(hash, "name"), "resolv.conf option")
            value = Support.fetch(hash, "value", default: nil)
            value ? "#{name}:#{Support.string(value, "resolv.conf option value")}" : name
          end
          case policy
          when "None"
            raise DNSProjectionError, "dnsConfig.nameservers is required for dnsPolicy None" if nameservers.empty?
          when "Default"
            nameservers, search, options = parse_host_resolv(host_resolv_conf) if nameservers.empty?
          when "ClusterFirst", "ClusterFirstWithHostNet"
            nameservers.unshift(Support.ip(cluster_ip, name: "cluster DNS IP").to_s) unless nameservers.include?(cluster_ip.to_s)
            search = ["#{namespace}.svc.#{@domain}", "svc.#{@domain}", @domain] + search
          else
            raise DNSProjectionError, "unsupported dnsPolicy #{policy.inspect}"
          end
          nameservers = nameservers.uniq
          raise DNSProjectionError, "resolv.conf supports at most three nameservers" if nameservers.length > 3
          raise DNSProjectionError, "resolv.conf supports at most six search domains" if search.uniq.length > 6
          raise DNSProjectionError, "resolv.conf search list is too large" if search.join(" ").bytesize > 2048
          [nameservers, search.uniq, options.uniq]
        end

        def parse_host_resolv(path)
          source = File.expand_path(String(path))
          raise DNSProjectionError, "host resolv.conf must not be a symlink" if File.symlink?(source)
          validate_parent_path!(File.dirname(source))
          nameservers = []
          search = []
          options = []
          File.foreach(source) do |line|
            fields = line.strip.split
            next if fields.empty? || fields.first.start_with?("#", ";")
            nameservers.concat(fields.drop(1).filter_map { |value| validate_upstream(value) }) if fields.first == "nameserver"
            search.concat(fields.drop(1)) if fields.first == "search"
            options.concat(fields.drop(1)) if fields.first == "options"
          end
          [nameservers.uniq.first(3), search, options]
        rescue SystemCallError => error
          raise DNSProjectionError, "cannot read host resolv.conf: #{error.message}"
        end

        def atomic_write(path, content, fsync:)
          directory = File.dirname(path)
          FileUtils.mkdir_p(directory)
          validate_parent_path!(directory)
          raise DNSProjectionError, "resolv.conf target must not be a symlink" if File.symlink?(path)
          temporary = "#{path}.tmp-#{Process.pid}-#{SecureRandom.hex(8)}"
          File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
            file.write(content)
            file.flush
            file.fsync if fsync
          end
          File.rename(temporary, path)
          directory_handle = File.open(directory, File::RDONLY)
          directory_handle.fsync if fsync
          true
        ensure
          directory_handle&.close
          File.delete(temporary) if temporary && File.exist?(temporary)
        end

        def validate_parent_path!(directory)
          absolute = File.expand_path(directory)
          components = absolute.delete_prefix("/").split("/")
          current = "/"
          components.each do |component|
            current = File.join(current, component)
            raise DNSProjectionError, "resolv.conf parent path must not contain symlinks" if File.symlink?(current)
          end
        end
      end
    end

    Dns = DNS::Resolver
    DNSResolver = DNS::Resolver
    Resolver = DNS::Resolver
  end
end

# The wire codec and socket server build on the resolver defined above.
require_relative "dns_wire"
require_relative "dns_server"
