# frozen_string_literal: true

require "ipaddr"
require "time"

module Rubernetes
  module Proxy
    # Shared normalization helpers for Kubernetes objects.  API objects are
    # accepted with either string or symbol keys because watch adapters and
    # typed callers commonly use different representations.
    module ModelSupport
      module_function

      def key(value, name, default = nil)
        return default unless value.respond_to?(:key?)

        return value[name] if value.key?(name)

        string = name.to_s
        return value[string] if value.key?(string)

        symbol = string.to_sym
        return value[symbol] if value.key?(symbol)

        default
      end

      def string_keys(value)
        case value
        when Hash
          value.each_with_object({}) { |(name, child), result| result[name.to_s] = string_keys(child) }
        when Array
          value.map { |child| string_keys(child) }
        else
          value
        end
      end

      def deep_copy(value)
        case value
        when Hash
          value.each_with_object({}) { |(name, child), result| result[name] = deep_copy(child) }
        when Array
          value.map { |child| deep_copy(child) }
        when String
          value.dup
        else
          value
        end
      end

      def deep_freeze(value)
        case value
        when Hash
          value.each do |name, child|
            deep_freeze(name)
            deep_freeze(child)
          end
        when Array
          value.each { |child| deep_freeze(child) }
        end
        value.freeze
      end

      def immutable(value)
        deep_freeze(deep_copy(value))
      end

      def bool(value, default: false)
        return default if value.nil?
        return value if [true, false].include?(value)

        %w[true yes 1].include?(value.to_s.downcase)
      end

      def integer(value, default = nil)
        return default if value.nil? || value == ""

        Integer(value)
      rescue ArgumentError, TypeError
        default
      end

      def strict_integer(value, name)
        return nil if value.nil? || value == ""

        Integer(value)
      rescue ArgumentError, TypeError
        raise ValidationError, "#{name} must be an integer"
      end

      def normalize_protocol(value)
        protocol = value.to_s.upcase
        protocol = "TCP" if protocol.empty?
        raise ValidationError, "unsupported protocol #{value.inspect}" unless Service::PROTOCOLS.include?(protocol)

        protocol
      end

      def normalize_family(value)
        family = value.to_s
        return "IPv4" if %w[IPv4 ipv4 4].include?(family)
        return "IPv6" if %w[IPv6 ipv6 6].include?(family)

        family
      end

      def parse_ip(value)
        return nil if value.nil? || value.to_s.empty?

        IPAddr.new(value.to_s)
      rescue IPAddr::InvalidAddressError
        raise ValidationError, "invalid IP address #{value.inspect}"
      end

      def ip_family(value)
        ip = value.is_a?(IPAddr) ? value : parse_ip(value)
        return nil unless ip

        ip.ipv4? ? "IPv4" : "IPv6"
      end

      def canonical_ip(value)
        parse_ip(value)&.to_s
      end

      def canonicalize(value)
        case value
        when Hash
          value.keys.map(&:to_s).sort.each_with_object({}) do |name, result|
            original = value.key?(name) ? value[name] : value[name.to_sym]
            result[name] = canonicalize(original)
          end
        when Array
          value.map { |item| canonicalize(item) }
        when IPAddr
          value.to_string
        when Time
          value.utc.iso8601(9)
        when String
          # Kernel readback can carry raw bytes (rule userdata markers);
          # canonical JSON must stay valid UTF-8, so bytes that are not text
          # are represented as a tagged hex string.
          if value.encoding == Encoding::BINARY || !value.valid_encoding?
            utf8 = value.dup.force_encoding(Encoding::UTF_8)
            utf8.valid_encoding? ? utf8 : "hex:#{value.unpack1("H*")}"
          else
            value
          end
        else
          value
        end
      end

      def service_key(namespace, name)
        "#{namespace.to_s.empty? ? "default" : namespace}/#{name}"
      end
    end

    class Error < StandardError; end
    class ValidationError < Error; end
    class NoRoute < Error; end
    class BackendError < Error; end
    class StaleRevisionError < BackendError; end
    class AllocationError < Error; end

    # A Kubernetes Service port with protocol and target port semantics.
    class ServicePort
      include Comparable

      attr_reader :name, :port, :target_port, :protocol, :node_port, :app_protocol

      def initialize(port:, name: nil, target_port: nil, protocol: "TCP", node_port: nil, app_protocol: nil)
        @name = name.to_s.empty? ? nil : name.to_s
        @port = Integer(port)
        @target_port = if target_port.nil? || target_port == ""
                         @port
                       elsif target_port.is_a?(Integer)
                         target_port
                       else
                         target_port.to_s
                       end
        @protocol = ModelSupport.normalize_protocol(protocol)
        @node_port = node_port.nil? || node_port == "" ? nil : Integer(node_port)
        @app_protocol = app_protocol&.to_s
        validate!
        freeze
      end

      def <=>(other)
        [port, protocol, name.to_s] <=> [other.port, other.protocol, other.name.to_s]
      end

      def target_port_number
        target_port.is_a?(Integer) ? target_port : nil
      end

      def named_target_port?
        target_port.is_a?(String)
      end

      def key
        [port, protocol, name].freeze
      end

      def to_h
        {
          "name" => name,
          "port" => port,
          "targetPort" => target_port,
          "protocol" => protocol,
          "nodePort" => node_port,
          "appProtocol" => app_protocol
        }.compact
      end

      private

      def validate!
        raise ValidationError, "service port must be between 1 and 65535" unless port.between?(1, 65_535)
        raise ValidationError, "target port must be between 1 and 65535" if target_port.is_a?(Integer) && !target_port.between?(1, 65_535)
        raise ValidationError, "invalid service port name #{name.inspect}" if name && !valid_port_name?(name)
        raise ValidationError, "invalid named target port #{target_port.inspect}" if target_port.is_a?(String) && !valid_port_name?(target_port)
        return unless node_port && !node_port.between?(1, 65_535)

        raise ValidationError, "node port must be between 1 and 65535"
      end

      def valid_port_name?(value)
        value.match?(/\A[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\z/) && value.length <= 63
      end
    end

    # Normalized Kubernetes Service model.  The object keeps enough metadata
    # for routing decisions while preserving the original object for adapters.
    class Service
      TYPES = %w[ClusterIP NodePort LoadBalancer ExternalName].freeze
      PROTOCOLS = %w[TCP UDP SCTP].freeze
      TRAFFIC_POLICIES = %w[Cluster Local].freeze
      AFFINITIES = %w[None ClientIP].freeze
      IP_FAMILIES = %w[IPv4 IPv6].freeze
      MAX_SESSION_AFFINITY_TIMEOUT = 86_400

      attr_reader :name, :namespace, :uid, :resource_version, :generation, :labels,
                  :service_type, :cluster_ips, :ip_families, :ports, :selector,
                  :session_affinity, :session_affinity_timeout_seconds,
                  :internal_traffic_policy, :external_traffic_policy,
                  :external_ips, :load_balancer_ips, :external_name,
                  :health_check_node_port, :publish_not_ready_addresses,
                  :allocate_load_balancer_node_ports, :load_balancer_source_ranges,
                  :topology_aware_hints, :raw

      def initialize(object = nil, name: nil, namespace: nil, uid: nil, service_type: nil, type: nil,
                     cluster_ips: nil, cluster_ip: nil, ip_families: nil, ports: nil, selector: nil,
                     session_affinity: nil, session_affinity_timeout_seconds: nil, session_affinity_timeout: nil,
                     internal_traffic_policy: nil, external_traffic_policy: nil,
                     external_ips: nil, load_balancer_ips: nil, external_name: nil,
                     health_check_node_port: nil, publish_not_ready_addresses: nil,
                     allocate_load_balancer_node_ports: nil, load_balancer_source_ranges: nil,
                     topology_aware_hints: nil, topology_hints: nil, **options)
        object = options if object.nil? && (options.key?(:metadata) || options.key?("metadata") || options.key?(:spec) || options.key?("spec"))
        source = ModelSupport.string_keys(object || {})
        metadata = ModelSupport.key(source, "metadata", {})
        spec = ModelSupport.key(source, "spec", source)
        @name = (name || ModelSupport.key(metadata, "name", ModelSupport.key(spec, "name", nil))).to_s
        @namespace = (namespace || ModelSupport.key(metadata, "namespace", "default")).to_s
        raise ValidationError, "service name is required" if @name.empty?

        @uid = (uid || ModelSupport.key(metadata, "uid", nil))&.to_s
        @resource_version = ModelSupport.key(metadata, "resourceVersion", nil)&.to_s
        @generation = ModelSupport.integer(ModelSupport.key(metadata, "generation", nil))
        @labels = ModelSupport.immutable(ModelSupport.key(metadata, "labels", {}) || {})
        @service_type = (service_type || type || ModelSupport.key(spec, "type", "ClusterIP")).to_s
        @service_type = "ClusterIP" if @service_type.empty?
        raise ValidationError, "unsupported service type #{@service_type.inspect}" unless TYPES.include?(@service_type)

        raw_cluster_ips = cluster_ips || (cluster_ip.nil? ? ModelSupport.key(spec, "clusterIPs", nil) : [cluster_ip])
        raw_cluster_ips = [ModelSupport.key(spec, "clusterIP", nil)] if raw_cluster_ips.nil?
        raw_cluster_ips = Array(raw_cluster_ips).reject { |value| value.nil? || value.to_s.empty? }
        @cluster_ips = raw_cluster_ips.reject do |value|
          value.to_s.casecmp("none").zero?
        end.filter_map { |value| ModelSupport.canonical_ip(value) }.uniq.freeze
        primary_cluster_ip = cluster_ip.nil? ? ModelSupport.key(spec, "clusterIP", nil) : cluster_ip
        if primary_cluster_ip && !primary_cluster_ip.to_s.empty? && primary_cluster_ip.to_s.casecmp("none").nonzero?
          canonical_primary = ModelSupport.canonical_ip(primary_cluster_ip)
          raise ValidationError, "clusterIP must match the first clusterIPs entry" unless @cluster_ips.first == canonical_primary
        end
        raw_ip_families = Array(ip_families || ModelSupport.key(spec, "ipFamilies", nil)).map do |family|
          ModelSupport.normalize_family(family)
        end
        raise ValidationError, "unsupported IP family" unless raw_ip_families.all? { |family| IP_FAMILIES.include?(family) }
        raise ValidationError, "service IP families must be unique" unless raw_ip_families.uniq.length == raw_ip_families.length

        @ip_families = raw_ip_families
        @ip_families = @cluster_ips.map { |ip| ModelSupport.ip_family(ip) } if @ip_families.empty? && @cluster_ips.any?
        @ip_families = @ip_families.uniq.freeze

        raw_ports = ports || ModelSupport.key(spec, "ports", [])
        @ports = Array(raw_ports).map { |entry| self.class.port_from(entry) }.sort.freeze
        raise ValidationError, "service must define at least one port" if @ports.empty? && @service_type != "ExternalName"

        ensure_unique_ports!
        @selector = ModelSupport.immutable(selector || ModelSupport.key(spec, "selector", {}) || {})
        @session_affinity = (session_affinity || ModelSupport.key(spec, "sessionAffinity", "None")).to_s
        raise ValidationError, "unsupported session affinity #{@session_affinity.inspect}" unless AFFINITIES.include?(@session_affinity)

        affinity_config = ModelSupport.key(ModelSupport.key(spec, "sessionAffinityConfig", {}) || {}, "clientIP", {}) || {}
        timeout_value = session_affinity_timeout_seconds || session_affinity_timeout || ModelSupport.key(affinity_config, "timeoutSeconds",
                                                                                                         10_800)
        @session_affinity_timeout_seconds = ModelSupport.strict_integer(timeout_value, "session affinity timeout") || 10_800
        unless @session_affinity_timeout_seconds.between?(
          1, MAX_SESSION_AFFINITY_TIMEOUT
        )
          raise ValidationError,
                "session affinity timeout must be between 1 and #{MAX_SESSION_AFFINITY_TIMEOUT}"
        end

        @internal_traffic_policy = (internal_traffic_policy || ModelSupport.key(spec, "internalTrafficPolicy", "Cluster")).to_s
        @external_traffic_policy = (external_traffic_policy || ModelSupport.key(spec, "externalTrafficPolicy", "Cluster")).to_s
        [@internal_traffic_policy, @external_traffic_policy].each do |policy|
          raise ValidationError, "unsupported traffic policy #{policy.inspect}" unless TRAFFIC_POLICIES.include?(policy)
        end
        @external_ips = Array(external_ips || ModelSupport.key(spec, "externalIPs", [])).filter_map do |ip|
          ModelSupport.canonical_ip(ip)
        end.uniq.freeze
        status = ModelSupport.key(source, "status", {}) || {}
        ingress = Array(ModelSupport.key(ModelSupport.key(status, "loadBalancer", {}) || {}, "ingress", []) || {})
        status_load_balancer_ips = ingress.filter_map { |entry| ModelSupport.key(ModelSupport.string_keys(entry || {}), "ip", nil) }
        @load_balancer_ips = Array(load_balancer_ips || ModelSupport.key(spec, "loadBalancerIPs",
                                                                         nil) || ModelSupport.key(spec, "loadBalancerIP",
                                                                                                  nil) || status_load_balancer_ips).filter_map do |ip|
          ModelSupport.canonical_ip(ip)
        end.uniq.freeze
        @external_name = (external_name || ModelSupport.key(spec, "externalName", nil))&.to_s
        health_port_value = health_check_node_port || ModelSupport.key(spec, "healthCheckNodePort", nil)
        @health_check_node_port = ModelSupport.strict_integer(health_port_value, "healthCheckNodePort")
        @publish_not_ready_addresses = ModelSupport.bool(
          publish_not_ready_addresses.nil? ? ModelSupport.key(spec, "publishNotReadyAddresses", false) : publish_not_ready_addresses
        )
        @allocate_load_balancer_node_ports = ModelSupport.bool(
          allocate_load_balancer_node_ports.nil? ? ModelSupport.key(spec, "allocateLoadBalancerNodePorts",
                                                                    true) : allocate_load_balancer_node_ports,
          true
        )
        @load_balancer_source_ranges = Array(load_balancer_source_ranges || ModelSupport.key(spec, "loadBalancerSourceRanges",
                                                                                             [])).map(&:to_s).freeze
        @topology_aware_hints = ModelSupport.bool(
          if topology_aware_hints.nil?
            topology_hints.nil? || topology_hints
          else
            topology_aware_hints
          end, true
        )
        @raw = ModelSupport.immutable(source)
        validate_service!
        freeze
      end

      def self.port_from(entry)
        return entry if entry.is_a?(ServicePort)

        port = ModelSupport.string_keys(entry || {})
        target = ModelSupport.key(port, "targetPort", ModelSupport.key(port, "target_port", nil))
        # SetDefaults_ServicePort: an unset targetPort is the port itself.
        # intstr's zero value is the integer 0, so a Service written before the
        # default was applied -- or by a client that sent the zero -- reaches
        # the proxy with targetPort 0, which is not a port.  Reading it as
        # "unset" is what upstream's defaulting already decided it means.
        target = nil if target == 0
        ServicePort.new(
          name: ModelSupport.key(port, "name", nil),
          port: ModelSupport.key(port, "port", nil),
          target_port: target,
          protocol: ModelSupport.key(port, "protocol", "TCP"),
          node_port: ModelSupport.key(port, "nodePort", ModelSupport.key(port, "node_port", nil)),
          app_protocol: ModelSupport.key(port, "appProtocol", nil)
        )
      end

      def key
        ModelSupport.service_key(namespace, name)
      end

      alias service_type_name service_type
      alias type service_type

      def cluster_ip
        cluster_ips.first
      end

      def session_affinity_timeout
        session_affinity_timeout_seconds
      end

      def headless?
        cluster_ips.empty?
      end

      alias headless headless?

      def cluster_ip?
        !headless?
      end

      def external_name?
        service_type == "ExternalName"
      end

      def node_port?
        %w[NodePort LoadBalancer].include?(service_type)
      end

      def vip_addresses
        (cluster_ips + external_ips + load_balancer_ips).uniq.freeze
      end

      def port_for(port:, protocol: "TCP", name: nil)
        normalized_protocol = ModelSupport.normalize_protocol(protocol)
        candidates = ports.select { |candidate| candidate.protocol == normalized_protocol }
        candidates = candidates.select { |candidate| candidate.name == name.to_s } if name
        candidates.find { |candidate| candidate.port == Integer(port) } || candidates.find do |candidate|
          candidate.node_port == Integer(port)
        end
      rescue ArgumentError, TypeError
        nil
      end

      def to_h
        {
          "apiVersion" => "v1",
          "kind" => "Service",
          "metadata" => {
            "name" => name,
            "namespace" => namespace,
            "uid" => uid,
            "resourceVersion" => resource_version,
            "generation" => generation,
            "labels" => ModelSupport.deep_copy(labels)
          }.compact,
          "spec" => {
            "type" => service_type,
            "clusterIP" => (headless? ? "None" : cluster_ips.first),
            "clusterIPs" => cluster_ips,
            "ipFamilies" => ip_families,
            "ports" => ports.map(&:to_h),
            "selector" => ModelSupport.deep_copy(selector),
            "sessionAffinity" => session_affinity,
            "internalTrafficPolicy" => internal_traffic_policy,
            "externalTrafficPolicy" => external_traffic_policy,
            "externalIPs" => external_ips,
            "loadBalancerIPs" => load_balancer_ips,
            "externalName" => external_name,
            "healthCheckNodePort" => health_check_node_port,
            "publishNotReadyAddresses" => publish_not_ready_addresses,
            "allocateLoadBalancerNodePorts" => allocate_load_balancer_node_ports
          }.compact
        }
      end

      private

      def ensure_unique_ports!
        keys = ports.map(&:key)
        raise ValidationError, "service ports must be unique by port and protocol" unless keys.uniq.length == keys.length
      end

      def validate_service!
        if external_name?
          raise ValidationError, "ExternalName requires externalName" if external_name.to_s.empty?
          raise ValidationError, "ExternalName cannot define clusterIP" if cluster_ip?
          raise ValidationError, "ExternalName cannot define externalIPs or loadBalancerIPs" if external_ips.any? || load_balancer_ips.any?
          raise ValidationError, "ExternalName must use a DNS name, not an IP address" if external_name_ip_address?
          raise ValidationError, "ExternalName contains an invalid DNS name" unless valid_external_name?
        end
        raise ValidationError, "LoadBalancer requires a cluster IP" if headless? && service_type == "LoadBalancer"
        raise ValidationError, "healthCheckNodePort must be between 1 and 65535" if health_check_node_port && !health_check_node_port.between?(1, 65_535)
        raise ValidationError, "healthCheckNodePort requires externalTrafficPolicy Local" if health_check_node_port && external_traffic_policy != "Local"

        # A headless Service has ipFamilies but no ClusterIP ("None" is
        # dropped above); only an allocated address list must line up.
        if ip_families.any? && cluster_ips.any?
          raise ValidationError, "clusterIPs and ipFamilies must have the same length" if cluster_ips.length != ip_families.length

          cluster_ips.each_with_index do |ip, index|
            next if ModelSupport.ip_family(ip) == ip_families[index]

            raise ValidationError, "service IP family does not match ipFamilies"
          end
        end
        load_balancer_source_ranges.each do |range|
          IPAddr.new(range)
        rescue IPAddr::InvalidAddressError
          raise ValidationError, "invalid load balancer source range #{range.inspect}"
        end
      end

      def external_name_ip_address?
        IPAddr.new(external_name)
        true
      rescue IPAddr::InvalidAddressError
        false
      end

      def valid_external_name?
        value = external_name.to_s.chomp(".")
        return false if value.empty? || value.bytesize > 253

        value.split(".").all? do |label|
          label.bytesize.between?(1, 63) && label.match?(/\A[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\z/)
        end
      end
    end

    # A normalized EndpointSlice endpoint.  `ready`, `serving`, and
    # `terminating` are retained independently because terminating endpoints
    # may serve existing connections while new connections avoid them.
    class Endpoint
      attr_reader :address, :addresses, :port, :port_name, :protocol, :node_name, :zone, :hostname,
                  :target_ref, :ready, :serving, :terminating, :hints, :family, :slice_name

      def initialize(value = nil, address: nil, addresses: nil, ip: nil, port: nil, protocol: nil,
                     node_name: nil, zone: nil, hostname: nil, target_ref: nil,
                     ready: nil, serving: nil, terminating: nil, hints: nil,
                     family: nil, slice_name: nil, port_name: nil, **_options)
        source = ModelSupport.string_keys(value || {})
        address ||= ip
        raw_addresses = addresses || ModelSupport.key(source, "addresses",
                                                      nil) || ModelSupport.key(source, "address",
                                                                               nil) || address || ModelSupport.key(source, "ip", nil)
        @addresses = Array(raw_addresses).map(&:to_s).reject(&:empty?).filter_map { |ip| ModelSupport.canonical_ip(ip) }.freeze
        @address = (address || @addresses.first)&.to_s
        @address = ModelSupport.canonical_ip(@address) if @address
        raise ValidationError, "endpoint address is required" if @address.to_s.empty?

        @port = ModelSupport.integer(port || ModelSupport.key(source, "port", nil), nil)
        raise ValidationError, "endpoint port is required" if @port.nil?
        raise ValidationError, "endpoint port must be between 1 and 65535" unless @port.between?(1, 65_535)

        @protocol = ModelSupport.normalize_protocol(protocol || ModelSupport.key(source, "protocol", "TCP"))
        @port_name = (port_name || ModelSupport.key(source, "name", nil))&.to_s
        @node_name = (node_name || ModelSupport.key(source, "nodeName", ModelSupport.key(source, "node_name", nil)))&.to_s
        @zone = (zone || ModelSupport.key(source, "zone", nil))&.to_s
        @hostname = (hostname || ModelSupport.key(source, "hostname", nil))&.to_s
        @target_ref = ModelSupport.immutable(target_ref || ModelSupport.key(source, "targetRef", {}) || {})
        @ready = ready.nil? ? default_condition(source, "ready", true) : ModelSupport.bool(ready, true)
        @serving = serving.nil? ? default_condition(source, "serving", @ready) : ModelSupport.bool(serving, @ready)
        @terminating = terminating.nil? ? default_condition(source, "terminating", false) : ModelSupport.bool(terminating)
        raw_hints = hints || ModelSupport.key(source, "hints", {}) || {}
        @hints = Array(ModelSupport.key(raw_hints, "forZones", nil) || ModelSupport.key(raw_hints, "for_zones", nil)).map do |hint|
          ModelSupport.key(ModelSupport.string_keys(hint), "name", hint).to_s
        end.reject(&:empty?).uniq.freeze
        @family = ModelSupport.normalize_family(family || ModelSupport.key(source, "addressType", nil) || ModelSupport.ip_family(@address))
        raise ValidationError, "endpoint address family must be IPv4 or IPv6" unless Service::IP_FAMILIES.include?(@family)

        address_families = @addresses.map { |candidate| ModelSupport.ip_family(candidate) }.uniq
        raise ValidationError, "endpoint address does not match address family #{@family}" if address_families.any? { |candidate| candidate != @family }

        @slice_name = slice_name&.to_s
        freeze
      end

      def self.from_endpoint_slice(endpoint:, port:, slice: nil, family: nil)
        source = ModelSupport.string_keys(endpoint || {})
        port_value = ModelSupport.string_keys(port || {})
        conditions = ModelSupport.key(source, "conditions", {}) || {}
        new(
          source,
          addresses: ModelSupport.key(source, "addresses", []),
          port: ModelSupport.key(port_value, "port", nil),
          port_name: ModelSupport.key(port_value, "name", nil),
          protocol: ModelSupport.key(port_value, "protocol", "TCP"),
          node_name: ModelSupport.key(source, "nodeName", nil),
          zone: ModelSupport.key(source, "zone", nil),
          hostname: ModelSupport.key(source, "hostname", nil),
          target_ref: ModelSupport.key(source, "targetRef", {}),
          ready: ModelSupport.key(conditions, "ready", nil),
          serving: ModelSupport.key(conditions, "serving", nil),
          terminating: ModelSupport.key(conditions, "terminating", nil),
          hints: ModelSupport.key(source, "hints", {}),
          family: family,
          slice_name: ModelSupport.key(ModelSupport.key(slice || {}, "metadata", {}) || {}, "name", nil)
        )
      end

      def identity
        [address, port, port_name, protocol, node_name, target_ref_identity].join("|")
      end

      alias ip address
      alias node node_name

      # kube-proxy pairs an EndpointSlice port with a Service port by *name*
      # (and protocol); the slice's number is the real target port, so
      # backends on different ports (three API servers behind
      # default/kubernetes) all qualify.  The name is the SERVICE port's name,
      # not its targetPort: upstream keys endpoints by
      # ServicePortName{namespace/name, *port.Name, protocol}
      # (pkg/proxy/endpointslicecache.go).  An unnamed Service port matches an
      # unnamed slice port, and only then does the numeric targetPort decide.
      def port_compatible?(service_port)
        return false unless service_port.respond_to?(:protocol) && service_port.protocol == protocol

        service_name = service_port.respond_to?(:name) ? service_port.name.to_s : ""
        return port_name.to_s == service_name unless service_name.empty? && port_name.to_s.empty?
        return true if service_name.empty? && port_name.to_s.empty?

        target = service_port.target_port
        return port == target.to_i if target.is_a?(Integer)

        target.nil? || target.to_s.empty? || port_name.to_s == target.to_s
      end

      def healthy?
        ready && serving && !terminating
      end

      alias ready? healthy?

      def serving?
        serving
      end

      def terminating?
        terminating
      end

      def eligible?(allow_terminating: false)
        return healthy? unless allow_terminating

        healthy? || (terminating? && serving?)
      end

      def local_to?(node)
        node && !node_name.to_s.empty? && node_name == node.to_s
      end

      def in_zone?(requested_zone)
        requested_zone && !hints.empty? && hints.include?(requested_zone.to_s)
      end

      def to_h
        {
          "addresses" => addresses,
          "name" => port_name,
          "port" => port,
          "protocol" => protocol,
          "nodeName" => node_name,
          "zone" => zone,
          "hostname" => hostname,
          "targetRef" => ModelSupport.deep_copy(target_ref),
          "conditions" => {"ready" => ready, "serving" => serving, "terminating" => terminating},
          "hints" => (hints.empty? ? nil : {"forZones" => hints.map { |name| {"name" => name} }})
        }.compact
      end

      private

      def default_condition(source, name, default)
        value = ModelSupport.key(ModelSupport.key(source, "conditions", {}) || {}, name, default)
        ModelSupport.bool(value, default)
      end

      def target_ref_identity
        return "" unless target_ref.is_a?(Hash)

        [ModelSupport.key(target_ref, "namespace", ""), ModelSupport.key(target_ref, "name", ""),
         ModelSupport.key(target_ref, "uid", "")].join("/")
      end
    end

    # EndpointSlice model with a stable service association.
    class EndpointSlice
      attr_reader :name, :namespace, :uid, :resource_version, :service_name,
                  :address_type, :ports, :endpoints, :raw

      def initialize(object = nil, name: nil, namespace: nil, service_name: nil,
                     address_type: nil, ports: nil, endpoints: nil, **options)
        object = options if object.nil? && (options.key?(:metadata) || options.key?("metadata") || options.key?(:spec) || options.key?("spec"))
        source = ModelSupport.string_keys(object || {})
        metadata = ModelSupport.key(source, "metadata", {})
        @name = (name || ModelSupport.key(metadata, "name", nil)).to_s
        @namespace = (namespace || ModelSupport.key(metadata, "namespace", "default")).to_s
        @uid = ModelSupport.key(metadata, "uid", nil)&.to_s
        @resource_version = ModelSupport.key(metadata, "resourceVersion", nil)&.to_s
        labels = ModelSupport.key(metadata, "labels", {}) || {}
        @service_name = (service_name || ModelSupport.key(labels, "kubernetes.io/service-name",
                                                          nil) || ModelSupport.key(source, "serviceName", nil)).to_s
        raise ValidationError, "endpoint slice name is required" if @name.empty?
        raise ValidationError, "endpoint slice service name is required" if @service_name.empty?

        spec = ModelSupport.key(source, "spec", source)
        @address_type = ModelSupport.normalize_family(address_type || ModelSupport.key(spec, "addressType", "IPv4"))
        raise ValidationError, "endpoint slice addressType must be IPv4 or IPv6" unless %w[IPv4 IPv6].include?(@address_type)

        raw_ports = ports || ModelSupport.key(spec, "ports", [])
        @ports = ModelSupport.immutable(Array(raw_ports).map { |entry| ModelSupport.string_keys(entry || {}) })
        raw_endpoints = endpoints || ModelSupport.key(spec, "endpoints", [])
        @endpoints = Array(raw_endpoints).flat_map do |endpoint|
          source_endpoint = ModelSupport.string_keys(endpoint || {})
          addresses = Array(ModelSupport.key(source_endpoint, "addresses", []))
          @ports.flat_map do |port|
            addresses.map do |address|
              Endpoint.from_endpoint_slice(endpoint: source_endpoint.merge("addresses" => [address]), port: port,
                                           slice: source, family: @address_type)
            end
          end
        end.freeze
        @raw = ModelSupport.immutable(source)
        freeze
      end

      def key
        ModelSupport.service_key(namespace, service_name)
      end

      def endpoint_set
        endpoints.map(&:identity).sort.freeze
      end

      def to_h
        {
          "apiVersion" => "discovery.k8s.io/v1",
          "kind" => "EndpointSlice",
          "metadata" => {"name" => name, "namespace" => namespace, "uid" => uid, "resourceVersion" => resource_version}.compact,
          "addressType" => address_type,
          "ports" => ModelSupport.deep_copy(ports),
          "endpoints" => endpoints.map(&:to_h)
        }
      end
    end

    # Packet input accepted by the datapath.  A plain Hash remains supported
    # by Proxy#route; this object gives callers a typed, immutable alternative.
    class Packet
      attr_reader :source_ip, :source_port, :destination_ip, :destination_port,
                  :protocol, :node_name, :zone, :external, :connection_id,
                  :metadata

      def initialize(value = nil, source_ip: nil, source_port: nil, destination_ip: nil,
                     destination_port: nil, protocol: nil, node_name: nil, zone: nil,
                     external: nil, connection_id: nil, metadata: {}, **_options)
        source = ModelSupport.string_keys(value || {})
        @source_ip = ModelSupport.canonical_ip(source_ip || ModelSupport.key(source, "sourceIP",
                                                                             ModelSupport.key(source, "srcIP", ModelSupport.key(source, "source", nil))))
        @source_port = ModelSupport.integer(source_port || ModelSupport.key(source, "sourcePort", ModelSupport.key(source, "srcPort", nil)))
        @destination_ip = ModelSupport.canonical_ip(destination_ip || ModelSupport.key(source, "destinationIP",
                                                                                       ModelSupport.key(source, "dstIP", ModelSupport.key(source, "destination", nil))))
        @destination_port = ModelSupport.integer(destination_port || ModelSupport.key(source, "destinationPort",
                                                                                      ModelSupport.key(source, "dstPort", nil)))
        @protocol = ModelSupport.normalize_protocol(protocol || ModelSupport.key(source, "protocol", "TCP"))
        @node_name = (node_name || ModelSupport.key(source, "nodeName", ModelSupport.key(source, "node", nil)))&.to_s
        @zone = (zone || ModelSupport.key(source, "zone", nil))&.to_s
        @external = external.nil? ? ModelSupport.key(source, "external", nil) : external
        @external = nil if @external.nil?
        @external = ModelSupport.bool(@external) unless @external.nil?
        @connection_id = (connection_id || ModelSupport.key(source, "connectionID", ModelSupport.key(source, "connection_id", nil)))&.to_s
        @metadata = ModelSupport.immutable(metadata || {})
        raise ValidationError, "destination IP is required" if destination_ip.to_s.empty? && @destination_ip.nil?
        raise ValidationError, "destination port is required" if @destination_port.nil?
        raise ValidationError, "source port must be between 0 and 65535" if @source_port && !@source_port.between?(0, 65_535)
        raise ValidationError, "destination port must be between 1 and 65535" unless @destination_port.between?(1, 65_535)

        freeze
      end

      def key
        [protocol, source_ip, source_port, destination_ip, destination_port].freeze
      end

      alias src_ip source_ip
      alias src_port source_port
      alias dst_ip destination_ip
      alias dst_port destination_port
      alias node node_name

      def to_h
        {
          "sourceIP" => source_ip,
          "sourcePort" => source_port,
          "destinationIP" => destination_ip,
          "destinationPort" => destination_port,
          "protocol" => protocol,
          "nodeName" => node_name,
          "zone" => zone,
          "external" => external,
          "connectionID" => connection_id
        }.compact
      end
    end
  end
end
