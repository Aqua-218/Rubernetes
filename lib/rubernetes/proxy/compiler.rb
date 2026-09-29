# frozen_string_literal: true

require "digest"
require "json"

module Rubernetes
  module Proxy
    # A datapath rule is deliberately backend-neutral.  eBPF and nftables
    # consume the same immutable rule so their routing semantics cannot drift.
    class Rule
      attr_reader :key, :service_key, :service_type, :kind, :virtual_ip,
                  :port, :protocol, :node_port, :health_check, :backends,
                  :external_traffic_policy, :internal_traffic_policy,
                  :session_affinity, :session_affinity_timeout_seconds,
                  :metadata

      def initialize(service_key:, service_type:, kind:, virtual_ip: nil, port:, protocol:,
                     node_port: nil, health_check: false, backends: [],
                     external_traffic_policy: "Cluster", internal_traffic_policy: "Cluster",
                     session_affinity: "None", session_affinity_timeout_seconds: 10_800,
                     metadata: {})
        @service_key = service_key.to_s.freeze
        @service_type = service_type.to_s.freeze
        @kind = kind.to_s.freeze
        @virtual_ip = virtual_ip&.to_s&.freeze
        @port = Integer(port)
        @protocol = protocol.to_s.upcase.freeze
        @node_port = node_port.nil? ? nil : Integer(node_port)
        @health_check = !!health_check
        @backends = Array(backends).sort_by { |backend| backend.respond_to?(:identity) ? backend.identity : backend.to_s }.freeze
        @external_traffic_policy = external_traffic_policy.to_s.freeze
        @internal_traffic_policy = internal_traffic_policy.to_s.freeze
        @session_affinity = session_affinity.to_s.freeze
        @session_affinity_timeout_seconds = Integer(session_affinity_timeout_seconds)
        @metadata = ModelSupport.immutable(metadata || {})
        @key = [@kind, @service_key, @virtual_ip, @port, @protocol, @node_port].freeze
        freeze
      end

      alias virtual_address virtual_ip
      alias target_port port

      def ==(other)
        other.is_a?(Rule) && to_h == other.to_h
      end

      alias eql? ==

      def hash
        to_h.hash
      end

      def backend_ids
        backends.map { |backend| backend.respond_to?(:identity) ? backend.identity : backend.to_s }
      end

      def to_h
        {
          "key" => key,
          "serviceKey" => service_key,
          "serviceType" => service_type,
          "kind" => kind,
          "virtualIP" => virtual_ip,
          "port" => port,
          "protocol" => protocol,
          "nodePort" => node_port,
          "healthCheck" => health_check,
          "backends" => backends.map { |backend| backend.respond_to?(:to_h) ? backend.to_h : backend },
          "externalTrafficPolicy" => external_traffic_policy,
          "internalTrafficPolicy" => internal_traffic_policy,
          "sessionAffinity" => session_affinity,
          "sessionAffinityTimeoutSeconds" => session_affinity_timeout_seconds,
          "metadata" => ModelSupport.deep_copy(metadata)
        }
      end
    end

    # Immutable result of compiling one Service and its EndpointSlices.
    class CompiledService
      attr_reader :service, :endpoints, :rules, :revision, :digest, :compiled_at

      def initialize(service:, endpoints:, rules:, revision: 0, compiled_at: nil)
        @service = service
        @endpoints = Array(endpoints).sort_by(&:identity).freeze
        @rules = Array(rules).sort_by(&:key).freeze
        @revision = Integer(revision)
        @digest = Digest::SHA256.hexdigest(
          JSON.generate(ModelSupport.canonicalize(@rules.map(&:to_h)))
        ).freeze
        @compiled_at = compiled_at
        freeze
      end

      def service_key
        service.key
      end

      def rule_map
        rules.each_with_object({}) { |rule, result| result[rule.key] = rule }
      end

      def headless?
        service.headless?
      end

      def external_name?
        service.external_name?
      end

      def to_h
        {
          "service" => service.to_h,
          "endpoints" => endpoints.map(&:to_h),
          "rules" => rules.map(&:to_h),
          "revision" => revision,
          "digest" => digest
        }
      end
    end

    # Rules are generated from a Service + all of its EndpointSlices.  The
    # compiler performs no I/O and is therefore safe to run in a watch thread
    # before atomically publishing the resulting RuleSet.
    class RuleCompiler
      attr_reader :local_node, :node_addresses, :node_zone

      def initialize(local_node: nil, node_addresses: [], node_name: nil, node_zone: nil, zone: nil)
        @local_node = (local_node || node_name)&.to_s
        @node_addresses = Array(node_addresses).map { |ip| ModelSupport.canonical_ip(ip) }.compact.freeze
        @node_zone = (node_zone || zone)&.to_s
      end

      def compile(service, endpoint_slices = nil, endpoints: nil, revision: 0, compiled_at: nil, **options)
        endpoint_slices ||= options[:endpoint_slices] || options["endpoint_slices"]
        endpoint_slices ||= []
        normalized_service = service.is_a?(Service) ? service : Service.new(service)
        normalized_endpoints = if endpoints
                                 Array(endpoints).map { |endpoint| endpoint.is_a?(Endpoint) ? endpoint : Endpoint.new(endpoint) }
                               else
                                 Array(endpoint_slices).flat_map do |slice|
                                   normalized_slice = slice.is_a?(EndpointSlice) ? slice : EndpointSlice.new(slice)
                                   normalized_slice.key == normalized_service.key ? normalized_slice.endpoints : []
                                 end
                               end
        normalized_endpoints = normalized_endpoints.select { |endpoint| endpoint_matches_service?(endpoint, normalized_service) }
        rules = compile_rules(normalized_service, normalized_endpoints)
        CompiledService.new(service: normalized_service, endpoints: normalized_endpoints, rules: rules,
                            revision: revision, compiled_at: compiled_at)
      end

      alias call compile

      private

      def endpoint_matches_service?(endpoint, service)
        return true if service.external_name?

        family_allowed = service.ip_families.empty? || service.ip_families.include?(endpoint.family)
        protocol_allowed = service.ports.any? { |port| port.protocol == endpoint.protocol }
        family_allowed && protocol_allowed
      end

      def compile_rules(service, endpoints)
        return [] if service.external_name?

        rules = []
        service.ports.each do |service_port|
          endpoint_set = endpoints.select { |endpoint| endpoint.protocol == service_port.protocol }
          if service.cluster_ip?
            service.cluster_ips.each do |vip|
              backend_groups = backend_groups_for(service, service_port, endpoint_set, family: ModelSupport.ip_family(vip))
              rules << build_rule(service, service_port, backend_groups, kind: "ClusterIP", virtual_ip: vip)
            end
          end
          service.external_ips.each do |vip|
            backend_groups = backend_groups_for(service, service_port, endpoint_set, family: ModelSupport.ip_family(vip))
            rules << build_rule(service, service_port, backend_groups, kind: "ExternalIP", virtual_ip: vip)
          end
          service.load_balancer_ips.each do |vip|
            backend_groups = backend_groups_for(service, service_port, endpoint_set, family: ModelSupport.ip_family(vip))
            rules << build_rule(service, service_port, backend_groups, kind: "LoadBalancer", virtual_ip: vip)
          end
          if service.node_port?
            node_port = service_port.node_port
            if node_port
              backend_groups = backend_groups_for(service, service_port, endpoint_set)
              rules << build_rule(service, service_port, backend_groups, kind: "NodePort", virtual_ip: nil, node_port: node_port)
            end
          end
        end
        if service.node_port? && service.health_check_node_port
          health_port = service.ports.find { |service_port| service_port.protocol == "TCP" }
          health_port ||= ServicePort.new(port: service.health_check_node_port,
                                          target_port: service.health_check_node_port, protocol: "TCP")
          health_groups = backend_groups_for(service, health_port, endpoints)
          rules << build_rule(service, health_port, health_groups, kind: "HealthCheckNodePort", virtual_ip: nil,
                              node_port: service.health_check_node_port, health_check: true)
        end
        rules
      end

      def backend_groups_for(service, service_port, endpoints, family: nil)
        endpoint_set = endpoints.select do |endpoint|
          endpoint.port_compatible?(service_port) && (family.nil? || endpoint.family == family)
        end
        # EndpointSlice ports can use a named target port.  Endpoint#port is
        # already the resolved numeric target port, so only protocol matters
        # here; named target ports are handled by Endpoint#port_compatible?.
        {
          "all" => stable_endpoints(endpoint_set),
          "local" => stable_endpoints(endpoint_set.select { |endpoint| endpoint.local_to?(local_node) }),
          "healthy" => stable_endpoints(endpoint_set.select(&:healthy?)),
          "serving" => stable_endpoints(endpoint_set.select(&:serving?)),
          "terminating" => stable_endpoints(endpoint_set.select(&:terminating?))
        }
      end

      def stable_endpoints(endpoints)
        Array(endpoints).sort_by(&:identity)
      end

      def build_rule(service, service_port, groups, kind:, virtual_ip:, node_port: nil, health_check: false)
        metadata = {
          "backendGroups" => groups.transform_values { |items| items.map(&:identity) },
          "node" => local_node,
          "nodeAddresses" => node_addresses,
          "zone" => @node_zone,
          "topologyAwareHints" => service.topology_aware_hints,
          "servicePort" => service_port.to_h,
          "serviceFamilies" => service.ip_families,
          "publishNotReadyAddresses" => service.publish_not_ready_addresses,
          "loadBalancerSourceRanges" => service.load_balancer_source_ranges
        }
        Rule.new(
          service_key: service.key,
          service_type: service.service_type,
          kind: kind,
          virtual_ip: virtual_ip,
          port: service_port.port,
          protocol: service_port.protocol,
          node_port: node_port,
          health_check: health_check,
          backends: groups.fetch("all"),
          external_traffic_policy: service.external_traffic_policy,
          internal_traffic_policy: service.internal_traffic_policy,
          session_affinity: service.session_affinity,
          session_affinity_timeout_seconds: service.session_affinity_timeout_seconds,
          metadata: metadata
        )
      end
    end

    ServiceCompiler = RuleCompiler
    Compiler = RuleCompiler

    # A compiled rule change.  Add/update/delete are all explicit so backends
    # can apply a differential transaction without flushing existing rules.
    class RuleDiff
      attr_reader :added, :updated, :deleted, :from_revision, :to_revision, :digest

      def initialize(added: [], updated: [], deleted: [], from_revision: 0, to_revision: 0)
        @added = Array(added).sort_by(&:key).freeze
        @updated = Array(updated).sort_by { |pair| pair.is_a?(Array) ? pair.first.key : pair.key }
                              .map { |pair| pair.is_a?(Array) ? pair.freeze : pair }.freeze
        @deleted = Array(deleted).sort_by { |entry| entry.is_a?(Rule) ? entry.key : entry }.freeze
        @from_revision = Integer(from_revision)
        @to_revision = Integer(to_revision)
        @digest = Digest::SHA256.hexdigest(JSON.generate(ModelSupport.canonicalize(to_h))).freeze
        freeze
      end

      def empty?
        added.empty? && updated.empty? && deleted.empty?
      end

      def changes
        added + updated + deleted
      end

      def to_h
        {
          "fromRevision" => from_revision,
          "toRevision" => to_revision,
          "added" => added.map(&:to_h),
          "updated" => updated.map { |old_rule, new_rule| {"before" => old_rule.to_h, "after" => new_rule.to_h} },
          "deleted" => deleted.map { |entry| entry.respond_to?(:to_h) ? entry.to_h : entry }
        }
      end
    end

    class RuleSet
      attr_reader :revision, :rules, :last_diff

      def initialize
        @mutex = Mutex.new
        @rules = {}
        @revision = 0
        @last_diff = RuleDiff.new
      end

      def snapshot
        @mutex.synchronize { @rules.values.sort_by(&:key).freeze }
      end

      def [](key)
        @mutex.synchronize { @rules[key] }
      end

      def apply(compiled_or_rules, revision: nil)
        incoming = if compiled_or_rules.respond_to?(:rule_map)
                     compiled_or_rules.rule_map
                   else
                     Array(compiled_or_rules).each_with_object({}) { |rule, result| result[rule.key] = rule }
                   end
        incoming = incoming.freeze
        @mutex.synchronize do
          next_revision = revision.nil? ? @revision + 1 : Integer(revision)
          raise StaleRevisionError, "rule revision #{next_revision} is older than #{@revision}" if next_revision < @revision

          added = incoming.keys.reject { |key| @rules.key?(key) }.map { |key| incoming.fetch(key) }
          deleted = @rules.keys.reject { |key| incoming.key?(key) }.map { |key| @rules.fetch(key) }
          updated = incoming.keys.filter_map do |key|
            old_rule = @rules[key]
            new_rule = incoming[key]
            old_rule && new_rule != old_rule ? [old_rule, new_rule] : nil
          end
          from_revision = @revision
          @rules = incoming
          @revision = next_revision
          @last_diff = RuleDiff.new(added: added, updated: updated, deleted: deleted,
                                    from_revision: from_revision, to_revision: @revision)
        end
      end

      alias apply_diff apply
    end

    # Thread-safe Service/EndpointSlice cache.  A watcher adapter can call the
    # apply/delete methods directly; callbacks receive immutable snapshots.
    class EndpointStore
      attr_reader :revision

      def initialize(clock: -> { Time.now.utc })
        @clock = clock
        @mutex = Mutex.new
        @services = {}
        @slices = {}
        @revision = 0
        @subscribers = []
      end

      def apply_service(value)
        service = value.is_a?(Service) ? value : Service.new(value)
        publish(:service, service.key, service)
        service
      end

      alias upsert_service apply_service

      def delete_service(value, namespace: nil)
        key = if value.is_a?(Service)
                value.key
              elsif value.to_s.include?("/")
                value.to_s
              else
                ModelSupport.service_key(namespace || "default", value)
              end
        removed = nil
        revision = nil
        @mutex.synchronize do
          removed = @services.delete(key)
          @slices.delete_if { |_slice_key, slice| slice.key == key }
          @revision += 1 if removed
          revision = @revision
        end
        notify(:service_deleted, key, removed, revision: revision) if removed
        removed
      end

      def apply_endpoint_slice(value)
        slice = value.is_a?(EndpointSlice) ? value : EndpointSlice.new(value)
        publish(:endpoint_slice, [slice.key, slice.name], slice)
        slice
      end

      alias upsert_endpoint_slice apply_endpoint_slice

      def delete_endpoint_slice(value, namespace: nil, name: nil)
        key = if value.is_a?(EndpointSlice)
                [value.key, value.name]
              elsif value.is_a?(Hash)
                object = ModelSupport.string_keys(value)
                metadata = ModelSupport.key(object, "metadata", {})
                [ModelSupport.service_key(namespace || ModelSupport.key(metadata, "namespace", "default"),
                                           ModelSupport.key(ModelSupport.key(metadata, "labels", {}) || {}, "kubernetes.io/service-name", "")),
                 name || ModelSupport.key(metadata, "name", "")]
              else
                [ModelSupport.service_key(namespace || "default", ""), name || value.to_s]
              end
        removed = nil
        revision = nil
        @mutex.synchronize do
          removed = @slices.delete(key)
          @revision += 1 if removed
          revision = @revision
        end
        notify(:endpoint_slice_deleted, key, removed, revision: revision) if removed
        removed
      end

      def service(key, namespace: nil)
        normalized = key.is_a?(Service) ? key.key : (key.to_s.include?("/") ? key.to_s : ModelSupport.service_key(namespace || "default", key))
        @mutex.synchronize { @services[normalized] }
      end

      alias [] service

      def services
        @mutex.synchronize { @services.values.sort_by(&:key).freeze }
      end

      def endpoint_slices(service_key = nil, namespace: nil, name: nil)
        normalized = if service_key.nil?
                       nil
                     elsif service_key.to_s.include?("/")
                       service_key.to_s
                     else
                       ModelSupport.service_key(namespace || "default", service_key)
                     end
        @mutex.synchronize do
          result = @slices.values
          result = result.select { |slice| slice.key == normalized } if normalized
          result = result.select { |slice| slice.name == name.to_s } if name
          result.sort_by(&:name).freeze
        end
      end

      def endpoints_for(service_key, namespace: nil)
        endpoint_slices(service_key, namespace: namespace).flat_map(&:endpoints).sort_by(&:identity).freeze
      end

      def subscribe(&block)
        raise ArgumentError, "subscriber block is required" unless block

        @mutex.synchronize { @subscribers << block }
        Subscription.new(self, block)
      end

      def watch(kind = nil, **options, &block)
        return subscribe(&block) if block

        if respond_to_watch_source?(options[:source])
          options.fetch(:source).watch(kind, **options.except(:source))
        else
          watcher = Watcher.new
          subscription = subscribe do |event|
            watcher.push(event) if kind.nil? || event.kind == kind.to_sym
          end
          watcher.attach(subscription)
          watcher
        end
      end

      def snapshot
        @mutex.synchronize do
          {
            services: @services.values.sort_by(&:key).freeze,
            endpoint_slices: @slices.values.sort_by { |slice| [slice.key, slice.name] }.freeze,
            revision: @revision
          }.freeze
        end
      end

      private

      def publish(kind, key, value)
        revision = nil
        @mutex.synchronize do
          if kind == :service
            @services[key] = value
          else
            @slices[key] = value
          end
          @revision += 1
          revision = @revision
        end
        notify(kind, key, value, revision: revision)
      end

      def notify(kind, key, value, revision: nil)
        revision ||= @mutex.synchronize { @revision }
        event = Event.new(kind: kind, key: key, object: value, revision: revision, at: @clock.call)
        subscribers = @mutex.synchronize { @subscribers.dup }
        subscribers.each { |subscriber| subscriber.call(event) }
        event
      end

      def respond_to_watch_source?(source)
        source && source.respond_to?(:watch)
      end

      Event = Struct.new(:kind, :key, :object, :revision, :at, keyword_init: true) do
        def initialize(**attributes)
          super(**attributes)
          freeze
        end

        def type
          kind.to_s.upcase
        end
      end

      class Subscription
        def initialize(store, block)
          @store = store
          @block = block
          @closed = false
        end

        def close
          return false if @closed

          @closed = true
          @store.remove_subscriber(@block)
          true
        end

        alias stop close
      end

      # Blocking watch stream used when a caller does not provide a callback.
      # It keeps the subscription alive until close and has bounded memory so a
      # stalled consumer cannot grow without limit.
      class Watcher
        def initialize(capacity: 1_024)
          @capacity = Integer(capacity)
          raise ArgumentError, "watch capacity must be positive" unless @capacity.positive?
          @mutex = Mutex.new
          @condition = ConditionVariable.new
          @events = []
          @closed = false
          @subscription = nil
        end

        def attach(subscription)
          @subscription = subscription
          self
        end

        def push(event)
          @mutex.synchronize do
            return false if @closed
            @events.shift if @events.length >= @capacity
            @events << event
            @condition.broadcast
          end
          true
        end

        def next(timeout: nil)
          deadline = timeout && Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout.to_f
          @mutex.synchronize do
            loop do
              return @events.shift unless @events.empty?
              return nil if @closed
              remaining = deadline && deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
              return nil if remaining && remaining <= 0
              @condition.wait(@mutex, remaining)
            end
          end
        end

        def each(timeout: nil)
          return enum_for(__method__, timeout: timeout) unless block_given?

          loop do
            event = self.next(timeout: timeout)
            break if event.nil?
            yield event
          end
          self
        end

        def close
          @mutex.synchronize do
            return self if @closed
            @closed = true
            @condition.broadcast
          end
          @subscription&.close
          self
        end

        alias stop close

        def closed?
          @mutex.synchronize { @closed }
        end
      end

      public

      def remove_subscriber(block)
        @mutex.synchronize { @subscribers.delete(block) }
      end
    end
  end
end
