# frozen_string_literal: true

module Rubernetes
  module Proxy
    # A transactional in-memory store used by default.  The allocator accepts
    # any Store implementing `transaction`, `reservations`, and `replace` so a
    # durable API/RAFT store can provide the same atomic boundary.
    class NodePortStore
      Transaction = Struct.new(:reservations, keyword_init: true) do
        def initialize(reservations: {})
          super(reservations: reservations.each_with_object({}) { |(key, value), copy| copy[key] = value.dup })
        end

        def reserve(key, value)
          reservations[key] = value
        end

        def release(key)
          reservations.delete(key)
        end

        def [](key)
          reservations[key]
        end
      end

      def initialize
        @mutex = Mutex.new
        @reservations = {}
        @transactions = 0
      end

      attr_reader :transactions

      def transaction
        raise ArgumentError, "transaction block is required" unless block_given?

        @mutex.synchronize do
          @transactions += 1
          transaction = Transaction.new(reservations: @reservations)
          result = yield(transaction)
          @reservations = transaction.reservations
          result
        end
      end

      def reservations
        @mutex.synchronize { @reservations.each_with_object({}) { |(key, value), copy| copy[key] = value.dup }.freeze }
      end

      def [](key)
        @mutex.synchronize { @reservations[key]&.dup }
      end

      def clear
        @mutex.synchronize { @reservations.clear }
      end
    end

    class NodePortReservation
      attr_reader :service_key, :protocol, :port, :node_port

      def initialize(service_key:, protocol:, port:, node_port:)
        @service_key = service_key.to_s.freeze
        @protocol = protocol.to_s.upcase.freeze
        @port = Integer(port)
        @node_port = Integer(node_port)
        freeze
      end

      def key
        [service_key, protocol, port].freeze
      end

      def to_h
        {"serviceKey" => service_key, "protocol" => protocol, "port" => port, "nodePort" => node_port}
      end
    end

    # Kubernetes NodePort allocation with a single Store transaction for all
    # ports of one Service.  No in-memory side write is made before the Store
    # transaction commits, so partial allocations cannot escape an error.
    class NodePortAllocator
      DEFAULT_MIN = 30_000
      DEFAULT_MAX = 32_767
      DEFAULT_RANGE = (DEFAULT_MIN..DEFAULT_MAX)

      attr_reader :store, :range_min, :range_max

      def initialize(store: NodePortStore.new, min: DEFAULT_MIN, max: DEFAULT_MAX,
                     range: nil, clock: -> { Time.now.utc })
        @store = store
        if range
          @range_min, @range_max = Array(range).map { |value| Integer(value) }
        else
          @range_min = Integer(min)
          @range_max = Integer(max)
        end
        raise ArgumentError, "node port range is invalid" unless @range_min.between?(1, 65_535) && @range_max.between?(@range_min, 65_535)

        @clock = clock
      end

      def allocate(service_key = nil, protocol: "TCP", port: nil, requested: nil, transaction: nil, **options)
        service_key ||= options[:service] || options["service"] || options[:service_key] || options["service_key"]
        raise ArgumentError, "service_key is required" if service_key.nil?

        normalized_protocol = ModelSupport.normalize_protocol(protocol)
        operation = lambda do |tx|
          normalized_service = service_key.to_s
          service_port = Integer(port || requested || 0)
          raise AllocationError, "service port must be between 1 and 65535" unless service_port.between?(1, 65_535)

          requested_port = requested.nil? ? nil : Integer(requested)
          validate_requested!(requested_port) if requested_port
          existing = find_reservation(tx, normalized_service, normalized_protocol, service_port)
          if existing
            if requested_port && existing["nodePort"].to_i != requested_port
              raise AllocationError, "service port #{normalized_service}/#{service_port} is already allocated to #{existing["nodePort"]}"
            end

            return reservation_from(existing)
          end
          node_port = requested_port || find_free_port(tx, normalized_protocol)
          collision = reservation_for_node_port(tx, normalized_protocol, node_port)
          if collision && reservation_key(collision["serviceKey"].to_s, collision["protocol"].to_s,
                                          collision["port"].to_i) != reservation_key(normalized_service, normalized_protocol, service_port)
            raise AllocationError, "node port #{node_port} is already allocated"
          end

          timestamp = @clock.call
          record = {
            "serviceKey" => normalized_service,
            "protocol" => normalized_protocol,
            "port" => service_port,
            "nodePort" => node_port,
            "allocatedAt" => timestamp.respond_to?(:iso8601) ? timestamp.iso8601(9) : timestamp.to_s
          }
          tx.reserve(reservation_key(normalized_service, normalized_protocol, service_port), record)
          reservation_from(record)
        end
        return operation.call(transaction) if transaction

        @store.transaction { |tx| operation.call(tx) }
      end

      alias reserve allocate

      def allocate_for_service(service_value)
        service = service_value.is_a?(Service) ? service_value : Service.new(service_value)
        return service unless service.node_port?
        return service if service.service_type == "LoadBalancer" && !service.allocate_load_balancer_node_ports

        @store.transaction do |tx|
          allocated_ports = service.ports.map do |service_port|
            requested = service_port.node_port
            allocate(service_key: service.key, protocol: service_port.protocol, port: service_port.port,
                     requested: requested, transaction: tx)
          end
          health_reservation = if service.health_check_node_port
                                 allocate(service_key: service.key, protocol: "TCP",
                                          port: service.health_check_node_port,
                                          requested: service.health_check_node_port,
                                          transaction: tx)
                               end
          desired_keys = allocated_ports.map(&:key)
          desired_keys << health_reservation.key if health_reservation
          tx.reservations.keys.each do |key|
            record = tx.reservations[key]
            next unless record["serviceKey"].to_s == service.key
            next if desired_keys.include?(reservation_key(record["serviceKey"].to_s, record["protocol"].to_s,
                                                          record["port"].to_i))

            tx.release(key)
          end
          replace_service_ports(service, allocated_ports)
        end
      end

      alias allocate_service allocate_for_service

      def release(service_key = nil, protocol: nil, port: nil, **options)
        service_key ||= options[:service] || options["service"] || options[:service_key] || options["service_key"]
        raise ArgumentError, "service_key is required" if service_key.nil?

        @store.transaction do |tx|
          keys = tx.reservations.keys.select do |key|
            record = tx.reservations[key]
            next false unless record["serviceKey"].to_s == service_key.to_s
            next false if protocol && record["protocol"].to_s != protocol.to_s.upcase
            next false if port && record["port"].to_i != Integer(port)

            true
          end
          keys.each { |key| tx.release(key) }
          keys.length
        end
      end

      def release_service(service_value)
        service = service_value.is_a?(Service) ? service_value : Service.new(service_value)
        release(service_key: service.key)
      end

      def reservation(service_key:, protocol:, port:)
        record = if @store.respond_to?(:reservations)
                   @store.reservations.values.find do |value|
                     value["serviceKey"].to_s == service_key.to_s && value["protocol"].to_s == protocol.to_s.upcase && value["port"].to_i == Integer(port)
                   end
                 end
        record && reservation_from(record)
      end

      def allocations
        records = @store.respond_to?(:reservations) ? @store.reservations.values : []
        records.map { |record| reservation_from(record) }.sort_by { |entry| [entry.node_port, entry.protocol, entry.service_key] }.freeze
      end

      private

      def reservation_key(service_key, protocol, port)
        [service_key, protocol, port].freeze
      end

      def find_reservation(tx, service_key, protocol, port)
        tx.reservations[reservation_key(service_key, protocol, port)]
      end

      def reservation_for_node_port(tx, protocol, node_port)
        tx.reservations.values.find { |record| record["protocol"].to_s == protocol && record["nodePort"].to_i == node_port }
      end

      def find_free_port(tx, protocol)
        used = tx.reservations.values.filter_map do |record|
          record["nodePort"].to_i if record["protocol"].to_s == protocol
        end
        (@range_min..@range_max).find { |candidate| !used.include?(candidate) } || raise(AllocationError, "node port range is exhausted")
      end

      def validate_requested!(node_port)
        return if node_port.between?(@range_min, @range_max)

        raise AllocationError, "requested node port #{node_port} is outside #{@range_min}..#{@range_max}"
      end

      def reservation_from(record)
        NodePortReservation.new(service_key: record["serviceKey"], protocol: record["protocol"],
                                port: record["port"], node_port: record["nodePort"])
      end

      def replace_service_ports(service, allocated)
        by_key = allocated.to_h { |reservation| [[reservation.port, reservation.protocol], reservation] }
        ports = service.ports.map do |service_port|
          reservation = by_key[[service_port.port, service_port.protocol]]
          ServicePort.new(name: service_port.name, port: service_port.port, target_port: service_port.target_port,
                          protocol: service_port.protocol, node_port: reservation&.node_port || service_port.node_port,
                          app_protocol: service_port.app_protocol)
        end
        Service.new(service.raw.merge("metadata" => service.raw.fetch("metadata", {}).merge("name" => service.name,
                                                                                            "namespace" => service.namespace),
                                      "spec" => service.raw.fetch("spec",
                                                                  {}).merge("ports" => ports.map(&:to_h))),
                    name: service.name, namespace: service.namespace, uid: service.uid, service_type: service.service_type,
                    cluster_ips: service.cluster_ips, ip_families: service.ip_families, ports: ports,
                    selector: service.selector, session_affinity: service.session_affinity,
                    session_affinity_timeout_seconds: service.session_affinity_timeout_seconds,
                    internal_traffic_policy: service.internal_traffic_policy,
                    external_traffic_policy: service.external_traffic_policy,
                    external_ips: service.external_ips, load_balancer_ips: service.load_balancer_ips,
                    external_name: service.external_name, health_check_node_port: service.health_check_node_port,
                    publish_not_ready_addresses: service.publish_not_ready_addresses,
                    allocate_load_balancer_node_ports: service.allocate_load_balancer_node_ports,
                    load_balancer_source_ranges: service.load_balancer_source_ranges,
                    topology_aware_hints: service.topology_aware_hints)
      end
    end

    TransactionalNodePortAllocator = NodePortAllocator
  end
end
