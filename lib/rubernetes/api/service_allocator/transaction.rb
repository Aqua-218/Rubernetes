# frozen_string_literal: true

module Rubernetes
  module API
    class ServiceAllocator
      class Transaction
        def initialize(allocator)
          @allocator = allocator
          @reservations = []
          @node_ports = {}
          @release_on_commit = nil
          @committed = false
        end

        attr_reader :reservations
        attr_writer :release_on_commit, :release_ports_on_commit

        def claim_node_port(port, service)
          return true if @node_ports.key?(port)

          record = @allocator.node_port_reservations.claim(port, service)
          @node_ports[port] = record if record
          !record.nil?
        end

        def write_preconditions
          versions = @node_ports.to_h do |port, record|
            [@allocator.node_port_reservations.key(port), record.dig("metadata", "resourceVersion")]
          end
          @reservations.each do |record|
            name = record.dig("metadata", "name")
            versions[@allocator.ipaddress_key(name)] = record.dig("metadata", "resourceVersion")
          end
          versions.empty? ? {} : {related_versions: versions}
        end

        def commit!
          @committed = true
          @allocator.release_committed_ips(@release_on_commit) if @release_on_commit
          @allocator.release_committed_ports(*@release_ports_on_commit) if @release_ports_on_commit
        end

        def finish
          return if @committed

          @allocator.rollback_reservations(@reservations)
          @allocator.rollback_node_ports(@node_ports.values)
        end
      end

      def transaction
        transaction = Transaction.new(self)
        yield transaction
      ensure
        transaction&.finish
      end

      def release_committed_ips(service)
        release_cluster_ips!(service)
      rescue StandardError
        @metrics&.increment("apiserver_clusterip_repair_reconcile_errors_total")
      end

      def node_port_reservations
        @node_port_reservations ||= NodePortReservations.new(@store, service_resource, @clock)
      end

      def ipaddress_key(ip)
        @store.object_key(ipaddress_resource, :cluster, ip)
      end

      def release_committed_ports(service, ports)
        node_port_reservations.release(ports, service)
      rescue StandardError
        @metrics&.increment("apiserver_nodeport_repair_reconcile_errors_total")
      end

      def rollback_node_ports(records)
        records.reverse_each do |record|
          node_port_reservations.release_if_unused(record)
        rescue StandardError
          @metrics&.increment("apiserver_nodeport_repair_reconcile_errors_total")
        end
      end

      def rollback_reservations(reservations)
        reservations.reverse_each do |record|
          release_ipaddress_if_unused(record)
        rescue StandardError
          @metrics&.increment("apiserver_clusterip_repair_reconcile_errors_total")
        end
      end

      private

      def committed_allocation
        transaction do |allocation|
          yield(allocation).tap { allocation.commit! }
        end
      end

      def service_holds_ip?(owner, ip)
        service = find_service(owner)
        service && service_ips(service).include?(ip)
      end

      def service_key(owner)
        @store.object_key(service_resource, owner.fetch("namespace"), owner.fetch("name"))
      end

      def find_service(owner)
        return unless service_resource && owner

        @store.get(resource: service_resource, namespace: owner.fetch("namespace"), name: owner.fetch("name"))
      rescue MemoryStore::NotFound
        nil
      end

      def release_ipaddress_if_unused(record)
        owner = record.dig("spec", "parentRef")
        name = record.dig("metadata", "name")
        version = record.dig("metadata", "resourceVersion")
        return false if version.to_s.empty?

        service = find_service(owner)
        return false if service && service_ips(service).include?(name)

        @store.delete(resource: ipaddress_resource, namespace: :cluster, name: name, resource_version: version,
                      related_versions: {service_key(owner) => service&.dig("metadata", "resourceVersion")})
        true
      rescue MemoryStore::NotFound, MemoryStore::Conflict
        false
      end
    end
  end
end
