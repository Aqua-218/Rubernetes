# frozen_string_literal: true

require "ipaddr"

module Rubernetes
  module Bootstrap
    # The endpoint lease is private datastore state, as in upstream's
    # /peerserverleases. The public identity Lease is used for membership,
    # never as the address to dial with the front-proxy client certificate.
    class PeerDirectory
      KEY_PREFIX = "peerserverleases/"
      LEASE_TTL = 15
      ENDPOINT_ANNOTATION = "kubernetes.io/peer-advertise-address"
      Endpoint = Data.define(:host, :port, :expires, :holder)

      attr_reader :identity

      def initialize(store:, registry:, identity:, host:, port:, clock: -> { Time.now.utc })
        @store = store.is_a?(API::StoreAdapter) ? store.store : store
        @adapter = API::StoreAdapter.new(@store)
        @identity = identity
        @host = IPAddr.new(host).to_s
        @port = port
        @clock = clock
        @leases = registry.find_gvr(group: "coordination.k8s.io", version: "v1", resource: "leases")
        @crds = registry.find_gvr(group: "apiextensions.k8s.io", version: "v1", resource: "customresourcedefinitions")
        @services = registry.find_gvr(group: "apiregistration.k8s.io", version: "v1", resource: "apiservices")
      end

      def address
        host = @host.include?(":") ? "[#{@host}]" : @host
        "#{host}:#{@port}"
      end

      def assign_default_port(port)
        @port = port if @port.zero?
      end

      def publish(holder)
        object = {
          "metadata" => {"name" => @identity},
          "address" => @host, "port" => @port, "holder" => holder, "expires" => @clock.call.to_f + LEASE_TTL
        }
        key = KEY_PREFIX + @identity
        @store.create(key, object)
      rescue Storage::AlreadyExists
        @store.update(key, object)
      end

      def withdraw(holder)
        key = KEY_PREFIX + @identity
        lease = @store.get(key)
        return unless lease["holder"] == holder

        @store.delete(key, resource_version: lease.dig("metadata", "resourceVersion"))
      rescue Storage::NotFound, Storage::Conflict
        nil
      end

      def snapshot
        private_leases = @store.list(KEY_PREFIX).items.to_h { |lease| [lease.dig("metadata", "name"), lease] }
        identity = KubernetesServiceReconciler
        selector = API::Selectors.new(label_selector: "#{identity::LEASE_LABEL}=#{identity::LEASE_LABEL_VALUE}")
        endpoints = items(@leases, namespace: identity::LEASE_NAMESPACE, selectors: selector).filter_map do |lease|
          name = lease.dig("metadata", "name")
          holder = lease.dig("spec", "holderIdentity")
          next if name == @identity || name.to_s.empty? || holder.to_s.empty?

          [name, endpoint(private_leases[name], holder)]
        end.to_h
        [endpoints, active_group_versions]
      end

      def resolve(identity, holder)
        endpoint(@store.get(KEY_PREFIX + identity), holder)
      rescue Storage::Error, Consensus::Error
        nil
      end

      private

      def items(resource, namespace: :cluster, selectors: nil)
        resource ? @adapter.list(resource: resource, namespace: namespace, selectors: selectors).items : []
      end

      def endpoint(lease, holder)
        return unless lease && lease["holder"] == holder && lease["expires"] > @clock.call.to_f

        address = IPAddr.new(lease.fetch("address")).to_s
        port = Integer(lease.fetch("port"))
        Endpoint.new(address, port, lease.fetch("expires"), holder) if port.between?(1, 65_535)
      rescue ArgumentError, KeyError, TypeError
        nil
      end

      def active_group_versions
        custom = items(@crds).flat_map do |crd|
          group = crd.dig("spec", "group")
          Array(crd.dig("spec", "versions")).map { |version| [group, version["name"]] }
        end
        aggregated = items(@services).filter_map do |service|
          next if service.dig("spec", "service").nil?

          [service.dig("spec", "group"), service.dig("spec", "version")]
        end
        (custom + aggregated).to_set
      end
    end
  end
end
