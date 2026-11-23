# frozen_string_literal: true

require_relative "../registry"
require_relative "../../support/service_traffic"

module Rubernetes
  module API
    class ServiceAllocator
      # This group can't be registered through the public API. Each port has
      # one durable key, shared by data and health-check ports in all protocols.
      class NodePortReservations
        RESOURCE = Resource.new(group: "_internal", resource: "servicenodeports", kind: "ServiceNodePort")
        GRACE_SECONDS = 60

        def initialize(store, service_resource, clock)
          @store = store
          @service_resource = service_resource
          @clock = clock
        end

        def self.ports(service)
          spec = service.fetch("spec", {})
          return Set.new unless Support::ServiceTraffic.uses_node_ports?(spec)

          ports = Support::ServiceTraffic.node_ports(spec)
          health_port = spec["healthCheckNodePort"].to_i
          ports << health_port if Support::ServiceTraffic.health_check?(spec) && health_port.positive?
          ports
        end

        def self.owner(service)
          service.fetch("metadata", {}).slice("namespace", "name", "uid")
        end

        def claim(port, service, existing_version: nil)
          owner = self.class.owner(service)
          versions = existing_version ? {service_key(owner) => existing_version} : {}
          record = {"metadata" => {"name" => port.to_s}, "owner" => owner, "reservedAt" => @clock.call.to_f}
          @store.create(resource: RESOURCE, namespace: :cluster, object: record, related_versions: versions)
        rescue MemoryStore::AlreadyExists, MemoryStore::Conflict
          nil
        end

        def record(port)
          @store.get(resource: RESOURCE, namespace: :cluster, name: port.to_s)
        rescue MemoryStore::NotFound
          nil
        end

        def key(port)
          @store.object_key(RESOURCE, :cluster, port.to_s)
        end

        def all
          @store.list(resource: RESOURCE, namespace: :cluster, selectors: nil).items
        end

        def release(ports, service)
          owner = self.class.owner(service)
          ports.each do |port|
            claim = record(port)
            release_if_unused(claim) if claim && claim["owner"] == owner
          end
        end

        def reap(record)
          return false if @clock.call.to_f - record.fetch("reservedAt") < GRACE_SECONDS

          release_if_unused(record)
        end

        # The Service write checks the claim's revision, and claim removal
        # checks the Service's revision (nil if absent). This also fences a
        # delayed write that resumes after another API server reaps its claim.
        def release_if_unused(record)
          owner = record.fetch("owner")
          name = record.dig("metadata", "name")
          service = find_service(owner)
          return false if service && self.class.owner(service) == owner && self.class.ports(service).include?(name.to_i)

          @store.delete(resource: RESOURCE, namespace: :cluster, name: name, resource_version: record.dig("metadata", "resourceVersion"),
                        related_versions: {service_key(owner) => service&.dig("metadata", "resourceVersion")})
          true
        rescue MemoryStore::NotFound, MemoryStore::Conflict
          false
        end

        private

        def service_key(owner)
          @store.object_key(@service_resource, owner.fetch("namespace", "default"), owner.fetch("name"))
        end

        def find_service(owner)
          @store.get(resource: @service_resource, namespace: owner.fetch("namespace", "default"), name: owner.fetch("name"))
        rescue MemoryStore::NotFound
          nil
        end
      end

      class NodePortSelection
        def initialize(used, &reserve)
          @used = used.to_set
          @reserve = reserve
        end

        def include?(port) = @used.include?(port)
        def <<(port) = @used << port
        def claim(port) = !include?(port) && @reserve.call(port)
      end
    end
  end
end
