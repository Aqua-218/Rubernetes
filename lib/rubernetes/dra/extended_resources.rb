# frozen_string_literal: true

module Rubernetes
  module DRA
    # DRAExtendedResource (beta, on in v1.36.2): a Pod asks for an extended
    # resource ("example.com/gpu: 1", or "deviceclass.resource.kubernetes.io/
    # <class>: 1") that no node advertises, and a DeviceClass with that
    # extendedResourceName provides it -- the scheduler allocates a claim for
    # it (created in PreBind, owned by the Pod, annotated
    # resource.kubernetes.io/extended-resource-claim) and records it in
    # status.extendedResourceClaimStatus.
    module ExtendedResources
      DEVICE_CLASS_PREFIX = "deviceclass.resource.kubernetes.io/"
      ANNOTATION = "resource.kubernetes.io/extended-resource-claim"
      REQUESTS_PREFIX = "requests."

      module_function

      # schedutil.IsDRAExtendedResourceName.
      def extended_resource_name?(name)
        name = name.to_s
        return true if name.start_with?(DEVICE_CLASS_PREFIX)
        return false unless name.include?("/")
        return false if name.include?("kubernetes.io/") || name.start_with?(REQUESTS_PREFIX)

        qualified_name?("#{REQUESTS_PREFIX}#{name}")
      end

      QUALIFIED_PREFIX = /\A[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\z/
      QUALIFIED_NAME = /\A([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]\z/

      def qualified_name?(value)
        parts = value.split("/")
        return false if parts.length > 2

        name = parts.last
        return false if name.empty? || name.length > 63 || !QUALIFIED_NAME.match?(name)
        return true if parts.length == 1

        prefix = parts.first
        !prefix.empty? && prefix.length <= 253 && QUALIFIED_PREFIX.match?(prefix)
      end

      # extendedresourcecache.ExtendedResourceCache over a list of classes.
      class Resolver
        def initialize(classes)
          @by_resource = {}
          @by_class = {}
          Array(classes).sort_by { |klass| [creation(klass), klass.dig("metadata", "name").to_s] }.each do |klass|
            name = klass.dig("metadata", "name").to_s
            @by_resource["#{DEVICE_CLASS_PREFIX}#{name}"] = klass
            explicit = klass.dig("spec", "extendedResourceName")
            next if explicit.to_s.empty?

            current = @by_resource[explicit]
            # The newest class wins; equal creation times prefer the lower name.
            next if current && (creation(klass) < creation(current) ||
                                (creation(klass) == creation(current) && name >= current.dig("metadata", "name").to_s))

            @by_resource[explicit] = klass
          end
          Array(classes).each do |klass|
            explicit = klass.dig("spec", "extendedResourceName")
            @by_class[klass.dig("metadata", "name").to_s] = explicit.to_s unless explicit.to_s.empty?
          end
        end

        def device_class(resource_name) = @by_resource[resource_name.to_s]
        def extended_resource(class_name) = @by_class[class_name.to_s]
        def empty? = @by_resource.empty?

        private

        def creation(klass) = klass.dig("metadata", "creationTimestamp").to_s
      end

      # createRequestsAndMappings: the device requests of the Pod's
      # extended-resource claim and which container request maps to which.
      def requests_and_mappings(pod, extended_resources, resolver)
        init = Array(pod.dig("spec", "initContainers"))
        containers = init + Array(pod.dig("spec", "containers"))
        long_lived = []
        short_lived = []
        containers.each_with_index do |container, index|
          sidecar = index < init.length && container["restartPolicy"].to_s == "Always"
          if index < init.length && !sidecar
            short_lived << index
          else
            long_lived << index
          end
        end

        requests = []
        mappings = []
        extended_resources.keys.sort.each do |resource|
          klass = resolver.device_class(resource)
          next unless klass

          class_name = klass.dig("metadata", "name").to_s
          long_requests = Array.new(containers.length)
          long_mappings = []
          long_lived.each do |index|
            request, found = request_and_mappings(index, containers[index], resource, class_name, [])
            long_requests[index] = request
            long_mappings.concat(found)
          end
          largest = nil
          short_names = []
          short_mappings = []
          short_lived.each do |index|
            request, found = request_and_mappings(index, containers[index], resource, class_name, long_requests[index..] || [])
            if request
              short_names << request["name"]
              largest = request if largest.nil? || largest.dig("exactly", "count") < request.dig("exactly", "count")
            end
            short_mappings.concat(found)
          end
          if largest && short_names.uniq.length > 1
            others = short_names.uniq - [largest["name"]]
            short_mappings.each { |mapping| mapping["requestName"] = largest["name"] if others.include?(mapping["requestName"]) }
          end
          requests << largest if largest
          long_requests.compact.each { |request| requests << request }
          mappings.concat(long_mappings)
          mappings.concat(short_mappings)
        end
        [requests.sort_by { |request| request["name"] }, mappings]
      end

      # createResourceRequestAndMappings.
      def request_and_mappings(index, container, resource, class_name, reusable)
        requests = container.dig("resources", "requests") || {}
        value = requests[resource]
        return [nil, []] if value.nil?

        wanted = begin
          amount = Schema::Quantity.from_json(value).value
          amount.denominator == 1 ? amount.to_i : nil
        rescue StandardError
          nil
        end
        return [nil, []] if wanted.nil? || wanted.zero?

        mappings = []
        sum = 0
        reusable.compact.each do |request|
          sum += request.dig("exactly", "count").to_i
          mappings << {"containerName" => container["name"].to_s, "resourceName" => resource, "requestName" => request["name"]}
          return [nil, mappings] if sum >= wanted
        end
        position = requests.keys.map(&:to_s).sort.index(resource) || 0
        name = "container-#{index}-request-#{position}"
        request = {"name" => name, "exactly" => {"deviceClassName" => class_name, "allocationMode" => "ExactCount", "count" => wanted - sum}}
        mappings << {"containerName" => container["name"].to_s, "resourceName" => resource, "requestName" => name}
        [request, mappings]
      end
    end
  end
end
