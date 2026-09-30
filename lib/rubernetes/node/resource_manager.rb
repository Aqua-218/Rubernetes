# frozen_string_literal: true

require_relative "../resource_helpers"

# Node resource accounting and QoS classification.  Quantities are converted
# to exact Rational values while calculating; no floating-point rounding can
# make a pod fit on a full node.  The public snapshot keeps Kubernetes quantity
# strings for status and diagnostics.

require_relative "registration"

module Rubernetes
  module Node
    class ResourceManager
      class Error < StandardError; end

      class InsufficientResources < Error
        attr_reader :requested, :available

        def initialize(message, requested:, available:)
          @requested = requested
          @available = available
          super(message)
        end
      end

      Quantity = Data.define(:value, :resource) do
        def <=>(other)
          value <=> other.value
        end

        include Comparable

        def to_r
          value
        end

        def to_i
          value.to_i
        end

        def to_f
          value.to_f
        end
      end

      Reservation = Data.define(:key, :requests, :qos_class, :pod) do
        def to_h
          {"key" => key, "requests" => requests, "qosClass" => qos_class, "pod" => pod}
        end
      end

      DEFAULT_RESOURCES = %w[cpu memory ephemeral-storage pods].freeze
      CPU_SUFFIXES = {"n" => Rational(1, 1_000_000_000), "u" => Rational(1, 1_000_000),
                      "m" => Rational(1, 1_000)}.freeze
      # resource.Quantity: binary suffixes Ki..Ei and decimal SI suffixes
      # n u m k M G T P E -- the kilo is a LOWER-case k.  The table had an
      # upper-case "K" (which Kubernetes rejects) and no "k", so the canonical
      # form of 1000, "1k", could not be parsed: the Node an e2e spec patched
      # with example.com/fakecpu: 1000 came back as "1k" and every quantity
      # computation over it raised.  "K" stays accepted for anything that
      # already wrote it.
      MEMORY_SUFFIXES = {
        "Ki" => 1024, "Mi" => 1024**2, "Gi" => 1024**3, "Ti" => 1024**4, "Pi" => 1024**5, "Ei" => 1024**6,
        "k" => 1000, "K" => 1000, "M" => 1000**2, "G" => 1000**3, "T" => 1000**4, "P" => 1000**5, "E" => 1000**6
      }.freeze

      def initialize(capacity: {}, allocatable: nil, system_reserved: {}, kube_reserved: {}, eviction_reserved: {},
                     reserved: {}, pod_capacity: nil, clock: -> { Time.now.utc })
        @capacity = normalize_quantities(capacity || {})
        reservations = [system_reserved, kube_reserved, eviction_reserved, reserved].map { |item| normalize_quantities(item || {}) }
        @reservation_totals = sum_maps(reservations)
        @allocatable = if allocatable
                         normalize_quantities(allocatable)
                       else
                         subtract_maps(@capacity, @reservation_totals)
                       end
        if pod_capacity
          @capacity["pods"] = quantity_value(pod_capacity, "pods")
          @allocatable["pods"] = [@allocatable.fetch("pods", @capacity.fetch("pods")), quantity_value(pod_capacity, "pods")].min
        end
        @clock = clock
        @mutex = Mutex.new
        @reservations = {}
        @observed_usage = {}
      end

      def capacity
        capacity_strings
      end

      # Extended resources are advertised by whoever writes them into the
      # Node's capacity (a device plugin, or a client patching the status),
      # not by this agent.  kubelet admits against the Node's allocatable, so
      # the ones currently advertised replace the previous set here.
      def replace_extended(resources)
        incoming = normalize_quantities(resources || {})
        @mutex.synchronize do
          [@capacity, @allocatable].each do |map|
            map.delete_if { |name, _| self.class.extended_resource?(name) && !incoming.key?(name) }
            map.merge!(incoming)
          end
        end
        self
      end

      # v1helper.IsExtendedResourceName: a fully qualified name outside the
      # kubernetes.io/ namespace that is not a quota "requests." name.
      def self.extended_resource?(name)
        value = name.to_s
        value.include?("/") && !value.start_with?("kubernetes.io/") && !value.start_with?("requests.")
      end

      def allocatable
        allocatable_strings
      end

      def capacity_values
        @capacity.dup
      end

      def allocatable_values
        @allocatable.dup
      end

      def capacity_strings
        format_map(@capacity)
      end

      def allocatable_strings
        format_map(@allocatable)
      end

      alias node_allocatable allocatable_strings

      def parse_quantity(value, resource = nil)
        quantity_value(value, resource)
      end

      alias quantity parse_quantity

      def format_quantity(value, resource = nil)
        format_value(value, resource)
      end

      # resourcehelper.PodRequests: pod-level requests replace the containers'
      # aggregate for the resources they name (PodLevelResources); overhead
      # on top.  A container limit without a request counts as the request
      # (the API server's defaulting, for Pods that did not come through it).
      def request_for(pod, include_overhead: true)
        requests = Rubernetes::ResourceHelpers.pod_requests(defaulted_pod(pod), exclude_overhead: !include_overhead)
        format_map(requests.transform_values(&:value))
      end

      def defaulted_pod(pod)
        object = Support.object_hash(pod)
        spec = Support.object_hash(Support.value(object, "spec", {}))
        %w[containers initContainers].each do |field|
          next unless spec[field].is_a?(Array)

          spec[field] = spec[field].map do |container|
            next container unless container.is_a?(Hash)

            resources = Support.object_hash(Support.value(container, "resources", {}))
            requests = Support.object_hash(Support.value(resources, "requests", {}))
            limits = Support.object_hash(Support.value(resources, "limits", {}))
            missing = limits.reject { |name, _| requests.key?(name) }
            next container if missing.empty?

            Support.object_hash(container).merge("resources" => resources.merge("requests" => requests.merge(missing)))
          end
        end
        object.merge("spec" => spec)
      end

      alias requested_for request_for

      # qos.ComputePodQOS, pod-level resources included.
      def qos_class(pod, requests: nil)
        Rubernetes::ResourceHelpers.qos_class(defaulted_pod(pod))
      end

      alias classify_qos qos_class
      alias qos_for qos_class

      def reserve(pod, requests: nil, key: nil)
        pod_hash = Support.object_hash(pod)
        key ||= reservation_key(pod_hash)
        requested = normalize_quantities(requests || request_for(pod_hash))
        @mutex.synchronize do
          existing = @reservations[key]
          current_without = existing ? subtract_maps(used_map, existing.requests) : used_map
          available = subtract_maps(@allocatable, current_without)
          unless fits?(requested, available: available)
            missing = requested.each_with_object({}) do |(resource, amount), output|
              deficit = amount - available.fetch(resource, Rational(0))
              output[resource] = deficit if deficit.positive?
            end
            raise InsufficientResources.new("pod #{key} does not fit on the node", requested: format_map(requested),
                                                                                   available: format_map(available.merge(missing)))
          end
          reservation = Reservation.new(key: key, requests: requested.freeze, qos_class: qos_class(pod_hash), pod: pod_hash.freeze)
          @reservations[key] = reservation
          reservation
        end
      end

      alias reserve_pod reserve
      alias allocate reserve

      def release(pod_or_key)
        key = pod_or_key.is_a?(String) || pod_or_key.is_a?(Symbol) ? pod_or_key.to_s : reservation_key(pod_or_key)
        @mutex.synchronize { @reservations.delete(key) }
      end

      alias release_pod release
      alias deallocate release

      def reservation(key)
        @mutex.synchronize { @reservations[key.to_s] }
      end

      def reservations
        @mutex.synchronize { @reservations.values.map(&:to_h).map { |item| Support.deep_copy(item) } }
      end

      def used
        @mutex.synchronize { format_map(used_map) }
      end

      alias allocated used

      def observed_usage
        @mutex.synchronize { format_map(@observed_usage) }
      end

      def record_usage(pod_or_key, usage)
        key = pod_or_key.is_a?(String) || pod_or_key.is_a?(Symbol) ? pod_or_key.to_s : reservation_key(pod_or_key)
        normalized = normalize_quantities(usage || {})
        @mutex.synchronize { @observed_usage[key] = normalized }
        format_map(normalized)
      end

      alias update_usage record_usage

      def usage_for(pod_or_key)
        key = pod_or_key.is_a?(String) || pod_or_key.is_a?(Symbol) ? pod_or_key.to_s : reservation_key(pod_or_key)
        @mutex.synchronize { format_map(@observed_usage.fetch(key, {})) }
      end

      def available
        @mutex.synchronize { format_map(subtract_maps(@allocatable, used_map)) }
      end

      def fits?(requests, available: nil)
        requested = normalize_quantities(requests || {})
        available = normalize_quantities(available || self.available)
        requested.all? { |resource, amount| amount <= available.fetch(resource, Rational(0)) }
      end

      def snapshot
        @mutex.synchronize do
          {
            "capacity" => format_map(@capacity),
            "allocatable" => format_map(@allocatable),
            "used" => format_map(used_map),
            "available" => format_map(subtract_maps(@allocatable, used_map)),
            "observedUsage" => format_map(sum_maps(@observed_usage.values)),
            "reservations" => @reservations.values.map(&:to_h).map { |item| Support.deep_copy(item) }
          }
        end
      end

      alias status snapshot

      def node_status
        {"capacity" => capacity_strings, "allocatable" => allocatable_strings}
      end

      private

      def reservation_key(pod)
        uid = Support.uid(pod)
        return "uid:#{uid}" unless uid.to_s.empty?

        namespace = Support.namespace(pod, "default")
        name = Support.name(pod)
        raise ArgumentError, "pod identity is required for resource reservation" if name.to_s.empty?

        "pod:#{namespace}/#{name}"
      end

      def sum_container_requests(containers)
        Array(containers).each_with_object({}) do |container, output|
          resources = Support.object_hash(Support.value(container, "resources", {}))
          output.merge!(sum_maps([output, effective_requests(resources)]))
        end
      end

      def max_container_requests(containers)
        Array(containers).map do |container|
          resources = Support.object_hash(Support.value(container, "resources", {}))
          effective_requests(resources)
        end.reduce({}) do |maximum, current|
          current.each_with_object(maximum.dup) do |(resource, amount), output|
            output[resource] = [output.fetch(resource, Rational(0)), amount].max
          end
        end
      end

      def empty_resources?(container)
        resources = Support.object_hash(Support.value(container, "resources", {}))
        effective_requests(resources).empty? && normalize_quantities(Support.value(resources, "limits", {})).empty?
      end

      def effective_requests(resources)
        requests = normalize_quantities(Support.value(resources, "requests", {}))
        limits = normalize_quantities(Support.value(resources, "limits", {}))
        limits.each { |resource, amount| requests[resource] ||= amount }
        requests
      end

      def normalize_quantities(values)
        Support.object_hash(values || {}).each_with_object({}) do |(resource, value), output|
          next if value.nil? || value.to_s.empty?

          output[resource.to_s] = quantity_value(value, resource.to_s)
        end
      end

      def quantity_value(value, _resource = nil)
        return value if value.is_a?(Rational)
        return Rational(value, 1) if value.is_a?(Integer)
        return value.to_r if value.is_a?(Float)

        string = String(value).strip
        raise ArgumentError, "invalid resource quantity #{value.inspect}" if string.empty?

        match = /\A([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)([A-Za-z]*)\z/.match(string)
        raise ArgumentError, "invalid resource quantity #{value.inspect}" unless match

        number = Rational(match[1])
        suffix = match[2]
        # Every resource takes the full suffix set; cpu is not special
        # ("2k" cpu is a valid, if unusual, quantity).
        multiplier = if CPU_SUFFIXES.key?(suffix)
                       CPU_SUFFIXES.fetch(suffix)
                     elsif MEMORY_SUFFIXES.key?(suffix)
                       MEMORY_SUFFIXES.fetch(suffix)
                     elsif suffix == "n"
                       Rational(1, 1_000_000_000)
                     elsif suffix == "u"
                       Rational(1, 1_000_000)
                     elsif suffix == "m"
                       Rational(1, 1_000)
                     elsif suffix.empty?
                       Rational(1, 1)
                     else
                       raise ArgumentError, "unsupported resource quantity suffix #{suffix.inspect}"
                     end
        number * multiplier
      end

      def format_map(values)
        Support.object_hash(values || {}).each_with_object({}) do |(resource, value), output|
          output[resource.to_s] = format_value(value, resource.to_s)
        end
      end

      def format_value(value, resource)
        rational = quantity_value(value, resource)
        if resource.to_s == "cpu"
          return rational.to_i.to_s if rational.denominator == 1

          milli = rational * 1000
          return "#{milli.to_i}m" if milli.denominator == 1

          return rational.to_f.to_s
        end
        if %w[memory ephemeral-storage].include?(resource.to_s) && rational.denominator == 1
          binary_suffixes = {"Ei" => 1024**6, "Pi" => 1024**5, "Ti" => 1024**4, "Gi" => 1024**3,
                             "Mi" => 1024**2, "Ki" => 1024}
          binary_suffixes.each do |suffix, multiplier|
            next unless rational.to_i >= multiplier && (rational.to_i % multiplier).zero?

            return "#{rational.to_i / multiplier}#{suffix}"
          end
        end
        return rational.to_i.to_s if rational.denominator == 1

        rational.to_f.to_s
      end

      def sum_maps(maps)
        Array(maps).compact.each_with_object({}) do |map, output|
          normalize_quantities(map).each do |resource, amount|
            output[resource] = output.fetch(resource, Rational(0)) + amount
          end
        end
      end

      def max_maps(*maps)
        Array(maps).flatten.compact.each_with_object({}) do |map, output|
          normalize_quantities(map).each do |resource, amount|
            output[resource] = [output.fetch(resource, Rational(0)), amount].max
          end
        end
      end

      def used_map
        sum_maps(@reservations.values.map(&:requests))
      end

      def subtract_maps(left, right)
        keys = Support.object_hash(left).keys | Support.object_hash(right).keys
        keys.each_with_object({}) do |resource, output|
          amount = quantity_value(Support.value(left, resource, 0), resource) - quantity_value(Support.value(right, resource, 0), resource)
          output[resource] = amount.negative? ? Rational(0) : amount
        end
      end
    end

    NodeResourceManager = ResourceManager unless const_defined?(:NodeResourceManager, false)
  end
end
