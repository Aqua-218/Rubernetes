# frozen_string_literal: true

require_relative "../resource_helpers"

require "digest"
require "json"
require "rational"
require "time"

module Rubernetes
  module Scheduler
    # Internal helpers used at the scheduler boundary.  Scheduler inputs are
    # copied and frozen before a plugin sees them so a plugin cannot mutate
    # informer state or make one scheduling cycle depend on another.
    module Support
      CPU_SUFFIXES = {
        "n" => Rational(1, 1_000_000_000),
        "u" => Rational(1, 1_000_000),
        "m" => Rational(1, 1_000)
      }.freeze
      MEMORY_SUFFIXES = {
        "Ki" => 1024, "Mi" => 1024**2, "Gi" => 1024**3,
        "Ti" => 1024**4, "Pi" => 1024**5, "Ei" => 1024**6,
        # The decimal kilo is a LOWER-case k in resource.Quantity; "1k" is the
        # canonical form of 1000.  Only "K" (which Kubernetes rejects) was
        # known, so a Node advertising example.com/fakecpu: 1000 -- stored as
        # "1k" -- could not be scored or fitted, and "[sig-scheduling]
        # SchedulerPreemption PreemptionExecutionPath" never scheduled a Pod.
        "k" => 1000, "K" => 1000, "M" => 1000**2, "G" => 1000**3,
        "T" => 1000**4, "P" => 1000**5, "E" => 1000**6
      }.freeze

      module_function

      # Everything this module deep-freezes has been through normalisation
      # first (string keys all the way down), so a value it froze needs no
      # second pass.  Filter and score plugins ask for the same sub-objects
      # of a Pod snapshot over and over -- affinity terms, spread
      # constraints, selectors, resource maps -- and re-normalising them was
      # most of what a scheduling cycle spent its time on.
      def object_hash(value)
        return value if DEEP_FROZEN.key?(value)

        source = if value.is_a?(Hash)
                   value
                 elsif value.respond_to?(:to_h)
                   value.to_h
                 else
                   raise TypeError, "expected a Hash-like object, got #{value.class}"
                 end
        normalize_hash(source)
      end

      def normalize(value)
        return value if DEEP_FROZEN.key?(value)

        case value
        when Hash
          normalize_hash(value)
        when Array
          value.map { |child| normalize(child) }
        when Struct
          normalize_hash(value.to_h)
        else
          value.respond_to?(:to_h) && !value.nil? && !value.is_a?(String) ? normalize_hash(value.to_h) : value
        end
      end

      def normalize_hash(source)
        source.each_with_object({}) do |(key, child), result|
          canonical_key = key.to_s
          if result.key?(canonical_key)
            raise ArgumentError, "duplicate scheduler field #{canonical_key.inspect}"
          end

          result[canonical_key] = normalize(child)
        end
      end

      def deep_copy(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, child), result| result[key.to_s] = deep_copy(child) }
        when Array
          value.map { |child| deep_copy(child) }
        when String
          value.dup
        else
          value
        end
      end

      # Every composite node is registered, not only the root: a Pod
      # snapshot's accessors ask for its spec, metadata and containers, which
      # are nodes inside the snapshot the Pod already froze.
      def deep_freeze(value)
        return value if (value.is_a?(Hash) || value.is_a?(Array)) && DEEP_FROZEN.key?(value)

        case value
        when Hash
          value.each do |key, child|
            key.freeze
            deep_freeze(child)
          end
          DEEP_FROZEN[value] = true
        when Array
          value.each { |child| deep_freeze(child) }
          DEEP_FROZEN[value] = true
        end
        value.freeze
      end

      # Snapshots this module has produced are shared instead of rebuilt.  A
      # Pod snapshot's every accessor -- spec, metadata, status, containers,
      # volumes, tolerations -- normalised, deep-copied and deep-froze its
      # already normalised, already frozen value on every call, and a
      # scheduling cycle calls them per plugin per node: normalisation alone
      # was a third of the scheduler's CPU.
      DEEP_FROZEN = ObjectSpace::WeakMap.new

      def snapshot(value)
        return value if DEEP_FROZEN.key?(value)

        deep_freeze(deep_copy(normalize(value)))
      end

      def deep_frozen?(value)
        DEEP_FROZEN.key?(value)
      end

      def value(object, key, default = nil)
        return default if object.nil?

        object = object.raw if object.respond_to?(:raw) && object.raw.is_a?(Hash)

        if object.is_a?(Hash)
          return object[key.to_s] if object.key?(key.to_s)
          return object[key.to_sym] if object.key?(key.to_sym)

          # A Hash must never fall through to method dispatch: field names like
          # "key" (taints), "count", "min" or "select" collide with real Hash
          # methods, and Hash#key(value) then raises ArgumentError instead of
          # reporting an absent field.  The method fallback is for typed
          # objects only.
          return default
        elsif object.respond_to?(:[])
          result = object[key.to_s]
          return result unless result.nil?
        end

        method_name = key.to_s.gsub(/([A-Z])/, '_\\1').downcase
        return object.public_send(method_name) if object.respond_to?(method_name)
        return object.public_send(key.to_sym) if object.respond_to?(key.to_sym)

        default
      end

      def present_value(object, key)
        return [nil, false] if object.nil?

        object = object.raw if object.respond_to?(:raw) && object.raw.is_a?(Hash)

        if object.is_a?(Hash)
          return [object[key.to_s], true] if object.key?(key.to_s)
          return [object[key.to_sym], true] if object.key?(key.to_sym)

          return [nil, false]
        elsif object.respond_to?(:key?) && object.key?(key)
          return [object[key], true]
        end
        method_name = key.to_s.gsub(/([A-Z])/, '_\\1').downcase
        return [object.public_send(method_name), true] if object.respond_to?(method_name)

        [nil, false]
      end

      # A frozen source (an informer's object) never changes, so its
      # normalised, frozen metadata is computed once; name/namespace/uid are
      # read from it many times per scheduling cycle.
      METADATA = ObjectSpace::WeakMap.new

      def metadata(object)
        source = value(object, "metadata", {})
        return source if DEEP_FROZEN.key?(source)

        if source.frozen? && (cached = METADATA[source])
          return cached
        end

        result = deep_freeze(object_hash(source))
        METADATA[source] = result if source.frozen?
        result
      end

      def name(object)
        metadata(object).fetch("name", "").to_s
      end

      def namespace(object)
        metadata(object).fetch("namespace", "default").to_s
      end

      def uid(object)
        metadata(object).fetch("uid", "").to_s
      end

      def labels(object)
        raw = object_hash(value(metadata(object), "labels", {}))
        deep_freeze(raw.each_with_object({}) { |(key, item), result| result[key.to_s] = item.to_s.dup })
      end

      def annotations(object)
        values = object_hash(value(metadata(object), "annotations", {}))
        deep_freeze(values.transform_values { |item| item.to_s.dup })
      end

      def canonical(value)
        case value
        when Hash
          value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
            child = value.key?(key) ? value[key] : value[key.to_sym]
            result[key] = canonical(child)
          end
        when Array
          value.map { |child| canonical(child) }
        when Rational
          {"__rational__" => "#{value.numerator}/#{value.denominator}"}
        when Float
          if value.nan?
            {"__float__" => "NaN"}
          elsif value.infinite? == 1
            {"__float__" => "Infinity"}
          elsif value.infinite? == -1
            {"__float__" => "-Infinity"}
          else
            value
          end
        when Time
          value.utc.iso8601(9)
        when Symbol
          value.to_s
        else
          if value.respond_to?(:to_h) && !value.is_a?(String)
            canonical(value.to_h)
          else
            value
          end
        end
      end

      def canonical_json(value)
        JSON.generate(canonical(value), allow_nan: false)
      end

      def digest(value)
        Digest::SHA256.hexdigest(canonical_json(value))
      end

      def quantity(value, resource = nil)
        result = if value.is_a?(Rational)
                   value
                 elsif value.is_a?(Integer)
                   Rational(value, 1)
                 elsif value.is_a?(Float) && value.finite?
                   value.to_r
                 else
                   string = String(value).strip
                   raise ArgumentError, "invalid resource quantity #{value.inspect}" if string.empty?

                   match = /\A([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)([A-Za-z]*)\z/.match(string)
                   raise ArgumentError, "invalid resource quantity #{value.inspect}" unless match

                   number = Rational(match[1])
                   suffix = match[2]
                   # Every resource takes the full suffix set, cpu included.
                   multiplier = if CPU_SUFFIXES.key?(suffix)
                                  CPU_SUFFIXES.fetch(suffix)
                                elsif MEMORY_SUFFIXES.key?(suffix)
                                  MEMORY_SUFFIXES.fetch(suffix)
                                elsif %w[n u m].include?(suffix)
                                  CPU_SUFFIXES.fetch(suffix)
                                elsif suffix.empty?
                                  Rational(1, 1)
                                else
                                  raise ArgumentError, "unsupported resource quantity suffix #{suffix.inspect}"
                                end
                   number * multiplier
                 end
        raise ArgumentError, "resource quantity must be non-negative" if result.negative?

        result
      rescue KeyError
        raise ArgumentError, "unsupported resource quantity suffix #{suffix.inspect}"
      end

      def quantity_map(value)
        object_hash(value || {}).each_with_object({}) do |(resource, amount), result|
          next if amount.nil? || amount.to_s.empty?

          result[resource.to_s] = quantity(amount, resource.to_s)
        end
      end

      def sum_maps(*maps)
        Array(maps).flatten.compact.each_with_object({}) do |map, result|
          quantity_map(map).each do |resource, amount|
            result[resource] = result.fetch(resource, Rational(0)) + amount
          end
        end
      end

      def max_maps(*maps)
        Array(maps).flatten.compact.each_with_object({}) do |map, result|
          quantity_map(map).each do |resource, amount|
            result[resource] = [result.fetch(resource, Rational(0)), amount].max
          end
        end
      end

      def subtract_maps(left, right)
        keys = quantity_map(left).keys | quantity_map(right).keys
        keys.each_with_object({}) do |resource, result|
          amount = quantity_map(left).fetch(resource, Rational(0)) - quantity_map(right).fetch(resource, Rational(0))
          result[resource] = amount.negative? ? Rational(0) : amount
        end
      end

      # resourcehelper.PodRequests as fit.go computes it: pod-level requests
      # replace the containers' aggregate for the resources they name, the
      # overhead is added, and a Pod on a node is sized by what its status
      # says it was allocated and actuated (in-place resize).  A container
      # limit without a request counts as the request -- the API server's
      # defaulting, applied here to Pods that did not come through it.
      def requests_for(pod)
        source = object_hash(pod)
        defaulted = source.merge("spec" => request_defaulted_spec(object_hash(value(source, "spec", {}))))
        Rubernetes::ResourceHelpers.pod_requests(defaulted, use_status_resources: true).to_h do |name, amount|
          [name, amount.value]
        end
      end

      # schedutil.DefaultMilliCPURequest / DefaultMemoryRequest: what a
      # container that requests nothing counts as when LeastAllocated scores
      # a node (resource_allocation.go NonMissingContainerRequests), so a
      # node full of BestEffort Pods does not look empty.
      NON_ZERO_DEFAULTS = {"cpu" => Rubernetes::Schema::Quantity.parse("100m"),
                           "memory" => Rubernetes::Schema::Quantity.parse("209715200")}.freeze

      def non_zero_requests_for(pod, skip_pod_level: false)
        source = object_hash(pod)
        defaulted = source.merge("spec" => request_defaulted_spec(object_hash(value(source, "spec", {}))))
        Rubernetes::ResourceHelpers.pod_requests(defaulted, use_status_resources: true, non_missing: NON_ZERO_DEFAULTS,
                                                            skip_pod_level: skip_pod_level).to_h do |name, amount|
          [name, amount.value]
        end
      end

      def request_defaulted_spec(spec)
        %w[containers initContainers].each_with_object(spec.dup) do |field, result|
          next unless result[field].is_a?(Array)

          result[field] = result[field].map do |container|
            next container unless container.is_a?(Hash) && container["resources"].is_a?(Hash)

            limits = container["resources"]["limits"]
            next container unless limits.is_a?(Hash) && !limits.empty?

            requests = container["resources"]["requests"].is_a?(Hash) ? container["resources"]["requests"] : {}
            missing = limits.reject { |name, _| requests.key?(name) }
            next container if missing.empty?

            container.merge("resources" => container["resources"].merge("requests" => requests.merge(missing)))
          end
        end
      end

      def effective_requests(resources)
        source = object_hash(resources || {})
        requests = quantity_map(value(source, "requests", {}))
        quantity_map(value(source, "limits", {})).each do |resource, amount|
          requests[resource] ||= amount
        end
        requests
      end

      def sum_container_requests(containers)
        Array(containers).each_with_object({}) do |container, result|
          result.replace(sum_maps(result, effective_requests(value(container, "resources", {}))))
        end
      end

      def max_container_requests(containers)
        max_maps(Array(containers).map { |container| effective_requests(value(container, "resources", {})) })
      end

      def priority_for(pod)
        spec = object_hash(value(pod, "spec", {}))
        raw = value(spec, "priority", value(pod, "priority", 0))
        if raw.is_a?(Integer)
          raw
        elsif raw.is_a?(String) && raw.strip.match?(/\A[+-]?\d+\z/)
          Integer(raw, 10)
        else
          raise ArgumentError
        end
      rescue ArgumentError, TypeError
        raise ValidationError, "pod priority must be an integer"
      end

      def node_name(object)
        metadata_name = name(object)
        return metadata_name unless metadata_name.empty?

        value(object, "name", "").to_s
      end

      def truthy?(value)
        value == true || value.to_s.casecmp("true").zero?
      end

      # QueueSort uses creation time when Kubernetes supplies it.  Synthetic
      # fixtures often omit the field; a zero-like timestamp stays the stable
      # earliest value, matching Kubernetes' zero CreationTimestamp ordering.
      def timestamp_key(object)
        raw = value(metadata(object), "creationTimestamp", nil)
        return [0, raw.to_s] if raw.nil? || raw.to_s.empty?

        parsed = Time.parse(raw.to_s).utc
        [1, parsed.iso8601(9)]
      rescue ArgumentError, TypeError
        [0, raw.to_s]
      end
    end
  end
end
