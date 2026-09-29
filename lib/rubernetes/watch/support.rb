# frozen_string_literal: true

# Internal value and API-shape helpers shared by the watch pipeline.  The
# helpers intentionally live inside the watch boundary so loading a single
# component does not require the full Rubernetes package.
module Rubernetes
  module Watch
    module Support
      module_function

      # Make a detached copy of API values.  Kubernetes objects are normally
      # Hash/Array trees, but copying strings as well prevents a caller from
      # changing a value after it crossed the cache boundary.
      def deep_copy(value, seen = nil)
        case value
        when Hash
          return seen.fetch(value) if seen&.key?(value)

          copy = {}
          (seen ||= {}.compare_by_identity)[value] = copy
          value.each do |key, child|
            copy[deep_copy(key, seen)] = deep_copy(child, seen)
          end
          copy
        when Array
          return seen.fetch(value) if seen&.key?(value)

          copy = []
          (seen ||= {}.compare_by_identity)[value] = copy
          value.each { |child| copy << deep_copy(child, seen) }
          copy
        when String
          value.dup
        when Symbol, Numeric, TrueClass, FalseClass, NilClass
          value
        else
          copy_object(value, seen)
        end
      end

      # As in the store and the controller runtime: an object this module has
      # already deep-frozen is handed back as it is.  Every informer event and
      # every indexer read copied whole objects that nobody could mutate.
      DEEP_FROZEN = ObjectSpace::WeakMap.new

      def immutable_copy(value)
        return value if DEEP_FROZEN.key?(value)

        result = deep_freeze(deep_copy(value))
        DEEP_FROZEN[result] = true if result.is_a?(Hash) || result.is_a?(Array)
        result
      end

      def deep_frozen?(value)
        DEEP_FROZEN.key?(value)
      end

      def deep_freeze(value, seen = nil)
        return value if immutable_scalar?(value)
        return value if seen&.key?(value)

        (seen ||= {}.compare_by_identity)[value] = true
        case value
        when Hash
          value.each { |key, child| deep_freeze(key, seen); deep_freeze(child, seen) }
        when Array
          value.each { |child| deep_freeze(child, seen) }
        end
        value.freeze
      end

      def immutable_scalar?(value)
        value.nil? || value == true || value == false || value.is_a?(Symbol) || value.is_a?(Numeric)
      end

      def copy_object(value, seen)
        return value if value.frozen? && !value.respond_to?(:to_h) && !value.respond_to?(:to_a)
        return value.dup if !value.respond_to?(:each) && !value.respond_to?(:to_h)

        if value.respond_to?(:to_h)
          deep_copy(value.to_h, seen)
        elsif value.respond_to?(:to_a)
          deep_copy(value.to_a, seen)
        else
          value.dup
        end
      rescue TypeError, NoMethodError
        value.dup
      end

      def value_at(value, *names)
        names.each do |name|
          if value.is_a?(Hash)
            return value[name] if value.key?(name)

            string_name = name.to_s
            return value[string_name] if value.key?(string_name)
          elsif value.respond_to?(name)
            return value.public_send(name)
          end
        end
        nil
      end

      def metadata(value)
        candidate = value_at(value, :metadata, "metadata")
        candidate.is_a?(Hash) ? candidate : {}
      end

      def resource_version(value)
        candidate = value_at(value, :resource_version, :resourceVersion, "resourceVersion", "resource_version", :revision,
                             "revision")
        candidate = value_at(metadata(value), :resource_version, :resourceVersion, "resourceVersion", "resource_version") if candidate.nil?
        candidate.nil? || candidate.to_s.empty? ? nil : candidate.to_s
      end

      def event_type(value)
        value_at(value, :type, "type", :event_type, "eventType").to_s.upcase
      end

      def event_object(value)
        value_at(value, :object, "object")
      end

      def object_key(value)
        return value.to_s unless value.is_a?(Hash)

        object_metadata = metadata(value)
        namespace = value_at(object_metadata, :namespace, "namespace")
        name = value_at(object_metadata, :name, "name")
        return [namespace, name].compact.join("/") unless name.nil? || name.to_s.empty?

        explicit = value_at(value, :key, "key")
        return explicit.to_s unless explicit.nil? || explicit.to_s.empty?

        value.object_id.to_s
      end

      def numeric_version(value)
        text = value.to_s
        Integer(text, 10)
      rescue ArgumentError, TypeError
        nil
      end

      def version_newer?(candidate, current)
        return false if candidate.nil?
        return true if current.nil?

        candidate_number = numeric_version(candidate)
        current_number = numeric_version(current)
        return candidate_number > current_number unless candidate_number.nil? || current_number.nil?

        candidate.to_s != current.to_s
      end
    end
  end
end
