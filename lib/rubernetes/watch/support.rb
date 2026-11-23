# frozen_string_literal: true

require_relative "../support/object_graph"

# Internal value and API-shape helpers shared by the watch pipeline.  The
# helpers intentionally live inside the watch boundary so loading a single
# component does not require the full Rubernetes package.
module Rubernetes
  module Watch
    module Support
      module_function

      def immutable_scalar?(value)
        value.nil? || value == true || value == false || value.is_a?(Symbol) || value.is_a?(Numeric)
      end

      def copy_object(value, seen, immutable: false)
        return value if value.frozen? && !value.respond_to?(:to_h) && !value.respond_to?(:to_a)

        if value.respond_to?(:to_h)
          return ObjectGraph.copy(value.to_h, seen, immutable: immutable, &COPY_OBJECT)
        elsif value.respond_to?(:each) && value.respond_to?(:to_a)
          return ObjectGraph.copy(value.to_a, seen, immutable: immutable, &COPY_OBJECT)
        end

        immutable ? value.dup.freeze : value.dup
      rescue TypeError, NoMethodError
        immutable ? value.dup.freeze : value.dup
      end

      DEEP_FROZEN = ObjectSpace::WeakMap.new
      COPY_OBJECT = method(:copy_object).to_proc
      private_constant :COPY_OBJECT

      def deep_copy(value, seen = nil) = ObjectGraph.copy(value, seen, &COPY_OBJECT)
      def deep_freeze(value, seen = nil) = ObjectGraph.deep_freeze(value, seen)
      def immutable_copy(value) = ObjectGraph.immutable_copy(value, DEEP_FROZEN, &COPY_OBJECT)
      def deep_frozen?(value) = DEEP_FROZEN.key?(value)

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
