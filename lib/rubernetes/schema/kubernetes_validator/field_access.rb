# frozen_string_literal: true

module Rubernetes
  module Schema
    # Reading untyped JSON objects and building issues: the helpers every
    # other validator file is written in.  Request bodies are plain Hashes
    # (String or Symbol keys) of unknown shape, so every read goes through
    # `fetch` and every nested value is type-checked before use.
    module KubernetesValidator
      module_function

      def issue(path, code, message)
        kubernetes_type = case code
                          when :required then "Required value"
                          when :unsupported then "Unsupported value"
                          when :not_found then "Not found"
                          when :forbidden then "Forbidden"
                          when :duplicate then "Duplicate value"
                          when :internal then "Internal error"
                          when :too_long then "Too long"
                          when :too_many then "Too many"
                          else "Invalid value"
                          end
        ValidationIssue.new(path: path, code: code, message: message, kubernetes_type: kubernetes_type)
      end

      def required(object, name, path, issues, detail = "")
        issues << issue(path + [name], :required, detail) if blank?(fetch(object, name))
      end

      def invalid_messages(path, messages, code = :invalid)
        messages.map { |message| issue(path, code, message) }
      end

      def unsupported_detail(values)
        "supported values: #{values.map { |value| "\"#{value}\"" }.join(", ")}"
      end

      def object_like?(value)
        value.is_a?(Hash) || value.is_a?(ValueObject)
      end

      def plain_object(value)
        return value if value.is_a?(Hash)

        value.to_h
      end

      def fetch(object, key)
        return nil unless object.is_a?(Hash)
        return object[key] if object.key?(key)
        return object[key.to_sym] if object.key?(key.to_sym)

        nil
      end

      def value_at_path(object, path)
        path.reduce(object) do |current, segment|
          if current.is_a?(Hash)
            fetch(current, segment)
          elsif current.is_a?(Array) && segment.to_s.match?(/\A\d+\z/)
            current[segment.to_i]
          end
        end
      end

      # Walk all nested objects and arrays.  A resource fixture can reach the
      # Pod template through several paths (Job, CronJob, controller sets), so
      # the probe/enum rules must not be tied to one owner layout.
      #
      # Scalars yield nothing, so no path is built for them.  Server-managed
      # metadata.managedFields is bookkeeping no strategy validates (its
      # fieldsV1 trees spell every key "f:<name>"), yet it was most of the
      # nodes every walk visited on an updated Pod.
      def walk(value, path = [], &)
        if value.is_a?(Hash)
          yield(value, path)
          value.each do |key, child|
            next unless child.is_a?(Hash) || child.is_a?(Array)

            name = key.to_s
            next if name == "managedFields" && path.last == "metadata"

            walk(child, path + [name], &)
          end
        elsif value.is_a?(Array)
          yield(value, path)
          value.each_with_index do |child, index|
            walk(child, path + [index.to_s], &) if child.is_a?(Hash) || child.is_a?(Array)
          end
        end
      end

      def blank?(value)
        value.nil? || (value.is_a?(String) && value.empty?)
      end

      def blank_array?(value)
        value.nil? || (value.is_a?(Array) && value.empty?)
      end

      # nil, "", {} and []: a JSON value Go decodes to the zero value.
      def unset_value?(value)
        value.nil? || ((value.is_a?(String) || value.is_a?(Hash) || value.is_a?(Array)) && value.empty?)
      end

      def provided?(value)
        return false if value.nil?
        return false if value.is_a?(String) && value.empty?
        return false if value.is_a?(Hash) && value.empty?

        true
      end

      def zero_value?(value)
        return true if value.nil? || value == false || value == 0 || value == ""
        return value.all? { |item| zero_value?(item) } if value.is_a?(Array)
        return value.empty? || value.values.all? { |item| zero_value?(item) } if value.is_a?(Hash)

        false
      end

      def source_key_present?(object, name)
        object.is_a?(Hash) && (object.key?(name) || object.key?(name.to_sym)) && !fetch(object, name).nil?
      end

      # apiequality.Semantic.DeepEqual treats nil and empty maps and slices
      # alike; drop both before comparing.
      def semantic_value(value)
        case value
        when Hash
          result = value.each_with_object({}) do |(key, item), hash|
            normalized = semantic_value(item)
            hash[key.to_s] = normalized unless normalized.nil?
          end
          result.empty? ? nil : result
        when Array
          items = value.map { |item| semantic_value(item) }
          items.empty? ? nil : items
        else
          value
        end
      end

      def without_nil_fields(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, entry), result| result[key] = without_nil_fields(entry) unless entry.nil? }
        when Array
          value.map { |entry| without_nil_fields(entry) }
        else
          value
        end
      end

      # A String-keyed copy the caller may mask field by field.
      def deep_copy_value(value)
        case value
        when Hash then value.each_with_object({}) { |(k, v), out| out[k.to_s] = deep_copy_value(v) }
        when Array then value.map { |item| deep_copy_value(item) }
        else value
        end
      end

      def kubernetes_type_name(value)
        return "null" if value.nil?
        return "bool" if [true, false].include?(value)
        return "string" if value.is_a?(String)
        return "int" if value.is_a?(Integer)
        return "float" if value.is_a?(Float)
        return "array" if value.is_a?(Array)
        return "object" if value.is_a?(Hash)

        value.class.name.to_s.downcase
      end
    end
  end
end
