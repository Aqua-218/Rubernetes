# frozen_string_literal: true

require "time"

module Rubernetes
  module API
    # CRD decoding coerces root metadata through the typed ObjectMeta.
    module ObjectMetaWire
      ZERO_TIME = Time.utc(1).freeze
      ZERO_TIMESTAMP = "0001-01-01T00:00:00Z"
      RFC3339 = /\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\z/

      module_function

      def empty_finalizers?(object)
        return false unless object.is_a?(Hash)

        metadata = object["metadata"]
        return false unless metadata.is_a?(Hash) && metadata.key?("finalizers")

        value = metadata["finalizers"]
        value.nil? || (value.is_a?(Array) && value.empty?)
      end

      def omit_empty_finalizers(object)
        return object unless empty_finalizers?(object)

        object.merge("metadata" => object.fetch("metadata").except("finalizers"))
      end

      def normalize_times(object)
        return object unless object.is_a?(Hash)

        metadata = object["metadata"]
        return object unless metadata.is_a?(Hash)

        normalized = normalize_time_field(metadata, "creationTimestamp", omit_zero: true)
        normalized = normalize_time_field(normalized, "deletionTimestamp")
        normalized = normalize_managed_times(normalized)
        normalized.equal?(metadata) ? object : object.merge("metadata" => normalized)
      end

      def normalize_managed_times(metadata)
        entries = metadata["managedFields"]
        return metadata unless entries.is_a?(Array)

        normalized = entries.map { |entry| entry.is_a?(Hash) ? normalize_time_field(entry, "time") : entry }
        normalized == entries ? metadata : metadata.merge("managedFields" => normalized)
      end

      def normalize_time_field(fields, key, omit_zero: false)
        return fields unless fields.key?(key)

        original = fields[key]
        canonical = second_precision(original)
        # CreationTimestamp uses omitzero. The other two fields are *Time:
        # a nil pointer is omitted and a non-nil zero Time serializes as null.
        return fields.except(key) if original.nil? || (omit_zero && canonical.nil?)
        return fields if original == canonical

        fields.merge(key => canonical)
      end

      def second_precision(value)
        return value unless value.is_a?(String)
        return nil if value == ZERO_TIMESTAMP
        return value if value.bytesize == 20 && value.end_with?("Z")
        return value unless RFC3339.match?(value)

        time = Time.iso8601(value).utc
        time == ZERO_TIME ? nil : time.iso8601
      rescue ArgumentError
        value
      end
    end
  end
end
