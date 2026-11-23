# frozen_string_literal: true

module Rubernetes
  module API
    # The core/v1 typed references serialize a nil apiGroup as null. Keep
    # the shape at the response boundary so defaulting and field managers
    # continue to see the fields supplied by the client or read from storage.
    module PersistentVolumeClaimWire
      SOURCES = %w[dataSource dataSourceRef].freeze

      module_function

      def response(object)
        return object unless object["apiVersion"] == "v1"

        case object["kind"]
        when "PersistentVolumeClaim" then claim(object)
        when "PersistentVolumeClaimList"
          items = object["items"]
          return object unless items.is_a?(Array)

          normalized = items.map { |item| claim(item) }
          normalized == items ? object : object.merge("items" => normalized)
        else object
        end
      end

      def claim(object)
        spec = object["spec"] if object.is_a?(Hash)
        return object unless spec.is_a?(Hash)

        changes = SOURCES.filter_map do |field|
          reference = spec[field]
          [field, reference.merge("apiGroup" => nil)] if reference.is_a?(Hash) && !reference.key?("apiGroup")
        end
        changes.empty? ? object : object.merge("spec" => spec.merge(changes.to_h))
      end
    end
  end
end
