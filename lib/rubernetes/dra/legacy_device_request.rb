# frozen_string_literal: true

module Rubernetes
  module DRA
    # The v1beta1 wire shape flattens the ExactDeviceRequest fields into
    # DeviceRequest. Match upstream hasAnyMainRequestFieldsSet when deciding
    # whether those fields represent an exact request.
    module LegacyDeviceRequest
      NULLABLE_FIELDS = %w[selectors adminAccess tolerations capacity].freeze
      FIELDS = (%w[deviceClassName allocationMode count] + NULLABLE_FIELDS).freeze

      module_function

      def fields_set?(request)
        !request["deviceClassName"].to_s.empty? || !request["allocationMode"].to_s.empty? ||
          ![nil, 0].include?(request["count"]) || NULLABLE_FIELDS.any? { |field| !request[field].nil? }
      end
    end
  end
end
