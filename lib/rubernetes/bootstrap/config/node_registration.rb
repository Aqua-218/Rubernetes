# frozen_string_literal: true

require_relative "../../api/object_validation"

module Rubernetes
  module Bootstrap
    class Config
      module NodeRegistration
        TAINT_FIELDS = %w[key value effect timeAdded].freeze
        EFFECTS = %w[NoSchedule PreferNoSchedule NoExecute].freeze

        module_function

        def validate_flag!(value, field)
          raise Error, "#{field} must be a boolean" unless [true, false].include?(value)
        end

        def validate_taints!(taints, field)
          raise Error, "#{field} must be an array of taints" unless taints.is_a?(Array)

          taints.each_with_index { |taint, index| validate_taint!(taint, "#{field}[#{index}]") }
        end

        def validate_taint!(taint, field)
          raise Error, "#{field} must contain only #{TAINT_FIELDS.join(", ")}" unless taint.is_a?(Hash) && (taint.keys - TAINT_FIELDS).empty?
          raise Error, "#{field}.timeAdded must be nil (taint.TimeAdded is not nil)" unless taint["timeAdded"].nil?

          key, value, effect = taint.values_at("key", "value", "effect")
          validate_key!(key, field)
          validate_value!(value, field)
          return if effect.nil? || effect == "" || EFFECTS.include?(effect)

          raise Error, "#{field}.effect must be one of #{EFFECTS.join(", ")}"
        end

        def validate_key!(key, field)
          raise Error, "#{field}.key must be a non-empty qualified name" unless key.is_a?(String) && !key.empty?

          errors = API::ObjectValidation.qualified_name_errors(key)
          raise Error, "#{field}.key is invalid: #{errors.join("; ")}" unless errors.empty?
        end

        def validate_value!(value, field)
          return if value.nil? || (value.is_a?(String) && value.bytesize <= API::ObjectValidation::LABEL_VALUE_MAX &&
                                   API::ObjectValidation::LABEL_VALUE.match?(value))

          raise Error, "#{field}.value must be a valid label value"
        end
      end
    end
  end
end
