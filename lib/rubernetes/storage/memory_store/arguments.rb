# frozen_string_literal: true

module Rubernetes
  module Storage
    # Normalising what callers pass: option spellings, selectors, limits and durations.
    class MemoryStore
      private

      def selector_callable(selector, kind: :combined, shard: nil)
        ExternalSelectorPredicate.new(selector, kind: kind, shard: shard)
      end

      # {"labels" => ..., "fields" => ...}, as opposed to a Hash of label values.
      def labels_and_fields?(selector)
        selector.is_a?(Hash) && (selector.key?("labels") || selector.key?(:labels) || selector.key?("fields") || selector.key?(:fields))
      end

      # The one Selector a list or watch filters with, whichever of the three
      # selector keywords the caller used.
      def build_selector(selector, label_selector, field_selector, shard: nil)
        if labels_and_fields?(selector)
          label_selector ||= selector["labels"] || selector[:labels]
          field_selector ||= selector["fields"] || selector[:fields]
          selector = nil
        end
        if external_selector?(selector)
          selector = selector_callable(selector, kind: :combined, shard: shard)
          label_selector = nil
          field_selector = nil
        else
          label_selector = selector_callable(label_selector, kind: :label) if external_selector?(label_selector)
          field_selector = selector_callable(field_selector, kind: :field) if external_selector?(field_selector)
        end
        Selector.new(label_selector: label_selector || selector, field_selector: field_selector)
      end

      # A watch buffer bound under either of its two spellings; the first wins
      # and a second is left behind to be rejected as unknown.
      def buffer_option(options, name, other_name, default)
        if options.key?(name)
          options.delete(name)
        elsif options.key?(other_name)
          options.delete(other_name)
        else
          default
        end
      end

      def discard_options(options, *names)
        names.each do |name|
          options.delete(name)
          options.delete(name.to_s)
        end
        options
      end

      def option_value(options, *names, default:)
        supplied = names.select { |name| options.key?(name) }
        return default if supplied.empty?

        first = supplied.first
        supplied.drop(1).each do |name|
          raise ArgumentError, "conflicting options: #{first} and #{name}" unless options.fetch(name) == options.fetch(first)
        end
        value = options.delete(first)
        supplied.drop(1).each { |name| options.delete(name) }
        value
      end

      def compaction_value(options, *names, default:)
        keys = names.select { |name| options.key?(name) || options.key?(name.to_s) }
        return default if keys.empty?

        first = keys.first
        value_for = ->(name) { options.key?(name) ? options.delete(name) : options.delete(name.to_s) }
        value = value_for.call(first)
        keys.drop(1).each do |name|
          candidate = value_for.call(name)
          raise ArgumentError, "conflicting compaction options: #{first} and #{name}" unless candidate == value
        end
        value
      end

      def validate_history_revisions(value)
        validate_positive_limit(value, "history_revisions", allow_zero: true) unless value.nil?
      rescue ArgumentError
        raise ArgumentError, "history_revisions must be a non-negative integer or nil"
      end

      def validate_positive_limit(value, name, allow_zero: false)
        number = Integer(value)
        valid = allow_zero ? number >= 0 : number.positive?
        raise ArgumentError, "#{name} must be #{allow_zero ? "non-negative" : "positive"}" unless valid

        number
      rescue TypeError, ArgumentError
        raise ArgumentError, "#{name} must be an #{allow_zero ? "non-negative" : "positive"} number"
      end

      def validate_interval(value, name, optional: false)
        return if optional && value.nil?

        number = Float(value)
        return number unless number.negative?

        raise ArgumentError
      rescue TypeError, ArgumentError
        raise ArgumentError, "#{name} must be a non-negative number#{" or nil" if optional}"
      end
    end
  end
end
