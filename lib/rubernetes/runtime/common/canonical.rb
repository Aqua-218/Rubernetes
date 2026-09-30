# frozen_string_literal: true

require "digest"
require "json"
require "time"

module Rubernetes
  module Runtime
    # Canonical encoding is shared by WAL, snapshots, and config fingerprints.
    module Canonical
      module_function

      def copy(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, child), result| result[String(key)] = copy(child) }
        when Array
          value.map { |child| copy(child) }
        when Time
          value.utc.iso8601(6)
        when String
          value.dup
        else
          value
        end
      end

      def normalize(value)
        case value
        when Hash
          value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
            source_key = value.keys.find { |candidate| candidate.to_s == key }
            result[key] = normalize(value.fetch(source_key))
          end
        when Array
          value.map { |child| normalize(child) }
        when Time
          value.utc.iso8601(6)
        else
          value
        end
      end

      def json(value)
        JSON.generate(normalize(copy(value)))
      end

      def digest(value)
        Digest::SHA256.hexdigest(json(value))
      end

      def immutable(value)
        copied = copy(value)
        deep_freeze(copied)
      end

      def deep_freeze(value)
        case value
        when Hash
          value.each do |key, child|
            deep_freeze(key)
            deep_freeze(child)
          end
        when Array
          value.each { |child| deep_freeze(child) }
        end
        value.freeze
      end
      private_class_method :deep_freeze
    end
  end
end
