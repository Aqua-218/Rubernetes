# frozen_string_literal: true

require_relative "../../support/object_tree"

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

      def normalize(value, prefer_string_keys: false)
        case value
        when Hash
          fields = {}
          value.each_pair do |key, child|
            name = key.to_s
            fields[name] = child if !fields.key?(name) || (prefer_string_keys && key.is_a?(String))
          end
          fields.keys.sort.to_h { |name| [name, normalize(fields.fetch(name), prefer_string_keys: prefer_string_keys)] }
        when Array then value.map { |child| normalize(child, prefer_string_keys: prefer_string_keys) }
        when Time then value.utc.iso8601(6)
        else value
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

      def deep_freeze(value) = ObjectTree.deep_freeze(value)
      private_class_method :deep_freeze
    end
  end
end
