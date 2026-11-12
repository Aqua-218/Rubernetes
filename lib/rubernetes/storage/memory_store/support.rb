# frozen_string_literal: true

module Rubernetes
  module Storage
    # Copying, freezing and canonical encoding shared by the store's value objects.
    module MemoryStoreSupport
      module_function

      def deep_dup(value, seen = nil)
        case value
        when Hash
          return seen.fetch(value) if seen&.key?(value)

          duplicate = {}
          (seen ||= {}.compare_by_identity)[value] = duplicate
          value.each { |key, child| duplicate[deep_dup(key, seen)] = deep_dup(child, seen) }
          duplicate
        when Array
          return seen.fetch(value) if seen&.key?(value)

          duplicate = []
          (seen ||= {}.compare_by_identity)[value] = duplicate
          value.each { |child| duplicate << deep_dup(child, seen) }
          duplicate
        when String
          value.dup
        else
          value
        end
      end

      # Roots this module has deep-frozen itself.  An object that is known to
      # be frozen all the way down can be handed out as it is: every copy of a
      # stored object -- the response to a create, each item of a list, the
      # event for each of the watchers a write fans out to -- used to be a
      # fresh deep copy, about a quarter of a millisecond for a Pod, and a
      # write with twenty informers watching spent most of its 9 ms copying.
      DEEP_FROZEN = ObjectSpace::WeakMap.new

      def deep_freeze(value, seen = nil)
        return deep_freeze_walk(value, seen) if seen

        walked = !value.frozen? && (value.is_a?(Hash) || value.is_a?(Array))
        result = deep_freeze_walk(value, nil)
        DEEP_FROZEN[result] = true if walked
        result
      end

      def deep_frozen?(value)
        DEEP_FROZEN.key?(value)
      end

      def deep_freeze_walk(value, seen)
        return value if value.nil? || value.is_a?(Numeric) || value == true || value == false || value.frozen?
        return value if seen&.key?(value)

        (seen ||= {}.compare_by_identity)[value] = true
        case value
        when Hash
          value.each do |key, child|
            deep_freeze_walk(key, seen)
            deep_freeze_walk(child, seen)
          end
        when Array
          value.each { |child| deep_freeze_walk(child, seen) }
        end
        value.freeze
      end

      def immutable_copy(value)
        return value if DEEP_FROZEN.key?(value)

        deep_freeze(deep_dup(value))
      end

      def canonical(value)
        case value
        when Hash
          value.keys.map(&:to_s).zip(value.values).sort_by(&:first).to_h do |key, child|
            [key, canonical(child)]
          end
        when Array
          value.map { |child| canonical(child) }
        when Time
          value.utc.iso8601(9)
        when Proc
          {
            "__proc__" => value.source_location,
            "parameters" => value.parameters
          }
        when ExternalSelectorPredicate
          {"__selector__" => canonical(value.selector_signature)}
        else
          Shape.callable?(value) ? {"__callable__" => value.class.name, "inspect" => value.inspect} : value
        end
      end

      def digest(value)
        Digest::SHA256.hexdigest(canonical_json(value))
      end

      # Exactly the bytes JSON.generate(canonical(value)) produces -- digests
      # must stay comparable with those in a snapshot written before this
      # existed -- written straight into one buffer instead of through a tree
      # of sorted intermediate hashes, which cost more than the hashing did.
      def canonical_json(value, out = +"")
        case value
        when Hash
          by_key = {}
          value.each { |key, child| by_key[key.to_s] = child }
          out << "{"
          by_key.keys.sort.each_with_index do |key, index|
            out << "," unless index.zero?
            out << key.to_json << ":"
            canonical_json(by_key[key], out)
          end
          out << "}"
        when Array
          out << "["
          value.each_with_index do |child, index|
            out << "," unless index.zero?
            canonical_json(child, out)
          end
          out << "]"
        when String, Integer, Float, Symbol, true, false, nil
          out << value.to_json
        else
          out << JSON.generate(canonical(value))
        end
        out
      end

      # Array#pack is part of Ruby's core and keeps the M1 store independent of
      # the optional `base64` default gem removed from Ruby 3.4.
      def base64_url_encode(value)
        [value].pack("m0").tr("+/", "-_").delete("=")
      end

      def base64_url_decode(value)
        encoded = String(value).tr("-_", "+/")
        encoded += "=" * ((4 - (encoded.length % 4)) % 4)
        encoded.unpack1("m0")
      rescue ArgumentError, TypeError
        raise InvalidContinueToken
      end
    end
  end
end
