# frozen_string_literal: true

require "digest"
require "ipaddr"
require "json"
require "securerandom"
require "time"

module Rubernetes
  module Network
    # Small policy-free helpers shared by the network components.  Input is
    # copied before it is retained so callers cannot mutate a durable view
    # after a transaction has been accepted.
    module Support
      module_function

      MISSING = Object.new.freeze

      def fetch(value, *keys, default: MISSING)
        keys.each do |key|
          return value[key] if value.respond_to?(:key?) && value.key?(key)

          string_key = key.to_s
          return value[string_key] if value.respond_to?(:key?) && value.key?(string_key)

          symbol_key = string_key.to_sym
          return value[symbol_key] if value.respond_to?(:key?) && value.key?(symbol_key)
        end
        return default unless default.equal?(MISSING)

        raise KeyError, "missing network field #{keys.join("/")}"
      end

      def string(value, name, allow_empty: false)
        result = String(value)
        if !allow_empty && result.empty?
          raise ValidationError, "#{name} must not be empty"
        end
        raise ValidationError, "#{name} contains a NUL byte" if result.include?("\0")

        result
      rescue TypeError
        raise ValidationError, "#{name} must be a string"
      end

      def integer(value, name, min: nil, max: nil)
        result = Integer(value)
        raise ValidationError, "#{name} must be at least #{min}" if min && result < min
        raise ValidationError, "#{name} must be at most #{max}" if max && result > max

        result
      rescue ArgumentError, TypeError
        raise ValidationError, "#{name} must be an integer"
      end

      def bool(value, default: false)
        return default if value.nil?
        return value if value == true || value == false
        return true if %w[true 1 yes on].include?(value.to_s.downcase)
        return false if %w[false 0 no off].include?(value.to_s.downcase)

        raise ValidationError, "boolean value expected, got #{value.inspect}"
      end

      # Sorted string keys, first key wins when two spell the same string.
      # The old form looked every sorted key up again with a linear scan --
      # quadratic per Hash -- and the network durable state is canonicalised
      # whole on every persist, a dozen or more times per Pod attach; it was
      # the node agent's single largest CPU consumer.
      # Subtrees sealed by #freeze_canonical are already in canonical form and
      # can never change, so they are shared instead of rebuilt.  Every
      # network state write canonicalised and round-tripped the whole node's
      # state (every operation of every Pod) about eighteen times per Pod
      # attach; now only the operation that changed is walked.
      CANONICAL = ObjectSpace::WeakMap.new

      def canonical(value)
        return value if (value.is_a?(Hash) || value.is_a?(Array)) && CANONICAL.key?(value)

        case value
        when Hash
          by_string = {}
          value.each do |key, child|
            string = key.to_s
            by_string[string] = child unless by_string.key?(string)
          end
          by_string.keys.sort.each_with_object({}) { |key, result| result[key] = canonical(by_string[key]) }
        when Array
          value.map { |child| canonical(child) }
        when IPAddr
          value.to_s
        when Time
          value.utc.iso8601(6)
        when Symbol
          value.to_s
        when String, Integer, Float, true, false, nil
          value
        else
          # Whatever else JSON would turn it into (what #copy used to do).
          JSON.parse(JSON.generate([value])).first
        end
      end

      # Deep-freezes a value produced by #canonical and records every Hash
      # and Array in it as canonical.  Shared subtrees already sealed are not
      # walked again.
      def freeze_canonical(value)
        case value
        when Hash
          return value if CANONICAL.key?(value)

          value.each_value { |child| freeze_canonical(child) }
          value.each_key(&:freeze)
          value.freeze
          CANONICAL[value] = true
        when Array
          return value if CANONICAL.key?(value)

          value.each { |child| freeze_canonical(child) }
          value.freeze
          CANONICAL[value] = true
        else
          value.freeze
        end
        value
      end

      # A mutable working copy whose two top levels (the state and its maps)
      # can be changed in place; every record below them is the sealed object
      # itself.  Records are replaced, never edited.
      def working_copy(value)
        return copy(value) unless value.is_a?(Hash)

        value.each_with_object({}) do |(key, child), result|
          result[key] = case child
                        when Hash then child.dup
                        when Array then child.dup
                        else child
                        end
        end
      end

      def copy(value)
        JSON.parse(JSON.generate(canonical(value)))
      end

      def immutable(value)
        copied = copy(value)
        freeze_deeply(copied)
      end

      # Public so a caller that already owns a private copy can seal it
      # without paying for another: DurableState hands back what it wrote,
      # and a JSON round trip of the whole state per write is what the node's
      # concurrent Pod starts were queueing behind.
      def freeze_deeply(value)
        case value
        when Hash
          value.each { |key, child| freeze_deeply(key); freeze_deeply(child) }
        when Array
          value.each { |child| freeze_deeply(child) }
        end
        value.freeze
      end

      def digest(value)
        Digest::SHA256.hexdigest(JSON.generate(canonical(value)))
      end

      def family(value)
        normalized = value.to_s.downcase
        return "ipv4" if %w[ipv4 v4 4 af_inet].include?(normalized)
        return "ipv6" if %w[ipv6 v6 6 af_inet6].include?(normalized)

        raise ValidationError, "unsupported address family #{value.inspect}"
      end

      def ip(value, name: "ip")
        address = value.is_a?(IPAddr) ? value : IPAddr.new(string(value, name))
        address
      rescue IPAddr::InvalidAddressError => error
        raise ValidationError, "#{name} is not a valid IP address: #{error.message}"
      end

      def cidr(value, name: "cidr")
        text = string(value, name)
        address = IPAddr.new(text)
        prefix = text.include?("/") ? Integer(text.split("/", 2).last) : (address.ipv4? ? 32 : 128)
        max = address.ipv4? ? 32 : 128
        raise ValidationError, "#{name} prefix must be between 0 and #{max}" unless (0..max).cover?(prefix)

        [IPAddr.new(address.mask(prefix).to_s), prefix]
      rescue IPAddr::InvalidAddressError, ArgumentError => error
        raise ValidationError, "#{name} is not a valid CIDR: #{error.message}"
      end

      def address_family(address)
        ip(address).ipv4? ? "ipv4" : "ipv6"
      end

      def now(clock)
        value = clock.call
        value.is_a?(Time) ? value.utc : Time.iso8601(value.to_s).utc
      end

      def identifier(value, name)
        string(value, name)
      end

      def symbolize(value)
        return value unless value.is_a?(Hash)

        value.each_with_object({}) { |(key, child), result| result[key.to_sym] = symbolize(child) }
      end

      # A caller may hand the network either a flat config or the Pod object
      # itself, in which case hostNetwork lives under `spec`.  Reading only
      # the flat spelling planned a veth pair for a host-network Pod, which
      # then collided in the kernel with EEXIST.
      def host_network?(config)
        hash = config.respond_to?(:to_h) ? config.to_h : config
        return false unless hash.is_a?(Hash)

        direct = fetch(hash, "hostNetwork", "host_network", default: nil)
        return bool(direct) unless direct.nil?

        spec = fetch(hash, "spec", default: nil)
        spec = spec.respond_to?(:to_h) ? spec.to_h : spec
        return false unless spec.is_a?(Hash)

        bool(fetch(spec, "hostNetwork", "host_network", default: false))
      end
    end
  end
end
