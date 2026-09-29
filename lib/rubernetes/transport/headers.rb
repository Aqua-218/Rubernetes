# frozen_string_literal: true

require_relative "errors"

module Rubernetes
  module Transport
    # A small case-insensitive header collection that keeps repeated fields.
    #
    # HTTP field names are case-insensitive, while a caller may still want to
    # retain the spelling it supplied when inspecting a request or response.
    class Headers
      include Enumerable

      TOKEN_PATTERN = /\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/.freeze
      MISSING = Object.new.freeze

      def initialize(source = nil)
        @fields = {}
        import(source) unless source.nil?
      end

      def add(name, value)
        field_name = validate_name(name)
        field_value = validate_value(value)
        entry = (@fields[field_name.downcase] ||= { name: field_name, values: [] })
        entry[:values] << field_value
        self
      end

      def []=(name, value)
        set(name, value)
      end

      def [](name)
        values = raw_values(name)
        return nil if values.empty?

        values.length == 1 ? values.first : values.dup
      end

      def set(name, value)
        field_name = validate_name(name)
        @fields.delete(field_name.downcase)
        Array(value).each { |entry| add(field_name, entry) }
        self
      end

      def delete(name)
        entry = @fields.delete(String(name).downcase)
        entry && (entry[:values].length == 1 ? entry[:values].first : entry[:values])
      end

      def include?(name)
        @fields.key?(String(name).downcase)
      end
      alias key? include?
      alias has_key? include?

      def fetch(name, default = MISSING, &block)
        return self[name] if include?(name)
        return block.call(name) if block
        return default unless default.equal?(MISSING)

        raise KeyError, "key not found: #{name.inspect}"
      end

      def raw_values(name)
        entry = @fields[String(name).downcase]
        entry ? entry[:values].dup : []
      end

      def each
        return enum_for(__method__) unless block_given?

        @fields.each_value do |entry|
          value = entry[:values].length == 1 ? entry[:values].first : entry[:values].join(", ")
          yield entry[:name], value
        end
        self
      end

      def each_pair(&block)
        each(&block)
      end

      def size
        @fields.size
      end
      alias length size

      def empty?
        @fields.empty?
      end

      def to_h
        each_with_object({}) { |(name, value), result| result[name] = value }
      end
      alias to_hash to_h

      def ==(other)
        case other
        when Headers
          to_h == other.to_h
        when Hash
          to_h == other
        else
          false
        end
      end

      def dup
        self.class.new(to_h)
      end

      private

      def import(source)
        case source
        when Headers
          source.each { |name, value| add(name, value) }
        when Hash
          source.each { |name, value| Array(value).each { |entry| add(name, entry) } }
        else
          unless source.respond_to?(:each)
            raise ArgumentError, "headers must be a Hash or Enumerable"
          end

          source.each do |entry|
            unless entry.respond_to?(:to_ary) && entry.to_ary.length == 2
              raise ArgumentError, "header entries must contain a name and value"
            end
            name, value = entry.to_ary
            Array(value).each { |item| add(name, item) }
          end
        end
      end

      def validate_name(name)
        field_name = String(name)
        return field_name if TOKEN_PATTERN.match?(field_name)

        raise ArgumentError, "invalid HTTP header name: #{field_name.inspect}"
      end

      def validate_value(value)
        field_value = String(value)
        if field_value.include?("\r") || field_value.include?("\n") || field_value.each_byte.any? { |byte| (byte < 0x20 && byte != 0x09) || byte == 0x7f }
          raise ArgumentError, "invalid HTTP header value"
        end

        field_value.strip
      end
    end
  end
end
