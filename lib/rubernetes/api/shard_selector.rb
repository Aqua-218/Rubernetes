# frozen_string_literal: true

require_relative "../security/cel"

module Rubernetes
  module API
    # Kubernetes v1.36.2 shard selectors select a fixed set of ranges over the
    # FNV-1a hash of one metadata field. CEL supplies syntax only.
    class ShardSelector
      class Error < StandardError; end

      GATE = "ShardedListAndWatch"
      FIELDS = %w[object.metadata.uid object.metadata.namespace].freeze
      FNV_OFFSET = 0xcbf29ce484222325
      FNV_PRIME = 0x100000001b3
      FNV_MASK = (1 << 64) - 1
      CEL_EXPRESSION_KINDS = {comprehension: 2, ident: 3, list: 4, literal: 5, map: 6, select: 7, struct: 8}.freeze

      def self.parse(expression)
        return if expression.nil? || expression.empty?

        source = expression.gsub(/\A[[:space:]]+|[[:space:]]+\z/, "")
        raise Error, "empty shard selector is not allowed; omit the parameter for unfiltered lists" if source.empty?
        # The default CEL parser bounds an expression to 100,000 code points.
        raise Error, "CEL parse error: expression code point size exceeds limit" if source.length > 100_000

        new(Security::CEL::Parser.new(source).parse)
      rescue Security::CEL::SyntaxError, ArgumentError => error
        raise Error, "CEL parse error: #{error.message}"
      end

      def initialize(ast)
        pending = [ast]
        ranges = []
        until pending.empty?
          type, name, left, right = pending.pop
          if type == :binary && name == "||"
            pending.push(right, left)
            next
          end

          ranges << parse_range(type, name, left, right)
        end
        first_field = ranges.first.first
        other_field = ranges.find { |field, _, _| field != first_field }&.first
        raise Error, "all shard ranges must use the same field, got #{first_field.inspect} and #{other_field.inspect}" if other_field

        @field = first_field.split(".").last.freeze
        @expression = ranges.map { |field, start, stop| "shardRange(#{field}, '#{start}', '#{stop}')" }.join(" || ").freeze
        @ranges = ranges.map { |_, start, stop| Range.new(start.to_i(16), stop.to_i(16), true).freeze }.freeze
        freeze
      end

      def matches?(object)
        metadata = object["metadata"] || object[:metadata] || {}
        value = (metadata[@field] || metadata[@field.to_sym]).to_s
        hash = value.each_byte.reduce(FNV_OFFSET) { |digest, byte| ((digest ^ byte) * FNV_PRIME) & FNV_MASK }
        @ranges.any? { |range| range.cover?(hash) }
      end

      def to_s = @expression

      private

      def parse_range(type, name, _target, arguments)
        if (kind = CEL_EXPRESSION_KINDS[type])
          raise Error, "unexpected expression kind #{kind}; expected shardRange() call or || operator"
        end

        unless type == :call && name == "shardRange"
          name = "_#{name}_" if type == :binary
          raise Error, "unsupported function #{name.inspect}; only shardRange() and || are allowed"
        end
        raise Error, "shardRange() requires exactly 3 arguments, got #{arguments.length}" unless arguments.length == 3

        field = parse_field(arguments[0])
        start = parse_bound(arguments[1], "hexStart")
        stop = parse_bound(arguments[2], "hexEnd")
        raise Error, "shard range start #{start} must be less than end #{stop}" unless start.to_i(16) < stop.to_i(16)

        [field, start, stop]
      end

      def parse_field(ast)
        parts = []
        while ast.first == :select && !ast[3]
          parts.unshift(ast[2])
          ast = ast[1]
        end
        raise Error, "shardRange() first argument: expected field path (e.g. object.metadata.uid)" unless ast.first == :ident

        path = ([ast[1]] + parts).join(".")
        raise Error, "unsupported field path #{path.inspect}; supported: #{FIELDS.join(", ")}" unless FIELDS.include?(path)

        path
      end

      def parse_bound(ast, name)
        type, value = ast
        raise Error, "#{name} must be a string literal (e.g. '0xff'), got expression kind #{CEL_EXPRESSION_KINDS.fetch(type, 1)}" unless type == :literal
        raise Error, "#{name} must be a string literal, got #{cel_literal_type(value)}" unless value.is_a?(String)
        raise Error, "#{name} must have '0x' prefix, got #{value.inspect}" unless value.start_with?("0x")

        hex = value.delete_prefix("0x")
        raise Error, "#{name}: hex value is required after '0x'" if hex.empty?
        raise Error, "#{name}: hex value too long (#{hex.bytesize} chars, max 17): #{hex.inspect}" if hex.bytesize > 17
        if (invalid = hex[/[^0-9a-f]/])
          raise Error, "#{name}: invalid hex character #{invalid.inspect} in #{value.inspect}"
        end

        if hex.length < 16
          padded = "0x#{hex.rjust(16, "0")}"
          raise Error, "#{name} must be a 0x-prefixed 16-digit hex value, got #{value.inspect} (did you mean #{padded.inspect}?)"
        end
        if hex.length == 17 && value != "0x10000000000000000"
          raise Error, "#{name}: 17-digit hex value must be '0x10000000000000000' (2^64), got #{value.inspect}"
        end

        value
      end

      def cel_literal_type(value)
        case value
        when Integer then "int64"
        when Float then "float64"
        when TrueClass, FalseClass then "bool"
        when Security::CEL::Values::UInt then "uint64"
        when Security::CEL::Values::Bytes then "[]uint8"
        when NilClass then "structpb.NullValue"
        end
      end
    end
  end
end
