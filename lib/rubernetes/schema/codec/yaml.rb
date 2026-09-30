# frozen_string_literal: true

module Rubernetes
  module Schema
    class Codec
      # Psych is used only through safe_load.  Inspecting its node tree before
      # materialization gives strict YAML the same duplicate-key guarantee as
      # strict JSON while aliases and Ruby object tags remain disabled.
      module YAMLCodec
        module_function

        def load(input, strict: true, max_bytes: Codec::DEFAULT_MAX_BYTES, max_depth: Codec::DEFAULT_MAX_DEPTH)
          Codec.validate_body!(input, max_bytes)
          stream = Psych.parse_stream(input)
          documents = stream.children
          raise Codec::ParseError, "YAML input must contain exactly one document" if strict && documents.length > 1

          check_nodes!(stream, max_depth: max_depth, strict: strict)
          value = Psych.safe_load(
            input,
            permitted_classes: [],
            permitted_symbols: [],
            aliases: false,
            filename: "<codec>"
          )
          Codec.validate_depth!(value, max_depth)
          Codec.validate_finite_numbers!(value)
          value
        rescue Codec::Error
          raise
        rescue Psych::Exception, EncodingError, ArgumentError => error
          raise Codec::ParseError.new("invalid YAML: #{error.message}"), cause: error
        end

        def dump(object, canonical: false, max_bytes: Codec::DEFAULT_MAX_BYTES, max_depth: Codec::DEFAULT_MAX_DEPTH)
          normalized = Codec.normalize_value(object, max_depth: max_depth)
          Codec.validate_depth!(normalized, max_depth)
          normalized = sort_keys(normalized, max_depth: max_depth) if canonical
          output = Psych.dump(normalized, line_width: -1)
          Codec.validate_output!(output, max_bytes)
        rescue Codec::Error
          raise
        rescue Psych::Exception, EncodingError, TypeError => error
          raise Codec::EncodeError.new("cannot encode YAML: #{error.message}"), cause: error
        end

        def check_nodes!(node, max_depth:, strict:, depth: 0)
          raise Codec::LimitError, "codec nesting exceeds #{max_depth} levels" if depth > max_depth

          case node
          when Psych::Nodes::Stream, Psych::Nodes::Document
            node.children.each do |child|
              check_nodes!(child, max_depth: max_depth, strict: strict, depth: depth)
            end
          when Psych::Nodes::Mapping
            keys = {}
            node.children.each_slice(2) do |key_node, value_node|
              key = key_token(key_node)
              raise Codec::DuplicateKeyError, "duplicate YAML mapping key #{key.inspect}" if strict && key && keys.key?(key)

              keys[key] = true if key
              check_nodes!(key_node, max_depth: max_depth, strict: strict, depth: depth + 1)
              check_nodes!(value_node, max_depth: max_depth, strict: strict, depth: depth + 1)
            end
          when Psych::Nodes::Sequence
            node.children.each do |child|
              check_nodes!(child, max_depth: max_depth, strict: strict, depth: depth + 1)
            end
          when Psych::Nodes::Alias
            raise Codec::ParseError, "YAML aliases are disabled"
          end
        end

        def key_token(node)
          return unless node.is_a?(Psych::Nodes::Scalar)

          # A tag/style pair prevents a quoted "1" from colliding with the
          # plain scalar 1, while still catching the common duplicate-key case.
          [node.value, node.tag, node.style].freeze
        end

        def sort_keys(value, max_depth:, depth: 0)
          raise Codec::LimitError, "codec nesting exceeds #{max_depth} levels" if depth > max_depth

          case value
          when Array
            value.map { |child| sort_keys(child, max_depth: max_depth, depth: depth + 1) }
          when Hash
            value.keys.sort_by(&:to_s).to_h do |key|
              [key.to_s, sort_keys(value[key], max_depth: max_depth, depth: depth + 1)]
            end
          else
            value
          end
        end

        alias parse load
        alias generate dump
        module_function :parse, :generate
      end

      YAML = YAMLCodec unless const_defined?(:YAML, false)
      Yaml = YAMLCodec unless const_defined?(:Yaml, false)
    end
  end
end
